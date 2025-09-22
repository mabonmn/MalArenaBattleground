#!/usr/bin/env python3
"""
Challenge Dataset Evaluation Script

This script evaluates the Docker malware classifier against the challenge dataset,
calculating accuracy per folder and overall metrics.

Expected API: POST http://localhost:9000/ with PE file, returns {"result": 0/1}
"""

import os
import requests
import json
import time
import csv
from pathlib import Path
from collections import defaultdict
import argparse
import sys


class ChallengeEvaluator:
    def __init__(self, base_url="http://localhost:9000", challenge_dir="challenge_ds"):
        self.base_url = base_url
        self.challenge_dir = Path(challenge_dir)
        self.results = []
        self.folder_stats = defaultdict(lambda: {"correct": 0, "total": 0, "samples": []})
        
    def classify_sample(self, file_path):
        """Classify a single sample using the Docker API"""
        try:
            with open(file_path, 'rb') as f:
                response = requests.post(
                    self.base_url,
                    data=f.read(),
                    headers={'Content-Type': 'application/octet-stream'},
                    timeout=10
                )
            
            if response.status_code == 200:
                result = response.json()
                return result.get('result', -1)
            else:
                print(f"API error for {file_path}: {response.status_code}")
                return -1
                
        except Exception as e:
            print(f"Error classifying {file_path}: {e}")
            return -1
    
    def evaluate_folder(self, folder_type, folder_num):
        """Evaluate all samples in a specific folder"""
        folder_path = self.challenge_dir / folder_type / str(folder_num)
        
        if not folder_path.exists():
            print(f"Folder {folder_path} does not exist")
            return
            
        expected_label = 0 if folder_type == "goodware" else 1
        folder_key = f"{folder_type}/{folder_num}"
        
        print(f"\nEvaluating {folder_key}...")
        
        samples = sorted([f for f in folder_path.iterdir() if f.is_file()])
        
        for sample_file in samples:
            print(f"  Classifying {sample_file.name}...", end=" ")
            
            start_time = time.time()
            predicted_label = self.classify_sample(sample_file)
            classification_time = time.time() - start_time
            
            if predicted_label == -1:
                print("FAILED")
                continue
                
            is_correct = predicted_label == expected_label
            print(f"{'✓' if is_correct else '✗'} (pred: {predicted_label}, actual: {expected_label}, {classification_time:.2f}s)")
            
            # Store detailed results
            result = {
                "folder": folder_key,
                "sample": sample_file.name,
                "file_path": str(sample_file),
                "expected": expected_label,
                "predicted": predicted_label,
                "correct": is_correct,
                "time_seconds": classification_time
            }
            self.results.append(result)
            
            # Update folder statistics
            self.folder_stats[folder_key]["total"] += 1
            if is_correct:
                self.folder_stats[folder_key]["correct"] += 1
            self.folder_stats[folder_key]["samples"].append(result)
    
    def run_evaluation(self):
        """Run complete evaluation on all folders"""
        print("Starting Challenge Dataset Evaluation")
        print("=" * 50)
        
        # Check if API is running
        try:
            response = requests.get(f"{self.base_url.replace('http://', 'http://').replace(':9000', ':9000')}")
            print(f"API connection test: {response.status_code}")
        except Exception as e:
            print(f"Warning: Could not connect to API at {self.base_url}: {e}")
            print("Make sure your Docker container is running:")
            print("  docker run --rm -p 9000:9000 mydefender")
            return False
        
        # Evaluate goodware folders
        goodware_folders = sorted([int(d.name) for d in (self.challenge_dir / "goodware").iterdir() if d.is_dir()])
        for folder_num in goodware_folders:
            self.evaluate_folder("goodware", folder_num)
        
        # Evaluate malware folders  
        malware_folders = sorted([int(d.name) for d in (self.challenge_dir / "malware").iterdir() if d.is_dir()])
        for folder_num in malware_folders:
            self.evaluate_folder("malware", folder_num)
        
        return True
    
    def calculate_metrics(self):
        """Calculate and display detailed metrics"""
        print("\n" + "=" * 60)
        print("EVALUATION RESULTS")
        print("=" * 60)
        
        # Per-folder accuracy
        print("\nPER-FOLDER ACCURACY:")
        print("-" * 40)
        
        goodware_accuracies = []
        malware_accuracies = []
        
        for folder_key in sorted(self.folder_stats.keys()):
            stats = self.folder_stats[folder_key]
            accuracy = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
            print(f"{folder_key:12}: {stats['correct']:2}/{stats['total']:2} = {accuracy:6.1%}")
            
            if folder_key.startswith("goodware"):
                goodware_accuracies.append(accuracy)
            else:
                malware_accuracies.append(accuracy)
        
        # Average accuracies
        print("\nAVERAGE ACCURACIES:")
        print("-" * 40)
        
        if goodware_accuracies:
            goodware_avg = sum(goodware_accuracies) / len(goodware_accuracies)
            print(f"Goodware Average: {goodware_avg:6.1%} (across {len(goodware_accuracies)} folders)")
        
        if malware_accuracies:
            malware_avg = sum(malware_accuracies) / len(malware_accuracies)
            print(f"Malware Average:  {malware_avg:6.1%} (across {len(malware_accuracies)} folders)")
        
        if goodware_accuracies and malware_accuracies:
            overall_avg = (goodware_avg + malware_avg) / 2
            print(f"Overall Average:  {overall_avg:6.1%}")
        
        # Overall metrics
        total_correct = sum([r["correct"] for r in self.results])
        total_samples = len(self.results)
        
        if total_samples > 0:
            overall_accuracy = total_correct / total_samples
            
            # Calculate precision, recall, F1 for malware detection
            tp = sum([1 for r in self.results if r["expected"] == 1 and r["predicted"] == 1])
            fp = sum([1 for r in self.results if r["expected"] == 0 and r["predicted"] == 1])
            fn = sum([1 for r in self.results if r["expected"] == 1 and r["predicted"] == 0])
            tn = sum([1 for r in self.results if r["expected"] == 0 and r["predicted"] == 0])
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
            
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            
            print("\nOVERALL METRICS:")
            print("-" * 40)
            print(f"Total Samples:    {total_samples}")
            print(f"Overall Accuracy: {overall_accuracy:6.1%}")
            print(f"Precision:        {precision:6.1%}")
            print(f"Recall (TPR):     {recall:6.1%}")
            print(f"F1-Score:         {f1:6.1%}")
            print(f"False Pos Rate:   {fpr:6.1%}")
            
            avg_time = sum([r["time_seconds"] for r in self.results]) / len(self.results)
            print(f"Avg Time/Sample:  {avg_time:.2f}s")
    
    def save_results(self, output_file="challenge_evaluation_results.csv"):
        """Save detailed results to CSV"""
        if not self.results:
            print("No results to save")
            return
            
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ["folder", "sample", "file_path", "expected", "predicted", "correct", "time_seconds"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)
        
        print(f"\nDetailed results saved to: {output_file}")
        
        # Also save summary
        summary_file = output_file.replace('.csv', '_summary.csv')
        with open(summary_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Folder", "Correct", "Total", "Accuracy"])
            
            goodware_accuracies = []
            malware_accuracies = []
            
            for folder_key in sorted(self.folder_stats.keys()):
                stats = self.folder_stats[folder_key]
                accuracy = stats["correct"] / stats["total"] if stats["total"] > 0 else 0
                writer.writerow([folder_key, stats["correct"], stats["total"], f"{accuracy:.3f}"])
                
                if folder_key.startswith("goodware"):
                    goodware_accuracies.append(accuracy)
                else:
                    malware_accuracies.append(accuracy)
            
            # Add average rows
            writer.writerow([])  # Empty row for separation
            if goodware_accuracies:
                goodware_avg = sum(goodware_accuracies) / len(goodware_accuracies)
                writer.writerow([f"GOODWARE_AVERAGE ({len(goodware_accuracies)} folders)", "", "", f"{goodware_avg:.3f}"])
            
            if malware_accuracies:
                malware_avg = sum(malware_accuracies) / len(malware_accuracies)
                writer.writerow([f"MALWARE_AVERAGE ({len(malware_accuracies)} folders)", "", "", f"{malware_avg:.3f}"])
            
            if goodware_accuracies and malware_accuracies:
                overall_avg = (goodware_avg + malware_avg) / 2
                writer.writerow([f"OVERALL_AVERAGE", "", "", f"{overall_avg:.3f}"])
        
        print(f"Summary results saved to: {summary_file}")


def main():
    parser = argparse.ArgumentParser(description="Evaluate Docker malware classifier on challenge dataset")
    parser.add_argument("--url", default="http://localhost:9000", 
                       help="Base URL for the Docker API (default: http://localhost:9000)")
    parser.add_argument("--challenge-dir", default="challenge_ds",
                       help="Path to challenge dataset directory (default: challenge_ds)")
    parser.add_argument("--output", default="challenge_evaluation_results.csv",
                       help="Output CSV file for results (default: challenge_evaluation_results.csv)")
    
    args = parser.parse_args()
    
    if not Path(args.challenge_dir).exists():
        print(f"Error: Challenge directory '{args.challenge_dir}' not found")
        print("Make sure you've extracted challenge.zip first")
        sys.exit(1)
    
    evaluator = ChallengeEvaluator(args.url, args.challenge_dir)
    
    if evaluator.run_evaluation():
        evaluator.calculate_metrics()
        evaluator.save_results(args.output)
    else:
        print("Evaluation failed - check API connection")
        sys.exit(1)


if __name__ == "__main__":
    main()