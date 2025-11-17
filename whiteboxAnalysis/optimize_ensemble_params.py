#!/usr/bin/env python3
"""
Ensemble Parameter Optimization Script

This script systematically tests different combinations of model thresholds and voting weights
to find the optimal configuration for the challenge dataset.

Optimization Goals:
- Maximize TPR (Target: ≥ 95%)
- Minimize FPR (Target: < 1%)
- Balance overall accuracy

Usage:
    python optimize_ensemble_params.py --challenge-dir challenge_ds --docker-port 9000
"""

import argparse
import csv
import itertools
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple
import requests
from collections import defaultdict


class EnsembleOptimizer:
    def __init__(self, challenge_dir: str, docker_port: int = 9000, docker_image: str = "mydefender"):
        self.challenge_dir = Path(challenge_dir)
        self.docker_port = docker_port
        self.docker_image = docker_image
        self.base_url = f"http://localhost:{docker_port}"
        self.results_dir = Path(__file__).parent / "OptimizationResults"
        self.results_dir.mkdir(exist_ok=True)
        
        # Container management
        self.current_container_id = None
        
    def stop_current_container(self):
        """Stop the currently running container if any"""
        if self.current_container_id:
            print(f"Stopping container {self.current_container_id[:12]}...")
            try:
                subprocess.run(
                    ["docker", "stop", self.current_container_id],
                    capture_output=True,
                    timeout=30
                )
            except Exception as e:
                print(f"Warning: Failed to stop container: {e}")
            self.current_container_id = None
            time.sleep(2)  # Give Docker time to clean up
    
    def start_container_with_params(self, params: Dict[str, float]) -> bool:
        """Start Docker container with specific parameter configuration"""
        self.stop_current_container()
        
        # Build environment variable arguments
        env_args = []
        for key, value in params.items():
            env_args.extend(["--env", f"{key}={value}"])
        
        # Start container
        cmd = [
            "docker", "run", "-d",
            "-p", f"{self.docker_port}:8080",
            "--memory=1g",
            "--cpus=1"
        ] + env_args + [self.docker_image]
        
        print(f"Starting container with params: {json.dumps(params, indent=2)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                print(f"Failed to start container: {result.stderr}")
                return False
            
            self.current_container_id = result.stdout.strip()
            print(f"Container started: {self.current_container_id[:12]}")
            
            # Wait for API to be ready
            max_retries = 30
            for i in range(max_retries):
                try:
                    response = requests.get(f"{self.base_url}/", timeout=2)
                    if response.status_code in [200, 404, 405]:  # Any response means it's up
                        print(f"API ready after {i+1} attempts")
                        return True
                except requests.exceptions.RequestException:
                    pass
                time.sleep(1)
            
            print("Warning: API did not become ready in time")
            return False
            
        except Exception as e:
            print(f"Error starting container: {e}")
            return False
    
    def classify_sample(self, file_path: Path) -> Tuple[int, float]:
        """Classify a single sample and return (prediction, time_taken)"""
        try:
            with open(file_path, 'rb') as f:
                start_time = time.time()
                response = requests.post(
                    self.base_url,
                    data=f.read(),
                    headers={'Content-Type': 'application/octet-stream'},
                    timeout=30
                )
                elapsed = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                return result.get('result', -1), elapsed
            else:
                return -1, elapsed
                
        except Exception as e:
            print(f"Error classifying {file_path.name}: {e}")
            return -1, 0.0
    
    def evaluate_configuration(self, params: Dict[str, float]) -> Dict:
        """Evaluate a specific parameter configuration on the challenge dataset"""
        print(f"\n{'='*60}")
        print(f"Evaluating configuration:")
        for key, value in params.items():
            print(f"  {key}: {value}")
        print(f"{'='*60}")
        
        # Start container with these parameters
        if not self.start_container_with_params(params):
            return {"error": "Failed to start container"}
        
        # Collect all samples
        results = []
        
        # Count total samples for progress tracking
        total_samples = 0
        goodware_samples = []
        malware_samples = []
        
        goodware_dir = self.challenge_dir / "goodware"
        if goodware_dir.exists():
            for folder in sorted(goodware_dir.iterdir()):
                if folder.is_dir():
                    for sample_file in folder.iterdir():
                        if sample_file.is_file():
                            goodware_samples.append(sample_file)
                            total_samples += 1
        
        malware_dir = self.challenge_dir / "malware"
        if malware_dir.exists():
            for folder in sorted(malware_dir.iterdir()):
                if folder.is_dir():
                    for sample_file in folder.iterdir():
                        if sample_file.is_file():
                            malware_samples.append(sample_file)
                            total_samples += 1
        
        print(f"Processing {len(goodware_samples)} goodware + {len(malware_samples)} malware = {total_samples} total samples")
        
        processed = 0
        
        # Process goodware
        for sample_file in goodware_samples:
            processed += 1
            print(f"  [{processed}/{total_samples}] {sample_file.name}...", end=" ")
            
            pred, elapsed = self.classify_sample(sample_file)
            if pred != -1:
                results.append({
                    "expected": 0,
                    "predicted": pred,
                    "time": elapsed,
                    "file": str(sample_file)
                })
                print(f"pred={pred}, time={elapsed:.2f}s")
            else:
                print("FAILED")
        
        # Process malware
        for sample_file in malware_samples:
            processed += 1
            print(f"  [{processed}/{total_samples}] {sample_file.name}...", end=" ")
            
            pred, elapsed = self.classify_sample(sample_file)
            if pred != -1:
                results.append({
                    "expected": 1,
                    "predicted": pred,
                    "time": elapsed,
                    "file": str(sample_file)
                })
                print(f"pred={pred}, time={elapsed:.2f}s")
            else:
                print("FAILED")
        
        # Calculate metrics
        if not results:
            return {"error": "No valid results"}
        
        tp = sum(1 for r in results if r["expected"] == 1 and r["predicted"] == 1)
        fp = sum(1 for r in results if r["expected"] == 0 and r["predicted"] == 1)
        fn = sum(1 for r in results if r["expected"] == 1 and r["predicted"] == 0)
        tn = sum(1 for r in results if r["expected"] == 0 and r["predicted"] == 0)
        
        total_malware = tp + fn
        total_goodware = fp + tn
        
        tpr = tp / total_malware if total_malware > 0 else 0
        fpr = fp / total_goodware if total_goodware > 0 else 0
        accuracy = (tp + tn) / len(results) if results else 0
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        f1 = 2 * (precision * tpr) / (precision + tpr) if (precision + tpr) > 0 else 0
        
        avg_time = sum(r["time"] for r in results) / len(results)
        
        metrics = {
            "params": params.copy(),
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "tpr": tpr,
            "fpr": fpr,
            "accuracy": accuracy,
            "precision": precision,
            "f1": f1,
            "avg_time": avg_time,
            "total_samples": len(results),
            "meets_competition_req": tpr >= 0.95 and fpr < 0.01
        }
        
        print(f"\nResults:")
        print(f"  TPR: {tpr*100:.2f}% (target: ≥95%)")
        print(f"  FPR: {fpr*100:.2f}% (target: <1%)")
        print(f"  Accuracy: {accuracy*100:.2f}%")
        print(f"  F1: {f1:.4f}")
        print(f"  Avg Time: {avg_time:.2f}s")
        print(f"  Competition Requirements: {'✓ PASS' if metrics['meets_competition_req'] else '✗ FAIL'}")
        
        return metrics
    
    def grid_search(self, param_grid: Dict[str, List[float]]) -> List[Dict]:
        """Perform grid search over parameter space"""
        # Generate all combinations
        param_names = list(param_grid.keys())
        param_values = list(param_grid.values())
        
        all_combinations = list(itertools.product(*param_values))
        total_combinations = len(all_combinations)
        
        print(f"\n{'='*60}")
        print(f"GRID SEARCH: {total_combinations} configurations to test")
        print(f"{'='*60}")
        
        results = []
        
        for idx, combination in enumerate(all_combinations, 1):
            params = dict(zip(param_names, combination))
            
            print(f"\n[{idx}/{total_combinations}]")
            
            metrics = self.evaluate_configuration(params)
            
            if "error" not in metrics:
                results.append(metrics)
                
                # Save intermediate results
                self.save_results(results, suffix="_intermediate")
        
        return results
    
    def random_search(self, param_ranges: Dict[str, Tuple[float, float, float]], 
                     n_iterations: int = 20) -> List[Dict]:
        """
        Perform random search over parameter space
        
        param_ranges: Dict mapping param name to (min, max, step)
        """
        import random
        
        print(f"\n{'='*60}")
        print(f"RANDOM SEARCH: {n_iterations} configurations to test")
        print(f"{'='*60}")
        
        results = []
        
        for idx in range(1, n_iterations + 1):
            # Generate random configuration
            params = {}
            for param_name, (min_val, max_val, step) in param_ranges.items():
                # Generate random value in range with step granularity
                n_steps = int((max_val - min_val) / step)
                random_step = random.randint(0, n_steps)
                params[param_name] = min_val + (random_step * step)
            
            print(f"\n[{idx}/{n_iterations}]")
            
            metrics = self.evaluate_configuration(params)
            
            if "error" not in metrics:
                results.append(metrics)
                
                # Save intermediate results
                self.save_results(results, suffix="_intermediate")
        
        return results
    
    def save_results(self, results: List[Dict], suffix: str = ""):
        """Save optimization results to CSV"""
        if not results:
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.results_dir / f"optimization_results{suffix}_{timestamp}.csv"
        
        # Flatten params into the main dict for easier CSV writing
        flattened_results = []
        for r in results:
            flat = {k: v for k, v in r.items() if k != "params"}
            flat.update(r["params"])
            flattened_results.append(flat)
        
        fieldnames = list(flattened_results[0].keys())
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(flattened_results)
        
        print(f"\nResults saved to: {output_file}")
    
    def print_best_results(self, results: List[Dict], top_n: int = 5):
        """Print the best configurations found"""
        if not results:
            print("No results to display")
            return
        
        print(f"\n{'='*60}")
        print(f"TOP {top_n} CONFIGURATIONS")
        print(f"{'='*60}")
        
        # Filter for configurations meeting competition requirements
        valid_results = [r for r in results if r.get("meets_competition_req", False)]
        
        if valid_results:
            print(f"\n✓ Configurations meeting competition requirements (TPR≥95%, FPR<1%):")
            # Sort by F1 score
            valid_results.sort(key=lambda x: x["f1"], reverse=True)
            
            for idx, r in enumerate(valid_results[:top_n], 1):
                print(f"\n{idx}. F1={r['f1']:.4f}, TPR={r['tpr']*100:.2f}%, FPR={r['fpr']*100:.2f}%, Acc={r['accuracy']*100:.2f}%")
                print(f"   Parameters:")
                for key, value in r["params"].items():
                    print(f"     {key}: {value}")
        else:
            print("\n⚠ No configurations met competition requirements")
            print("\nBest configurations by F1 score:")
            results.sort(key=lambda x: x["f1"], reverse=True)
            
            for idx, r in enumerate(results[:top_n], 1):
                meets_req = "✓" if r.get("meets_competition_req", False) else "✗"
                print(f"\n{idx}. {meets_req} F1={r['f1']:.4f}, TPR={r['tpr']*100:.2f}%, FPR={r['fpr']*100:.2f}%, Acc={r['accuracy']*100:.2f}%")
                print(f"   Parameters:")
                for key, value in r["params"].items():
                    print(f"     {key}: {value}")
    
    def cleanup(self):
        """Clean up resources"""
        self.stop_current_container()


def create_default_param_grid() -> Dict[str, List[float]]:
    """Create a default parameter grid for optimization"""
    return {
        "DF_ENSEMBLE_THRESHOLD": [0.5, 0.6, 0.7, 0.8],
        "DF_MALCONV_THRESH": [0.7, 0.8, 0.9],
        "DF_MALCONV_VOTE_WEIGHT": [0.5, 1.0, 1.5, 2.0],
        "DF_LIGHTGBM_THRESH": [0.7, 0.8, 0.9],
        "DF_LIGHTGBM_VOTE_WEIGHT": [0.5, 1.0, 1.5],
        "DF_LIGHTGBM800K_THRESH": [0.85, 0.90, 0.92, 0.95],
        "DF_LIGHTGBM800K_VOTE_WEIGHT": [0.3, 0.5, 0.7],
        "DF_STRINGCNN_THRESH": [0.5, 0.7, 0.9],
        "DF_STRINGCNN_VOTE_WEIGHT": [0.3, 0.5, 0.7],
    }


def create_focused_param_grid() -> Dict[str, List[float]]:
    """Create a more focused parameter grid based on current best settings"""
    return {
        "DF_ENSEMBLE_THRESHOLD": [0.6, 0.65, 0.7, 0.75],
        "DF_MALCONV_THRESH": [0.85, 0.88, 0.90, 0.92],
        "DF_MALCONV_VOTE_WEIGHT": [1.0, 1.25, 1.5],
        "DF_LIGHTGBM_THRESH": [0.85, 0.88, 0.90, 0.92],
        "DF_LIGHTGBM_VOTE_WEIGHT": [0.8, 1.0, 1.2],
        "DF_LIGHTGBM800K_THRESH": [0.88, 0.90, 0.92, 0.94],
        "DF_LIGHTGBM800K_VOTE_WEIGHT": [0.4, 0.5, 0.6],
        "DF_STRINGCNN_THRESH": [0.85, 0.88, 0.90, 0.92],
        "DF_STRINGCNN_VOTE_WEIGHT": [0.4, 0.5, 0.6],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Optimize ensemble model parameters for challenge dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Grid search with default parameters (coarse)
  python optimize_ensemble_params.py --challenge-dir challenge_ds --mode grid
  
  # Grid search with focused parameters (fine-tuning)
  python optimize_ensemble_params.py --challenge-dir challenge_ds --mode grid --focused
  
  # Random search (good for quick exploration)
  python optimize_ensemble_params.py --challenge-dir challenge_ds --mode random --iterations 30
  
  # Test a single configuration
  python optimize_ensemble_params.py --challenge-dir challenge_ds --mode single \\
    --params '{"DF_ENSEMBLE_THRESHOLD": 0.7, "DF_MALCONV_THRESH": 0.9}'
        """
    )
    
    parser.add_argument("--challenge-dir", default="challenge_ds",
                       help="Path to challenge dataset directory")
    parser.add_argument("--docker-port", type=int, default=9000,
                       help="Port to run Docker container on (default: 9000)")
    parser.add_argument("--docker-image", default="mydefender",
                       help="Docker image name (default: mydefender)")
    parser.add_argument("--mode", choices=["grid", "random", "single"], default="grid",
                       help="Optimization mode: grid search, random search, or single test")
    parser.add_argument("--focused", action="store_true",
                       help="Use focused parameter grid for fine-tuning (grid mode only)")
    parser.add_argument("--iterations", type=int, default=20,
                       help="Number of iterations for random search (default: 20)")
    parser.add_argument("--params", type=str,
                       help="JSON string of parameters for single mode, e.g., '{\"DF_ENSEMBLE_THRESHOLD\": 0.7}'")
    
    args = parser.parse_args()
    
    if not Path(args.challenge_dir).exists():
        print(f"Error: Challenge directory '{args.challenge_dir}' not found")
        sys.exit(1)
    
    optimizer = EnsembleOptimizer(args.challenge_dir, args.docker_port, args.docker_image)
    
    try:
        if args.mode == "grid":
            param_grid = create_focused_param_grid() if args.focused else create_default_param_grid()
            print(f"Parameter grid: {json.dumps(param_grid, indent=2)}")
            results = optimizer.grid_search(param_grid)
            
        elif args.mode == "random":
            # Define parameter ranges for random search
            param_ranges = {
                "DF_ENSEMBLE_THRESHOLD": (0.5, 0.9, 0.05),
                "DF_MALCONV_THRESH": (0.7, 0.95, 0.05),
                "DF_MALCONV_VOTE_WEIGHT": (0.5, 2.0, 0.25),
                "DF_LIGHTGBM_THRESH": (0.7, 0.95, 0.05),
                "DF_LIGHTGBM_VOTE_WEIGHT": (0.5, 2.0, 0.25),
                "DF_LIGHTGBM800K_THRESH": (0.85, 0.98, 0.02),
                "DF_LIGHTGBM800K_VOTE_WEIGHT": (0.3, 1.0, 0.1),
                "DF_STRINGCNN_THRESH": (0.5, 0.95, 0.05),
                "DF_STRINGCNN_VOTE_WEIGHT": (0.3, 1.0, 0.1),
            }
            results = optimizer.random_search(param_ranges, args.iterations)
            
        elif args.mode == "single":
            if not args.params:
                print("Error: --params required for single mode")
                sys.exit(1)
            
            try:
                params = json.loads(args.params)
            except json.JSONDecodeError as e:
                print(f"Error parsing params JSON: {e}")
                sys.exit(1)
            
            metrics = optimizer.evaluate_configuration(params)
            results = [metrics] if "error" not in metrics else []
        
        # Save and display results
        if results:
            optimizer.save_results(results)
            optimizer.print_best_results(results)
        else:
            print("No successful evaluations completed")
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    finally:
        optimizer.cleanup()


if __name__ == "__main__":
    main()
