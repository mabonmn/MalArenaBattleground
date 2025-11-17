#!/usr/bin/env python3
"""
Extract EMBER features from challenge_ds files for analysis.

This script extracts EMBER features from all PE files in the challenge_ds directory
and saves them in a structured format for analysis and debugging classifier performance.
"""
import os
import sys
import time
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple
import traceback

try:
    import thrember
    HAVE_THREMBER = True
except ImportError:
    HAVE_THREMBER = False
    print("Error: thrember not found. Install with:")
    print("pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")
    sys.exit(1)


class ChallengeFeatureExtractor:
    """Extract EMBER features from challenge dataset files."""
    
    def __init__(self, max_bytes: int = 2_097_152):
        """Initialize the feature extractor."""
        self.max_bytes = max_bytes
        self.feature_extractor = thrember.features.PEFeatureExtractor()
        self.extraction_stats = {
            'total_files': 0,
            'successful_extractions': 0,
            'failed_extractions': 0,
            'total_time': 0.0
        }
        self.failed_files = []
    
    def extract_features_from_file(self, file_path: str) -> Tuple[np.ndarray, bool]:
        """
        Extract EMBER features from a single file.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Tuple of (features_array, success_flag)
        """
        try:
            with open(file_path, 'rb') as f:
                bytez = f.read(self.max_bytes)
            
            # Extract features using thrember
            features = self.feature_extractor.feature_vector(bytez)
            
            # Convert to numpy array and ensure consistent length
            if isinstance(features, (list, tuple)):
                features_array = np.array(features, dtype=np.float32)
            else:
                features_array = np.asarray(features, dtype=np.float32)
            
            # Ensure we have the expected number of features (EMBER should be 2381)
            expected_length = 2381
            if len(features_array) != expected_length:
                # Pad or truncate to expected length
                if len(features_array) < expected_length:
                    # Pad with zeros
                    padded = np.zeros(expected_length, dtype=np.float32)
                    padded[:len(features_array)] = features_array
                    features_array = padded
                else:
                    # Truncate
                    features_array = features_array[:expected_length]
            
            # Handle any NaN or infinite values
            features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)
            
            return features_array, True
            
        except Exception as e:
            # More specific error handling for known issues
            error_msg = str(e)
            if "'CertificateStore' object is not subscriptable" in error_msg:
                print(f"Certificate parsing error in {file_path} - using fallback")
            else:
                print(f"Failed to extract features from {file_path}: {error_msg}")
            
            self.failed_files.append((file_path, error_msg))
            # Return zero vector with expected number of features
            return np.zeros(2381, dtype=np.float32), False
    
    def process_directory(self, base_dir: str, label: int) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Process all files in a directory structure.
        
        Args:
            base_dir: Base directory (malware or goodware)
            label: 0 for goodware, 1 for malware
            
        Returns:
            Tuple of (features_matrix, labels_array, file_paths)
        """
        print(f"\nProcessing {base_dir} (label={label})...")
        
        all_features = []
        all_labels = []
        all_paths = []
        
        # Walk through all subdirectories and files
        for root, dirs, files in os.walk(base_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                
                print(f"Processing: {file_path}")
                start_time = time.time()
                
                features, success = self.extract_features_from_file(file_path)
                
                elapsed = time.time() - start_time
                self.extraction_stats['total_time'] += elapsed
                self.extraction_stats['total_files'] += 1
                
                if success:
                    self.extraction_stats['successful_extractions'] += 1
                else:
                    self.extraction_stats['failed_extractions'] += 1
                
                all_features.append(features)
                all_labels.append(label)
                all_paths.append(file_path)
                
                print(f"  Time: {elapsed:.3f}s, Success: {success}")
        
        return np.array(all_features), np.array(all_labels), all_paths
    
    def extract_all_features(self, challenge_ds_dir: str) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Extract features from all files in challenge_ds.
        
        Args:
            challenge_ds_dir: Path to challenge_ds directory
            
        Returns:
            Tuple of (features_matrix, labels_array, file_paths)
        """
        goodware_dir = os.path.join(challenge_ds_dir, 'goodware')
        malware_dir = os.path.join(challenge_ds_dir, 'malware')
        
        print("=== EMBER Feature Extraction for Challenge Dataset ===")
        print(f"Max file size: {self.max_bytes:,} bytes")
        print(f"Goodware directory: {goodware_dir}")
        print(f"Malware directory: {malware_dir}")
        
        # Process goodware (label=0)
        goodware_features, goodware_labels, goodware_paths = self.process_directory(goodware_dir, 0)
        
        # Process malware (label=1)  
        malware_features, malware_labels, malware_paths = self.process_directory(malware_dir, 1)
        
        # Combine all data
        all_features = np.vstack([goodware_features, malware_features])
        all_labels = np.hstack([goodware_labels, malware_labels])
        all_paths = goodware_paths + malware_paths
        
        return all_features, all_labels, all_paths
    
    def print_stats(self):
        """Print extraction statistics."""
        stats = self.extraction_stats
        print("\n=== Extraction Statistics ===")
        print(f"Total files processed: {stats['total_files']}")
        print(f"Successful extractions: {stats['successful_extractions']}")
        print(f"Failed extractions: {stats['failed_extractions']}")
        print(f"Success rate: {stats['successful_extractions']/stats['total_files']*100:.1f}%")
        print(f"Total processing time: {stats['total_time']:.2f}s")
        print(f"Average time per file: {stats['total_time']/stats['total_files']:.3f}s")
        
        if self.failed_files:
            print(f"\nFailed files ({len(self.failed_files)}):")
            for file_path, error in self.failed_files:
                print(f"  {file_path}: {error}")


def save_features(features: np.ndarray, labels: np.ndarray, paths: List[str], output_dir: str):
    """Save extracted features in multiple formats."""
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\nSaving features to {output_dir}...")
    
    # Save as numpy arrays (most efficient for ML)
    np.save(os.path.join(output_dir, 'challenge_features.npy'), features)
    np.save(os.path.join(output_dir, 'challenge_labels.npy'), labels)
    
    # Save paths as text file
    with open(os.path.join(output_dir, 'challenge_paths.txt'), 'w') as f:
        for path in paths:
            f.write(f"{path}\n")
    
    # Save as CSV for easy analysis (smaller sample due to size)
    print("Creating summary CSV...")
    df_summary = pd.DataFrame({
        'file_path': paths,
        'label': labels,
        'label_name': ['goodware' if l == 0 else 'malware' for l in labels]
    })
    
    # Add first 10 features as columns for quick inspection
    for i in range(min(10, features.shape[1])):
        df_summary[f'feature_{i}'] = features[:, i]
    
    df_summary.to_csv(os.path.join(output_dir, 'challenge_features_summary.csv'), index=False)
    
    # Save feature statistics
    feature_stats = pd.DataFrame({
        'feature_idx': range(features.shape[1]),
        'mean': np.mean(features, axis=0),
        'std': np.std(features, axis=0),
        'min': np.min(features, axis=0),
        'max': np.max(features, axis=0),
        'zero_count': np.sum(features == 0, axis=0)
    })
    feature_stats.to_csv(os.path.join(output_dir, 'feature_statistics.csv'), index=False)
    
    print(f"✓ Saved features: {features.shape[0]} samples, {features.shape[1]} features")
    print(f"✓ Label distribution: {np.sum(labels == 0)} goodware, {np.sum(labels == 1)} malware")


def main():
    """Main execution function."""
    challenge_ds_dir = '/home/benchodbaap/DataAna/challenge_ds'
    output_dir = '/home/benchodbaap/DataAna/challenge_features'
    
    if not os.path.exists(challenge_ds_dir):
        print(f"Error: Challenge dataset not found at {challenge_ds_dir}")
        sys.exit(1)
    
    # Initialize extractor
    extractor = ChallengeFeatureExtractor(max_bytes=2_097_152)
    
    # Extract features
    print("Starting feature extraction...")
    start_time = time.time()
    
    try:
        features, labels, paths = extractor.extract_all_features(challenge_ds_dir)
        
        # Print statistics
        extractor.print_stats()
        
        # Save results
        save_features(features, labels, paths, output_dir)
        
        total_time = time.time() - start_time
        print(f"\n=== Extraction Complete ===")
        print(f"Total time: {total_time:.2f}s")
        print(f"Output directory: {output_dir}")
        
    except KeyboardInterrupt:
        print("\nExtraction interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError during extraction: {e}")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()