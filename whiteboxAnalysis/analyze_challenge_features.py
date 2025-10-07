#!/usr/bin/env python3
"""
Analyze extracted EMBER features from challenge dataset.

This script provides insights into the types of files and their characteristics
to help understand classifier performance on different file types.
"""
import numpy as np
import pandas as pd
import os
from pathlib import Path

def analyze_challenge_features():
    """Analyze the extracted features and provide insights."""
    
    features_dir = '/home/benchodbaap/DataAna/challenge_features'
    
    print("=== Challenge Dataset Feature Analysis ===\n")
    
    # Load data
    features = np.load(os.path.join(features_dir, 'challenge_features.npy'))
    labels = np.load(os.path.join(features_dir, 'challenge_labels.npy'))
    
    with open(os.path.join(features_dir, 'challenge_paths.txt'), 'r') as f:
        paths = [line.strip() for line in f.readlines()]
    
    df_summary = pd.read_csv(os.path.join(features_dir, 'challenge_features_summary.csv'))
    
    print(f"Dataset Overview:")
    print(f"  Total samples: {len(features)}")
    print(f"  Goodware samples: {np.sum(labels == 0)}")
    print(f"  Malware samples: {np.sum(labels == 1)}")
    print(f"  Feature dimensions: {features.shape[1]}")
    print()
    
    # Identify files with failed feature extraction (all zeros)
    zero_features = np.all(features == 0, axis=1)
    print(f"Files with failed feature extraction: {np.sum(zero_features)}")
    
    failed_goodware = np.sum(zero_features & (labels == 0))
    failed_malware = np.sum(zero_features & (labels == 1))
    print(f"  Failed goodware: {failed_goodware}")
    print(f"  Failed malware: {failed_malware}")
    print()
    
    if np.sum(zero_features) > 0:
        print("Failed extraction files:")
        failed_paths = [paths[i] for i in range(len(paths)) if zero_features[i]]
        for path in failed_paths[:10]:  # Show first 10
            print(f"  {path}")
        if len(failed_paths) > 10:
            print(f"  ... and {len(failed_paths) - 10} more")
        print()
    
    # Analyze successful extractions
    successful_features = features[~zero_features]
    successful_labels = labels[~zero_features]
    successful_paths = [paths[i] for i in range(len(paths)) if not zero_features[i]]
    
    print(f"Successfully processed files: {len(successful_features)}")
    print(f"  Goodware: {np.sum(successful_labels == 0)}")
    print(f"  Malware: {np.sum(successful_labels == 1)}")
    print()
    
    # Feature analysis for successful extractions
    if len(successful_features) > 0:
        print("Feature Statistics (successful extractions only):")
        
        # File size analysis (feature 0 is typically file size)
        goodware_sizes = successful_features[successful_labels == 0, 0]
        malware_sizes = successful_features[successful_labels == 1, 0]
        
        print(f"File Size Analysis:")
        print(f"  Goodware sizes - Mean: {np.mean(goodware_sizes):,.0f} bytes, "
              f"Std: {np.std(goodware_sizes):,.0f}, "
              f"Range: {np.min(goodware_sizes):,.0f} - {np.max(goodware_sizes):,.0f}")
        print(f"  Malware sizes  - Mean: {np.mean(malware_sizes):,.0f} bytes, "
              f"Std: {np.std(malware_sizes):,.0f}, "
              f"Range: {np.min(malware_sizes):,.0f} - {np.max(malware_sizes):,.0f}")
        print()
        
        # Entropy analysis (feature 1 is typically entropy)
        goodware_entropy = successful_features[successful_labels == 0, 1]
        malware_entropy = successful_features[successful_labels == 1, 1]
        
        print(f"Entropy Analysis:")
        print(f"  Goodware entropy - Mean: {np.mean(goodware_entropy):.3f}, "
              f"Std: {np.std(goodware_entropy):.3f}, "
              f"Range: {np.min(goodware_entropy):.3f} - {np.max(goodware_entropy):.3f}")
        print(f"  Malware entropy  - Mean: {np.mean(malware_entropy):.3f}, "
              f"Std: {np.std(malware_entropy):.3f}, "
              f"Range: {np.min(malware_entropy):.3f} - {np.max(malware_entropy):.3f}")
        print()
    
    # Analyze by directory structure
    print("Analysis by Directory Structure:")
    path_analysis = {}
    
    for i, path in enumerate(paths):
        # Extract directory number (e.g., /path/malware/3/file -> "malware_3")
        parts = Path(path).parts
        if 'malware' in parts:
            dir_idx = parts.index('malware')
            if len(parts) > dir_idx + 1:
                dir_key = f"malware_{parts[dir_idx + 1]}"
            else:
                dir_key = "malware_unknown"
        elif 'goodware' in parts:
            dir_idx = parts.index('goodware')
            if len(parts) > dir_idx + 1:
                dir_key = f"goodware_{parts[dir_idx + 1]}"
            else:
                dir_key = "goodware_unknown"
        else:
            dir_key = "unknown"
        
        if dir_key not in path_analysis:
            path_analysis[dir_key] = {
                'count': 0,
                'failed_extraction': 0,
                'avg_size': 0,
                'avg_entropy': 0
            }
        
        path_analysis[dir_key]['count'] += 1
        if zero_features[i]:
            path_analysis[dir_key]['failed_extraction'] += 1
        else:
            path_analysis[dir_key]['avg_size'] += features[i, 0]
            path_analysis[dir_key]['avg_entropy'] += features[i, 1]
    
    # Calculate averages
    for key, data in path_analysis.items():
        successful_count = data['count'] - data['failed_extraction']
        if successful_count > 0:
            data['avg_size'] /= successful_count
            data['avg_entropy'] /= successful_count
        else:
            data['avg_size'] = 0
            data['avg_entropy'] = 0
    
    # Sort by type and directory number
    sorted_dirs = sorted(path_analysis.keys(), key=lambda x: (x.split('_')[0], int(x.split('_')[1]) if x.split('_')[1].isdigit() else 999))
    
    for dir_key in sorted_dirs:
        data = path_analysis[dir_key]
        failure_rate = (data['failed_extraction'] / data['count']) * 100
        print(f"  {dir_key}: {data['count']} files, "
              f"{failure_rate:.1f}% failed extraction, "
              f"avg size: {data['avg_size']:,.0f} bytes, "
              f"avg entropy: {data['avg_entropy']:.3f}")
    
    print()
    
    # Recommendations
    print("=== Analysis Summary & Recommendations ===")
    print()
    
    if np.sum(zero_features) > 0:
        print("1. Feature Extraction Issues:")
        print(f"   - {np.sum(zero_features)} files ({np.sum(zero_features)/len(features)*100:.1f}%) failed feature extraction")
        print("   - These files have certificate parsing issues in thrember")
        print("   - Consider using alternative feature extraction methods for these files")
        print("   - Or handle these cases explicitly in your classifier")
        print()
    
    print("2. File Characteristics:")
    if len(successful_features) > 0:
        if np.mean(goodware_sizes) > np.mean(malware_sizes):
            print("   - Goodware files are generally larger than malware")
        else:
            print("   - Malware files are generally larger than goodware")
        
        if np.mean(goodware_entropy) > np.mean(malware_entropy):
            print("   - Goodware has higher entropy (more randomness/compression)")
        else:
            print("   - Malware has higher entropy (more randomness/packing)")
        print()
    
    print("3. Directory-specific Issues:")
    high_failure_dirs = [k for k, v in path_analysis.items() if v['failed_extraction'] / v['count'] > 0.5]
    if high_failure_dirs:
        print("   - Directories with high extraction failure rates:")
        for dir_key in high_failure_dirs:
            data = path_analysis[dir_key]
            failure_rate = (data['failed_extraction'] / data['count']) * 100
            print(f"     {dir_key}: {failure_rate:.1f}% failure rate")
        print()
    
    print("4. For Classifier Analysis:")
    print("   - Use challenge_features.npy and challenge_labels.npy for ML analysis")
    print("   - Filter out zero-feature samples or treat them separately")
    print("   - Consider the directory structure for understanding sample types")
    print("   - Focus on files where your classifier gives wrong predictions")


if __name__ == "__main__":
    analyze_challenge_features()