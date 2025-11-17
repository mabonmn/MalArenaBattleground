#!/usr/bin/env python3
"""
Enhanced EMBER feature extraction with fallback extractor for challenge_ds files.

This script uses thrember as the primary extractor and falls back to a custom
LIEF-based extractor when thrember fails (e.g., certificate parsing issues).
"""
import os
import sys
import time
import math
import re
import numpy as np
import pandas as pd
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import traceback

try:
    import thrember
    HAVE_THREMBER = True
except ImportError:
    HAVE_THREMBER = False
    print("Error: thrember not found. Install with:")
    print("pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")

try:
    import lief
    HAVE_LIEF = True
except ImportError:
    HAVE_LIEF = False
    print("Warning: LIEF not found. Install with: pip install lief")

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    HAVE_PEFILE = False
    print("Warning: pefile not found. Install with: pip install pefile")


class FallbackPEExtractor:
    """
    Fallback PE feature extractor using LIEF and basic analysis.
    Extracts a subset of features that can be mapped to EMBER's 2381-feature space.
    """
    
    def __init__(self):
        """Initialize the fallback extractor."""
        self.ember_feature_size = 2381
    
    def extract_basic_features(self, bytez: bytes) -> np.ndarray:
        """Extract basic features from PE bytes using LIEF."""
        features = np.zeros(50, dtype=np.float32)  # Start with basic feature set
        
        try:
            # Parse with LIEF
            if not HAVE_LIEF:
                return self._extract_raw_features(bytez)
            
            binary = lief.PE.parse(list(bytez))
            if binary is None:
                return self._extract_raw_features(bytez)
            
            idx = 0
            
            # File size and virtual size
            features[idx] = len(bytez)
            idx += 1
            features[idx] = binary.virtual_size if hasattr(binary, 'virtual_size') else 0
            idx += 1
            
            # Entropy
            features[idx] = self._calculate_entropy(bytez)
            idx += 1
            
            # Header information
            if hasattr(binary, 'header'):
                features[idx] = binary.header.time_date_stamps if hasattr(binary.header, 'time_date_stamps') else 0
                idx += 1
                features[idx] = binary.header.numberof_sections if hasattr(binary.header, 'numberof_sections') else 0
                idx += 1
                features[idx] = binary.header.numberof_symbols if hasattr(binary.header, 'numberof_symbols') else 0
                idx += 1
                features[idx] = int(binary.header.characteristics) if hasattr(binary.header, 'characteristics') else 0
                idx += 1
            else:
                idx += 4
            
            # Optional header
            if hasattr(binary, 'optional_header'):
                oh = binary.optional_header
                features[idx] = oh.sizeof_code if hasattr(oh, 'sizeof_code') else 0
                idx += 1
                features[idx] = oh.sizeof_headers if hasattr(oh, 'sizeof_headers') else 0
                idx += 1
                features[idx] = oh.sizeof_image if hasattr(oh, 'sizeof_image') else 0
                idx += 1
                features[idx] = oh.imagebase if hasattr(oh, 'imagebase') else 0
                idx += 1
                features[idx] = oh.file_alignment if hasattr(oh, 'file_alignment') else 0
                idx += 1
                features[idx] = oh.major_operating_system_version if hasattr(oh, 'major_operating_system_version') else 0
                idx += 1
                features[idx] = oh.minor_operating_system_version if hasattr(oh, 'minor_operating_system_version') else 0
                idx += 1
                features[idx] = oh.major_image_version if hasattr(oh, 'major_image_version') else 0
                idx += 1
                features[idx] = oh.minor_image_version if hasattr(oh, 'minor_image_version') else 0
                idx += 1
            else:
                idx += 8
            
            # Boolean flags
            features[idx] = int(binary.has_imports) if hasattr(binary, 'has_imports') else 0
            idx += 1
            features[idx] = int(binary.has_exports) if hasattr(binary, 'has_exports') else 0
            idx += 1
            features[idx] = int(binary.has_resources) if hasattr(binary, 'has_resources') else 0
            idx += 1
            features[idx] = int(binary.has_relocations) if hasattr(binary, 'has_relocations') else 0
            idx += 1
            features[idx] = int(binary.has_debug) if hasattr(binary, 'has_debug') else 0
            idx += 1
            features[idx] = int(binary.has_tls) if hasattr(binary, 'has_tls') else 0
            idx += 1
            
            # Counts
            features[idx] = len(binary.imports) if hasattr(binary, 'imports') else 0
            idx += 1
            features[idx] = len(binary.exported_functions) if hasattr(binary, 'exported_functions') else 0
            idx += 1
            features[idx] = len(binary.sections) if hasattr(binary, 'sections') else 0
            idx += 1
            
            # String-based features
            string_features = self._extract_string_features(bytez)
            features[idx:idx+len(string_features)] = string_features[:min(len(string_features), len(features)-idx)]
            
        except Exception as e:
            print(f"LIEF extraction failed, using raw features: {e}")
            return self._extract_raw_features(bytez)
        
        return features
    
    def _extract_raw_features(self, bytez: bytes) -> np.ndarray:
        """Extract minimal features from raw bytes when LIEF fails."""
        features = np.zeros(50, dtype=np.float32)
        
        # Basic file properties
        features[0] = len(bytez)
        features[1] = self._calculate_entropy(bytez)
        
        # String-based features
        string_features = self._extract_string_features(bytez)
        features[2:2+len(string_features)] = string_features[:min(len(string_features), 48)]
        
        return features
    
    def _calculate_entropy(self, bytez: bytes) -> float:
        """Calculate Shannon entropy of byte sequence."""
        if not bytez:
            return 0.0
        
        # Count byte frequencies
        byte_counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(bytez)
        
        # Calculate entropy
        entropy = 0.0
        for p in probabilities:
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def _extract_string_features(self, bytez: bytes) -> np.ndarray:
        """Extract string-based features from binary."""
        features = np.zeros(20, dtype=np.float32)
        
        try:
            # String patterns
            paths = re.compile(b'c:\\\\', re.IGNORECASE)
            urls = re.compile(b'https?://', re.IGNORECASE)
            registry = re.compile(b'HKEY_')
            mz = re.compile(b'MZ')
            pe = re.compile(b'PE\x00\x00')
            
            features[0] = len(paths.findall(bytez))
            features[1] = len(urls.findall(bytez))
            features[2] = len(registry.findall(bytez))
            features[3] = len(mz.findall(bytez))
            features[4] = len(pe.findall(bytez))
            
            # Byte statistics
            byte_array = np.frombuffer(bytez, dtype=np.uint8)
            features[5] = np.mean(byte_array)
            features[6] = np.std(byte_array)
            features[7] = np.min(byte_array)
            features[8] = np.max(byte_array)
            
            # Null byte ratio
            features[9] = np.sum(byte_array == 0) / len(byte_array) if len(byte_array) > 0 else 0
            
            # Printable ASCII ratio
            printable_count = np.sum((byte_array >= 32) & (byte_array <= 126))
            features[10] = printable_count / len(byte_array) if len(byte_array) > 0 else 0
            
        except Exception as e:
            print(f"String feature extraction failed: {e}")
        
        return features
    
    def extract_features(self, bytez: bytes) -> np.ndarray:
        """
        Extract features and pad/map to EMBER's 2381-feature space.
        """
        # Extract basic features
        basic_features = self.extract_basic_features(bytez)
        
        # Create full feature vector (same size as EMBER)
        full_features = np.zeros(self.ember_feature_size, dtype=np.float32)
        
        # Map basic features to appropriate positions
        # Place core features at the beginning (file size, entropy, etc.)
        full_features[:len(basic_features)] = basic_features
        
        # Add some derived features in other positions
        if len(basic_features) > 2:  # If we have entropy
            # Spread some key features across the vector to match EMBER's structure
            full_features[100] = basic_features[0]  # File size
            full_features[200] = basic_features[2]  # Entropy
            full_features[500] = np.sum(basic_features[20:30])  # Sum of string features
            full_features[1000] = np.mean(basic_features[5:15])  # Mean of header features
        
        return full_features


class EnhancedChallengeFeatureExtractor:
    """Enhanced EMBER feature extractor with fallback capability."""
    
    def __init__(self, max_bytes: int = 2_097_152):
        """Initialize the enhanced extractor."""
        self.max_bytes = max_bytes
        
        # Primary extractor (thrember)
        if HAVE_THREMBER:
            self.primary_extractor = thrember.features.PEFeatureExtractor()
        else:
            self.primary_extractor = None
        
        # Fallback extractor
        self.fallback_extractor = FallbackPEExtractor()
        
        # Statistics
        self.extraction_stats = {
            'total_files': 0,
            'primary_success': 0,
            'fallback_success': 0,
            'total_failures': 0,
            'total_time': 0.0
        }
        self.failed_files = []
    
    def extract_features_from_file(self, file_path: str) -> Tuple[np.ndarray, str]:
        """
        Extract EMBER features from a single file using primary or fallback extractor.
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Tuple of (features_array, extraction_method)
        """
        try:
            with open(file_path, 'rb') as f:
                bytez = f.read(self.max_bytes)
            
            # Try primary extractor (thrember) first
            if self.primary_extractor is not None:
                try:
                    features = self.primary_extractor.feature_vector(bytez)
                    features_array = self._normalize_features(features, 2381)
                    return features_array, "primary"
                except Exception as e:
                    if "'CertificateStore' object is not subscriptable" in str(e):
                        # Known issue - try fallback
                        pass
                    else:
                        print(f"Primary extractor failed on {file_path}: {e}")
            
            # Try fallback extractor
            try:
                features_array = self.fallback_extractor.extract_features(bytez)
                return features_array, "fallback"
            except Exception as e:
                print(f"Fallback extractor failed on {file_path}: {e}")
                # Return zero vector as last resort
                return np.zeros(2381, dtype=np.float32), "zero"
                
        except Exception as e:
            print(f"File read failed for {file_path}: {e}")
            self.failed_files.append((file_path, str(e)))
            return np.zeros(2381, dtype=np.float32), "zero"
    
    def _normalize_features(self, features, expected_length: int) -> np.ndarray:
        """Normalize features to expected length."""
        if isinstance(features, (list, tuple)):
            features_array = np.array(features, dtype=np.float32)
        else:
            features_array = np.asarray(features, dtype=np.float32)
        
        # Ensure correct length
        if len(features_array) != expected_length:
            if len(features_array) < expected_length:
                # Pad with zeros
                padded = np.zeros(expected_length, dtype=np.float32)
                padded[:len(features_array)] = features_array
                features_array = padded
            else:
                # Truncate
                features_array = features_array[:expected_length]
        
        # Handle NaN/inf values
        features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)
        
        return features_array
    
    def process_directory(self, base_dir: str, label: int) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
        """
        Process all files in a directory structure.
        
        Args:
            base_dir: Base directory (malware or goodware)
            label: 0 for goodware, 1 for malware
            
        Returns:
            Tuple of (features_matrix, labels_array, file_paths, extraction_methods)
        """
        print(f"\nProcessing {base_dir} (label={label})...")
        
        all_features = []
        all_labels = []
        all_paths = []
        all_methods = []
        
        # Walk through all subdirectories and files
        for root, dirs, files in os.walk(base_dir):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                
                print(f"Processing: {file_path}")
                start_time = time.time()
                
                features, method = self.extract_features_from_file(file_path)
                
                elapsed = time.time() - start_time
                self.extraction_stats['total_time'] += elapsed
                self.extraction_stats['total_files'] += 1
                
                # Update statistics
                if method == "primary":
                    self.extraction_stats['primary_success'] += 1
                elif method == "fallback":
                    self.extraction_stats['fallback_success'] += 1
                else:
                    self.extraction_stats['total_failures'] += 1
                
                all_features.append(features)
                all_labels.append(label)
                all_paths.append(file_path)
                all_methods.append(method)
                
                print(f"  Time: {elapsed:.3f}s, Method: {method}")
        
        return np.array(all_features), np.array(all_labels), all_paths, all_methods
    
    def extract_all_features(self, challenge_ds_dir: str) -> Tuple[np.ndarray, np.ndarray, List[str], List[str]]:
        """
        Extract features from all files in challenge_ds.
        
        Args:
            challenge_ds_dir: Path to challenge_ds directory
            
        Returns:
            Tuple of (features_matrix, labels_array, file_paths, extraction_methods)
        """
        goodware_dir = os.path.join(challenge_ds_dir, 'goodware')
        malware_dir = os.path.join(challenge_ds_dir, 'malware')
        
        print("=== Enhanced EMBER Feature Extraction for Challenge Dataset ===")
        print(f"Max file size: {self.max_bytes:,} bytes")
        print(f"Primary extractor: {'thrember' if self.primary_extractor else 'None'}")
        print(f"Fallback extractor: Custom LIEF-based")
        print(f"Goodware directory: {goodware_dir}")
        print(f"Malware directory: {malware_dir}")
        
        # Process goodware (label=0)
        gw_features, gw_labels, gw_paths, gw_methods = self.process_directory(goodware_dir, 0)
        
        # Process malware (label=1)  
        mw_features, mw_labels, mw_paths, mw_methods = self.process_directory(malware_dir, 1)
        
        # Combine all data
        all_features = np.vstack([gw_features, mw_features])
        all_labels = np.hstack([gw_labels, mw_labels])
        all_paths = gw_paths + mw_paths
        all_methods = gw_methods + mw_methods
        
        return all_features, all_labels, all_paths, all_methods
    
    def print_stats(self):
        """Print extraction statistics."""
        stats = self.extraction_stats
        print("\n=== Enhanced Extraction Statistics ===")
        print(f"Total files processed: {stats['total_files']}")
        print(f"Primary extractor success: {stats['primary_success']} ({stats['primary_success']/stats['total_files']*100:.1f}%)")
        print(f"Fallback extractor success: {stats['fallback_success']} ({stats['fallback_success']/stats['total_files']*100:.1f}%)")
        print(f"Total failures: {stats['total_failures']} ({stats['total_failures']/stats['total_files']*100:.1f}%)")
        print(f"Overall success rate: {(stats['primary_success'] + stats['fallback_success'])/stats['total_files']*100:.1f}%")
        print(f"Total processing time: {stats['total_time']:.2f}s")
        print(f"Average time per file: {stats['total_time']/stats['total_files']:.3f}s")
        
        if self.failed_files:
            print(f"\nCompletely failed files ({len(self.failed_files)}):")
            for file_path, error in self.failed_files:
                print(f"  {file_path}: {error}")


def save_enhanced_features(features: np.ndarray, labels: np.ndarray, paths: List[str], 
                         methods: List[str], output_dir: str):
    """Save extracted features with extraction method information."""
    
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\nSaving enhanced features to {output_dir}...")
    
    # Save as numpy arrays
    np.save(os.path.join(output_dir, 'challenge_features_enhanced.npy'), features)
    np.save(os.path.join(output_dir, 'challenge_labels_enhanced.npy'), labels)
    
    # Save paths and methods
    with open(os.path.join(output_dir, 'challenge_paths_enhanced.txt'), 'w') as f:
        for path in paths:
            f.write(f"{path}\n")
    
    with open(os.path.join(output_dir, 'extraction_methods.txt'), 'w') as f:
        for method in methods:
            f.write(f"{method}\n")
    
    # Create enhanced summary CSV
    df_summary = pd.DataFrame({
        'file_path': paths,
        'label': labels,
        'label_name': ['goodware' if l == 0 else 'malware' for l in labels],
        'extraction_method': methods
    })
    
    # Add first 10 features
    for i in range(min(10, features.shape[1])):
        df_summary[f'feature_{i}'] = features[:, i]
    
    df_summary.to_csv(os.path.join(output_dir, 'challenge_features_enhanced_summary.csv'), index=False)
    
    # Method statistics
    method_stats = pd.DataFrame(pd.Series(methods).value_counts()).reset_index()
    method_stats.columns = ['extraction_method', 'count']
    method_stats.to_csv(os.path.join(output_dir, 'extraction_method_stats.csv'), index=False)
    
    print(f"✓ Saved enhanced features: {features.shape[0]} samples, {features.shape[1]} features")
    print(f"✓ Label distribution: {np.sum(labels == 0)} goodware, {np.sum(labels == 1)} malware")
    print(f"✓ Extraction methods: {dict(pd.Series(methods).value_counts())}")


def main():
    """Main execution function."""
    challenge_ds_dir = '/home/benchodbaap/DataAna/challenge_ds'
    output_dir = '/home/benchodbaap/DataAna/challenge_features_enhanced'
    
    if not os.path.exists(challenge_ds_dir):
        print(f"Error: Challenge dataset not found at {challenge_ds_dir}")
        sys.exit(1)
    
    # Initialize enhanced extractor
    extractor = EnhancedChallengeFeatureExtractor(max_bytes=2_097_152)
    
    # Extract features
    print("Starting enhanced feature extraction...")
    start_time = time.time()
    
    try:
        features, labels, paths, methods = extractor.extract_all_features(challenge_ds_dir)
        
        # Print statistics
        extractor.print_stats()
        
        # Save results
        save_enhanced_features(features, labels, paths, methods, output_dir)
        
        total_time = time.time() - start_time
        print(f"\n=== Enhanced Extraction Complete ===")
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