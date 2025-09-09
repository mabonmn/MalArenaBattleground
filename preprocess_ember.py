#!/usr/bin/env python3
"""
EMBER Dataset Preprocessing Script for Malware Detection

This script preprocesses the EMBER 2018 dataset for LightGBM training.
It handles feature extraction, data cleaning, and creates balanced samples
for initial testing with 200 samples before full-scale training.

Requirements:
- ember library (pip install git+https://github.com/elastic/ember.git)
- numpy, pandas, scikit-learn, lightgbm

Author: Malware Detection Training Script
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Tuple, List, Dict, Any
import pickle
import psutil
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('preprocessing.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class EmberPreprocessor:
    """
    Handles EMBER dataset preprocessing with memory-efficient techniques
    """
    
    def __init__(self, data_dir: str, sample_size: int = 200):
        """
        Initialize preprocessor
        
        Args:
            data_dir: Directory containing EMBER dataset files
            sample_size: Number of samples for initial training (default: 200)
        """
        self.data_dir = Path(data_dir)
        self.sample_size = sample_size
        self.feature_dim = 2381  # EMBER feature dimension
        
        # Memory monitoring
        self.memory_threshold = 0.8  # 80% memory usage threshold
        
        logger.info(f"Initialized EMBER preprocessor for {sample_size} samples")
        logger.info(f"Available RAM: {psutil.virtual_memory().total / (1024**3):.2f} GB")
    
    def monitor_memory(self) -> None:
        """Monitor memory usage and warn if approaching limits"""
        memory = psutil.virtual_memory()
        memory_percent = memory.percent / 100
        
        if memory_percent > self.memory_threshold:
            logger.warning(f"Memory usage: {memory_percent:.1%}")
            logger.warning("Consider reducing batch size or sample count")
    
    def load_ember_features(self) -> Tuple[np.ndarray, np.ndarray]:
        """
        Load and vectorize EMBER features from JSON files
        
        Returns:
            X: Feature matrix (n_samples, n_features)
            y: Labels (n_samples,)
        """
        logger.info("Loading EMBER dataset...")
        
        try:
            import ember
            
            # Check if vectorized features already exist
            vectorized_path = self.data_dir / "X_train.dat"
            labels_path = self.data_dir / "y_train.dat"
            
            if not (vectorized_path.exists() and labels_path.exists()):
                logger.info("Vectorizing raw EMBER features...")
                ember.create_vectorized_features(str(self.data_dir))
            
            # Load vectorized features
            logger.info("Loading vectorized features...")
            X_train, y_train, X_test, y_test = ember.read_vectorized_features(str(self.data_dir))
            
            # Combine train and test for sampling
            X = np.vstack([X_train, X_test])
            y = np.hstack([y_train, y_test])
            
            logger.info(f"Loaded {X.shape[0]} samples with {X.shape[1]} features")
            
            return X, y
            
        except ImportError as e:
            logger.error("EMBER library not installed. Please install with:")
            logger.error("pip install git+https://github.com/elastic/ember.git")
            raise e
        except Exception as e:
            logger.error(f"Error loading EMBER features: {e}")
            raise e
    
    def clean_data(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Clean the dataset by removing unlabeled samples and handling missing values
        
        Args:
            X: Feature matrix
            y: Labels (-1: unlabeled, 0: benign, 1: malicious)
        
        Returns:
            Cleaned X and y arrays
        """
        logger.info("Cleaning dataset...")
        
        # Remove unlabeled samples (y == -1)
        labeled_mask = (y != -1)
        X_clean = X[labeled_mask]
        y_clean = y[labeled_mask]
        
        logger.info(f"Removed {np.sum(~labeled_mask)} unlabeled samples")
        
        # Handle missing values (replace with median)
        nan_mask = np.isnan(X_clean)
        if np.any(nan_mask):
            logger.info(f"Found {np.sum(nan_mask)} missing values")
            
            # Calculate median for each feature
            medians = np.nanmedian(X_clean, axis=0)
            
            # Replace NaN values with medians
            for i in range(X_clean.shape[1]):
                X_clean[nan_mask[:, i], i] = medians[i]
        
        # Handle infinite values
        inf_mask = ~np.isfinite(X_clean)
        if np.any(inf_mask):
            logger.info(f"Found {np.sum(inf_mask)} infinite values")
            X_clean[inf_mask] = 0
        
        logger.info(f"Cleaned dataset: {X_clean.shape[0]} samples, {X_clean.shape[1]} features")
        logger.info(f"Class distribution - Malicious: {np.sum(y_clean == 1)}, Benign: {np.sum(y_clean == 0)}")
        
        return X_clean, y_clean
    
    def create_balanced_sample(self, X: np.ndarray, y: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Create a balanced sample for initial training
        
        Args:
            X: Feature matrix
            y: Labels
        
        Returns:
            Balanced sample of X and y
        """
        logger.info(f"Creating balanced sample of {self.sample_size} samples...")
        
        # Get indices for each class
        malicious_indices = np.where(y == 1)[0]
        benign_indices = np.where(y == 0)[0]
        
        # Sample equal numbers from each class
        n_per_class = self.sample_size // 2
        
        # Randomly sample from each class
        np.random.seed(42)  # For reproducibility
        
        if len(malicious_indices) >= n_per_class:
            mal_sample_idx = np.random.choice(malicious_indices, n_per_class, replace=False)
        else:
            logger.warning(f"Not enough malicious samples. Using all {len(malicious_indices)} available")
            mal_sample_idx = malicious_indices
        
        if len(benign_indices) >= n_per_class:
            ben_sample_idx = np.random.choice(benign_indices, n_per_class, replace=False)
        else:
            logger.warning(f"Not enough benign samples. Using all {len(benign_indices)} available")
            ben_sample_idx = benign_indices
        
        # Combine indices
        sample_indices = np.concatenate([mal_sample_idx, ben_sample_idx])
        np.random.shuffle(sample_indices)  # Shuffle the combined sample
        
        X_sample = X[sample_indices]
        y_sample = y[sample_indices]
        
        logger.info(f"Created balanced sample: {len(sample_indices)} samples")
        logger.info(f"Sample class distribution - Malicious: {np.sum(y_sample == 1)}, Benign: {np.sum(y_sample == 0)}")
        
        return X_sample, y_sample
    
    def save_preprocessed_data(self, X: np.ndarray, y: np.ndarray, suffix: str = "sample") -> None:
        """
        Save preprocessed data to files
        
        Args:
            X: Feature matrix
            y: Labels
            suffix: File suffix for identification
        """
        output_dir = self.data_dir / "preprocessed"
        output_dir.mkdir(exist_ok=True)
        
        # Save as compressed numpy arrays
        X_path = output_dir / f"X_{suffix}.npz"
        y_path = output_dir / f"y_{suffix}.npz"
        
        np.savez_compressed(X_path, X=X)
        np.savez_compressed(y_path, y=y)
        
        # Save metadata
        metadata = {
            'n_samples': X.shape[0],
            'n_features': X.shape[1],
            'n_malicious': np.sum(y == 1),
            'n_benign': np.sum(y == 0),
            'feature_dim': self.feature_dim
        }
        
        metadata_path = output_dir / f"metadata_{suffix}.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Saved preprocessed data to {output_dir}")
        logger.info(f"Files: {X_path.name}, {y_path.name}, {metadata_path.name}")
    
    def run_preprocessing(self, create_sample: bool = True) -> None:
        """
        Run the complete preprocessing pipeline
        
        Args:
            create_sample: Whether to create a small sample for testing
        """
        logger.info("Starting EMBER preprocessing pipeline...")
        
        # Monitor initial memory
        self.monitor_memory()
        
        # Load raw features
        X, y = self.load_ember_features()
        self.monitor_memory()
        
        # Clean data
        X_clean, y_clean = self.clean_data(X, y)
        self.monitor_memory()
        
        if create_sample:
            # Create balanced sample for initial training
            X_sample, y_sample = self.create_balanced_sample(X_clean, y_clean)
            self.save_preprocessed_data(X_sample, y_sample, "sample")
        
        # Save full cleaned dataset (optional, memory permitting)
        if psutil.virtual_memory().percent < 70:  # Only if memory usage < 70%
            logger.info("Saving full cleaned dataset...")
            self.save_preprocessed_data(X_clean, y_clean, "full")
        else:
            logger.warning("Skipping full dataset save due to memory constraints")
        
        logger.info("Preprocessing complete!")


def main():
    """Main preprocessing function"""
    # Configuration
    data_directory = "ember2018"  # Adjust path as needed
    sample_size = 200
    
    # Check if data directory exists
    if not os.path.exists(data_directory):
        logger.error(f"Data directory '{data_directory}' not found!")
        logger.error("Please ensure the EMBER dataset is extracted to the correct path")
        sys.exit(1)
    
    # Initialize preprocessor
    preprocessor = EmberPreprocessor(data_directory, sample_size)
    
    try:
        # Run preprocessing
        preprocessor.run_preprocessing(create_sample=True)
        
        logger.info("Preprocessing completed successfully!")
        logger.info("Ready for training with train_lightgbm.py")
        
    except Exception as e:
        logger.error(f"Preprocessing failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()