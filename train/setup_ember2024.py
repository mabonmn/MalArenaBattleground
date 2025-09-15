#!/usr/bin/env python3
"""
Setup script for EMBER2024 dataset download and installation.
This script handles:
1. Installing the thrember package (EMBER2024)
2. Downloading PE files (Win32, Win64, .NET) for Windows malware detection
3. Downloading challenge set for evaluation
4. Vectorizing features for training
"""
import os
import subprocess
import sys
from pathlib import Path


def install_ember2024():
    """Install EMBER2024 (thrember) package."""
    print("Installing EMBER2024...")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", 
        "git+https://github.com/FutureComputing4AI/EMBER2024.git"
    ])
    print("EMBER2024 installation complete!")


def download_dataset(data_dir: str = "data/ember2024"):
    """Download EMBER2024 dataset (PE files only for Windows malware detection)."""
    try:
        import thrember
    except ImportError:
        print("Installing thrember first...")
        install_ember2024()
        import thrember
    
    data_path = Path(data_dir)
    data_path.mkdir(parents=True, exist_ok=True)
    
    print(f"Downloading EMBER2024 PE dataset to {data_path}...")
    print("This may take a while depending on your internet connection...")
    
    # Download all PE files (Win32, Win64, .NET) for Windows malware detection
    print("Downloading PE training and test data...")
    thrember.download_dataset(str(data_path), file_type="PE")
    
    # Also download challenge set for evaluation
    print("Downloading challenge set...")
    thrember.download_dataset(str(data_path), split="challenge")
    
    print("Dataset download complete!")



def vectorize_features(data_dir: str = "data/ember2024"):
    """Vectorize raw features into training-ready format."""
    try:
        import thrember
    except ImportError:
        print("thrember not installed. Please run install_ember2024() first.")
        return
    
    print(f"Vectorizing features in {data_dir}...")
    print("This process extracts feature vectors from raw data...")
    
    # Vectorize for malicious/benign classification
    thrember.create_vectorized_features(data_dir, label_type="malicious")
    
    print("Feature vectorization complete!")


def verify_installation():
    """Verify that EMBER2024 is properly installed and accessible."""
    try:
        import thrember
        print("✓ thrember successfully imported")
        
        # Test basic functionality
        print("✓ Testing feature extractor...")
        extractor = thrember.features.PEFeatureExtractor()
        print(f"✓ Feature extractor created with {extractor.dim} features")
        
        return True
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        return False


def main():
    print("=== EMBER2024 Setup ===")
    
    data_dir = "data/ember2024"
    
    # Step 1: Install EMBER2024
    print("\nStep 1: Installing EMBER2024...")
    install_ember2024()
    
    # Step 2: Verify installation
    print("\nStep 2: Verifying installation...")
    if not verify_installation():
        print("Installation verification failed. Please check error messages above.")
        return 1
    
    # Step 3: Download dataset
    print("\nStep 3: Downloading dataset...")
    try:
        download_dataset(data_dir)
    except Exception as e:
        print(f"Dataset download failed: {e}")
        print("You may need to retry the download due to network issues.")
        return 1
    
    # Step 4: Vectorize features
    print("\nStep 4: Vectorizing features...")
    try:
        vectorize_features(data_dir)
    except Exception as e:
        print(f"Feature vectorization failed: {e}")
        return 1
    
    print(f"\n=== Setup Complete! ===")
    print(f"Dataset location: {data_dir}")
    print(f"Ready for training with train_lightgbm_ember.py")
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
