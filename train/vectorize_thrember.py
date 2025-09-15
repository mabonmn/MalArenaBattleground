#!/usr/bin/env python3
"""
Vectorize EMBER2024 JSONL files using the official thrember library.
This script uses thrember.create_vectorized_features() to process raw JSONL files
into training-ready feature vectors.
"""
import argparse
import os
import json
from pathlib import Path

try:
    import thrember
    HAVE_THREMBER = True
except ImportError:
    HAVE_THREMBER = False


def check_dependencies():
    """Check if required dependencies are installed."""
    if not HAVE_THREMBER:
        print("ERROR: thrember library not installed.")
        print("Install with: pip install thrember")
        print("Or follow installation instructions from the EMBER2024 repository")
        return False
    return True


def show_dataset_info(data_dir: str):
    """Display information about the dataset files."""
    data_path = Path(data_dir)
    jsonl_files = sorted(list(data_path.glob("*.jsonl")))
    
    if not jsonl_files:
        print(f"No JSONL files found in {data_dir}")
        return
    
    print(f"Found {len(jsonl_files)} JSONL files:")
    
    # Categorize files by architecture and type
    win32_files = []
    win64_files = []
    other_files = []
    train_files = []
    test_files = []
    challenge_files = []
    
    for file_path in jsonl_files:
        filename = file_path.name
        print(f"  - {filename}")
        
        if "Win32" in filename:
            win32_files.append(file_path)
        elif "Win64" in filename:
            win64_files.append(file_path)
        else:
            other_files.append(file_path)
            
        if "train" in filename:
            train_files.append(file_path)
        elif "test" in filename:
            test_files.append(file_path)
        elif "challenge" in filename:
            challenge_files.append(file_path)
    
    print(f"\nFile breakdown:")
    print(f"  Win32 files: {len(win32_files)}")
    print(f"  Win64 files: {len(win64_files)}")
    print(f"  Other files: {len(other_files)}")
    print(f"  Train files: {len(train_files)}")
    print(f"  Test files: {len(test_files)}")
    print(f"  Challenge files: {len(challenge_files)}")


def vectorize_dataset(data_dir: str, label_type: str = "label", class_min: int = 10):
    """Vectorize the dataset using thrember's built-in function."""
    
    print(f"=== EMBER2024 Vectorization using thrember ===")
    print(f"Data directory: {data_dir}")
    print(f"Label type: {label_type}")
    print(f"Class minimum: {class_min}")
    
    # Show dataset information
    show_dataset_info(data_dir)
    
    print(f"\nStarting vectorization...")
    print(f"This will create .dat files for train, test, and challenge sets")
    
    try:
        # Use thrember's built-in vectorization
        thrember.create_vectorized_features(
            data_dir, 
            label_type=label_type, 
            class_min=class_min
        )
        
        print(f"\n✓ Vectorization completed successfully!")
        
        # Check what files were created
        data_path = Path(data_dir)
        created_files = []
        for pattern in ["X_*.dat", "y_*.dat"]:
            created_files.extend(data_path.glob(pattern))
        
        if created_files:
            print(f"\nCreated files:")
            for file_path in sorted(created_files):
                size_mb = file_path.stat().st_size / (1024 * 1024)
                print(f"  - {file_path.name} ({size_mb:.1f} MB)")
        
        return True
        
    except Exception as e:
        print(f"\n✗ Vectorization failed: {e}")
        return False


def convert_dat_to_npy(data_dir: str):
    """Convert .dat files to .npy files for compatibility with our training scripts."""
    
    print(f"\nConverting .dat files to .npy format for compatibility...")
    
    data_path = Path(data_dir)
    vectorized_dir = data_path / "vectorized"
    vectorized_dir.mkdir(exist_ok=True)
    
    # Load and convert each dataset split
    for subset in ["train", "test", "challenge"]:
        try:
            print(f"  Converting {subset} set...")
            
            # Use thrember's function to read the vectorized features
            X, y = thrember.read_vectorized_features(data_dir, subset)
            
            # Save as numpy arrays
            X_path = vectorized_dir / f"X_{subset}.npy"
            y_path = vectorized_dir / f"y_{subset}.npy"
            
            import numpy as np
            np.save(X_path, X)
            np.save(y_path, y)
            
            print(f"    Saved {X_path.name} - Shape: {X.shape}")
            print(f"    Saved {y_path.name} - Shape: {y.shape}")
            
        except Exception as e:
            print(f"    Warning: Could not convert {subset} set: {e}")
    
    # Create metadata file
    try:
        import numpy as np
        
        # Load a sample to get feature dimensions
        X_train, y_train = thrember.read_vectorized_features(data_dir, "train")
        
        metadata = {
            "source": "thrember.create_vectorized_features",
            "feature_dim": X_train.shape[1],
            "train_samples": X_train.shape[0],
            "label_distribution": {
                "malicious": int(np.sum(y_train == 1)),
                "benign": int(np.sum(y_train == 0)),
                "unlabeled": int(np.sum(y_train == -1))
            }
        }
        
        # Try to get test and challenge info too
        try:
            X_test, y_test = thrember.read_vectorized_features(data_dir, "test")
            metadata["test_samples"] = X_test.shape[0]
        except:
            pass
            
        try:
            X_challenge, y_challenge = thrember.read_vectorized_features(data_dir, "challenge")
            metadata["challenge_samples"] = X_challenge.shape[0]
        except:
            pass
        
        metadata_path = vectorized_dir / "vectorization_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"  Saved metadata to {metadata_path.name}")
        
    except Exception as e:
        print(f"  Warning: Could not create metadata: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Vectorize EMBER2024 JSONL files using thrember library"
    )
    parser.add_argument('--data-dir', default='data/ember2024',
                       help='Directory containing JSONL files')
    parser.add_argument('--label-type', default='label',
                       choices=['label', 'family', 'behavior', 'file_property', 'packer', 'exploit', 'group'],
                       help='Type of labels to extract')
    parser.add_argument('--class-min', type=int, default=10,
                       help='Minimum number of samples per class')
    parser.add_argument('--convert-to-npy', action='store_true',
                       help='Convert .dat files to .npy format for compatibility')
    
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    # Validate data directory
    if not os.path.isdir(args.data_dir):
        print(f"Error: Data directory does not exist: {args.data_dir}")
        return 1
    
    # Run vectorization
    success = vectorize_dataset(args.data_dir, args.label_type, args.class_min)
    
    if not success:
        return 1
    
    # Convert to numpy format if requested
    if args.convert_to_npy:
        convert_dat_to_npy(args.data_dir)
    
    print(f"\n=== Vectorization Complete ===")
    print(f"Files created in: {args.data_dir}")
    
    if args.convert_to_npy:
        print(f"NumPy files created in: {args.data_dir}/vectorized/")
        print(f"\nYou can now use the training scripts:")
        print(f"  python train/train_lgbm.py {args.data_dir} model.txt")
        print(f"  python train/eval_lgbm.py {args.data_dir} model.txt")
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)