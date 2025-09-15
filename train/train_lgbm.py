"""
Train a LightGBM classifier on vectorized EMBER2024 features.

The following LightGBM config files can be used for training:
 - Benign/malicious detection: lgbm_config.json
 - Malware family classification: lgbm_config_family.json
 - All other classification tasks: lgbm_config_tag.json
"""

import os
import json
import argparse
import numpy as np
import lightgbm as lgb
from pathlib import Path
from sklearn.model_selection import train_test_split


def load_vectorized_features(data_dir, subset):
    """Load vectorized EMBER2024 features from thrember .dat files or numpy files."""
    from pathlib import Path
    
    data_path = Path(data_dir)
    
    # Try to load from thrember .dat files first
    try:
        import thrember
        X, y = thrember.read_vectorized_features(data_dir, subset)
        # Handle NaN values
        import numpy as np
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        return X, y
    except (ImportError, Exception):
        pass
    
    # Fallback to numpy files
    vectorized_dir = data_path / "vectorized"
    
    if subset == "train":
        X = np.load(vectorized_dir / "X_train.npy")
        y = np.load(vectorized_dir / "y_train.npy")
    elif subset == "test":
        X = np.load(vectorized_dir / "X_test.npy")
        y = np.load(vectorized_dir / "y_test.npy")
    elif subset == "challenge":
        X = np.load(vectorized_dir / "X_challenge.npy")
        y = np.load(vectorized_dir / "y_challenge.npy")
    else:
        raise ValueError(f"Unknown subset: {subset}")
    
    # Handle NaN values
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    return X, y


def train_model(data_dir, params=None):
    """Train LightGBM model on EMBER2024 data."""
    
    # Load training and test data
    X_train, y_train = load_vectorized_features(data_dir, "train")
    X_test, y_test = load_vectorized_features(data_dir, "test")
    
    # Filter out unlabeled samples (label = -1)
    import numpy as np
    train_mask = y_train != -1
    test_mask = y_test != -1
    
    X_train = X_train[train_mask]
    y_train = y_train[train_mask]
    X_test = X_test[test_mask]
    y_test = y_test[test_mask]
    
    print(f"Training set: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    print(f"Test set: {X_test.shape[0]} samples")
    print(f"Train labels - Malicious: {np.sum(y_train)}, Benign: {len(y_train) - np.sum(y_train)}")
    
    # Default parameters if none provided
    if params is None:
        params = {
            "objective": "binary",
            "boosting": "gbdt",
            "num_iterations": 500,
            "learning_rate": 0.1,
            "num_leaves": 64,
            "min_data_in_leaf": 100,
            "bagging_fraction": 0.9,
            "feature_fraction": 0.9,
            "lambda_l2": 1.0,
            "metric": ["auc", "binary_logloss"],
            "verbosity": 1,
            "is_unbalance": True,
            "seed": 0
        }
    
    # Create LightGBM datasets
    train_data = lgb.Dataset(X_train, label=y_train)
    valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    # Train the model
    print("Training LightGBM model...")
    model = lgb.train(
        params,
        train_data,
        valid_sets=[train_data, valid_data],
        valid_names=['train', 'test'],
        callbacks=[lgb.log_evaluation(period=50)]
    )
    
    return model


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("data_dir", type=str,
                        help="Path to the directory containing the EMBER2024 dataset.")
    parser.add_argument("model_path", type=str,
                        help="Path to save the trained model.")
    parser.add_argument("--config-file", type=str, default="lgbm_config.json",
                        help="Path to LightGBM config file.")
    args = parser.parse_args()

    # Validate data directory and config file
    if not os.path.isdir(args.data_dir):
        raise ValueError("Not a directory: {}".format(args.data_dir))
    if not os.path.isfile(args.config_file):
        raise ValueError("Not a file: {}".format(args.config_file))

    # Parse LightGBM config file
    fit_params = json.load(open(args.config_file, "r"))

    # Load data and train model
    model = train_model(args.data_dir, params=fit_params)

    # Create directory for model if it doesn't exist
    model_path = Path(args.model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    # Save model
    model.save_model(args.model_path, num_iteration=model.best_iteration)
    print(f"Model saved to {args.model_path}")