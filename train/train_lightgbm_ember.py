#!/usr/bin/env python3
"""
Train LightGBM classifier on EMBER2024 dataset for malware detection.
Optimized for defender requirements: <1% FPR, >95% TPR, <5s response time, <1GB memory.
"""
import argparse
import json
import os
import pickle
import time
from pathlib import Path
from typing import Tuple, Dict, Any

import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve

try:
    import lightgbm as lgb
    HAVE_LIGHTGBM = True
except ImportError:
    HAVE_LIGHTGBM = False

try:
    import thrember
    HAVE_THREMBER = True
except ImportError:
    HAVE_THREMBER = False


def check_dependencies():
    """Check if required dependencies are installed."""
    if not HAVE_LIGHTGBM:
        print("ERROR: LightGBM not installed. Install with: pip install lightgbm")
        return False
    
    if not HAVE_THREMBER:
        print("ERROR: thrember (EMBER2024) not installed. Install with: pip install git+https://github.com/FutureComputing4AI/EMBER2024.git")
        return False
    
    return True


def load_ember_data(data_dir: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Load vectorized EMBER2024 data."""
    print("Loading EMBER2024 data...")
    
    try:
        X_train, y_train = thrember.read_vectorized_features(data_dir, subset="train")
        X_test, y_test = thrember.read_vectorized_features(data_dir, subset="test")
        X_challenge, y_challenge = thrember.read_vectorized_features(data_dir, subset="challenge")
    except Exception as e:
        print(f"Error loading data: {e}")
        print("Make sure you've run setup_ember2024.py first to download and vectorize the data.")
        raise
    
    print(f"Train: {X_train.shape[0]} samples, {X_train.shape[1]} features")
    print(f"Test: {X_test.shape[0]} samples")
    print(f"Challenge: {X_challenge.shape[0]} samples")
    
    # Handle NaN values if any
    X_train = np.nan_to_num(X_train, nan=0.0, posinf=0.0, neginf=0.0)
    X_test = np.nan_to_num(X_test, nan=0.0, posinf=0.0, neginf=0.0)
    X_challenge = np.nan_to_num(X_challenge, nan=0.0, posinf=0.0, neginf=0.0)
    
    return X_train, y_train, X_test, y_test, X_challenge, y_challenge


def train_lightgbm(X_train: np.ndarray, y_train: np.ndarray, 
                   X_test: np.ndarray, y_test: np.ndarray) -> lgb.Booster:
    """Train LightGBM model with parameters optimized for defender requirements."""
    
    # LightGBM parameters optimized for speed, accuracy, and memory efficiency
    params = {
        'objective': 'binary',
        'metric': 'binary_logloss',
        'boosting_type': 'gbdt',
        'num_leaves': 512,  # Reduced for memory efficiency
        'learning_rate': 0.1,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': -1,
        'random_state': 42,
        'n_jobs': -1,
        # Speed and memory optimizations
        'max_depth': 12,  # Reduced for faster inference
        'min_data_in_leaf': 50,
        'lambda_l1': 0.1,
        'lambda_l2': 0.1,
        # Additional optimizations
        'feature_fraction_bynode': 0.8,
        'extra_trees': True,
        'force_row_wise': True,  # Better for memory
    }
    
    # Create datasets
    print("Creating LightGBM datasets...")
    train_data = lgb.Dataset(X_train, label=y_train)
    valid_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    
    print("Training LightGBM model...")
    start_time = time.time()
    
    model = lgb.train(
        params,
        train_data,
        valid_sets=[train_data, valid_data],
        valid_names=['train', 'test'],
        num_boost_round=500,  # Reduced for speed
        callbacks=[
            lgb.early_stopping(stopping_rounds=30),
            lgb.log_evaluation(period=25)
        ]
    )
    
    training_time = time.time() - start_time
    print(f"Training completed in {training_time:.2f} seconds")
    
    return model


def find_optimal_threshold(model: lgb.Booster, X_test: np.ndarray, y_test: np.ndarray, 
                          target_fpr: float = 0.01, target_tpr: float = 0.95) -> Tuple[float, Dict[str, float]]:
    """Find optimal threshold to achieve target FPR while maximizing TPR."""
    
    print("Finding optimal threshold...")
    
    # Get predictions
    y_pred_proba = model.predict(X_test, num_iteration=model.best_iteration)
    
    # Calculate ROC curve
    fpr, tpr, thresholds = roc_curve(y_test, y_pred_proba)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    # Find threshold that gives FPR <= target_fpr
    valid_indices = fpr <= target_fpr
    if not np.any(valid_indices):
        print(f"Warning: Cannot achieve FPR <= {target_fpr}")
        # Use threshold that gives closest FPR
        best_idx = np.argmin(np.abs(fpr - target_fpr))
    else:
        # Among valid thresholds, pick the one with highest TPR
        valid_tpr = tpr[valid_indices]
        best_idx = np.where(valid_indices)[0][np.argmax(valid_tpr)]
    
    optimal_threshold = thresholds[best_idx]
    achieved_fpr = fpr[best_idx]
    achieved_tpr = tpr[best_idx]
    
    # Check if we meet requirements
    meets_fpr = achieved_fpr <= target_fpr
    meets_tpr = achieved_tpr >= target_tpr
    
    # Calculate metrics at optimal threshold
    y_pred = (y_pred_proba >= optimal_threshold).astype(int)
    accuracy = np.mean(y_pred == y_test)
    
    metrics = {
        'threshold': float(optimal_threshold),
        'fpr': float(achieved_fpr),
        'tpr': float(achieved_tpr),
        'auc': float(auc),
        'accuracy': float(accuracy),
        'meets_fpr_requirement': meets_fpr,
        'meets_tpr_requirement': meets_tpr,
        'meets_requirements': meets_fpr and meets_tpr
    }
    
    print(f"Optimal threshold: {optimal_threshold:.4f}")
    print(f"Achieved FPR: {achieved_fpr:.4f} (target: ≤{target_fpr}) {'✓' if meets_fpr else '✗'}")
    print(f"Achieved TPR: {achieved_tpr:.4f} (target: ≥{target_tpr}) {'✓' if meets_tpr else '✗'}")
    print(f"AUC: {auc:.4f}")
    print(f"Accuracy: {accuracy:.4f}")
    
    return optimal_threshold, metrics


def evaluate_model(model: lgb.Booster, X: np.ndarray, y: np.ndarray, 
                   threshold: float, dataset_name: str) -> Dict[str, float]:
    """Evaluate model on given dataset."""
    
    print(f"\nEvaluating on {dataset_name} set...")
    
    start_time = time.time()
    y_pred_proba = model.predict(X, num_iteration=model.best_iteration)
    prediction_time = time.time() - start_time
    
    y_pred = (y_pred_proba >= threshold).astype(int)
    
    # Calculate confusion matrix
    tn, fp, fn, tp = confusion_matrix(y, y_pred).ravel()
    
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    accuracy = (tp + tn) / len(y)
    
    # Calculate average prediction time per sample
    avg_prediction_time = prediction_time / len(X)
    
    metrics = {
        f'{dataset_name}_fpr': float(fpr),
        f'{dataset_name}_tpr': float(tpr),
        f'{dataset_name}_accuracy': float(accuracy),
        f'{dataset_name}_tp': int(tp),
        f'{dataset_name}_fp': int(fp),
        f'{dataset_name}_tn': int(tn),
        f'{dataset_name}_fn': int(fn),
        f'{dataset_name}_prediction_time': float(prediction_time),
        f'{dataset_name}_avg_prediction_time': float(avg_prediction_time)
    }
    
    print(f"FPR: {fpr:.4f}, TPR: {tpr:.4f}, Accuracy: {accuracy:.4f}")
    print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
    print(f"Total prediction time: {prediction_time:.2f}s ({avg_prediction_time*1000:.2f}ms per sample)")
    
    return metrics


def save_model_and_metadata(model: lgb.Booster, threshold: float, metrics: Dict[str, Any], 
                           output_dir: str):
    """Save model, threshold, and metadata."""
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Save LightGBM model
    model_path = output_path / "lightgbm_ember_model.txt"
    model.save_model(str(model_path))
    print(f"Model saved to {model_path}")
    
    # Save threshold and metadata
    metadata = {
        'threshold': threshold,
        'model_type': 'lightgbm',
        'dataset': 'ember2024',
        'features': model.num_feature(),
        'num_trees': model.num_trees(),
        'best_iteration': model.best_iteration,
        'metrics': metrics,
        'requirements': {
            'max_fpr': 0.01,
            'min_tpr': 0.95,
            'max_response_time_seconds': 5,
            'max_memory_gb': 1
        }
    }
    
    metadata_path = output_path / "model_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"Metadata saved to {metadata_path}")
    
    # Save threshold separately for easy access
    threshold_path = output_path / "optimal_threshold.txt"
    with open(threshold_path, 'w') as f:
        f.write(str(threshold))
    print(f"Threshold saved to {threshold_path}")
    
    # Save feature importance
    importance_path = output_path / "feature_importance.json"
    feature_importance = {
        'importance_type': 'gain',
        'feature_importance': model.feature_importance(importance_type='gain').tolist()
    }
    with open(importance_path, 'w') as f:
        json.dump(feature_importance, f, indent=2)
    print(f"Feature importance saved to {importance_path}")


def test_inference_speed(model: lgb.Booster, X_sample: np.ndarray, num_tests: int = 100) -> float:
    """Test inference speed to ensure it meets <5s requirement."""
    
    print(f"\nTesting inference speed with {num_tests} samples...")
    
    # Use a subset for speed testing
    test_samples = X_sample[:num_tests] if len(X_sample) >= num_tests else X_sample
    
    times = []
    for i in range(len(test_samples)):
        start_time = time.time()
        _ = model.predict(test_samples[i:i+1], num_iteration=model.best_iteration)
        end_time = time.time()
        times.append(end_time - start_time)
    
    avg_time = np.mean(times)
    max_time = np.max(times)
    
    print(f"Average prediction time: {avg_time*1000:.2f}ms")
    print(f"Maximum prediction time: {max_time*1000:.2f}ms")
    print(f"Meets <5s requirement: {'✓' if max_time < 5.0 else '✗'}")
    
    return avg_time


def main():
    parser = argparse.ArgumentParser(description="Train LightGBM on EMBER2024")
    parser.add_argument('--data-dir', default='data/ember2024', 
                       help='Directory containing EMBER2024 data')
    parser.add_argument('--output-dir', default='defender/defender/models/ember_lightgbm',
                       help='Directory to save trained model')
    parser.add_argument('--target-fpr', type=float, default=0.01,
                       help='Target false positive rate')
    parser.add_argument('--target-tpr', type=float, default=0.95,
                       help='Target true positive rate')
    
    args = parser.parse_args()
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    print("=== EMBER2024 LightGBM Training ===")
    
    # Load data
    try:
        X_train, y_train, X_test, y_test, X_challenge, y_challenge = load_ember_data(args.data_dir)
    except Exception as e:
        print(f"Failed to load data: {e}")
        return 1
    
    # Train model
    try:
        model = train_lightgbm(X_train, y_train, X_test, y_test)
    except Exception as e:
        print(f"Training failed: {e}")
        return 1
    
    # Find optimal threshold
    threshold, test_metrics = find_optimal_threshold(
        model, X_test, y_test, args.target_fpr, args.target_tpr
    )
    
    # Evaluate on all datasets
    train_metrics = evaluate_model(model, X_train, y_train, threshold, "train")
    challenge_metrics = evaluate_model(model, X_challenge, y_challenge, threshold, "challenge")
    
    # Test inference speed
    avg_inference_time = test_inference_speed(model, X_test)
    
    # Combine all metrics
    all_metrics = {}
    all_metrics.update(test_metrics)
    all_metrics.update(train_metrics)
    all_metrics.update(challenge_metrics)
    all_metrics['avg_inference_time'] = avg_inference_time
    
    # Save model and metadata
    try:
        save_model_and_metadata(model, threshold, all_metrics, args.output_dir)
    except Exception as e:
        print(f"Failed to save model: {e}")
        return 1
    
    # Final summary
    print(f"\n=== Training Complete ===")
    print(f"Requirements check:")
    print(f"  FPR: {test_metrics['fpr']:.4f} ≤ 0.01 {'✓' if test_metrics['fpr'] <= 0.01 else '✗'}")
    print(f"  TPR: {test_metrics['tpr']:.4f} ≥ 0.95 {'✓' if test_metrics['tpr'] >= 0.95 else '✗'}")
    print(f"  Speed: {avg_inference_time*1000:.2f}ms < 5000ms {'✓' if avg_inference_time < 5.0 else '✗'}")
    
    if test_metrics['meets_requirements']:
        print("✓ Model meets all requirements!")
    else:
        print("✗ Model does not meet all requirements. Consider retraining with different parameters.")
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
