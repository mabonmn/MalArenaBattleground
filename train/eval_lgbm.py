"""
Script for evaluating LightGBM models on EMBER2024 dataset.
"""

import pickle
import argparse
import numpy as np
import lightgbm as lgb
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.metrics import roc_curve, roc_auc_score, auc, precision_recall_curve


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


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser()
    parser.add_argument("data_dir", type=str,
                        help="Path to the directory containing the EMBER2024 dataset.")
    parser.add_argument("model_path", type=str,
                        help="Path to the trained model.")
    parser.add_argument("--output-dir", type=str, default=".",
                        help="Directory to save evaluation results.")
    args = parser.parse_args()

    # Load the trained model
    model = lgb.Booster(model_file=args.model_path)

    # Evaluate on the test set
    X_test, y_test = load_vectorized_features(args.data_dir, "test")
    
    # Filter out unlabeled samples (label = -1)
    test_mask = y_test != -1
    X_test = X_test[test_mask]
    y_test = y_test[test_mask]
    
    y_pred = model.predict(X_test)

    # Compute ROC AUC and PR AUC for test set
    roc_auc = roc_auc_score(y_test, y_pred)
    precision, recall, _ = precision_recall_curve(y_test, y_pred)
    pr_auc = auc(recall, precision)
    print("ROC AUC on test set: {:.4f}".format(roc_auc))
    print("PR AUC on test set: {:.4f}".format(pr_auc))

    # Compute and plot ROC curve
    fpr, tpr, thresholds = roc_curve(y_test, y_pred)
    plt.figure(figsize=(8, 6))
    plt.title("ROC Curve for EMBER2024 LightGBM Model")
    plt.plot(fpr, tpr, color='black', label=f'ROC Curve (AUC = {roc_auc:.4f})')
    plt.xlim(0.00001, 1.0)
    plt.ylim(0.65, 1.02)
    plt.xscale("log")
    
    # Show TPR at specific FPR values
    fpr_targets = [0.001, 0.01, 0.1]
    for fpr_target in fpr_targets:
        index = np.argmin(np.abs(fpr - fpr_target))
        tpr_at_fpr = tpr[index]
        plt.plot([fpr_target, fpr_target, 0], [0, tpr_at_fpr, tpr_at_fpr], 
                color='red', linestyle='--', alpha=0.7)
        print(f"TPR at {fpr_target*100}% FPR: {tpr_at_fpr:.4f}")
    
    plt.xlabel("False Positive Rate (log scale)")
    plt.ylabel("True Positive Rate")
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # Save plot
    output_path = Path(args.output_dir) / "Classifier_ROC_AUC.pdf"
    plt.savefig(output_path)
    print(f"Saved ROC curve plot to {output_path}")
    plt.close()

    # Load the challenge set
    X_challenge, y_challenge = load_vectorized_features(args.data_dir, "challenge")
    
    # Filter out unlabeled samples (label = -1)
    challenge_mask = y_challenge != -1
    X_challenge = X_challenge[challenge_mask]
    y_challenge = y_challenge[challenge_mask]

    # Combine with benign files in test set
    X_test_benign = X_test[y_test == 0]
    y_test_benign = y_test[y_test == 0]
    X_challenge_combined = np.concatenate((X_test_benign, X_challenge), axis=0)
    y_challenge_combined = np.concatenate((y_test_benign, y_challenge), axis=0)

    # Compute ROC AUC and PR AUC for challenge set
    y_pred_challenge = model.predict(X_challenge_combined)
    roc_auc_challenge = roc_auc_score(y_challenge_combined, y_pred_challenge)
    precision_challenge, recall_challenge, _ = precision_recall_curve(y_challenge_combined, y_pred_challenge)
    pr_auc_challenge = auc(recall_challenge, precision_challenge)
    print("ROC AUC on challenge set: {:.4f}".format(roc_auc_challenge))
    print("PR AUC on challenge set: {:.4f}".format(pr_auc_challenge))
    
    # Show TPR at specific FPR values for challenge set
    fpr_challenge, tpr_challenge, thresholds_challenge = roc_curve(y_challenge_combined, y_pred_challenge)
    for fpr_target in fpr_targets:
        index = np.argmin(np.abs(fpr_challenge - fpr_target))
        tpr_at_fpr = tpr_challenge[index]
        print(f"Challenge TPR at {fpr_target*100}% FPR: {tpr_at_fpr:.4f}")