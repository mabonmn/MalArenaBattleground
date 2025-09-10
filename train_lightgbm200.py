#!/usr/bin/env python3
"""
LightGBM Malware Detection Training Script

This script trains a LightGBM model for malware detection using preprocessed
EMBER dataset features. Optimized for competition constraints:
- FPR ≤ 1%
- TPR ≥ 95%
- Memory ≤ 1GB RAM
- Response time ≤ 5 seconds per sample

Requirements:
- lightgbm, scikit-learn, numpy, pandas

Author: Malware Detection Training Script
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Tuple, Dict, Any, Optional
import pickle
import time
import psutil
import logging
from pathlib import Path

# Machine learning imports
import lightgbm as lgb
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_auc_score, 
    precision_recall_curve, roc_curve, accuracy_score
)
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import seaborn as sns

# EMBER library import
try:
    import ember
    EMBER_AVAILABLE = True
except ImportError:
    EMBER_AVAILABLE = False
    logger = logging.getLogger(__name__)
    logger.warning("EMBER library not available. Some features will be disabled.")

# Configure logging
# Ensure Logs directory exists
logs_dir = Path('/home/benchodbaap/DataAna/Logs')
logs_dir.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / 'training.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class MalwareLightGBMTrainer:
    """
    LightGBM trainer optimized for malware detection with competition constraints
    """
    
    def __init__(self, data_dir: str = "ember2018"):
        """
        Initialize the trainer
        
        Args:
            data_dir: Directory containing preprocessed data
        """
        self.data_dir = Path(data_dir)
        self.model = None
        self.scaler = None
        
        # Competition constraints
        self.target_fpr = 0.01  # ≤ 1%
        self.target_tpr = 0.95  # ≥ 95%
        self.memory_limit_gb = 1  # ≤ 1GB
        self.response_time_limit = 5  # ≤ 5 seconds
        
        logger.info("Initialized LightGBM trainer for malware detection")
        self._log_system_info()
    
    def _log_system_info(self) -> None:
        """Log system information"""
        memory = psutil.virtual_memory()
        logger.info(f"Available RAM: {memory.total / (1024**3):.2f} GB")
        logger.info(f"Available RAM: {memory.available / (1024**3):.2f} GB")
        logger.info(f"CPU cores: {psutil.cpu_count()}")
    
    def load_preprocessed_data(self, dataset_type: str = "sample") -> Tuple[np.ndarray, np.ndarray]:
        """
        Load preprocessed data from npz files
        
        Args:
            dataset_type: Type of dataset to load ("sample" or "full")
        
        Returns:
            X: Feature matrix
            y: Labels
        """
        logger.info(f"Loading {dataset_type} dataset...")
        
        preprocessed_dir = self.data_dir / "preprocessed"
        X_path = preprocessed_dir / f"X_{dataset_type}.npz"
        y_path = preprocessed_dir / f"y_{dataset_type}.npz"
        metadata_path = preprocessed_dir / f"metadata_{dataset_type}.json"
        
        if not X_path.exists() or not y_path.exists():
            raise FileNotFoundError(f"Preprocessed data not found: {X_path} or {y_path}")
        
        # Load data from npz files
        X = np.load(X_path)['X']
        y = np.load(y_path)['y']
        
        logger.info(f"Loaded {X.shape[0]} samples with {X.shape[1]} features")
        logger.info(f"Class distribution - Malicious: {np.sum(y == 1)}, Benign: {np.sum(y == 0)}")
        
        # Load metadata if available
        if metadata_path.exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            logger.info(f"Metadata loaded: {metadata}")
        
        return X, y
    
    def get_optimized_lgb_params(self) -> Dict[str, Any]:
        """
        Get optimized LightGBM parameters for malware detection
        
        Based on research findings for EMBER dataset performance
        """
        params = {
            # Core parameters
            'objective': 'binary',
            'metric': ['binary_logloss', 'auc'],
            'boosting_type': 'gbdt',
            'verbosity': 1,
            
            # Performance optimization for competition constraints
            'num_leaves': 31,  # Default, good balance
            'max_depth': -1,   # No limit
            'learning_rate': 0.1,
            'feature_fraction': 0.9,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'min_data_in_leaf': 50,  # Increased for better generalization
            
            # Memory optimization
            'max_bin': 255,
            'data_sample_strategy': 'bagging',
            
            # Speed optimization
            'num_threads': min(4, psutil.cpu_count()),  # Limit threads for memory
            'force_col_wise': True,
            
            # Regularization to prevent overfitting
            'lambda_l1': 0.1,
            'lambda_l2': 0.1,
            'min_gain_to_split': 0.0,
            
            # For binary classification
            'is_unbalance': False,  # We'll handle class weights separately if needed
            'scale_pos_weight': 1.0,
        }
        
        return params
    
    def train_model(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> Dict[str, Any]:
        """
        Train LightGBM model with optimization for competition metrics
        
        Args:
            X: Feature matrix
            y: Labels
            test_size: Proportion of dataset for testing
        
        Returns:
            Dictionary containing training results and metrics
        """
        logger.info("Starting model training...")
        
        # Split data
        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        logger.info(f"Training set: {X_train.shape[0]} samples")
        logger.info(f"Validation set: {X_val.shape[0]} samples")
        
        # Prepare datasets for LightGBM
        train_data = lgb.Dataset(X_train, label=y_train)
        valid_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
        
        # Get optimized parameters
        params = self.get_optimized_lgb_params()
        logger.info(f"Training with parameters: {params}")
        
        # Training with early stopping
        start_time = time.time()
        
        self.model = lgb.train(
            params,
            train_data,
            valid_sets=[valid_data],
            num_boost_round=1000,
            callbacks=[
                lgb.early_stopping(stopping_rounds=50),
                lgb.log_evaluation(period=100)
            ]
        )
        
        training_time = time.time() - start_time
        logger.info(f"Training completed in {training_time:.2f} seconds")
        
        # Evaluate model
        results = self.evaluate_model(X_val, y_val)
        results['training_time'] = training_time
        results['model_size_mb'] = sys.getsizeof(pickle.dumps(self.model)) / (1024 * 1024)
        
        logger.info(f"Model size: {results['model_size_mb']:.2f} MB")
        
        return results
    
    def evaluate_model(self, X_val: np.ndarray, y_val: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate model performance with focus on competition metrics
        
        Args:
            X_val: Validation features
            y_val: Validation labels
        
        Returns:
            Dictionary containing evaluation metrics
        """
        logger.info("Evaluating model performance...")
        
        if self.model is None:
            raise ValueError("Model not trained yet!")
        
        # Predict probabilities
        start_time = time.time()
        y_pred_proba = self.model.predict(X_val, num_iteration=self.model.best_iteration)
        prediction_time = time.time() - start_time
        avg_prediction_time = prediction_time / len(X_val)
        
        # Find optimal threshold for competition constraints
        optimal_threshold = self.find_optimal_threshold(y_val, y_pred_proba)
        
        # Make binary predictions with optimal threshold
        y_pred = (y_pred_proba >= optimal_threshold).astype(int)
        
        # Calculate metrics
        tn, fp, fn, tp = confusion_matrix(y_val, y_pred).ravel()
        
        # Competition metrics
        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0  # True Positive Rate (Recall)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0  # False Positive Rate
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        accuracy = accuracy_score(y_val, y_pred)
        auc_score = roc_auc_score(y_val, y_pred_proba)
        
        results = {
            'accuracy': accuracy,
            'precision': precision,
            'tpr': tpr,  # True Positive Rate (≥ 95% required)
            'fpr': fpr,  # False Positive Rate (≤ 1% required)
            'auc': auc_score,
            'optimal_threshold': optimal_threshold,
            'avg_prediction_time': avg_prediction_time,
            'confusion_matrix': {
                'tn': int(tn), 'fp': int(fp),
                'fn': int(fn), 'tp': int(tp)
            }
        }
        
        # Log results
        logger.info("=== Model Performance ===")
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info(f"Precision: {precision:.4f}")
        logger.info(f"TPR (Recall): {tpr:.4f} {'✓' if tpr >= self.target_tpr else '✗'}")
        logger.info(f"FPR: {fpr:.4f} {'✓' if fpr <= self.target_fpr else '✗'}")
        logger.info(f"AUC: {auc_score:.4f}")
        logger.info(f"Optimal threshold: {optimal_threshold:.4f}")
        logger.info(f"Avg prediction time: {avg_prediction_time:.4f} seconds {'✓' if avg_prediction_time <= self.response_time_limit else '✗'}")
        
        # Competition compliance check
        competition_compliant = (
            tpr >= self.target_tpr and 
            fpr <= self.target_fpr and 
            avg_prediction_time <= self.response_time_limit
        )
        
        logger.info(f"Competition compliant: {'✓ YES' if competition_compliant else '✗ NO'}")
        results['competition_compliant'] = competition_compliant
        
        return results
    
    def find_optimal_threshold(self, y_true: np.ndarray, y_pred_proba: np.ndarray) -> float:
        """
        Find optimal threshold balancing TPR ≥ 95% and FPR ≤ 1%
        
        Args:
            y_true: True labels
            y_pred_proba: Predicted probabilities
        
        Returns:
            Optimal threshold
        """
        # Calculate precision-recall curve
        precision, recall, thresholds = precision_recall_curve(y_true, y_pred_proba)
        
        # Calculate FPR for each threshold
        fpr, tpr, roc_thresholds = roc_curve(y_true, y_pred_proba)
        
        # Find thresholds that satisfy TPR ≥ 95%
        valid_tpr_mask = tpr >= self.target_tpr
        
        if not np.any(valid_tpr_mask):
            logger.warning("Cannot achieve TPR ≥ 95%, using threshold for highest TPR")
            return roc_thresholds[np.argmax(tpr)]
        
        # Among valid TPR thresholds, find one with lowest FPR
        valid_fpr = fpr[valid_tpr_mask]
        valid_thresholds = roc_thresholds[valid_tpr_mask]
        
        # Prefer thresholds that also satisfy FPR ≤ 1%
        fpr_compliant_mask = valid_fpr <= self.target_fpr
        
        if np.any(fpr_compliant_mask):
            # Use threshold with lowest FPR among compliant ones
            best_idx = np.argmin(valid_fpr[fpr_compliant_mask])
            return valid_thresholds[fpr_compliant_mask][best_idx]
        else:
            # Use threshold with lowest FPR even if not fully compliant
            logger.warning("Cannot achieve both TPR ≥ 95% AND FPR ≤ 1%")
            best_idx = np.argmin(valid_fpr)
            return valid_thresholds[best_idx]
    
    def save_model(self, model_path: str = "malware_lightgbm_model.pkl", 
                   results_path: str = "training_results.json") -> None:
        """
        Save trained model and results
        
        Args:
            model_path: Path to save the model
            results_path: Path to save training results
        """
        if self.model is None:
            raise ValueError("No model to save!")
        
        # Ensure models directory exists
        models_dir = Path('/home/benchodbaap/DataAna/models')
        models_dir.mkdir(exist_ok=True)
        
        # Update paths to use models directory
        model_path = models_dir / model_path
        results_path = models_dir / results_path
        
        # Save model
        with open(model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'feature_dim': 2381,
                'model_type': 'lightgbm'
            }, f)
        
        logger.info(f"Model saved to {model_path}")
        
        # Save LightGBM native format for faster loading
        lgb_model_path = model_path.with_suffix('.txt')
        self.model.save_model(str(lgb_model_path))
        logger.info(f"LightGBM model saved to {lgb_model_path}")
    
    def cross_validate(self, X: np.ndarray, y: np.ndarray, cv_folds: int = 5) -> Dict[str, Any]:
        """
        Perform cross-validation to assess model stability
        
        Args:
            X: Feature matrix
            y: Labels  
            cv_folds: Number of CV folds
        
        Returns:
            Cross-validation results
        """
        logger.info(f"Performing {cv_folds}-fold cross-validation...")
        
        # Prepare LightGBM parameters
        params = self.get_optimized_lgb_params()
        
        # Stratified K-Fold
        skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
        
        cv_scores = []
        cv_tpr_scores = []
        cv_fpr_scores = []
        
        for fold, (train_idx, val_idx) in enumerate(skf.split(X, y)):
            logger.info(f"Training fold {fold + 1}/{cv_folds}...")
            
            X_train_fold, X_val_fold = X[train_idx], X[val_idx]
            y_train_fold, y_val_fold = y[train_idx], y[val_idx]
            
            # Create LightGBM datasets
            train_data = lgb.Dataset(X_train_fold, label=y_train_fold)
            val_data = lgb.Dataset(X_val_fold, label=y_val_fold, reference=train_data)
            
            # Train model
            fold_model = lgb.train(
                params,
                train_data,
                valid_sets=[val_data],
                num_boost_round=500,
                callbacks=[
                    lgb.early_stopping(stopping_rounds=30),
                    lgb.log_evaluation(period=0)  # 0 means no logging
                ]
            )
            
            # Evaluate fold
            y_pred_proba = fold_model.predict(X_val_fold, num_iteration=fold_model.best_iteration)
            optimal_threshold = self.find_optimal_threshold(y_val_fold, y_pred_proba)
            y_pred = (y_pred_proba >= optimal_threshold).astype(int)
            
            # Calculate metrics
            tn, fp, fn, tp = confusion_matrix(y_val_fold, y_pred).ravel()
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            accuracy = accuracy_score(y_val_fold, y_pred)
            
            cv_scores.append(accuracy)
            cv_tpr_scores.append(tpr)
            cv_fpr_scores.append(fpr)
        
        cv_results = {
            'accuracy_mean': np.mean(cv_scores),
            'accuracy_std': np.std(cv_scores),
            'tpr_mean': np.mean(cv_tpr_scores),
            'tpr_std': np.std(cv_tpr_scores),
            'fpr_mean': np.mean(cv_fpr_scores),
            'fpr_std': np.std(cv_fpr_scores),
        }
        
        logger.info("=== Cross-Validation Results ===")
        logger.info(f"Accuracy: {cv_results['accuracy_mean']:.4f} ± {cv_results['accuracy_std']:.4f}")
        logger.info(f"TPR: {cv_results['tpr_mean']:.4f} ± {cv_results['tpr_std']:.4f}")
        logger.info(f"FPR: {cv_results['fpr_mean']:.4f} ± {cv_results['fpr_std']:.4f}")
        
        return cv_results


    def train_with_ember_defaults(self) -> Dict[str, Any]:
        """
        Train model using EMBER's built-in training function
        
        Returns:
            Dictionary containing training results
        """
        if not EMBER_AVAILABLE:
            raise ImportError("EMBER library not available. Please install it first.")
        
        logger.info("Training model using EMBER's built-in training...")
        
        try:
            # Use EMBER's train_model function which handles optimization
            lgbm_model = ember.train_model(str(self.data_dir))
            
            # Save the model
            model_path = f"{self.data_dir}/ember_model_2018.txt"
            lgbm_model.save_model(model_path)
            
            logger.info(f"Model saved to {model_path}")
            
            # Load back as LightGBM booster for consistency
            self.model = lgb.Booster(model_file=model_path)
            
            return {"model_path": model_path, "training_method": "ember_builtin"}
            
        except Exception as e:
            logger.error(f"EMBER training failed: {e}")
            raise e
    
    def quick_train_and_evaluate(self) -> Dict[str, Any]:
        """
        Quick training using EMBER's optimized approach
        """
        if not EMBER_AVAILABLE:
            raise ImportError("EMBER library not available. Please install it first.")
        
        logger.info("Starting quick training with EMBER...")
        
        # Ensure vectorized features exist
        ember.create_vectorized_features(str(self.data_dir))
        
        # Train using EMBER's optimized parameters
        self.model = ember.train_model(str(self.data_dir))
        
        # Load test data for evaluation
        X_train, y_train, X_test, y_test = ember.read_vectorized_features(str(self.data_dir))
        
        # Evaluate on test set
        results = self.evaluate_model(X_test, y_test)
        
        return results


def main():
    """Main training function focused on 200-sample training"""
    data_directory = "ember2018"
    
    if not os.path.exists(data_directory):
        logger.error(f"Data directory '{data_directory}' not found!")
        sys.exit(1)
    
    # Check for preprocessed sample data
    preprocessed_dir = f"{data_directory}/preprocessed"
    sample_X_path = f"{preprocessed_dir}/X_sample.npz"
    sample_y_path = f"{preprocessed_dir}/y_sample.npz"
    
    if not os.path.exists(sample_X_path) or not os.path.exists(sample_y_path):
        logger.error(f"Sample data not found at {sample_X_path} or {sample_y_path}")
        logger.error("Please run preprocess_ember.py first to create sample data")
        sys.exit(1)
    
    trainer = MalwareLightGBMTrainer(data_directory)
    
    try:
        logger.info("=== Training on 200-sample dataset ===")
        
        # Load the preprocessed sample data
        logger.info("Loading preprocessed sample data...")
        X_data, y_data = trainer.load_preprocessed_data("sample")
        
        logger.info(f"Loaded sample data: {X_data.shape[0]} samples, {X_data.shape[1]} features")
        logger.info(f"Class distribution - Malicious: {np.sum(y_data == 1)}, Benign: {np.sum(y_data == 0)}")
        
        # Train the model on sample data
        logger.info("Training LightGBM model on sample data...")
        results = trainer.train_model(X_data, y_data, test_size=0.3)  # Use 30% for validation
        
        # Perform cross-validation for robustness assessment
        logger.info("Performing cross-validation...")
        cv_results = trainer.cross_validate(X_data, y_data, cv_folds=5)
        
        # Save the trained model
        model_name = "malware_lightgbm_200sample_model.pkl"
        trainer.save_model(model_path=model_name, results_path="training_results_200sample.json")
        
        # Log final results
        logger.info("=== Training Summary ===")
        logger.info(f"Training completed on {X_data.shape[0]} samples")
        logger.info(f"Model saved as: {model_name}")
        logger.info(f"Final Accuracy: {results.get('accuracy', 'N/A'):.4f}")
        logger.info(f"Final TPR: {results.get('tpr', 'N/A'):.4f}")
        logger.info(f"Final FPR: {results.get('fpr', 'N/A'):.4f}")
        logger.info(f"CV Accuracy: {cv_results.get('accuracy_mean', 'N/A'):.4f} ± {cv_results.get('accuracy_std', 'N/A'):.4f}")
        
        logger.info("Training completed successfully!")
        
    except Exception as e:
        logger.error(f"Training failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()