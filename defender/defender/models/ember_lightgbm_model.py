"""
LightGBM EMBER2024 model for malware detection.
Optimized for defender requirements: <1% FPR, >95% TPR, <5s response time, <1GB memory.
"""
import json
import os
import time
from typing import Dict, Union, Optional
import numpy as np

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


class EmberLightGBMModel:
    """
    LightGBM model wrapper for EMBER2024 features.
    Compatible with defender.apps.create_app interface:
      - predict(bytez: bytes) -> int in {0,1}
      - model_info() -> dict
    """
    
    def __init__(
        self,
        model_path: str,
        threshold: Optional[float] = None,
        metadata_path: Optional[str] = None,
        max_bytes: int = 2_097_152,  # 2MB limit per challenge requirements
    ) -> None:
        if not HAVE_LIGHTGBM:
            raise ImportError(
                "LightGBM is required. Install with: pip install lightgbm"
            )
        
        if not HAVE_THREMBER:
            raise ImportError(
                "thrember (EMBER2024) is required. Install with: "
                "pip install git+https://github.com/FutureComputing4AI/EMBER2024.git"
            )
        
        self.name = 'ember_lightgbm'
        self.max_bytes = int(max_bytes)
        
        # Resolve model path
        if not os.path.isabs(model_path):
            # If relative path, resolve relative to models directory
            base = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base, model_path)
        
        if not os.path.isfile(model_path):
            raise FileNotFoundError(f"LightGBM model not found: {model_path}")
        
        # Load model
        self.model = lgb.Booster(model_file=model_path)
        self.model_path = model_path
        
        # Load metadata if available
        self.metadata = {}
        if metadata_path is None:
            # Try to find metadata file in same directory
            model_dir = os.path.dirname(model_path)
            metadata_path = os.path.join(model_dir, "model_metadata.json")
        
        if os.path.isfile(metadata_path):
            try:
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load metadata from {metadata_path}: {e}")
        
        # Set threshold
        if threshold is not None:
            self.threshold = float(threshold)
        elif 'threshold' in self.metadata:
            self.threshold = float(self.metadata['threshold'])
        else:
            # Try to load from threshold file
            threshold_path = os.path.join(os.path.dirname(model_path), "optimal_threshold.txt")
            if os.path.isfile(threshold_path):
                try:
                    with open(threshold_path, 'r') as f:
                        self.threshold = float(f.read().strip())
                except Exception:
                    self.threshold = 0.5  # Default fallback
            else:
                self.threshold = 0.5  # Default fallback
        
        # Initialize feature extractor
        self.feature_extractor = thrember.features.PEFeatureExtractor()
        
        print(f"Loaded LightGBM EMBER model from {model_path}")
        print(f"Model features: {self.model.num_feature()}")
        print(f"Threshold: {self.threshold}")
        
        # Performance statistics
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        self.feature_extraction_time = 0.0
        self.model_inference_time = 0.0
    
    def _extract_ember_features(self, bytez: bytes) -> np.ndarray:
        """Extract EMBER features from raw bytes - abstain if fails."""
        start_time = time.time()
        
        try:
            # Use thrember to extract features
            features = self.feature_extractor.feature_vector(bytez)
            features_array = np.array(features, dtype=np.float32)
            
            # Handle any NaN or infinite values
            features_array = np.nan_to_num(features_array, nan=0.0, posinf=0.0, neginf=0.0)
            
            self.feature_extraction_time += time.time() - start_time
            return features_array
            
        except Exception as e:
            # If feature extraction fails, abstain
            print(f"Thrember feature extraction failed: {e} - model will abstain")
            self.feature_extraction_time += time.time() - start_time
            raise Exception(f"LGBM abstaining due to feature extraction failure: {e}")
    
    def predict(self, bytez: bytes) -> int:
        """
        Predict malware classification for given bytes.
        Returns 0 for benign, 1 for malicious.
        """
        start_time = time.time()
        self.prediction_count += 1
        
        try:
            # Limit file size to prevent memory issues and meet response time requirements
            if len(bytez) > self.max_bytes:
                bytez = bytez[:self.max_bytes]
            
            # Extract EMBER features
            features = self._extract_ember_features(bytez)
            
            # Ensure features are 2D for LightGBM
            if features.ndim == 1:
                features = features.reshape(1, -1)
            
            # Get prediction probability
            inference_start = time.time()
            prob = self.model.predict(features, num_iteration=self.model.best_iteration)[0]
            self.model_inference_time += time.time() - inference_start
            
            # Apply threshold
            prediction = int(prob >= self.threshold)
            
            # Track timing
            total_time = time.time() - start_time
            self.total_prediction_time += total_time
            
            # Warn if approaching 5s limit
            if total_time > 4.0:
                print(f"Warning: Prediction took {total_time:.2f}s (approaching 5s limit)")
            
            return prediction
            
        except Exception as e:
            # Re-raise to signal abstention to ensemble
            self.total_prediction_time += time.time() - start_time
            raise e
    
    def get_prediction_stats(self) -> Dict[str, float]:
        """Get performance statistics."""
        if self.prediction_count == 0:
            return {}
        
        return {
            'prediction_count': self.prediction_count,
            'avg_total_time': self.total_prediction_time / self.prediction_count,
            'avg_feature_extraction_time': self.feature_extraction_time / self.prediction_count,
            'avg_model_inference_time': self.model_inference_time / self.prediction_count,
            'total_prediction_time': self.total_prediction_time
        }
    
    def reset_stats(self):
        """Reset performance statistics."""
        self.prediction_count = 0
        self.total_prediction_time = 0.0
        self.feature_extraction_time = 0.0
        self.model_inference_time = 0.0
    
    def model_info(self) -> Dict[str, Union[str, int, float]]:
        """Return model information."""
        info = {
            'name': self.name,
            'model_path': self.model_path,
            'threshold': self.threshold,
            'max_bytes': self.max_bytes,
            'num_features': self.model.num_feature(),
            'num_trees': self.model.num_trees(),
            'model_type': 'lightgbm',
            'dataset': 'ember2024'
        }
        
        # Add metadata if available
        if self.metadata:
            if 'metrics' in self.metadata:
                info['training_metrics'] = self.metadata['metrics']
            if 'best_iteration' in self.metadata:
                info['best_iteration'] = self.metadata['best_iteration']
        
        # Add performance stats
        stats = self.get_prediction_stats()
        if stats:
            info['performance_stats'] = stats
        
        return info
