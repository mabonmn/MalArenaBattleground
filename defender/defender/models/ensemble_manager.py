"""
Ensemble Manager for Tournament-style Malware Classification
Supports weighted voting from multiple models with easy scalability.
"""
import json
import logging
from typing import Dict, List, Tuple, Any
from pathlib import Path


class EnsembleManager:
    """
    Manages multiple malware detection models with weighted voting.
    Supports easy addition of new models and configurable voting strategies.
    """
    
    def __init__(self, config_path: str = None):
        """
        Initialize the ensemble manager.
        
        Args:
            config_path: Path to ensemble configuration JSON file
        """
        self.models = {}
        self.weights = {}
        self.voting_strategy = "weighted_average"
        self.threshold = 0.5
        self.model_info = {}
        
        if config_path and Path(config_path).exists():
            self.load_config(config_path)
    
    def add_model(self, name: str, model_instance, weight: float = 1.0, info: Dict = None):
        """
        Add a model to the ensemble.
        
        Args:
            name: Unique identifier for the model
            model_instance: The model object with a predict() method
            weight: Voting weight (higher = more influence)
            info: Optional metadata about the model
        """
        self.models[name] = model_instance
        self.weights[name] = weight
        self.model_info[name] = info or {}
        
        logging.info(f"Added model '{name}' with weight {weight}")
    
    def remove_model(self, name: str):
        """Remove a model from the ensemble."""
        if name in self.models:
            del self.models[name]
            del self.weights[name]
            del self.model_info[name]
            logging.info(f"Removed model '{name}'")
    
    def set_voting_strategy(self, strategy: str, threshold: float = 0.5):
        """
        Set the voting strategy.
        
        Args:
            strategy: 'weighted_average', 'majority_vote', 'unanimous', 'any_positive'
            threshold: Decision threshold for weighted_average strategy
        """
        valid_strategies = ['weighted_average', 'majority_vote', 'unanimous', 'any_positive']
        if strategy not in valid_strategies:
            raise ValueError(f"Strategy must be one of {valid_strategies}")
        
        self.voting_strategy = strategy
        self.threshold = threshold
        logging.info(f"Set voting strategy to '{strategy}' with threshold {threshold}")
    
    def predict(self, data: bytes) -> int:
        """
        Predict using ensemble voting.
        
        Args:
            data: Input data (PE file bytes)
            
        Returns:
            int: 0 (benign) or 1 (malicious)
        """
        if not self.models:
            raise ValueError("No models loaded in ensemble")
        
        # Get predictions from all models
        predictions = {}
        errors = {}
        
        for name, model in self.models.items():
            try:
                pred = model.predict(data)
                if isinstance(pred, (int, float)) and pred in {0, 1}:
                    predictions[name] = pred
                else:
                    errors[name] = f"Invalid prediction: {pred}"
            except Exception as e:
                errors[name] = str(e)
                logging.warning(f"Model '{name}' prediction failed: {e}")
        
        if not predictions:
            # All models failed - default to malicious for safety
            logging.error("All models failed, defaulting to malicious")
            return 1
        
        # Apply voting strategy
        result = self._apply_voting_strategy(predictions)
        
        # Log decision details
        logging.info(f"Ensemble prediction: {result}, individual: {predictions}")
        if errors:
            logging.warning(f"Model errors: {errors}")
        
        return result
    
    def _apply_voting_strategy(self, predictions: Dict[str, int]) -> int:
        """Apply the configured voting strategy to predictions."""
        
        if self.voting_strategy == "weighted_average":
            # Weighted average of predictions
            total_weight = 0
            weighted_sum = 0
            
            for name, pred in predictions.items():
                weight = self.weights.get(name, 1.0)
                weighted_sum += pred * weight
                total_weight += weight
            
            average = weighted_sum / total_weight if total_weight > 0 else 0
            return 1 if average >= self.threshold else 0
        
        elif self.voting_strategy == "majority_vote":
            # Simple majority (ignoring weights)
            malicious_votes = sum(1 for pred in predictions.values() if pred == 1)
            return 1 if malicious_votes > len(predictions) / 2 else 0
        
        elif self.voting_strategy == "unanimous":
            # All models must agree on malicious
            return 1 if all(pred == 1 for pred in predictions.values()) else 0
        
        elif self.voting_strategy == "any_positive":
            # Any model predicting malicious triggers malicious result
            return 1 if any(pred == 1 for pred in predictions.values()) else 0
        
        else:
            raise ValueError(f"Unknown voting strategy: {self.voting_strategy}")
    
    def get_detailed_prediction(self, data: bytes) -> Dict[str, Any]:
        """
        Get detailed prediction results including individual model outputs.
        
        Args:
            data: Input data (PE file bytes)
            
        Returns:
            Dict containing ensemble result and individual model predictions
        """
        predictions = {}
        errors = {}
        
        for name, model in self.models.items():
            try:
                pred = model.predict(data)
                predictions[name] = {
                    'prediction': pred,
                    'weight': self.weights.get(name, 1.0),
                    'valid': isinstance(pred, (int, float)) and pred in {0, 1}
                }
            except Exception as e:
                errors[name] = str(e)
                predictions[name] = {
                    'prediction': -1,
                    'weight': self.weights.get(name, 1.0),
                    'valid': False,
                    'error': str(e)
                }
        
        # Get final ensemble decision
        valid_predictions = {k: v['prediction'] for k, v in predictions.items() if v['valid']}
        ensemble_result = self._apply_voting_strategy(valid_predictions) if valid_predictions else 1
        
        return {
            'ensemble_result': ensemble_result,
            'voting_strategy': self.voting_strategy,
            'threshold': self.threshold,
            'individual_predictions': predictions,
            'total_models': len(self.models),
            'successful_models': len(valid_predictions),
            'failed_models': len(errors)
        }
    
    def get_ensemble_info(self) -> Dict[str, Any]:
        """Get information about the ensemble configuration."""
        return {
            'models': list(self.models.keys()),
            'weights': self.weights.copy(),
            'voting_strategy': self.voting_strategy,
            'threshold': self.threshold,
            'total_models': len(self.models),
            'model_info': self.model_info.copy()
        }
    
    def load_config(self, config_path: str):
        """Load ensemble configuration from JSON file."""
        with open(config_path, 'r') as f:
            config = json.load(f)
        
        self.voting_strategy = config.get('voting_strategy', 'weighted_average')
        self.threshold = config.get('threshold', 0.5)
        
        # Note: Models still need to be added programmatically
        # This just loads the strategy and weights configuration
        if 'weights' in config:
            self.weights.update(config['weights'])
        
        logging.info(f"Loaded ensemble config from {config_path}")
    
    def save_config(self, config_path: str):
        """Save current ensemble configuration to JSON file."""
        config = {
            'voting_strategy': self.voting_strategy,
            'threshold': self.threshold,
            'weights': self.weights,
            'model_info': self.model_info
        }
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        logging.info(f"Saved ensemble config to {config_path}")