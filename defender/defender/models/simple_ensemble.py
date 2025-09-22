"""
Simple Ensemble Manager for Weighted Voting Malware Classification
"""
import logging


class SimpleEnsemble:
    """
    Simple ensemble manager with weighted voting only.
    """
    
    def __init__(self, threshold: float = 0.5):
        """
        Initialize the ensemble manager.
        
        Args:
            threshold: Decision threshold for weighted average (default 0.5)
        """
        self.models = {}
        self.weights = {}
        self.threshold = threshold
    
    def add_model(self, name: str, model_instance, weight: float = 1.0):
        """
        Add a model to the ensemble.
        
        Args:
            name: Unique identifier for the model
            model_instance: The model object with a predict() method
            weight: Voting weight (higher = more influence)
        """
        self.models[name] = model_instance
        self.weights[name] = weight
        logging.info(f"Added model '{name}' with weight {weight}")
    
    def predict(self, data: bytes) -> int:
        """
        Predict using weighted voting.
        
        Args:
            data: Input data (PE file bytes)
            
        Returns:
            int: 0 (benign) or 1 (malicious)
        """
        if not self.models:
            raise ValueError("No models loaded in ensemble")
        
        # Get predictions from all models
        total_weight = 0
        weighted_sum = 0
        
        for name, model in self.models.items():
            try:
                pred = model.predict(data)
                if isinstance(pred, (int, float)) and pred in {0, 1}:
                    weight = self.weights[name]
                    weighted_sum += pred * weight
                    total_weight += weight
                else:
                    logging.warning(f"Model '{name}' returned invalid prediction: {pred}")
            except Exception as e:
                logging.warning(f"Model '{name}' prediction failed: {e}")
        
        if total_weight == 0:
            # All models failed - default to malicious for safety
            logging.error("All models failed, defaulting to malicious")
            return 1
        
        # Weighted average
        average = weighted_sum / total_weight
        result = 1 if average >= self.threshold else 0
        
        logging.info(f"Ensemble prediction: {result} (weighted avg: {average:.3f})")
        return result