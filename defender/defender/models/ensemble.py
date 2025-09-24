"""
Simple Ensemble Manager for Weighted Voting Malware Classification
"""
import logging
import os


class Ensemble:
    """
    Simple ensemble manager with weighted voting and optional consensus (2-of-3).
    """
    
    def __init__(self, threshold: float = 0.5):
        """
        Initialize the ensemble manager.
        
        Args:
            threshold: Decision threshold for weighted average (default 0.5)
        """
        self.models = {}
        self.weights = {}
        # allow overriding threshold via ENV
        try:
            self.threshold = float(os.getenv("DF_ENSEMBLE_THRESHOLD", threshold))
        except Exception:
            self.threshold = threshold
        # enable consensus requirement via ENV (default true)
        self.require_2of3 = str(os.getenv("DF_ENSEMBLE_REQUIRE_2OF3", "true")).lower() in ("1", "true", "yes", "on")
    
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
        Predict using weighted voting and optional 2-of-3 consensus.
        
        Args:
            data: Input data (PE file bytes)
            
        Returns:
            int: 0 (benign) or 1 (malicious)
        """
        if not self.models:
            raise ValueError("No models loaded in ensemble")

        # Get predictions from all models
        total_weight = 0.0
        weighted_sum = 0.0
        votes = []  # store binary votes for consensus mode

        for name, model in self.models.items():
            try:
                pred = model.predict(data)
                if isinstance(pred, (int, float)) and pred in {0, 1}:
                    # collect vote for consensus
                    votes.append(int(pred))
                    weight = float(self.weights.get(name, 1.0))
                    weighted_sum += float(pred) * weight
                    total_weight += weight
                else:
                    logging.warning(f"Model '{name}' returned invalid prediction: {pred}; treating as abstain")
            except Exception as e:
                # Abstain on failure to reduce FPR spikes
                logging.warning(f"Model '{name}' prediction failed, abstaining: {e}")

        if total_weight == 0:
            # All models abstained/failed — bias to benign to reduce FPR
            logging.error("All models abstained/failed, defaulting to benign")
            return 0

        # If enabled and we have at least 3 models, require at least 2 malicious votes
        if self.require_2of3 and len(self.models) >= 3:
            positives = sum(votes)
            result = 1 if positives >= 2 else 0
            logging.info(f"Ensemble (2-of-3) votes={votes} -> {result}")
            return result

        # Weighted average
        average = weighted_sum / total_weight
        result = 1 if average >= self.threshold else 0

        logging.info(f"Ensemble prediction: {result} (weighted avg: {average:.3f}, thr={self.threshold})")
        return result