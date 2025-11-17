import os
import envparse
from defender.apps import create_app
from defender.models.malconv_model import MalConvTorchModel
from defender.models.ember_lightgbm_model import EmberLightGBMModel
from defender.models.enhanced_ember_lightgbm_model import EnhancedEmberLightGBMModel
from defender.models.stringcnn_model import StringCNNModel

from defender.models.ensemble import Ensemble

if __name__ == "__main__":
    # Retrieve config values from environment variables
    
    # Ensemble configuration
    ensemble_threshold = envparse.env("DF_ENSEMBLE_THRESHOLD", cast=float, default=0.5)
    
    # MalConv-specific config
    malconv_weights = envparse.env("DF_MALCONV_WEIGHTS", cast=str, default="models/malconv_model.pt")
    malconv_threshold = envparse.env("DF_MALCONV_THRESH", cast=float, default=0.80)
    malconv_max_bytes = envparse.env("DF_MALCONV_MAX_BYTES", cast=int, default=1048576)
    malconv_weight = envparse.env("DF_MALCONV_VOTE_WEIGHT", cast=float, default=1.5)  #Higher weight due to better performance
    
    # EMBER LightGBM-specific config
    lightgbm_model_path = envparse.env("DF_LIGHTGBM_MODEL_PATH", cast=str, default="models/newLGBM_model.txt")
    lightgbm_threshold = envparse.env("DF_LIGHTGBM_THRESH", cast=float, default=None)
    lightgbm_max_bytes = envparse.env("DF_LIGHTGBM_MAX_BYTES", cast=int, default=2097152)
    lightgbm_weight = envparse.env("DF_LIGHTGBM_VOTE_WEIGHT", cast=float, default=1.0)  
    lightgbm_use_enhanced = envparse.env("DF_LIGHTGBM_USE_ENHANCED", cast=bool, default=True)

    # EMBER LightGBM 800,000 this was trained on 800,000 samples, not 800k sized samples
    lightgbm800k_model_path = envparse.env("DF_LIGHTGBM800K_MODEL_PATH", cast=str, default="models/LGBM_model800k.txt")
    lightgbm800k_threshold = envparse.env("DF_LIGHTGBM800K_THRESH", cast=float, default=None)
    lightgbm800k_max_bytes = envparse.env("DF_LIGHTGBM800K_MAX_BYTES", cast=int, default=819200)
    lightgbm800k_weight = envparse.env("DF_LIGHTGBM800K_VOTE_WEIGHT", cast=float, default=1.0)
    lightgbm800k_use_enhanced = envparse.env("DF_LIGHTGBM800K_USE_ENHANCED", cast=bool, default=True)

    device = 'cpu'  # CPU only inside container per challenge limits
    
    # Initialize simple ensemble
    ensemble = Ensemble(threshold=ensemble_threshold)
    
    # Initialize and add MalConv model
    
    # StringCNN-specific config
    stringcnn_weights = envparse.env("DF_STRINGCNN_WEIGHTS", cast=str, default="models/cnn_strings_best.pt")
    stringcnn_threshold = envparse.env("DF_STRINGCNN_THRESH", cast=float, default=0.50)
    stringcnn_max_bytes = envparse.env("DF_STRINGCNN_MAX_BYTES", cast=int, default=1048576)

    # CUSTOMIZE: app and model instances
    device = 'cpu'  # CPU only inside container per challenge limits
    
    # Initialize MalConv model
    malconv_path_abs = malconv_weights
    if not malconv_path_abs.startswith(os.sep):
        malconv_path_abs = os.path.join(os.path.dirname(os.path.abspath(__file__)), malconv_path_abs)

    if os.path.isfile(malconv_path_abs):
        malconv_model = MalConvTorchModel(
            weights_path=malconv_path_abs,
            max_bytes=malconv_max_bytes,
            threshold=malconv_threshold,
            device=device,
        )
        ensemble.add_model("malconv", malconv_model, weight=malconv_weight)
        print(f"✓ Added MalConv model with weight {malconv_weight}")
    else:
        print(f"⚠ MalConv model not found at {malconv_path_abs}, skipping")
    
    # Initialize and add EMBER LightGBM model
    lightgbm_path_abs = lightgbm_model_path
    if not lightgbm_path_abs.startswith(os.sep):
        lightgbm_path_abs = os.path.join(os.path.dirname(os.path.abspath(__file__)), lightgbm_path_abs)

    if os.path.isfile(lightgbm_path_abs):
        if lightgbm_use_enhanced:
            lightgbm_model = EnhancedEmberLightGBMModel(
                model_path=lightgbm_path_abs,
                threshold=lightgbm_threshold,
                max_bytes=lightgbm_max_bytes
            )
        else:
            lightgbm_model = EmberLightGBMModel(
                model_path=lightgbm_path_abs,
                threshold=lightgbm_threshold,
                max_bytes=lightgbm_max_bytes
            )
        ensemble.add_model("lightgbm", lightgbm_model, weight=lightgbm_weight)
        enhanced_status = " (enhanced)" if lightgbm_use_enhanced else ""
        print(f"✓ Added LightGBM model{enhanced_status} with weight {lightgbm_weight}")
    else:
        print(f"⚠ LightGBM model not found at {lightgbm_path_abs}, skipping")
    
    # Initialize and add EMBER LightGBM 800k model
    lightgbm800k_path_abs = lightgbm800k_model_path
    if not lightgbm800k_path_abs.startswith(os.sep):
        lightgbm800k_path_abs = os.path.join(os.path.dirname(os.path.abspath(__file__)), lightgbm800k_path_abs)

    if os.path.isfile(lightgbm800k_path_abs):
        if lightgbm800k_use_enhanced:
            lightgbm800k_model = EnhancedEmberLightGBMModel(
                model_path=lightgbm800k_path_abs,
                threshold=lightgbm800k_threshold,
                max_bytes=lightgbm800k_max_bytes
            )
        else:
            lightgbm800k_model = EmberLightGBMModel(
                model_path=lightgbm800k_path_abs,
                threshold=lightgbm800k_threshold,
                max_bytes=lightgbm800k_max_bytes
            )
        ensemble.add_model("lightgbm800k", lightgbm800k_model, weight=lightgbm800k_weight)
        enhanced_status = " (enhanced)" if lightgbm800k_use_enhanced else ""
        print(f"✓ Added LightGBM 800k model{enhanced_status} with weight {lightgbm800k_weight}")
    else:
        print(f"⚠ LightGBM 800k model not found at {lightgbm800k_path_abs}, skipping")
    
    # Verify we have at least one model
    if len(ensemble.models) == 0:
        raise RuntimeError("No models were successfully loaded! Check your model paths.")
    
    print(f"🏆 Ensemble ready with {len(ensemble.models)} models using weighted voting")
    
    # Initialize and add StringCNN model to ensemble
    stringcnn_path_abs = stringcnn_weights
    if not stringcnn_path_abs.startswith(os.sep):
        stringcnn_path_abs = os.path.join(os.path.dirname(os.path.abspath(__file__)), stringcnn_path_abs)

    if os.path.isfile(stringcnn_path_abs):
        stringcnn_weight = envparse.env("DF_STRINGCNN_VOTE_WEIGHT", cast=float, default=1.0)
        stringcnn_model = StringCNNModel(
            weights_path=stringcnn_path_abs,
            max_bytes=stringcnn_max_bytes,
            threshold=stringcnn_threshold,
            device=device,
        )
        ensemble.add_model("stringcnn", stringcnn_model, weight=stringcnn_weight)
        print(f"✓ Added StringCNN model with weight {stringcnn_weight}")
    else:
        print(f"⚠ StringCNN model not found at {stringcnn_path_abs}, skipping")

    # Create app with ensemble
    app = create_app(ensemble)

    import sys
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080

    from gevent.pywsgi import WSGIServer
    http_server = WSGIServer(('', port), app)
    http_server.serve_forever()

    # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
