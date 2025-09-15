import os
import envparse
from defender.apps import create_app

if __name__ == "__main__":
    # Retrieve config values from environment variables
    model_type = envparse.env("DF_MODEL_TYPE", cast=str, default="ember_lightgbm")
    
    if model_type == "ember_lightgbm":
        # EMBER LightGBM model
        from defender.models.ember_lightgbm_model import EmberLightGBMModel
        
        # EMBER LightGBM config
        model_path = envparse.env("DF_EMBER_MODEL_PATH", cast=str, default="ember_lightgbm/lightgbm_ember_model.txt")
        threshold = envparse.env("DF_EMBER_THRESHOLD", cast=float, default=None)  # Use model's optimal threshold if None
        max_bytes = envparse.env("DF_EMBER_MAX_BYTES", cast=int, default=2097152)  # 2MB
        
        # Resolve model path
        if not model_path.startswith(os.sep):
            model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models", model_path)
        
        if not os.path.isfile(model_path):
            raise FileNotFoundError(f"EMBER LightGBM model not found at {model_path}. Train model first using train/train_lightgbm_ember.py")
        
        model = EmberLightGBMModel(
            model_path=model_path,
            threshold=threshold,
            max_bytes=max_bytes
        )
        
    else:
        # Fallback to MalConv for compatibility
        from defender.models.malconv_model import MalConvTorchModel
        
        # MalConv-specific config
        malconv_weights = envparse.env("DF_MALCONV_WEIGHTS", cast=str, default="models/malconv_model.pt")
        malconv_threshold = envparse.env("DF_MALCONV_THRESH", cast=float, default=0.80)
        malconv_max_bytes = envparse.env("DF_MALCONV_MAX_BYTES", cast=int, default=1048576)
        
        malconv_path_abs = malconv_weights
        if not malconv_path_abs.startswith(os.sep):
            malconv_path_abs = os.path.join(os.path.dirname(os.path.abspath(__file__)), malconv_path_abs)
        
        if not os.path.isfile(malconv_path_abs):
            raise FileNotFoundError(f"MalConv weights not found at {malconv_path_abs}. Set DF_MALCONV_WEIGHTS or copy weights to models/malconv_model.pt")
        
        device = 'cpu'  # CPU only inside container per challenge limits
        model = MalConvTorchModel(
            weights_path=malconv_path_abs,
            max_bytes=malconv_max_bytes,
            threshold=malconv_threshold,
            device=device,
        )
    # model = NFSModel(open(os.path.dirname(__file__) + "/models/nfs_libraries_functions_nostrings.pickle", "rb"))

    app = create_app(model)

    import sys
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080

    from gevent.pywsgi import WSGIServer
    http_server = WSGIServer(('', port), app)
    http_server.serve_forever()

    # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
