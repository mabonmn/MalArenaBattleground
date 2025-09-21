import os
import envparse
from defender.apps import create_app
from defender.models.malconv_model import MalConvTorchModel
from defender.models.stringcnn_model import StringCNNModel

if __name__ == "__main__":
    # retrive config values from environment variables
    # MalConv-specific config
    # Default path under the defender package
    malconv_weights = envparse.env("DF_MALCONV_WEIGHTS", cast=str, default="models/malconv_model.pt")
    malconv_threshold = envparse.env("DF_MALCONV_THRESH", cast=float, default=0.80)
    malconv_max_bytes = envparse.env("DF_MALCONV_MAX_BYTES", cast=int, default=1048576)
    
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

    if not os.path.isfile(malconv_path_abs):
        raise FileNotFoundError(f"MalConv weights not found at {malconv_path_abs}. Set DF_MALCONV_WEIGHTS or copy weights to models/malconv_model.pt")

    malconv_model = MalConvTorchModel(
        weights_path=malconv_path_abs,
        max_bytes=malconv_max_bytes,
        threshold=malconv_threshold,
        device=device,
    )
    
    # Initialize StringCNN model
    stringcnn_path_abs = stringcnn_weights
    if not stringcnn_path_abs.startswith(os.sep):
        stringcnn_path_abs = os.path.join(os.path.dirname(os.path.abspath(__file__)), stringcnn_path_abs)

    stringcnn_model = StringCNNModel(
        weights_path=stringcnn_path_abs,
        max_bytes=stringcnn_max_bytes,
        threshold=stringcnn_threshold,
        device=device,
    )

    # Create app with both models
    app = create_app(malconv_model, stringcnn_model)

    import sys
    port = int(sys.argv[1]) if len(sys.argv) == 2 else 8080

    from gevent.pywsgi import WSGIServer
    http_server = WSGIServer(('', port), app)
    http_server.serve_forever()

    # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
