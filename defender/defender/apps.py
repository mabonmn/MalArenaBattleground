from flask import Flask, jsonify, request


def create_app(malconv_model, stringcnn_model):
    app = Flask(__name__)
    app.config['malconv_model'] = malconv_model
    app.config['stringcnn_model'] = stringcnn_model

    # analyse a sample with both models
    @app.route('/', methods=['POST'])
    def post():
        # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp

        bytez = request.data

        malconv_model = app.config['malconv_model']
        stringcnn_model = app.config['stringcnn_model']

        # Query both models
        try:
            malconv_result = malconv_model.predict(bytez)
            if not isinstance(malconv_result, int) or malconv_result not in {0, 1}:
                malconv_result = -1  # Error indicator
        except Exception as e:
            print(f"MalConv error: {e}")
            malconv_result = -1

        try:
            stringcnn_result = stringcnn_model.predict(bytez)
            if not isinstance(stringcnn_result, int) or stringcnn_result not in {0, 1}:
                stringcnn_result = -1  # Error indicator
        except Exception as e:
            print(f"StringCNN error: {e}")
            stringcnn_result = -1

        # Return results from both models separately
        resp = jsonify({
            'malconv_result': malconv_result,
            'stringcnn_result': stringcnn_result,
            'result': malconv_result  # Keep backward compatibility - use MalConv as primary
        })
        resp.status_code = 200
        return resp

    # get the model info for both models
    @app.route('/model', methods=['GET'])
    def get_model():
        # curl -XGET http://127.0.0.1:8080/model
        malconv_model = app.config['malconv_model']
        stringcnn_model = app.config['stringcnn_model']
        
        model_info = {
            'malconv': malconv_model.model_info(),
            'stringcnn': stringcnn_model.get_info()
        }
        
        resp = jsonify(model_info)
        resp.status_code = 200
        return resp

    return app
