from flask import Flask, jsonify, request


def create_app(ensemble):
    app = Flask(__name__)
    app.config['ensemble'] = ensemble

    # analyse a sample with ensemble voting
    @app.route('/', methods=['POST'])
    def post():
        # curl -XPOST --data-binary @somePEfile http://127.0.0.1:8080/ -H "Content-Type: application/octet-stream"
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            return resp

        bytez = request.data
        ensemble = app.config['ensemble']

        try:
            # Get ensemble prediction
            result = ensemble.predict(bytez)
            
            if not isinstance(result, int) or result not in {0, 1}:
                resp = jsonify({'error': 'unexpected ensemble result (not in [0,1])'})
                resp.status_code = 500  # Internal Server Error
                return resp

            resp = jsonify({'result': result})
            resp.status_code = 200
            return resp
            
        except Exception as e:
            resp = jsonify({'error': f'ensemble prediction failed: {str(e)}'})
            resp.status_code = 500
            return resp

    return app
