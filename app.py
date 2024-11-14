from flask import Flask, jsonify
from gevent.pywsgi import WSGIServer

app = Flask(__name__)


@app.route('/callback', methods=['GET'])
def payment_callback():
    return jsonify({"response_code": "OK"}), 200

@app.route('/finish', methods=['GET'])
def payment_finish():
    return jsonify({"response_code": "OK"}), 200


if __name__ == '__main__':
    server = WSGIServer(('45.90.46.50', 5000), app)
    server.serve_forever()
