from flask import Flask, jsonify
from gevent.pywsgi import WSGIServer
import host

app = Flask(__name__)


@app.route('/callback', methods=['GET', 'POST'])
def payment_callback():
    return jsonify({"response_code": "OK"}), 200

@app.route('/finish', methods=['GET', 'POST'])
def payment_finish():
    return jsonify({"response_code": "OK"}), 200


if __name__ == '__main__':
    server = WSGIServer((host.ip, host.port), app)
    server.serve_forever()
