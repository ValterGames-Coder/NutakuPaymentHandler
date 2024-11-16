import os

from flask import Flask, jsonify, send_from_directory
from gevent.pywsgi import WSGIServer
import host

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'images'


@app.route('/callback', methods=['GET', 'POST'])
def payment_callback():
    return jsonify({"response_code": "OK"}), 200

@app.route('/finish', methods=['GET', 'POST'])
def payment_finish():
    return jsonify({"response_code": "OK"}), 200

@app.route('/images/<filename>', methods=['GET'])
def get_file_url(filename):
    full_path = os.path.join(app.root_path, app.config['UPLOAD_FOLDER'])
    return send_from_directory(full_path, filename, as_attachment=True)

if __name__ == '__main__':
    server = WSGIServer((host.ip, host.port), app)
    server.serve_forever()
