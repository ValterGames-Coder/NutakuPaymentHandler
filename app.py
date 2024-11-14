from flask import Flask, jsonify

app = Flask(__name__)


@app.route('/callback', methods=['GET'])
def payment_callback():
    return jsonify({"response_code": "OK"}), 200


if __name__ == '__main__':
    app.run(debug=True)
