import os
import time
import logging
from datetime import datetime, timedelta
import hmac
import hashlib
import base64
from urllib.parse import urlparse, parse_qs, quote
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from gevent.pywsgi import WSGIServer
import sqlite3
import host


class Config:
    # API Settings
    NUTAKU_API_BASE = "https://osapi.nutaku.com/social_android/rest/"
    CONSUMER_KEY = os.environ.get('NUTAKU_CONSUMER_KEY', 'j0TXH1blsH66HRrQ')
    CONSUMER_SECRET = os.environ.get('NUTAKU_CONSUMER_SECRET', 'U1VVMaD@bhLkHgkR?9CI0EVc]R]Kwsn[')

    # Server Settings
    ip = host.ip
    port = host.port

    # Security
    # ALLOWED_IMAGE_TYPES = {'.jpg', '.gif'}
    # MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5MB
    # IMAGE_TOKEN_EXPIRE = timedelta(minutes=30)

    # Paths
    UPLOAD_FOLDER = 'images'
    DB_FILE = 'payments.db'
    LOG_FILE = 'payment_server.log'


class Database:
    def __init__(self, db_file=Config.DB_FILE):
        self.db_file = db_file
        self.init_db()

    def get_db(self):
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_db()
        c = conn.cursor()

        c.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            payment_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            status INTEGER NOT NULL,
            ordered_time TEXT NOT NULL,
            item_id TEXT NOT NULL,
            item_name TEXT NOT NULL,
            quantity INTEGER NOT NULL,
            unit_price INTEGER NOT NULL,
            total_price INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        ''')

        conn.commit()
        conn.close()

    def create_payment(self, payment_data):
        conn = self.get_db()
        c = conn.cursor()

        now = datetime.utcnow().isoformat()

        c.execute('''
        INSERT INTO payments (
            payment_id, user_id, status, ordered_time,
            item_id, item_name, quantity, unit_price, total_price,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            payment_data['payment_id'],
            payment_data['user_id'],
            payment_data['status'],
            payment_data['ordered_time'],
            payment_data['item_id'],
            payment_data['item_name'],
            payment_data['quantity'],
            payment_data['unit_price'],
            payment_data['unit_price'] * payment_data['quantity'],
            now,
            now
        ))

        conn.commit()
        conn.close()

    def update_payment_status(self, payment_id, new_status):
        conn = self.get_db()
        c = conn.cursor()

        c.execute('''
        UPDATE payments 
        SET status = ?, updated_at = ? 
        WHERE payment_id = ?
        ''', (new_status, datetime.utcnow().isoformat(), payment_id))

        conn.commit()
        conn.close()

    def get_payment(self, payment_id):
        conn = self.get_db()
        c = conn.cursor()

        c.execute('SELECT * FROM payments WHERE payment_id = ?', (payment_id,))
        result = c.fetchone()

        conn.close()
        return dict(result) if result else None


# OAuth Validation
class OAuthSignature:
    def __init__(self, consumer_key, consumer_secret):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret

    def verify_signature(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('OAuth '):
                logger.error("Missing or invalid Authorization header")
                return False

            oauth_params = self._parse_auth_header(auth_header)

            timestamp = int(oauth_params.get('oauth_timestamp', '0'))
            if abs(time.time() - timestamp) > 300:
                logger.error("OAuth timestamp outside valid window")
                return False

            base_string = self._generate_signature_base_string(
                request.method,
                request.url,
                oauth_params,
                dict(request.args)  # Pass query params separately
            )

            signing_key = self._generate_signing_key(
                oauth_params.get('oauth_token_secret', '')
            )

            expected_signature = self._generate_signature(base_string, signing_key)
            received_signature = oauth_params.get('oauth_signature', '')

            return hmac.compare_digest(
                expected_signature.encode('utf-8'),
                received_signature.encode('utf-8')
            )

        except Exception as e:
            logger.error(f"Error verifying OAuth signature: {str(e)}")
            return False

    def _parse_auth_header(self, auth_header):
        """Parse OAuth parameters from Authorization header"""
        params = {}
        parts = auth_header[6:].split(',')

        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                params[key.strip()] = value.strip('"')

        return params

    # In OAuthSignature class
    def _generate_signature_base_string(self, method, url, oauth_params, query_params):
        """
        Generate OAuth signature base string according to RFC 5849
        """
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"

        all_params = []

        for k, v in oauth_params.items():
            if k != 'oauth_signature':
                all_params.append((k, quote(v, safe='')))

        payment_id_values = set()

        for k, v_list in query_params.items():
            if k.lower() in ['payment_id', 'paymentid']:
                payment_id_values.update(v_list)

        for value in payment_id_values:
            all_params.append(('payment_id', quote(value, safe='')))
            all_params.append(('paymentId', quote(value, safe='')))

        for k, v_list in query_params.items():
            if k.lower() not in ['payment_id', 'paymentid']:
                for v in v_list:
                    all_params.append((k, quote(v, safe='')))

        sorted_params = sorted(all_params, key=lambda x: (x[0], x[1]))

        param_string = '&'.join(f"{k}={v}" for k, v in sorted_params)

        base_string = '&'.join([
            method.upper(),
            quote(base_url, safe=''),
            quote(param_string, safe='')
        ])

        return base_string

    def _generate_signing_key(self, token_secret=''):
        return f"{self.consumer_secret}&{token_secret}"

    def _generate_signature(self, base_string, signing_key):
        hashed = hmac.new(
            signing_key.encode('utf-8'),
            base_string.encode('utf-8'),
            hashlib.sha1
        )
        return base64.b64encode(hashed.digest()).decode('utf-8')


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER

db = Database()
oauth = OAuthSignature(Config.CONSUMER_KEY, Config.CONSUMER_SECRET)

# Configure logging
logging.basicConfig(
    filename=Config.LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Request validation decorator
def require_oauth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not oauth.verify_signature(request):
            logger.error("OAuth validation failed")
            return jsonify({"response_code": "ERROR"}), 401
        return f(*args, **kwargs)

    return decorated


@app.route('/callback', methods=['GET', 'POST'])
@require_oauth
def payment_callback():
    try:
        logger.info(f"Received {request.method} request to callback")
        logger.info(f"Args: {request.args}")

        if request.method == 'POST':
            try:
                payment_data = request.get_json()
                logger.info(f"Payment data received: {payment_data}")

                payment_entry = payment_data.get('entry', {})
                if not payment_entry:
                    logger.error("No entry in payment data")
                    return jsonify({"response_code": "ERROR"}), 400

                payment_items = payment_entry.get('paymentItems', [])
                if not payment_items:
                    logger.error("No payment items found")
                    return jsonify({"response_code": "ERROR"}), 400

                payment_id = (payment_entry.get('paymentId') or
                              payment_entry.get('payment_id'))

                payment_info = {
                    'payment_id': payment_id,
                    'user_id': request.args.get('opensocial_viewer_id'),
                    'status': payment_entry.get('status', 0),
                    'ordered_time': payment_entry.get('orderedTime'),
                    'item_id': payment_items[0].get('itemId'),
                    'item_name': payment_items[0].get('itemName'),
                    'quantity': int(payment_items[0].get('quantity', '1')),
                    'unit_price': payment_items[0].get('unitPrice')
                }

                if not all(payment_info.values()):
                    logger.error(f"Missing required payment fields: {payment_info}")
                    return jsonify({"response_code": "ERROR"}), 400

                db.create_payment(payment_info)
                logger.info(f"Successfully stored payment: {payment_info['payment_id']}")

                return jsonify({"response_code": "OK"}), 200

            except Exception as e:
                logger.error(f"Error processing payment creation: {str(e)}")
                return jsonify({"response_code": "ERROR"}), 500

        elif request.method == 'GET':
            try:
                payment_id = (request.args.get('paymentId') or
                              request.args.get('payment_id'))
                status = request.args.get('status')
                user_id = request.args.get('opensocial_viewer_id')

                if not all([payment_id, status, user_id]):
                    logger.error("Missing required parameters in completion confirmation")
                    return jsonify({"response_code": "ERROR"}), 400

                payment = db.get_payment(payment_id)
                if not payment:
                    logger.error(f"Payment not found: {payment_id}")
                    return jsonify({"response_code": "ERROR"}), 404

                if payment['user_id'] != user_id:
                    logger.error(f"User ID mismatch: {user_id} != {payment['user_id']}")
                    return jsonify({"response_code": "ERROR"}), 401

                new_status = int(status)
                db.update_payment_status(payment_id, new_status)

                if new_status == 2:
                    logger.info(f"Payment {payment_id} successfully validated and completed")
                    return jsonify({"response_code": "OK"}), 200

            except Exception as e:
                logger.error(f"Error processing payment completion: {str(e)}")
                return jsonify({"response_code": "ERROR"}), 500

    except Exception as e:
        logger.error(f"Unexpected error in payment callback: {str(e)}")
        return jsonify({"response_code": "ERROR"}), 500


@app.route('/finish', methods=['GET', 'POST'])
def payment_finish():
    """Handle redirection after payment completion"""
    return jsonify({"response_code": "OK"}), 200


@app.route('/images/<filename>')
def serve_image(filename):
    """Simple static file serving for images"""
    try:
        if '..' in filename or filename.startswith('/'):
            logger.warning(f"Attempted path traversal with filename: {filename}")
            return "Access denied", 403

        safe_path = os.path.join(Config.UPLOAD_FOLDER, filename)
        if not os.path.exists(safe_path):
            return "File not found", 404

        if not os.path.dirname(os.path.abspath(safe_path)) == os.path.abspath(Config.UPLOAD_FOLDER):
            logger.warning(f"Attempted access outside images directory: {filename}")
            return "Access denied", 403

        return send_from_directory(Config.UPLOAD_FOLDER, filename)
    except Exception as e:
        logger.error(f"Error serving image {filename}: {str(e)}")
        return "Error serving image", 500


# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 error: {error}")
    return jsonify({"response_code": "ERROR"}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    db.session.rollback()
    return jsonify({"response_code": "ERROR"}), 500


if __name__ == '__main__':
    # Ensure images folder exists
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    # Initialize database
    db.init_db()

    # Start server
    logger.info(f"Starting server on {Config.ip}:{Config.port}")
    server = WSGIServer((Config.ip, Config.port), app)
    server.serve_forever()