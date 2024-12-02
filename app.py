import os
import time
import logging
from datetime import datetime, timedelta
import hmac
import hashlib
import base64
from urllib.parse import urlparse, parse_qs, quote
from functools import wraps
import pathlib

from flask import Flask, request, jsonify, send_from_directory, render_template
#from gevent.pywsgi import WSGIServer
import sqlite3


class Config:
    # API Settings
    NUTAKU_API_BASE = "https://sbox-osapi.nutaku.com/social_android/rest/"
    CONSUMER_KEY = os.environ.get('NUTAKU_CONSUMER_KEY', 'j0TXH1blsH66HRrQ')
    CONSUMER_SECRET = os.environ.get('NUTAKU_CONSUMER_SECRET', 'U1VVMaD@bhLkHgkR?9CI0EVc]R]Kwsn[')

    # Server Settings
    ip = "0.0.0.0"
    port = 5000

    # Paths
    UPLOAD_FOLDER = 'images'
    DB_FILE = 'payments.db'
    LOG_FILE = 'payment_server.log'

    # Payment Status Constants
    PAYMENT_STATUS = {
        'COMPLETED': 2,
        'CANCELED': 3
    }


class Database:
    def __init__(self, db_file=Config.DB_FILE):
        self.db_file = db_file
        self.init_db()

    def get_db(self):
        print(pathlib.Path(self.db_file))
        conn = sqlite3.connect(pathlib.Path(self.db_file))
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        conn = self.get_db()
        c = conn.cursor()

        c.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            payment_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            owner_id TEXT NOT NULL,
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
            payment_id, user_id, owner_id, status, ordered_time,
            item_id, item_name, quantity, unit_price, total_price,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            payment_data['payment_id'],
            payment_data['user_id'],
            payment_data['owner_id'],
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

    def _quote_uppercase(self, s):
        """URL encode string and convert hex digits to uppercase"""
        quoted = quote(s, safe='')
        return ''.join(c.upper() if c.isalnum() else c for c in quoted)

    def _get_payment_id_params(self, query_params):
        """Extract and sort payment_id parameters maintaining case-sensitive order"""
        payment_params = []
        for k, v_list in query_params.items():
            if k in ['payment_id', 'paymentId']:
                for v in v_list:
                    payment_params.append((k, v))
        return sorted(payment_params, key=lambda x: x[0])

    def _generate_signature_base_string(self, method, url, oauth_params, query_params):
        """Generate OAuth signature base string according to Nutaku specs"""
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        print(base_url)

        # 1. Collect OAuth parameters (excluding realm and oauth_signature)
        all_params = []
        for k, v in oauth_params.items():
            if k not in ['realm', 'oauth_signature']:
                all_params.append((k, v))

        # 2. Add payment_id parameters maintaining proper order
        all_params.extend(self._get_payment_id_params(query_params))

        # 3. Add remaining query parameters
        other_params = []
        for k, v_list in query_params.items():
            if k not in ['payment_id', 'paymentId']:
                for v in v_list:
                    # Keep original values, will be encoded later
                    other_params.append((k, v))

        # Sort remaining parameters case-sensitively
        all_params.extend(sorted(other_params, key=lambda x: (x[0], x[1])))

        # 4. Create parameter string with proper encoding
        param_string = '&'.join(
            f"{self._quote_uppercase(k)}={self._quote_uppercase(v)}"
            for k, v in all_params
        )

        # 5. Create final base string with proper encoding
        base_string = '&'.join([
            method.upper(),
            self._quote_uppercase(base_url),
            self._quote_uppercase(param_string)  # This creates the double-encoding mentioned in docs
        ])
        
        print(base_string)

        return base_string

    def _generate_signing_key(self, token_secret=''):
        """Generate signing key without URL encoding the secrets"""
        return f"{self.consumer_secret}&{token_secret if token_secret else ''}"

    def _generate_signature(self, base_string, signing_key):
        """Generate HMAC-SHA1 signature"""
        hashed = hmac.new(
            signing_key.encode('utf-8'),
            base_string.encode('utf-8'),
            hashlib.sha1
        )
        return base64.b64encode(hashed.digest()).decode('utf-8').rstrip('\n')

    def _parse_auth_header(self, auth_header):
        """Parse OAuth parameters from Authorization header"""
        params = {}
        parts = auth_header[6:].split(',')

        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                params[key.strip()] = value.strip().strip('"')

        return params

    def verify_signature(self, request):
        try:
            auth_header = request.headers.get('Authorization')
            print(auth_header)
            if not auth_header or not auth_header.startswith('OAuth '):
                logger.error("Missing or invalid Authorization header")
                return False

            # Parse OAuth parameters keeping original values
            oauth_params = self._parse_auth_header(auth_header)
            logger.debug(f"OAuth parameters: {oauth_params}")

            # Validate timestamp
            timestamp = int(oauth_params.get('oauth_timestamp', '0'))
            if abs(time.time() - timestamp) > 300:
                logger.error("OAuth timestamp outside valid window")
                return False

            # Generate base string using proper encoding rules
            base_string = self._generate_signature_base_string(
                request.method,
                request.url,
                oauth_params,
                dict(request.args)
            )
            logger.debug(f"Generated base string: {base_string}")

            # Generate signing key without URL encoding secrets
            signing_key = self._generate_signing_key(
                oauth_params.get('oauth_token_secret', '')
            )

            # Generate and compare signatures using constant-time comparison
            expected_signature = self._generate_signature(base_string, signing_key)
            received_signature = oauth_params.get('oauth_signature', '')

            if not hmac.compare_digest(
                    expected_signature.encode('utf-8'),
                    received_signature.encode('utf-8')
            ):
                logger.error("Signature mismatch")
                logger.debug(f"Expected signature: {expected_signature}")
                logger.debug(f"Received signature: {received_signature}")
                return False

            return True

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


def validate_payment_status(status):
    """Validate that status is an integer and has an expected value"""
    try:
        status_int = int(status)
        if status_int not in [Config.PAYMENT_STATUS['COMPLETED'],
                              Config.PAYMENT_STATUS['CANCELED']]:
            raise ValueError(f"Invalid status value: {status_int}")
        return status_int
    except ValueError as e:
        logger.error(f"Invalid status format: {str(e)}")
        return None


@app.route('/callback', methods=['GET', 'POST'])
@require_oauth
def payment_callback():
    try:
        logger.info(f"Received {request.method} request to callback")
        logger.info(f"Args: {request.args}")

        if request.method == 'POST':
            try:
                payment_data = request.get_json()
                print(payment_data)
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
                    'owner_id': request.args.get('opensocial_owner_id'),
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

                # Log if owner_id doesn't match viewer_id
                if payment_info['owner_id'] != payment_info['user_id']:
                    logger.warning(
                        f"owner_id ({payment_info['owner_id']}) does not match viewer_id ({payment_info['user_id']})")

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
                owner_id = request.args.get('opensocial_owner_id')
                ordered_time = request.args.get('orderedTime')

                # Log all received parameters
                logger.info(f"Received parameters: payment_id={payment_id}, "
                            f"status={status}, user_id={user_id}, "
                            f"owner_id={owner_id}, ordered_time={ordered_time}")

                if not all([payment_id, status, user_id, owner_id]):
                    logger.error("Missing required parameters in completion confirmation")
                    return jsonify({"response_code": "ERROR"}), 400

                # Validate status format and value
                validated_status = validate_payment_status(status)
                if validated_status is None:
                    return jsonify({"response_code": "ERROR"}), 400

                payment = db.get_payment(payment_id)
                if not payment:
                    logger.error(f"Payment not found: {payment_id}")
                    return jsonify({"response_code": "ERROR"}), 404

                if payment['user_id'] != user_id or payment['owner_id'] != owner_id:
                    logger.error(f"User/Owner ID mismatch: viewer={user_id}, "
                                 f"owner={owner_id}, stored_user={payment['user_id']}, "
                                 f"stored_owner={payment['owner_id']}")
                    return jsonify({"response_code": "ERROR"}), 401

                db.update_payment_status(payment_id, validated_status)
                logger.info(f"Payment {payment_id} status updated to {validated_status}")

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
    # db.session.rollback()
    return jsonify({"response_code": "ERROR"}), 500
    
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

if __name__ == '__main__':
    # Ensure images folder exists
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

    # Initialize database
    db.init_db()

    # Start server
    logger.info(f"Starting server on {Config.ip}:{Config.port}")
    #server = WSGIServer((Config.ip, Config.port), app)
    #server.serve_forever()
