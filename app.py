import os
import time
import logging
from datetime import datetime, timezone, timedelta
import hmac
import hashlib
import base64
import re
from urllib.parse import urlparse, parse_qs, quote, unquote
from functools import wraps

from flask import Flask, render_template, request, jsonify, send_from_directory
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
        

    # Payment Status Constants
    PAYMENT_STATUS = {
        'COMPLETED': 2,
        'CANCELED': 3
    }
    def __init__(self):
        # Initialize instance-specific attributes
        self.LOG_FILE = os.path.join(app.instance_path, 'payment_server.log')

class Database:
    def __init__(self):
        self.db_file = os.path.join(app.instance_path, 'payments.db')
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
        
        now = datetime.now(timezone.utc).isoformat()
        
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

    def _generate_signature(self, base_string, signing_key):
        """Generate HMAC-SHA1 signature according to OAuth spec"""
        try:
            # Create HMAC-SHA1 hash
            hashed = hmac.new(
                signing_key.encode('utf-8'),
                base_string.encode('utf-8'),
                hashlib.sha1
            )
            
            # Base64 encode the hash
            signature = base64.b64encode(hashed.digest()).decode('utf-8')
            
            logger.debug(f"Generated signature:")
            logger.debug(f"Base string: {base_string}")
            logger.debug(f"Signing key: {signing_key}")
            logger.debug(f"Signature: {signature}")
            
            return signature
            
        except Exception as e:
            logger.error(f"Error generating signature: {str(e)}")
            raise

    def _parse_auth_header(self, auth_header):
        """Parse OAuth parameters from Authorization header, keeping values URL-encoded"""
        params = {}
        if not auth_header:
            logger.debug("No Authorization header present")
            return params
            
        if not auth_header.startswith('OAuth '):
            logger.error(f"Invalid Authorization header format: {auth_header[:20]}...")
            return params
            
        # Clean header value and split parts
        header_value = auth_header.replace('\n', '').replace('\r', '')
        parts = header_value[6:].split(',')
        
        for part in parts:
            if '=' not in part:
                continue
                
            key, value = part.split('=', 1)
            key = key.strip()
            
            # Remove surrounding quotes but keep URL encoding
            value = value.strip(' "\'')
            
            # Skip realm parameter as per documentation
            if key == 'realm':
                continue
                
            # Store the still-encoded value
            params[key] = value
            
        logger.debug(f"Parsed OAuth params (URL-encoded): {params}")
        return params

    def _quote_uppercase(self, s):
        """
        URL encode maintaining UPPERCASE encoding as specified in documentation.
        All encoded characters must be uppercase (e.g. %2F not %2f).
        """
        if s is None:
            s = ''
        s = str(s)
        
        # Special handling for empty string
        if not s:
            return s
            
        # First URL encode the string
        encoded = quote(s, safe='')
        
        # Then force all percent-encoded sequences to uppercase
        final = re.sub(
            r'%[0-9a-fA-F]{2}',
            lambda m: m.group(0).upper(),
            encoded
        )
        
        logger.debug(f"URL Encoded (uppercase): {s} -> {final}")
        return final

    def _get_body_params(self, request):
        """Get parameters from request body if applicable"""
        if (request.method == 'POST' and 
            request.headers.get('Content-Type', '').startswith('application/x-www-form-urlencoded')):
            try:
                logger.debug("Processing form-encoded POST body parameters")
                return dict(request.form)
            except Exception as e:
                logger.error(f"Error processing form data: {e}")
                return {}
        return {}

    def _generate_base_string(self, method, url, oauth_params, query_params):
        """
        Generate OAuth base string according to OAuth 1.0a spec and Nutaku requirements.
        
        Args:
            method (str): HTTP method
            url (str): Full request URL
            oauth_params (dict): OAuth parameters from Authorization header
            query_params (dict): Query parameters from URL
            
        Returns:
            str: The generated base string
        """
        # 1. Get base URL (scheme, host, path)
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        if base_url.endswith('?'):
            base_url = base_url.rstrip('?')
            
        # 2. Parse raw query parameters to maintain original encoding
        raw_query_params = parse_qs(
            parsed_url.query,
            keep_blank_values=True
        )
        
        # 3. Collect all parameters
        all_params = []
        
        # Add OAuth parameters (except excluded ones)
        for k, v in oauth_params.items():
            if k not in ['realm', 'oauth_signature', 'oauth_token_secret']:
                all_params.append((k, v))
        
        # Add query parameters (handling multiple values)
        for k, v_list in raw_query_params.items():
            for v in sorted(v_list):  # Sort multiple values for consistency
                all_params.append((k, v))
        
        # 4. URL-encode each parameter name and value separately
        # Maintain case-sensitive ASCII sorting
        encoded_pairs = []
        for k, v in all_params:
            k_enc = self._quote_uppercase(k)
            v_enc = self._quote_uppercase(v)
            encoded_pairs.append((k_enc, v_enc))
        
        # Sort by ASCII value (case-sensitive)
        encoded_pairs.sort(key=lambda x: (x[0], x[1]))
        
        # 5. Create parameter string with already-encoded values
        param_string = '&'.join(f"{k}={v}" for k, v in encoded_pairs)
        
        # 6. Join components with &, encoding the parameter string again
        # This ensures double-encoding of separators
        components = [
            self._quote_uppercase(method.upper()),
            self._quote_uppercase(base_url),
            self._quote_uppercase(param_string)  # Second encoding of & and =
        ]
        
        base_string = '&'.join(components)
        logger.debug(f"Base String: {base_string}")
        
        return base_string

    def _generate_signing_key(self, token_secret='', method=''):
        """
        Generate signing key according to OAuth 1.0a spec and Nutaku requirements:
        
        First GET request: consumer_secret + "&"
        Second request with token: consumer_secret + "&" + oauth_token_secret
        """
        # First encode the consumer secret
        encoded_secret = self._quote_uppercase(self.consumer_secret)
        
        # For first request: secret + &
        if not token_secret:
            key = encoded_secret + '&'
            logger.debug("Using first request key (secret + &)")
        # For second request: secret + & + token_secret
        else:
            encoded_token_secret = self._quote_uppercase(token_secret)
            key = encoded_secret + '&' + encoded_token_secret
            logger.debug("Using second request key (secret + & + token_secret)")
        
        logger.debug(f"Signing key: {key}")
        return key

    def verify_signature(self, request):
        try:
            logger.debug("Starting OAuth signature verification")
            logger.debug(f"Request URL: {request.url}")
            logger.debug(f"Request Method: {request.method}")
            logger.debug(f"Request Args: {dict(request.args)}")  # Keep this for logging
            logger.debug(f"Headers: {dict(request.headers)}")
            
            # Handle HTTPS forwarding
            forwarded_proto = request.headers.get('X-Forwarded-Proto')
            base_url = request.url
            if forwarded_proto == 'https':
                base_url = base_url.replace('http:', 'https:', 1)

            # Parse OAuth parameters from Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                logger.error("Missing Authorization header")
                return False

            oauth_params = self._parse_auth_header(auth_header)
            if not oauth_params:
                logger.error("Invalid Authorization header format")
                return False

            # Parse query string directly from URL instead of using request.args
            parsed_url = urlparse(base_url)
            query_params = parse_qs(parsed_url.query, keep_blank_values=True)

            # Generate base string with all parameters
            base_string = self._generate_base_string(
                request.method,
                base_url,
                oauth_params,
                query_params  # Pass the raw parsed query parameters
            )
            
            # Generate signing key based on request type
            token_secret = oauth_params.get('oauth_token_secret', '')
            signing_key = self._generate_signing_key(token_secret)

            # Generate and verify signature
            expected_signature = self._generate_signature(base_string, signing_key)
            received_signature = unquote(oauth_params.get('oauth_signature', ''))

            # Debug logging
            logger.debug("Signature Verification Details:")
            logger.debug(f"Generated base string: {base_string}")
            logger.debug(f"Generated signing key: {signing_key}")
            logger.debug(f"Generated signature: {expected_signature}")
            logger.debug(f"Received signature: {received_signature}")

            # Compare signatures using constant-time comparison
            if not hmac.compare_digest(
                expected_signature.encode('utf-8'),
                received_signature.encode('utf-8')
            ):
                logger.error("=== Signature Mismatch Details ===")
                logger.error(f"Method: {request.method}")
                logger.error(f"URL: {base_url}")
                logger.error(f"OAuth Params: {oauth_params}")
                logger.error(f"Query Params: {dict(request.args)}")
                logger.error(f"Base String: {base_string}")
                logger.error(f"Signing Key: {signing_key}")
                logger.error(f"Expected Signature: {expected_signature}")
                logger.error(f"Received Signature: {received_signature}")
                logger.error("===============================")
                return False

            return True

        except Exception as e:
            logger.error(f"Error in OAuth validation: {str(e)}")
            logger.exception(e)
            return False

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = Config.UPLOAD_FOLDER

db = Database()
oauth = OAuthSignature(Config.CONSUMER_KEY, Config.CONSUMER_SECRET)

app.config.update(
    PROPAGATE_EXCEPTIONS = True  # This will help with debugging
)

# Add a request logging middleware
@app.before_request
def log_request_info():
    logger.debug('Headers: %s', dict(request.headers))
    logger.debug('Body: %s', request.get_data())
    logger.debug('Args: %s', dict(request.args))

# Configure logging
os.makedirs(app.instance_path, exist_ok=True)
config = Config()
logging.basicConfig(
    filename=config.LOG_FILE,
    level=logging.DEBUG,
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
                logger.info(f"Payment data received: {payment_data}")
                
                payment_info = {
                    'payment_id': payment_data.get('PAYMENT_ID'),
                    'user_id': request.args.get('opensocial_viewer_id'),
                    'owner_id': request.args.get('opensocial_owner_id'),
                    'status': 1,
                    'ordered_time': payment_data.get('ORDERED_TIME'),
                    'item_id': payment_data['ITEMS'][0]['SKU_ID'],
                    'item_name': payment_data['ITEMS'][0]['NAME'],
                    'quantity': int(payment_data['ITEMS'][0]['COUNT']),
                    'unit_price': int(payment_data['ITEMS'][0]['PRICE'])
                }
                
                if not all(payment_info.values()):
                    logger.error(f"Missing required payment fields: {payment_info}")
                    return jsonify({"response_code": "ERROR"}), 400
                
                if payment_info['owner_id'] != payment_info['user_id']:
                    logger.warning(
                        f"owner_id ({payment_info['owner_id']}) does not match "
                        f"viewer_id ({payment_info['user_id']})"
                    )
                
                db.create_payment(payment_info)
                logger.info(f"Successfully stored payment: {payment_info['payment_id']}")
                
                return jsonify({"response_code": "OK"}), 200
                
            except Exception as e:
                logger.error(f"Error processing payment creation: {str(e)}")
                return jsonify({"response_code": "ERROR"}), 400

        elif request.method == 'GET':
            try:
                payment_id = (request.args.get('paymentId') or 
                            request.args.get('payment_id'))
                status = request.args.get('status')
                user_id = request.args.get('opensocial_viewer_id')
                owner_id = request.args.get('opensocial_owner_id')
                
                logger.info(
                    f"Received parameters: payment_id={payment_id}, "
                    f"status={status}, user_id={user_id}, "
                    f"owner_id={owner_id}"
                )
                
                if not all([payment_id, status, user_id, owner_id]):
                    logger.error("Missing required parameters in completion confirmation")
                    return jsonify({"response_code": "ERROR"}), 400
                
                validated_status = validate_payment_status(status)
                if validated_status is None:
                    return jsonify({"response_code": "ERROR"}), 400
                
                payment = db.get_payment(payment_id)
                if not payment:
                    logger.error(f"Payment not found: {payment_id}")
                    return jsonify({"response_code": "ERROR"}), 404
                
                if payment['user_id'] != user_id or payment['owner_id'] != owner_id:
                    logger.error(
                        f"User/Owner ID mismatch: viewer={user_id}, "
                        f"owner={owner_id}, stored_user={payment['user_id']}, "
                        f"stored_owner={payment['owner_id']}"
                    )
                    return jsonify({"response_code": "ERROR"}), 401
                
                db.update_payment_status(payment_id, validated_status)
                logger.info(f"Payment {payment_id} status updated to {validated_status}")
                
                return jsonify({"response_code": "OK"}), 200
                
            except Exception as e:
                logger.error(f"Error processing payment completion: {str(e)}")
                return jsonify({"response_code": "ERROR"}), 400

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

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html')

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

if __name__ == '__main__':
    Config.__init__()
    # Ensure images folder exists
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    
    # Initialize database
    db.init_db()
    
    # Start server
    logger.info(f"Starting server on {Config.ip}:{Config.port}")