from flask import Flask, request, Response, render_template, redirect, url_for, session, flash, jsonify
from functools import wraps
import hashlib
import secrets
import os
from typing import Set, Dict, Optional, Tuple
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
import pyotp
import logging
from flask_session import Session
import redis

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Explicit debug mode setting
DEBUG_MODE = True

# Get environment variables for configuration
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
FLASK_SESSION_SALT = os.environ.get('FLASK_SESSION_SALT', 'flask-session-cookie')

# Redis session configuration
SESSION_TYPE = 'redis'
SESSION_PERMANENT = False  # Session dies when browser is closed
SESSION_USE_SIGNER = True  # Uses the Flask secret key to sign the session ID
SESSION_KEY_PREFIX = 'session:'
# Ensure Redis is running before the app starts
SESSION_REDIS = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379/0'))

app = Flask(__name__)
app.debug = DEBUG_MODE  # Explicitly set debug mode

# Set the secret key
app.secret_key = FLASK_SECRET_KEY

# Apply session configuration to app
app.config.update(
    SESSION_TYPE=SESSION_TYPE,
    SESSION_PERMANENT=SESSION_PERMANENT,
    SESSION_USE_SIGNER=SESSION_USE_SIGNER,
    SESSION_KEY_PREFIX=SESSION_KEY_PREFIX,
    SESSION_REDIS=SESSION_REDIS
)

# Initialize the session extension
Session(app)

# JWT configuration
JWT_SECRET = secrets.token_hex(32)
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = timedelta(hours=1)

# Simulated user database with MFA secrets
USERS: Dict[str, Dict[str, str]] = {
    'admin': {
        'password': generate_password_hash('secret'),
        'mfa_secret': None  # Will be set when user enables MFA
    }
}

# For digest auth
REALM = 'Restricted Access'
OPAQUE = secrets.token_hex(16)
NONCES: Set[str] = set()

def check_basic_auth(username: str, password: str) -> bool:
    """Check if username/password combination is valid."""
    user_data = USERS.get(username)
    if user_data and check_password_hash(user_data['password'], password):
        return True
    return False

def check_mfa(username: str, code: str) -> bool:
    """Check if MFA code is valid."""
    user_data = USERS.get(username)
    if not user_data or not user_data['mfa_secret']:
        return True  # If MFA is not set up, consider it valid
    totp = pyotp.TOTP(user_data['mfa_secret'])
    return totp.verify(code)

def basic_auth_required(f):
    """Decorator for basic authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return Response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials',
                401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        if not check_basic_auth(auth.username, auth.password):
            return Response(
                'Invalid credentials',
                401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated

def generate_nonce() -> str:
    """Generate a new nonce value"""
    nonce = secrets.token_hex(16)
    NONCES.add(nonce)
    return nonce

def check_digest_auth(auth) -> bool:
    """Check if digest authentication is valid"""
    if auth.username not in USERS:
        return False
    
    if auth.nonce not in NONCES:
        return False
    
    # Calculate expected response
    ha1 = hashlib.md5(
        f"{auth.username}:{REALM}:secret".encode()
    ).hexdigest()
    ha2 = hashlib.md5(
        f"{request.method}:{auth.uri}".encode()
    ).hexdigest()
    expected = hashlib.md5(
        f"{ha1}:{auth.nonce}:{ha2}".encode()
    ).hexdigest()
    
    return auth.response == expected

def digest_auth_required(f):
    """Decorator for digest authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        
        if not auth or not auth.type == 'digest' or not check_digest_auth(auth):
            nonce = generate_nonce()
            headers = {
                'WWW-Authenticate': (
                    f'Digest realm="{REALM}",'
                    f'nonce="{nonce}",opaque="{OPAQUE}"'
                )
            }
            return Response(
                'Could not verify your access level for that URL.\n'
                'You have to login with proper credentials',
                401,
                headers
            )
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    """Decorator for form-based authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def generate_token(username: str) -> str:
    """Generate a new JWT token for a user"""
    payload = {
        'username': username,
        'exp': datetime.now(timezone.utc) + JWT_EXPIRATION_DELTA
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token: str) -> Optional[Dict]:
    """Verify a JWT token and return the payload if valid"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        return None

def token_auth_required(f):
    """Decorator for token-based authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        return f(*args, **kwargs)
    return decorated

def mfa_required(f):
    """Decorator for MFA verification"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page')
            return redirect(url_for('login'))
        
        if 'mfa_verified' not in session:
            return redirect(url_for('verify_mfa'))
            
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return 'Welcome to the Authentication Demo! Try /basic or /digest.'

@app.route('/basic')
@basic_auth_required
def basic_protected():
    auth = request.authorization
    return f'Hello {auth.username}! This page uses Basic Auth.'

@app.route('/digest')
@digest_auth_required
def digest_protected():
    auth = request.authorization
    return f'Hello {auth.username}! This page uses Digest Auth.'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        mfa_code = request.form.get('mfa_code')
        
        if check_basic_auth(username, password):
            if not USERS[username]['mfa_secret'] or check_mfa(username, mfa_code):
                session['username'] = username
                session['mfa_verified'] = True
                session['mfa_setup'] = bool(USERS[username]['mfa_secret'])
                flash('Successfully logged in!')
                return redirect(url_for('form_protected'))
            else:
                flash('Invalid MFA code')
                return redirect(url_for('login'))
        
        flash('Invalid credentials')
        return redirect(url_for('login'))
    
    mfa_required = USERS['admin']['mfa_secret'] is not None
    return render_template('login.html', 
                         mfa_required=mfa_required,
                         mfa_secret=USERS['admin']['mfa_secret'] if mfa_required else None)

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('mfa_verified', None)
    flash('Successfully logged out')
    return redirect(url_for('login'))

@app.route('/setup-mfa', methods=['GET', 'POST'])
@login_required
def setup_mfa():
    username = session['username']
    user_data = USERS[username]
    logger.debug(f"Setting up MFA for user: {username}")
    logger.debug(f"Current session: {dict(session)}")
    
    if request.method == 'POST':
        code = request.form.get('code')
        secret = session.get('temp_mfa_secret')
        logger.debug(f"Verifying MFA setup code: {code}")
        logger.debug(f"Using temp secret: {secret}")
        
        if not secret:
            logger.warning("No temporary MFA secret found in session")
            flash('MFA setup session expired. Please try again.')
            return redirect(url_for('setup_mfa'))
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            logger.info(f"MFA setup successful for user: {username}")
            user_data['mfa_secret'] = secret
            session.pop('temp_mfa_secret', None)
            session['mfa_setup'] = True
            flash('MFA has been successfully set up!')
            return redirect(url_for('form_protected'))
        else:
            logger.warning(f"Invalid MFA setup code for user: {username}")
            flash('Invalid code. Please try again.')
            return redirect(url_for('setup_mfa'))
    
    if not session.get('temp_mfa_secret'):
        logger.debug("Generating new temporary MFA secret")
        session['temp_mfa_secret'] = pyotp.random_base32()
    
    totp = pyotp.TOTP(session['temp_mfa_secret'])
    provisioning_uri = totp.provisioning_uri(username, issuer_name="Flask Auth Demo")
    logger.debug(f"Generated provisioning URI: {provisioning_uri}")
    
    return render_template('setup_mfa.html', 
                         secret=session['temp_mfa_secret'],
                         provisioning_uri=provisioning_uri)

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'username' not in session:
        logger.warning("Attempted MFA verification without being logged in")
        return redirect(url_for('login'))
    
    username = session['username']
    logger.debug(f"Verifying MFA for user: {username}")
    logger.debug(f"Current session: {dict(session)}")
    
    if request.method == 'POST':
        code = request.form.get('code')
        logger.debug(f"Verifying MFA code: {code}")
        if check_mfa(session['username'], code):
            logger.info(f"MFA verification successful for user: {username}")
            session['mfa_verified'] = True
            return redirect(url_for('form_protected'))
        logger.warning(f"Invalid MFA code for user: {username}")
        flash('Invalid MFA code')
    
    return render_template('verify_mfa.html')

@app.route('/form')
@login_required
@mfa_required
def form_protected():
    username = session.get('username')
    logger.debug(f"Accessing protected page for user: {username}")
    logger.debug(f"Current session: {dict(session)}")
    return render_template('protected.html')

@app.route('/api/token', methods=['POST'])
def get_token():
    """Endpoint to obtain a JWT token"""
    print("Headers:", dict(request.headers))
    auth = request.authorization
    print("Auth:", auth)
    
    if not auth:
        print("No auth provided")
        return jsonify({
            'error': 'Could not verify your access level for that URL.\n'
                    'You have to login with proper credentials'
        }), 401
    
    if not check_basic_auth(auth.username, auth.password):
        print(f"Invalid credentials for user: {auth.username}")
        return jsonify({
            'error': 'Invalid credentials'
        }), 401
    
    print(f"Generating token for user: {auth.username}")
    token = generate_token(auth.username)
    return jsonify({'token': token})

@app.route('/api/protected')
@token_auth_required
def token_protected():
    """Protected endpoint requiring valid JWT token"""
    auth_header = request.headers.get('Authorization')
    token = auth_header.split(' ')[1]
    payload = verify_token(token)
    return jsonify({
        'message': f'Hello {payload["username"]}! This endpoint is protected by JWT.',
        'expires': datetime.fromtimestamp(payload["exp"]).isoformat()
    })

# --- !! DANGER !! Debug endpoint for demonstration only - REMOVE BEFORE DEPLOYMENT ---
@app.route('/debug/decode-session', methods=['GET', 'POST'])
def debug_decode_session():
    """
    DEBUG ONLY: Renders a form to paste a session cookie value and decodes it
    using the app's secret key.
    """
    if not app.debug:
        flash("This endpoint is only available in debug mode.")
        return redirect(url_for('index'))
        
    decoded_data = None
    error_message = None
    cookie_value = ""
    cookie_structure = None
    generated_cookie = None
    signature_valid = None
    
    if request.method == 'POST':
        cookie_value = request.form.get('cookie_value', '')
        generate_cookie = request.form.get('generate_cookie') == 'yes'
        
        # Generate a test cookie
        if generate_cookie:
            try:
                from itsdangerous import URLSafeTimedSerializer
                # Create a test session with sample data
                test_data = {
                    'username': 'admin',
                    'mfa_verified': True,
                    'mfa_setup': False
                }
                
                # Use the predefined salt and the current app's secret key
                salt = FLASK_SESSION_SALT  # Use the predefined salt instead of app.session_interface.salt
                secret_key = app.secret_key
                
                # Generate a new cookie with the current salt and key
                serializer = URLSafeTimedSerializer(secret_key, salt=salt)
                generated_cookie = serializer.dumps(test_data)
                logger.debug(f"Generated test cookie: {generated_cookie}")
            except Exception as e:
                error_message = f"An unexpected error occurred: {e}"
                logger.error(f"Error generating test cookie: {e}", exc_info=True)
        
        # Normal cookie decoding
        elif cookie_value:
            try:
                from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
                import base64
                import json
                
                # Parse and display the structure of the cookie
                try:
                    parts = cookie_value.split('.')
                    cookie_structure = {
                        'payload': parts[0],
                        'timestamp': parts[1] if len(parts) > 1 else 'Missing',
                        'signature': parts[2] if len(parts) > 2 else 'Missing'
                    }
                except Exception as e:
                    cookie_structure = {'error': f'Could not parse cookie structure: {e}'}
                
                # Create the serializer with the app's current key and salt
                serializer = URLSafeTimedSerializer(app.secret_key, salt=FLASK_SESSION_SALT)
                
                try:
                    # Try to decode and validate the cookie
                    decoded_data = serializer.loads(cookie_value)
                    signature_valid = True
                except (BadSignature, SignatureExpired) as e:
                    # If signature check fails, still try to decode the payload for display
                    signature_valid = False
                    error_message = str(e)
                    
                    # Try to decode the payload part (even if signature is invalid)
                    if parts[0]:
                        try:
                            # Add padding if necessary
                            payload = parts[0]
                            payload += '=' * (-len(payload) % 4)
                            # Decode base64 and then decode JSON
                            json_str = base64.urlsafe_b64decode(payload).decode('utf-8')
                            decoded_data = json.loads(json_str)
                        except Exception as payload_error:
                            error_message += f"\nCould not decode payload: {payload_error}"
            except Exception as e:
                error_message = f"An unexpected error occurred: {e}"
        else:
            error_message = "Please paste a cookie value."
    
    return render_template('debug_decode_session.html',
                          decoded_data=decoded_data,
                          error_message=error_message,
                          cookie_value=cookie_value,
                          cookie_structure=cookie_structure,
                          generated_cookie=generated_cookie,
                          signature_valid=signature_valid)

@app.route('/debug/redis-session')
def debug_redis_session():
    """Debug endpoint to decode Redis session data."""
    if not app.debug:
        # Only available in debug mode
        return redirect(url_for('index'))
    
    # Get current session ID from cookie
    session_id = request.cookies.get(app.config.get('SESSION_COOKIE_NAME', 'session'))
    
    # Get current session data
    current_session = dict(session)
    
    # Get all session keys from Redis
    redis_client = SESSION_REDIS
    session_keys = redis_client.keys(f"{SESSION_KEY_PREFIX}*")
    
    # Extract the clean session ID without signature (if present)
    clean_session_id = None
    if session_id:
        if '.' in session_id:  # Signed session ID format
            clean_session_id = session_id.split('.')[0]
        else:
            clean_session_id = session_id
    
    # Decode all sessions
    sessions = {}
    matched_session = None
    
    for key in session_keys:
        try:
            # Get raw data from Redis
            raw_data = redis_client.get(key)
            
            # Decode using pickle
            import pickle
            session_data = pickle.loads(raw_data)
            
            # Add to sessions dictionary
            key_str = key.decode('utf-8') if isinstance(key, bytes) else key
            sessions[key_str] = session_data
            
            # If this is the current session, save it specifically
            redis_key = f"{SESSION_KEY_PREFIX}{clean_session_id}"
            if key_str == redis_key:
                matched_session = session_data
        except Exception as e:
            sessions[key] = f"Error decoding: {str(e)}"
    
    # If we didn't find the session but we have a session ID, try to manually load it
    if matched_session is None and clean_session_id:
        try:
            # Try direct access through Redis
            direct_key = f"{SESSION_KEY_PREFIX}{clean_session_id}"
            raw_data = redis_client.get(direct_key)
            if raw_data:
                import pickle
                matched_session = pickle.loads(raw_data)
        except Exception as e:
            pass
    
    # Return as JSON
    return jsonify({
        'current_session_id': session_id,
        'clean_session_id': clean_session_id,
        'current_session': current_session,
        'current_session_from_redis': matched_session,
        'all_sessions': sessions
    })

if __name__ == '__main__':
    app.run(debug=True, port=5001) 