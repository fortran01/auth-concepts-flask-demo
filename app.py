from flask import (
    Flask, request, Response, render_template, redirect,
    url_for, session, flash, jsonify, g, get_flashed_messages
)
from functools import wraps
import hashlib
import secrets
import os
import json
from typing import Set, Dict, Optional, Tuple, Any, List
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
import pyotp
import logging
from flask_session import Session
import redis
import ldap
from urllib.parse import quote_plus, urlencode
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests

# Load environment variables from .env file
load_dotenv()

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

# LDAP configuration
LDAP_SERVER = os.environ.get('LDAP_SERVER', 'ldap://localhost:10389')
LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN', 'dc=example,dc=org')
LDAP_USER_DN_TEMPLATE = os.environ.get('LDAP_USER_DN_TEMPLATE', 'uid={username},ou=users,' + LDAP_BASE_DN)
LDAP_USER_FILTER = os.environ.get('LDAP_USER_FILTER', '(uid={username})')

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

# Auth0 configuration
oauth = OAuth(app)
oauth.register(
    "auth0",
    client_id=os.environ.get("AUTH0_CLIENT_ID"),
    client_secret=os.environ.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{os.environ.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

# Auth0 Machine-to-Machine OAuth client
oauth.register(
    "auth0_m2m",
    client_id=os.environ.get("AUTH0_M2M_CLIENT_ID"),
    client_secret=os.environ.get("AUTH0_M2M_CLIENT_SECRET"),
    client_kwargs={
        "scope": "read:data write:data",
    },
    server_metadata_url=f'https://{os.environ.get("AUTH0_DOMAIN")}/.well-known/openid-configuration',
)

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

def token_ui_required(f):
    """Decorator for token-based UI authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing or invalid token'}), 401
        
        token = auth_header.split(' ')[1]
        payload = verify_token(token)
        
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        # Store the payload in Flask's g object for the route to use
        g.user = payload
        
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    """Home page with links to different authentication demos"""
    return render_template('index.html')

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

@app.route('/token-login', methods=['GET', 'POST'])
def token_login():
    """
    GET: Render the token login page
    POST: Process token login (username/password) and return a JWT token
    """
    if request.method == 'GET':
        return render_template('token_login.html')
    
    # Handle POST request - this is an API endpoint that returns JSON
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing username or password'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if check_basic_auth(username, password):
        # Generate JWT token (no MFA check for this demo)
        token = generate_token(username)
        return jsonify({'token': token})
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/token-protected')
def token_protected_ui():
    """Render the protected page that will use client-side JS to fetch protected data"""
    return render_template('token_protected.html')

@app.route('/api/token-data')
@token_ui_required
def token_data():
    """API endpoint that returns protected data when given a valid JWT token"""
    # g.user is set by the token_ui_required decorator
    return jsonify({
        'message': f'Hello {g.user["username"]}! This is protected data '
                   f'accessible only with a valid token.',
        'timestamp': datetime.now().isoformat()
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
    if not DEBUG_MODE:
        # Only available in debug mode
        return redirect(url_for('index'))
    
    # Get current session ID from cookie
    session_id = request.cookies.get(app.config.get('SESSION_COOKIE_NAME', 'session'))
    
    # Get current session data
    current_session = dict(session)
    
    # Get all session keys from Redis
    # Use the Redis client from app config instead of global SESSION_REDIS
    redis_client = app.config.get('SESSION_REDIS')
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
        except Exception:
            pass
    
    # Return as JSON
    return jsonify({
        'current_session_id': session_id,
        'clean_session_id': clean_session_id,
        'current_session': current_session,
        'current_session_from_redis': matched_session,
        'all_sessions': sessions
    })

# CSRF Demo Routes
@app.route('/profile', methods=['GET'])
@login_required
@mfa_required
def profile():
    """User profile page with a form to update email (vulnerable to CSRF)"""
    # Default values for demo purposes
    email = session.get('email', 'user@example.com')
    username = session.get('username', 'default_user')
    
    # Store flash messages to return to the template
    flash_messages = get_flashed_messages(with_categories=True)
    
    return render_template('profile.html', email=email, username=username, csrf_protected=False)

@app.route('/update-email', methods=['POST'])
@login_required
@mfa_required
def update_email():
    """Endpoint to update email (vulnerable to CSRF)"""
    new_email = request.form.get('email')
    if new_email:
        # Store the new email in the session for demo purposes
        session['email'] = new_email
        flash('Email updated successfully!', 'success')
    else:
        flash('Email cannot be empty', 'danger')
    return redirect(url_for('profile'))

@app.route('/update-username', methods=['POST'])
@login_required
@mfa_required
def update_username():
    """Endpoint to update username (vulnerable to CSRF)"""
    new_username = request.form.get('username')
    if new_username:
        # Store the new username in the session for demo purposes
        session['username'] = new_username
        flash('Username updated successfully!', 'success')
    else:
        flash('Username cannot be empty', 'danger')
    return redirect(url_for('profile'))

# CSRF Token generation function
def generate_csrf_token():
    """Generate a CSRF token and store it in the session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

@app.route('/profile-protected', methods=['GET'])
@login_required
@mfa_required
def profile_protected():
    """User profile page with CSRF protection"""
    # Default values for demo purposes
    email = session.get('email', 'user@example.com')
    username = session.get('username', 'default_user')
    
    # Check if there was an attack attempt
    attack_attempted = session.pop('csrf_attack_attempted', False)
    
    return render_template('profile_protected.html', 
                          email=email, 
                          username=username, 
                          csrf_protected=True,
                          attack_attempted=attack_attempted)

@app.route('/update-email-protected', methods=['POST'])
@login_required
@mfa_required
def update_email_protected():
    """Endpoint to update email with CSRF protection"""
    # Check CSRF token
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        flash('Invalid CSRF token. This could be a cross-site request forgery attempt!', 'danger')
        return redirect(url_for('profile_protected'))
    
    new_email = request.form.get('email')
    if new_email:
        # Store the new email in the session for demo purposes
        session['email'] = new_email
        flash('Email updated successfully!', 'success')
    else:
        flash('Email cannot be empty', 'danger')
    return redirect(url_for('profile_protected'))

@app.route('/update-username-protected', methods=['POST'])
@login_required
@mfa_required
def update_username_protected():
    """Endpoint to update username with CSRF protection"""
    # Check CSRF token
    token = request.form.get('csrf_token')
    if not token or token != session.get('csrf_token'):
        # Set attack attempt flag to show an additional notification
        session['csrf_attack_attempted'] = True
        flash('Invalid CSRF token. This could be a cross-site request forgery attempt!', 'danger')
        return redirect(url_for('profile_protected'))
    
    new_username = request.form.get('username')
    if new_username:
        # Store the new username in the session for demo purposes
        session['username'] = new_username
        flash('Username updated successfully!', 'success')
    else:
        flash('Username cannot be empty', 'danger')
    return redirect(url_for('profile_protected'))

@app.route('/csrf-demo')
def csrf_demo():
    """Page explaining the CSRF demo with links to the vulnerable and protected pages"""
    return render_template('csrf_demo.html')

@app.route('/malicious-site')
def malicious_site():
    """Demo page showing a malicious site for CSRF attacks targeting the vulnerable endpoint"""
    return render_template('malicious.html', target_vulnerable=True, target_protected=False)

@app.route('/malicious-site-protected')
def malicious_site_protected():
    """Demo page showing a malicious site for CSRF attacks targeting the protected endpoint"""
    return render_template('malicious.html', target_vulnerable=False, target_protected=True)

@app.route('/cors-demo-info')
def cors_demo_info():
    """Information page about the CORS demo setup"""
    return render_template('cors_demo_info.html')

# Make CSRF token available to all templates
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf_token)

# LDAP Authentication functions
def ldap_authenticate(username: str, password: str) -> Tuple[bool, Optional[Dict[str, List[Any]]], Optional[str]]:
    """
    Authenticate a user against the LDAP server.
    
    Returns a tuple containing:
    - Success: Boolean indicating if authentication was successful
    - User Info: Dictionary of user attributes from LDAP (if successful)
    - DN: Distinguished Name of the user (if successful)
    - Error Message: String with error message (if failed)
    """
    try:
        # Initialize LDAP connection
        logger.debug(f"Connecting to LDAP server at {LDAP_SERVER}")
        ldap_conn = ldap.initialize(LDAP_SERVER)
        
        # Set LDAP protocol version
        ldap_conn.protocol_version = ldap.VERSION3
        
        # We don't need referrals for this demo
        ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        
        # Try directly binding as the admin user first to ensure connectivity
        admin_dn = f"cn=admin,{LDAP_BASE_DN}"
        logger.debug(f"Testing connection with admin bind: {admin_dn}")
        ldap_conn.simple_bind_s(admin_dn, "admin_password")
        
        # Create a clean filter with the username
        search_filter = f"(uid={username})"
        logger.debug(f"Searching for user with filter: {search_filter} in base DN: {LDAP_BASE_DN}")
        
        results = ldap_conn.search_s(
            LDAP_BASE_DN,
            ldap.SCOPE_SUBTREE,
            search_filter,
            ['uid', 'cn', 'mail', 'sn', 'givenName']
        )
        
        logger.debug(f"Search results: {results}")
        
        if not results:
            logger.warning(f"User not found: {username}")
            return False, None, f"User not found: {username}"
        
        # Get the user's DN from the search results
        user_dn, user_attrs = results[0]
        logger.debug(f"Found user DN: {user_dn}")
        
        # Now try to bind with the user's DN and password
        logger.debug(f"Attempting to bind with DN: {user_dn}")
        ldap_conn.simple_bind_s(user_dn, password)
        
        # Convert binary values to strings for easier handling in templates
        for key, values in user_attrs.items():
            user_attrs[key] = [
                v.decode('utf-8') if isinstance(v, bytes) else v
                for v in values
            ]
        
        # Close the connection
        ldap_conn.unbind_s()
        
        return True, user_attrs, user_dn
    
    except ldap.INVALID_CREDENTIALS:
        logger.warning(f"Invalid LDAP credentials for user: {username}")
        return False, None, "Invalid username or password."
    
    except ldap.NO_SUCH_OBJECT:
        logger.error(f"LDAP object not found for user: {username}")
        return False, None, "User not found in LDAP directory."
    
    except ldap.LDAPError as e:
        logger.error(f"LDAP error: {e}")
        return False, None, f"LDAP error: {str(e)}"
    
    except Exception as e:
        logger.error(f"Unexpected error during LDAP authentication: {e}", exc_info=True)
        return False, None, f"Unexpected error: {str(e)}"


def ldap_login_required(f):
    """Decorator for routes that require LDAP authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'ldap_authenticated' not in session or not session['ldap_authenticated']:
            flash('Please log in with LDAP to access this page', 'warning')
            return redirect(url_for('ldap_login'))
        return f(*args, **kwargs)
    return decorated


# LDAP routes
@app.route('/ldap-login', methods=['GET', 'POST'])
def ldap_login():
    """LDAP login route"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please provide both username and password', 'danger')
            return redirect(url_for('ldap_login'))
        
        # Trim whitespace from username to prevent search filter issues
        username = username.strip()
        
        success, user_info, error_or_dn = ldap_authenticate(username, password)
        
        if success:
            # Store LDAP authentication information in session
            session['ldap_authenticated'] = True
            session['ldap_username'] = username
            session['ldap_user_info'] = user_info
            session['ldap_dn'] = error_or_dn  # This should contain the DN on success
            
            flash(f'Successfully logged in as {username}', 'success')
            return redirect(url_for('ldap_protected'))
        else:
            flash(f'Authentication failed: {error_or_dn}', 'danger')
            return redirect(url_for('ldap_login'))
    
    return render_template('ldap_login.html')


@app.route('/ldap-protected')
@ldap_login_required
def ldap_protected():
    """Protected page that requires LDAP authentication"""
    user_info = session.get('ldap_user_info')
    dn = session.get('ldap_dn')
    
    return render_template('ldap_protected.html', 
                         user_info=user_info,
                         dn=dn)


@app.route('/ldap-logout')
def ldap_logout():
    """LDAP logout route"""
    session.pop('ldap_authenticated', None)
    session.pop('ldap_username', None)
    session.pop('ldap_user_info', None)
    session.pop('ldap_dn', None)
    
    flash('Successfully logged out of LDAP session', 'success')
    return redirect(url_for('index'))


# Auth0 routes
@app.route('/auth0-demo')
def auth0_demo():
    return render_template('auth0_login.html')


@app.route('/auth0/login')
def auth0_login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for('auth0_callback', _external=True)
    )


@app.route('/auth0/callback')
def auth0_callback():
    # Get the access token
    token = oauth.auth0.authorize_access_token()
    
    # Use the token to get user information from Auth0's userinfo endpoint
    userinfo = token.get('userinfo')
    if not userinfo:
        # If userinfo is not in the token response, fetch it separately
        resp = oauth.auth0.get('userinfo')
        userinfo = resp.json()
        token['userinfo'] = userinfo
    
    # Store the user information in the session under auth0_user key
    # to avoid conflicts with existing 'user' session key
    session['auth0_user'] = token
    
    flash('Successfully logged in via Auth0!')
    return redirect('/auth0/profile')


@app.route('/auth0/profile')
def auth0_profile():
    auth0_user = session.get('auth0_user')
    if not auth0_user:
        flash('Please log in with Auth0 first')
        return redirect('/auth0-demo')
    
    return render_template(
        'auth0_profile.html',
        auth0_user=auth0_user,
        user_info_pretty=json.dumps(auth0_user, indent=4)
    )


@app.route('/auth0/logout')
def auth0_logout():
    # Clear the Auth0 user from session
    session.pop('auth0_user', None)
    
    # Redirect to Auth0 logout endpoint which then redirects back to home page
    return redirect(
        f"https://{os.environ.get('AUTH0_DOMAIN')}/v2/logout?" +
        urlencode(
            {
                "returnTo": url_for('index', _external=True),
                "client_id": os.environ.get('AUTH0_CLIENT_ID'),
            },
            quote_via=quote_plus,
        )
    )


# Auth0 API Authentication - for Demo 4
def auth0_api_required(f):
    """Decorator for API routes that require Auth0 JWT token validation"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing authorization header'}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            # Validate the token using Auth0's JWKS endpoint
            jwks_url = f'https://{os.environ.get("AUTH0_DOMAIN")}/.well-known/jwks.json'
            jwks_client = jwt.PyJWKClient(jwks_url)
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            
            # Validate the token with the right audience and issuer
            payload = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=os.environ.get("AUTH0_API_AUDIENCE"),
                issuer=f'https://{os.environ.get("AUTH0_DOMAIN")}/'
            )
            
            # Store user info in flask.g for the route to use
            g.auth0_user = payload
            
            return f(*args, **kwargs)
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}")
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return jsonify({'error': 'Token validation error'}), 500
    
    return decorated


# Demo 4: API with Auth0 Routes
@app.route('/auth0/api-demo')
def auth0_api_demo():
    """Landing page for the Auth0 API demo"""
    return render_template('auth0_api_demo.html')

@app.route('/api/auth0-protected')
@auth0_api_required
def auth0_api_protected():
    """Protected API endpoint requiring a valid Auth0 access token"""
    # g.auth0_user is set by the auth0_api_required decorator
    user_info = g.auth0_user
    
    return jsonify({
        'message': 'This API is protected by Auth0!',
        'user': user_info.get('sub'),
        'permissions': user_info.get('permissions', []),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/auth0/get-token', methods=['GET', 'POST'])
def auth0_get_token():
    """Page with a form to get an access token for Auth0 API"""
    if request.method == 'POST':
        # This would normally call Auth0's token endpoint with client credentials
        # For demo purposes, we'll redirect to Auth0's login page
        # and request both openid and API permissions
        return oauth.auth0.authorize_redirect(
            redirect_uri=url_for('auth0_token_callback', _external=True),
            audience=os.environ.get("AUTH0_API_AUDIENCE"),
            scope="openid profile email"  # Add API scopes as needed
        )
    
    return render_template('auth0_get_token.html')

@app.route('/auth0/m2m-token', methods=['GET', 'POST'])
def auth0_m2m_token():
    """
    Get a machine-to-machine token directly from Auth0 using client credentials flow.
    This demonstrates a true machine-to-machine OAuth 2.0 flow.
    """
    if request.method == 'POST':
        try:
            # Get token endpoint from the Auth0 server metadata
            metadata_url = f'https://{os.environ.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
            metadata_response = requests.get(metadata_url)
            metadata = metadata_response.json()
            token_endpoint = metadata.get('token_endpoint')
            
            # Make a direct token request using client credentials grant
            token_response = requests.post(token_endpoint, data={
                'grant_type': 'client_credentials',
                'client_id': os.environ.get("AUTH0_M2M_CLIENT_ID"),
                'client_secret': os.environ.get("AUTH0_M2M_CLIENT_SECRET"),
                'audience': os.environ.get("AUTH0_API_AUDIENCE"),
                'scope': 'read:data write:data'
            })
            
            # Check if the request was successful
            if token_response.status_code == 200:
                token_data = token_response.json()
                access_token = token_data.get('access_token')
                
                # Store in session for demo purposes
                session['auth0_api_token'] = access_token
                session['auth0_api_token_type'] = 'Machine-to-Machine'
                session['auth0_api_token_data'] = token_data
                
                flash('Successfully obtained Machine-to-Machine token from Auth0!', 'success')
                
                # Instead of redirecting, show the token directly with ready-to-use curl command
                return render_template('auth0_m2m_token.html', 
                                     client_id=os.environ.get("AUTH0_M2M_CLIENT_ID", ""),
                                     audience=os.environ.get("AUTH0_API_AUDIENCE", ""),
                                     domain=os.environ.get("AUTH0_DOMAIN", ""),
                                     access_token=access_token,
                                     token_data=token_data,
                                     show_token=True)
            else:
                flash(f'Error getting token: {token_response.json().get("error_description", "Unknown error")}', 'danger')
                logger.error(f"M2M token error: {token_response.text}")
        
        except Exception as e:
            logger.error(f"Error obtaining M2M token: {str(e)}", exc_info=True)
            flash(f'Error: {str(e)}', 'danger')
    
    # Show the M2M token request page
    return render_template('auth0_m2m_token.html', 
                         client_id=os.environ.get("AUTH0_M2M_CLIENT_ID", ""),
                         audience=os.environ.get("AUTH0_API_AUDIENCE", ""),
                         domain=os.environ.get("AUTH0_DOMAIN", ""),
                         show_token=False)

@app.route('/auth0/token-callback')
def auth0_token_callback():
    """Callback endpoint after Auth0 login for API access token"""
    # Get the tokens from Auth0
    token_response = oauth.auth0.authorize_access_token()
    
    # Extract the access token
    access_token = token_response.get('access_token')
    
    # Store tokens in session
    session['auth0_api_token'] = access_token
    session['auth0_api_token_type'] = 'User Authentication'
    session['auth0_api_token_data'] = token_response
    
    # Also get user info if needed
    if 'id_token' in token_response:
        userinfo = token_response.get('userinfo', {})
        if not userinfo:
            resp = oauth.auth0.get('userinfo')
            userinfo = resp.json()
        
        session['auth0_api_user'] = userinfo
    
    flash('Successfully obtained API access token from Auth0!')
    return redirect('/auth0/api-client')

@app.route('/auth0/api-client')
def auth0_api_client():
    """Client page that will use the Auth0 access token to call the API"""
    access_token = session.get('auth0_api_token')
    user_info = session.get('auth0_api_user')
    
    if not access_token:
        flash('Please obtain an access token first')
        return redirect('/auth0/get-token')
    
    return render_template(
        'auth0_api_client.html',
        access_token=access_token,
        user_info=user_info
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001) 