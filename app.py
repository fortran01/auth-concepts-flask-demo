from flask import Flask, request, Response, render_template, redirect, url_for, session, flash, jsonify
from functools import wraps
import hashlib
import secrets
from typing import Set, Dict, Optional, Tuple
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, UTC
import pyotp

app = Flask(__name__)
# Set the secret key to a random value, required for session management
app.secret_key = secrets.token_hex(32)
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
        'exp': datetime.now(UTC) + JWT_EXPIRATION_DELTA
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
    
    if request.method == 'POST':
        code = request.form.get('code')
        secret = session.get('temp_mfa_secret')
        
        if not secret:
            flash('MFA setup session expired. Please try again.')
            return redirect(url_for('setup_mfa'))
        
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            user_data['mfa_secret'] = secret
            session.pop('temp_mfa_secret', None)
            session['mfa_setup'] = True
            flash('MFA has been successfully set up!')
            return redirect(url_for('form_protected'))
        else:
            flash('Invalid code. Please try again.')
    
    if not session.get('temp_mfa_secret'):
        session['temp_mfa_secret'] = pyotp.random_base32()
    
    totp = pyotp.TOTP(session['temp_mfa_secret'])
    provisioning_uri = totp.provisioning_uri(username, issuer_name="Flask Auth Demo")
    
    return render_template('setup_mfa.html', 
                         secret=session['temp_mfa_secret'],
                         provisioning_uri=provisioning_uri)

@app.route('/verify-mfa', methods=['GET', 'POST'])
def verify_mfa():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        code = request.form.get('code')
        if check_mfa(session['username'], code):
            session['mfa_verified'] = True
            return redirect(url_for('form_protected'))
        flash('Invalid MFA code')
    
    return render_template('verify_mfa.html')

@app.route('/form')
@login_required
@mfa_required
def form_protected():
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

if __name__ == '__main__':
    app.run(debug=True, port=5001) 