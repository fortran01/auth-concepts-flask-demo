from flask import Flask, request, Response, render_template, redirect, url_for, session, flash, jsonify
from functools import wraps
import hashlib
import secrets
from typing import Set, Dict, Optional
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, UTC

app = Flask(__name__)
# Set the secret key to a random value, required for session management
app.secret_key = secrets.token_hex(32)
# JWT configuration
JWT_SECRET = secrets.token_hex(32)
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DELTA = timedelta(hours=1)

# Simulated user database
USERS = {
    'admin': generate_password_hash('secret')
}

# For digest auth
REALM = 'Restricted Access'
OPAQUE = secrets.token_hex(16)
NONCES: Set[str] = set()

def check_basic_auth(username: str, password: str) -> bool:
    """Check if username/password combination is valid."""
    stored_password_hash = USERS.get(username)
    if stored_password_hash and check_password_hash(stored_password_hash, password):
        return True
    return False

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
        
        if check_basic_auth(username, password):
            session['username'] = username
            flash('Successfully logged in!')
            return redirect(url_for('form_protected'))
        
        flash('Invalid credentials')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Successfully logged out')
    return redirect(url_for('login'))

@app.route('/form')
@login_required
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