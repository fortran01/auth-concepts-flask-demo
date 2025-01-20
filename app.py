from flask import Flask, request, Response
from functools import wraps
import hashlib
import secrets
from typing import Set
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

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

if __name__ == '__main__':
    app.run(debug=True) 