import pytest
from app import app, generate_token, verify_token
import base64
import json


@pytest.fixture
def client():
    """Create a test client for the app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_index_no_auth(client):
    """Test that index page is accessible without auth."""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Welcome to the Authentication Demo!' in response.data


def test_basic_auth_no_credentials(client):
    """Test that /basic requires authentication."""
    response = client.get('/basic')
    assert response.status_code == 401
    assert 'Basic realm=' in response.headers['WWW-Authenticate']


def test_basic_auth_invalid_credentials(client, auth_headers):
    """Test that /basic rejects invalid credentials."""
    headers = auth_headers['basic']('wrong', 'password')
    response = client.get('/basic', headers=headers)
    assert response.status_code == 401
    assert 'Basic realm=' in response.headers['WWW-Authenticate']


def test_basic_auth_valid_credentials(client, auth_headers):
    """Test that /basic accepts valid credentials."""
    headers = auth_headers['basic']('admin', 'secret')
    response = client.get('/basic', headers=headers)
    assert response.status_code == 200
    assert b'Hello admin!' in response.data


def test_digest_auth_no_credentials(client):
    """Test that /digest requires authentication."""
    response = client.get('/digest')
    assert response.status_code == 401
    auth_header = response.headers['WWW-Authenticate']
    assert 'Digest ' in auth_header
    assert 'realm=' in auth_header
    assert 'nonce=' in auth_header
    assert 'opaque=' in auth_header


def test_digest_auth_invalid_username(client, auth_headers):
    """Test that /digest rejects non-existent usernames."""
    # First get a valid nonce and opaque
    response = client.get('/digest')
    auth_header = response.headers['WWW-Authenticate']
    
    # Extract realm and opaque
    realm = auth_header.split('realm="')[1].split('"')[0]
    nonce = auth_header.split('nonce="')[1].split('"')[0]
    opaque = auth_header.split('opaque="')[1].split('"')[0]
    
    # Create headers with invalid username
    headers = auth_headers['digest'](
        'nonexistent', 'secret', realm,
        nonce, '/digest', opaque
    )
    
    response = client.get('/digest', headers=headers)
    assert response.status_code == 401


def test_digest_auth_invalid_nonce(client, auth_headers):
    """Test that /digest rejects invalid nonces."""
    # First get a valid nonce and opaque
    response = client.get('/digest')
    auth_header = response.headers['WWW-Authenticate']
    
    # Extract realm and opaque
    realm = auth_header.split('realm="')[1].split('"')[0]
    opaque = auth_header.split('opaque="')[1].split('"')[0]
    
    # Create headers with invalid nonce
    headers = auth_headers['digest'](
        'admin', 'secret', realm,
        'invalid_nonce', '/digest', opaque
    )
    
    response = client.get('/digest', headers=headers)
    assert response.status_code == 401


def test_digest_auth_valid_credentials(client, auth_headers):
    """Test that /digest accepts valid credentials."""
    # First get a valid nonce
    response = client.get('/digest')
    auth_header = response.headers['WWW-Authenticate']
    
    # Extract required values
    realm = auth_header.split('realm="')[1].split('"')[0]
    nonce = auth_header.split('nonce="')[1].split('"')[0]
    opaque = auth_header.split('opaque="')[1].split('"')[0]
    
    # Create valid auth headers
    headers = auth_headers['digest'](
        'admin', 'secret', realm,
        nonce, '/digest', opaque
    )
    
    response = client.get('/digest', headers=headers)
    assert response.status_code == 200
    assert b'Hello admin!' in response.data


def test_form_login_page(client):
    """Test that login page loads correctly"""
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Login' in response.data


def test_form_login_success(client):
    """Test successful form-based login"""
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'secret'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Successfully logged in!' in response.data
    assert b'Welcome admin!' in response.data
    assert b'Protected Page' in response.data


def test_form_login_invalid_credentials(client):
    """Test form-based login with invalid credentials"""
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'wrong'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Invalid credentials' in response.data
    # Verify we're back at the login page
    assert b'<h3 class="text-center">Login</h3>' in response.data


def test_form_protected_without_login(client):
    """Test accessing protected page without login"""
    response = client.get('/form', follow_redirects=True)
    assert response.status_code == 200
    assert b'Please log in to access this page' in response.data
    # Verify we're redirected to login page
    assert b'<h3 class="text-center">Login</h3>' in response.data


def test_form_logout(client):
    """Test logout functionality"""
    # First login
    client.post('/login', data={
        'username': 'admin',
        'password': 'secret'
    })
    
    # Then logout
    response = client.get('/logout', follow_redirects=True)
    assert response.status_code == 200
    assert b'Successfully logged out' in response.data
    
    # Verify we can't access protected page
    response = client.get('/form', follow_redirects=True)
    assert b'Please log in to access this page' in response.data
    # Verify we're at login page
    assert b'<h3 class="text-center">Login</h3>' in response.data


def test_get_token_no_auth(client):
    """Test token endpoint with no authentication"""
    response = client.post('/api/token')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_get_token_invalid_auth(client):
    """Test token endpoint with invalid credentials"""
    credentials = base64.b64encode(b'wrong:password').decode('utf-8')
    headers = {'Authorization': f'Basic {credentials}'}
    response = client.post('/api/token', headers=headers)
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_get_token_valid_auth(client):
    """Test token endpoint with valid credentials"""
    credentials = base64.b64encode(b'admin:secret').decode('utf-8')
    headers = {'Authorization': f'Basic {credentials}'}
    response = client.post('/api/token', headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data
    # Verify the token is valid
    token = data['token']
    payload = verify_token(token)
    assert payload is not None
    assert payload['username'] == 'admin'


def test_protected_endpoint_no_token(client):
    """Test protected endpoint with no token"""
    response = client.get('/api/protected')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_protected_endpoint_invalid_token(client):
    """Test protected endpoint with invalid token"""
    headers = {'Authorization': 'Bearer invalid.token.here'}
    response = client.get('/api/protected', headers=headers)
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data


def test_protected_endpoint_valid_token(client):
    """Test protected endpoint with valid token"""
    # First get a valid token
    credentials = base64.b64encode(b'admin:secret').decode('utf-8')
    headers = {'Authorization': f'Basic {credentials}'}
    token_response = client.post('/api/token', headers=headers)
    token = json.loads(token_response.data)['token']
    
    # Test protected endpoint
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/api/protected', headers=headers)
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'admin' in data['message']
    assert 'expires' in data 