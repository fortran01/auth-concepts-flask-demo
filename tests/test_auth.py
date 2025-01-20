import pytest
from app import app


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