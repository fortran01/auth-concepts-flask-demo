import pytest
import json
from app import app, generate_token
from flask_session import Session


@pytest.fixture
def client(monkeypatch, redis_mock):
    """Create a test client for the app."""
    # Save original Redis client to restore later
    original_session_redis = app.config.get('SESSION_REDIS')
    
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'
    app.config['SESSION_COOKIE_SECURE'] = False
    
    # Replace the Redis client with the mock
    app.config['SESSION_REDIS'] = redis_mock
    
    # Re-initialize the Flask-Session with our fake Redis
    Session(app)
    
    with app.test_client() as client:
        yield client
    
    # Restore original Redis client after tests
    app.config['SESSION_REDIS'] = original_session_redis
    # Re-initialize the session with the original Redis client
    Session(app)


def test_token_login_page(client):
    """Test that token login page loads correctly"""
    response = client.get('/token-login')
    assert response.status_code == 200
    assert b'JWT Token Login' in response.data
    assert b'form id="login-form"' in response.data


def test_token_login_api_success(client):
    """Test successful token login API"""
    response = client.post('/token-login', 
                         json={
                             'username': 'admin',
                             'password': 'secret'
                         },
                         content_type='application/json')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data
    assert data['token'] is not None


def test_token_login_api_invalid_credentials(client):
    """Test token login API with invalid credentials"""
    response = client.post('/token-login', 
                         json={
                             'username': 'admin',
                             'password': 'wrong'
                         },
                         content_type='application/json')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid credentials' in data['error']


def test_token_login_api_missing_data(client):
    """Test token login API with missing data"""
    response = client.post('/token-login', 
                         json={
                             'username': 'admin'
                             # Missing password
                         },
                         content_type='application/json')
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing username or password' in data['error']


def test_token_protected_page(client):
    """Test that token protected page loads correctly"""
    response = client.get('/token-protected')
    assert response.status_code == 200
    assert b'JWT Token Protected Page' in response.data
    assert b'Loading protected data' in response.data


def test_api_token_data_no_token(client):
    """Test token data API endpoint without a token"""
    response = client.get('/api/token-data')
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Missing or invalid token' in data['error']


def test_api_token_data_invalid_token(client):
    """Test token data API endpoint with an invalid token"""
    headers = {'Authorization': 'Bearer invalid_token'}
    response = client.get('/api/token-data', headers=headers)
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid or expired token' in data['error']


def test_api_token_data_valid_token(client):
    """Test token data API endpoint with a valid token"""
    # Generate a valid token
    token = generate_token('admin')
    
    # Make request with token
    headers = {'Authorization': f'Bearer {token}'}
    response = client.get('/api/token-data', headers=headers)
    
    # Verify response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'message' in data
    assert 'Hello admin!' in data['message']
    assert 'timestamp' in data 