import pytest
import json
from app import app, FLASK_SESSION_SALT
from itsdangerous import URLSafeTimedSerializer
from bs4 import BeautifulSoup
import base64


@pytest.fixture
def client():
    """Create a test client for the app."""
    app.config['TESTING'] = True
    # Set a fixed secret key for testing
    app.config['SECRET_KEY'] = 'test_secret_key'
    app.config['DEBUG'] = True  # Ensure debug mode is enabled for testing
    
    with app.test_client() as client:
        yield client


def test_debug_decode_session_page_accessible(client):
    """Test that the debug session page is accessible."""
    response = client.get('/debug/decode-session')
    assert response.status_code == 200
    assert b'Decode Session Cookie' in response.data
    assert b'Generate Test Cookie' in response.data


def test_debug_decode_session_page_not_accessible_in_production():
    """Test that debug session page is not accessible in production mode."""
    # Create a new app instance with debug disabled
    import app as app_module
    original_debug_mode = app_module.DEBUG_MODE
    app_module.DEBUG_MODE = False
    app.config['DEBUG'] = False
    
    with app.test_client() as client:
        # First check that it redirects without follow_redirects
        response = client.get('/debug/decode-session')
        assert response.status_code == 302  # Redirect status code
        
        # Now check with follow_redirects that we end up at the index page
        response = client.get('/debug/decode-session', follow_redirects=True)
        assert response.status_code == 200
        assert b'Authentication Concepts Demo' in response.data
    
    # Restore debug mode
    app_module.DEBUG_MODE = original_debug_mode
    app.config['DEBUG'] = True


def test_generate_test_cookie(client):
    """Test generating a test cookie."""
    response = client.post('/debug/decode-session', data={
        'generate_cookie': 'yes'
    })
    
    assert response.status_code == 200
    assert b'Test Cookie Generated' in response.data
    
    # Parse the response to extract the generated cookie
    soup = BeautifulSoup(response.data, 'html.parser')
    cookie_element = soup.select_one('.alert-success code')
    assert cookie_element is not None
    
    generated_cookie = cookie_element.text
    assert generated_cookie is not None
    assert len(generated_cookie) > 0
    
    # Verify the cookie is properly structured
    parts = generated_cookie.split('.')
    # Should have payload, timestamp, and signature
    assert len(parts) == 3


def test_decode_valid_cookie(client):
    """Test decoding a valid session cookie."""
    # Generate a valid cookie
    serializer = URLSafeTimedSerializer('test_secret_key', salt=FLASK_SESSION_SALT)
    test_data = {
        'username': 'test_user',
        'mfa_verified': True,
        'mfa_setup': False
    }
    test_cookie = serializer.dumps(test_data)
    
    # Send the cookie to be decoded
    response = client.post('/debug/decode-session', data={
        'cookie_value': test_cookie
    })
    
    assert response.status_code == 200
    assert b'Valid Signature' in response.data
    assert b'Decoded Payload' in response.data
    assert b'test_user' in response.data
    assert b'mfa_verified' in response.data
    
    # Verify cookie structure is displayed
    soup = BeautifulSoup(response.data, 'html.parser')
    structure_table = soup.select('.card table')
    assert len(structure_table) > 0


def test_decode_invalid_cookie(client):
    """Test decoding an invalid session cookie."""
    # Generate an invalid cookie (tampered)
    serializer = URLSafeTimedSerializer('test_secret_key', salt=FLASK_SESSION_SALT)
    test_data = {
        'username': 'test_user',
        'mfa_verified': True
    }
    valid_cookie = serializer.dumps(test_data)
    
    # Tamper with the payload part
    parts = valid_cookie.split('.')
    
    # Decode the payload
    payload = parts[0]
    payload += '=' * (-len(payload) % 4)  # Add padding
    decoded_payload = base64.urlsafe_b64decode(payload).decode('utf-8')
    
    # Modify the payload (add admin privileges)
    modified_payload_dict = json.loads(decoded_payload)
    modified_payload_dict['is_admin'] = True
    
    # Re-encode the payload
    modified_payload = json.dumps(modified_payload_dict)
    encoded_bytes = base64.urlsafe_b64encode(modified_payload.encode())
    modified_payload_b64 = encoded_bytes.decode('utf-8')
    modified_payload_b64 = modified_payload_b64.rstrip('=')  # Remove padding
    
    # Create tampered cookie with modified payload but original timestamp/signature
    tampered_cookie = f"{modified_payload_b64}.{parts[1]}.{parts[2]}"
    
    # Send the tampered cookie to be decoded
    response = client.post('/debug/decode-session', data={
        'cookie_value': tampered_cookie
    })
    
    assert response.status_code == 200
    assert b'Invalid Signature' in response.data
    # It should still decode the payload
    assert b'Decoded Payload' in response.data
    assert b'is_admin' in response.data  # Our tampered field
    assert b'test_user' in response.data


def test_decode_malformed_cookie(client):
    """Test decoding a malformed cookie."""
    malformed_cookie = "this.is.not.a.valid.cookie"
    
    response = client.post('/debug/decode-session', data={
        'cookie_value': malformed_cookie
    })
    
    assert response.status_code == 200
    assert b'Error:' in response.data
    assert b'Could not' in response.data


def test_decode_empty_cookie(client):
    """Test submitting the form with an empty cookie value."""
    # With our updated code, the client-side validation prevents empty form
    # But let's test the server still handles it gracefully
    response = client.post('/debug/decode-session', data={
        'cookie_value': ''
    })
    
    assert response.status_code == 200
    assert b'Please paste a cookie value' in response.data 