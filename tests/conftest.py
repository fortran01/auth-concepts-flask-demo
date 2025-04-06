import pytest
from app import app, USERS
import fakeredis
import mock


@pytest.fixture(autouse=True)
def reset_mfa():
    """Reset MFA state before each test."""
    USERS['admin']['mfa_secret'] = None
    yield


@pytest.fixture
def client():
    """Create a test client for the app."""
    app.config['TESTING'] = True
    app.config['SECRET_KEY'] = 'test_secret_key'  # Set a fixed secret key for testing
    app.config['SESSION_COOKIE_SECURE'] = False  # Allow session cookie in testing
    
    # Mock Redis for testing
    redis_mock = fakeredis.FakeStrictRedis()
    with mock.patch('flask_session.RedisSessionInterface._get_connection', return_value=redis_mock):
        with app.test_client() as client:
            with app.app_context():
                with client.session_transaction() as sess:
                    sess['_fresh'] = True  # Mark session as fresh
                yield client


@pytest.fixture
def auth_headers():
    """Return helper functions for creating auth headers."""
    import base64
    import hashlib
    
    def basic_auth(username: str, password: str) -> dict:
        credentials = base64.b64encode(
            f"{username}:{password}".encode()
        ).decode('utf-8')
        return {'Authorization': f'Basic {credentials}'}
    
    def digest_auth(
        username: str,
        password: str,
        realm: str,
        nonce: str,
        uri: str,
        opaque: str
    ) -> dict:
        ha1 = hashlib.md5(
            f"{username}:{realm}:{password}".encode()
        ).hexdigest()
        ha2 = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
        response = hashlib.md5(
            f"{ha1}:{nonce}:{ha2}".encode()
        ).hexdigest()
        
        auth_string = (
            'Digest username="{}",'
            'realm="{}",'
            'nonce="{}",'
            'uri="{}",'
            'response="{}",'
            'opaque="{}"'
        ).format(username, realm, nonce, uri, response, opaque)
        
        return {'Authorization': auth_string}
    
    return {'basic': basic_auth, 'digest': digest_auth} 