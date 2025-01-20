import pytest
from app import app


@pytest.fixture
def client():
    """Create a test client for the app."""
    app.config['TESTING'] = True
    with app.test_client() as client:
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