import unittest
import json
import os
import sys
from unittest.mock import patch, MagicMock, Mock
from flask import url_for

# Add the parent directory to sys.path to import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app


class Auth0ApiTestCase(unittest.TestCase):
    """Test case for Auth0 API authentication features"""

    def setUp(self):
        """Set up test client and mocked environment variables"""
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test_secret_key'
        self.app.config['SERVER_NAME'] = 'localhost'
        self.app.config['PRESERVE_CONTEXT_ON_EXCEPTION'] = False
        self.client = self.app.test_client()
        
        # Set up test environment variables
        self.env_patcher = patch.dict('os.environ', {
            'AUTH0_DOMAIN': 'test-domain.auth0.com',
            'AUTH0_API_AUDIENCE': 'https://test-api.example.com',
            'AUTH0_M2M_CLIENT_ID': 'test-m2m-client-id',
            'AUTH0_M2M_CLIENT_SECRET': 'test-m2m-client-secret'
        })
        self.env_patcher.start()
        
        # Create app context
        self.app_context = self.app.app_context()
        self.app_context.push()
    
    def tearDown(self):
        """Clean up after tests"""
        self.app_context.pop()
        self.env_patcher.stop()

    @patch('requests.get')
    @patch('requests.post')
    def test_m2m_token_endpoint_success(self, mock_post, mock_get):
        """Test the machine-to-machine token endpoint with successful token retrieval"""
        # Mock the metadata response
        mock_metadata_response = MagicMock()
        mock_metadata_response.json.return_value = {
            'token_endpoint': 'https://test-domain.auth0.com/oauth/token'
        }
        mock_get.return_value = mock_metadata_response
        
        # Mock the token response
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            'access_token': 'test-access-token',
            'expires_in': 86400,
            'token_type': 'Bearer',
            'scope': 'read:data write:data'
        }
        mock_post.return_value = mock_token_response
        
        # Make the request
        with self.client.session_transaction() as session:
            session.clear()  # Clear any existing session
        
        response = self.client.post('/auth0/m2m-token')
        
        # Assert requests were made correctly
        mock_get.assert_called_once_with(
            'https://test-domain.auth0.com/.well-known/openid-configuration'
        )
        mock_post.assert_called_once_with(
            'https://test-domain.auth0.com/oauth/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': 'test-m2m-client-id',
                'client_secret': 'test-m2m-client-secret',
                'audience': 'https://test-api.example.com',
                'scope': 'read:data write:data'
            }
        )
        
        # Assert response details
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Machine-to-Machine Token Obtained', response.data)
        self.assertIn(b'test-access-token', response.data)
        self.assertIn(b'Token expires in 86400 seconds', response.data)
        self.assertIn(b'--header "authorization: Bearer test-access-token"', response.data)
        
        # Check session
        with self.client.session_transaction() as session:
            self.assertEqual(session['auth0_api_token'], 'test-access-token')
            self.assertEqual(session['auth0_api_token_type'], 'Machine-to-Machine')
            self.assertEqual(session['auth0_api_token_data']['expires_in'], 86400)

    @patch('requests.get')
    @patch('requests.post')
    def test_m2m_token_endpoint_failure(self, mock_post, mock_get):
        """Test the machine-to-machine token endpoint with failed token retrieval"""
        # Mock the metadata response
        mock_metadata_response = MagicMock()
        mock_metadata_response.json.return_value = {
            'token_endpoint': 'https://test-domain.auth0.com/oauth/token'
        }
        mock_get.return_value = mock_metadata_response
        
        # Mock the token response with error
        mock_token_response = MagicMock()
        mock_token_response.status_code = 401
        mock_token_response.json.return_value = {
            'error': 'access_denied',
            'error_description': 'Client authentication failed'
        }
        mock_token_response.text = json.dumps({
            'error': 'access_denied',
            'error_description': 'Client authentication failed'
        })
        mock_post.return_value = mock_token_response
        
        # Make the request
        with self.client.session_transaction() as session:
            session.clear()
        
        response = self.client.post('/auth0/m2m-token')
        
        # Assert error handling
        self.assertEqual(response.status_code, 200)  # Renders page with error message
        self.assertNotIn(b'Machine-to-Machine Token Obtained', response.data)
        self.assertIn(b'Get Machine-to-Machine Token', response.data)  # Form page
        
        # Session should not have token
        with self.client.session_transaction() as session:
            self.assertNotIn('auth0_api_token', session)

    @patch('jwt.PyJWKClient')
    def test_auth0_protected_api_success(self, mock_jwk_client):
        """Test the Auth0 protected API endpoint with valid token"""
        # Mock the JWT validation process
        mock_signing_key = MagicMock()
        mock_signing_key.key = 'test-key'
        
        mock_jwk_client_instance = MagicMock()
        mock_jwk_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwk_client.return_value = mock_jwk_client_instance
        
        # Mock jwt.decode to return payload
        with patch('jwt.decode') as mock_decode:
            mock_decode.return_value = {
                'sub': 'test-user-id',
                'iss': 'https://test-domain.auth0.com/',
                'aud': 'https://test-api.example.com',
                'permissions': ['read:data']
            }
            
            # Make the request with Authorization header
            headers = {
                'Authorization': 'Bearer test-access-token'
            }
            response = self.client.get('/api/auth0-protected', headers=headers)
            
            # Assertions
            self.assertEqual(response.status_code, 200)
            data = json.loads(response.data)
            self.assertEqual(data['message'], 'This API is protected by Auth0!')
            self.assertEqual(data['user'], 'test-user-id')
            self.assertEqual(data['permissions'], ['read:data'])
            
            # Verify JWT validation occurred correctly
            mock_jwk_client_instance.get_signing_key_from_jwt.assert_called_once_with('test-access-token')
            mock_decode.assert_called_once_with(
                'test-access-token',
                'test-key',
                algorithms=['RS256'],
                audience='https://test-api.example.com',
                issuer='https://test-domain.auth0.com/'
            )

    def test_auth0_protected_api_missing_token(self):
        """Test the Auth0 protected API endpoint with missing token"""
        response = self.client.get('/api/auth0-protected')
        
        # Assertions
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Missing authorization header')

    def test_auth0_protected_api_invalid_token_format(self):
        """Test the Auth0 protected API endpoint with invalid token format"""
        headers = {
            'Authorization': 'Invalid-Format test-access-token'
        }
        response = self.client.get('/api/auth0-protected', headers=headers)
        
        # Assertions
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertEqual(data['error'], 'Missing authorization header')

    @patch('jwt.PyJWKClient')
    def test_auth0_protected_api_token_validation_error(self, mock_jwk_client):
        """Test the Auth0 protected API endpoint with token validation error"""
        # Mock the JWT validation process to raise an error
        mock_signing_key = MagicMock()
        mock_signing_key.key = 'test-key'
        
        mock_jwk_client_instance = MagicMock()
        mock_jwk_client_instance.get_signing_key_from_jwt.return_value = mock_signing_key
        mock_jwk_client.return_value = mock_jwk_client_instance
        
        # Mock jwt.decode to raise exception
        with patch('jwt.decode') as mock_decode:
            from jwt import InvalidTokenError
            mock_decode.side_effect = InvalidTokenError('Invalid token')
            
            # Make the request with Authorization header
            headers = {
                'Authorization': 'Bearer test-invalid-token'
            }
            response = self.client.get('/api/auth0-protected', headers=headers)
            
            # Assertions
            self.assertEqual(response.status_code, 401)
            data = json.loads(response.data)
            self.assertEqual(data['error'], 'Invalid token')

    def test_auth0_api_demo_page(self):
        """Test the Auth0 API demo landing page"""
        response = self.client.get('/auth0/api-demo')
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Demo 4: Securing APIs with Auth0', response.data)
        self.assertIn(b'Option 1: User Authentication Flow', response.data)
        self.assertIn(b'Option 2: Machine-to-Machine Flow', response.data)
        
    def test_auth0_get_token_page(self):
        """Test the Auth0 get token page"""
        response = self.client.get('/auth0/get-token')
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Get Auth0 Access Token', response.data)
        self.assertIn(b'Authenticate with Auth0', response.data)
        
    def test_auth0_m2m_token_page(self):
        """Test the Auth0 M2M token page"""
        response = self.client.get('/auth0/m2m-token')
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Get Machine-to-Machine Token', response.data)
        self.assertIn(b'Client Credentials', response.data)
        self.assertIn(b'Test with curl commands', response.data)


if __name__ == '__main__':
    unittest.main() 