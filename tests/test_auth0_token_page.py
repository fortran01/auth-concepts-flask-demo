import sys
import os
import unittest
from unittest.mock import patch, MagicMock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app  # noqa


class Auth0TokenPageTestCase(unittest.TestCase):
    """Test case for Auth0 token page UI elements and functionality"""

    def setUp(self):
        """Set up test client and environment"""
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['SECRET_KEY'] = 'test_secret_key'
        self.app.config['SERVER_NAME'] = 'localhost'
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

    def test_auth0_api_client_page_with_token(self):
        """Test the API client page when a token is present"""
        test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMj"
        token_data = {
            'access_token': test_token,
            'expires_in': 86400,
            'scope': 'read:data write:data',
            'token_type': 'Bearer'
        }
        
        with self.client.session_transaction() as sess:
            # Simulate having obtained a token
            sess['auth0_api_token'] = test_token
            sess['auth0_api_token_type'] = 'Machine-to-Machine'
            sess['auth0_api_token_data'] = token_data
        
        # Access the API client page
        response = self.client.get('/auth0/api-client')
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        response_text = response.data.decode('utf-8')
        
        # Check for token display
        self.assertIn(test_token, response_text)
        self.assertIn('Machine-to-Machine', response_text)
        self.assertIn('Token expires in 86400 seconds', response_text)
        self.assertIn('--header "authorization: Bearer', response_text)
        
        # Check for curl command
        expected_cmd = 'curl --request GET'
        self.assertIn(expected_cmd, response_text)
        self.assertIn('id="copyBtn"', response_text)

    def test_auth0_api_client_page_without_token(self):
        """Test the API client page when no token is present"""
        with self.client.session_transaction() as sess:
            # Clear any tokens
            sess.pop('auth0_api_token', None)
        
        # Access the API client page
        response = self.client.get('/auth0/api-client')
        
        # Assertions
        self.assertEqual(response.status_code, 302)  # Should redirect
        self.assertTrue('/auth0/get-token' in response.location)

    def test_auth0_m2m_token_page_display(self):
        """Test the M2M token page content"""
        response = self.client.get('/auth0/m2m-token')
        response_text = response.data.decode('utf-8')
        
        # Check page elements
        self.assertEqual(response.status_code, 200)
        self.assertIn('Get Machine-to-Machine Token', response_text)
        self.assertIn('Client ID:', response_text)
        self.assertIn('test-m2m-client-id', response_text)
        self.assertIn('Audience:', response_text)
        self.assertIn('https://test-api.example.com', response_text)
        self.assertIn('Grant Type: <strong>client_credentials</strong>', response_text)
        
        # Check for curl command examples
        self.assertIn('Test with curl commands', response_text)
        self.assertIn('curl --request POST', response_text)
        self.assertIn('curl --request GET', response_text)
        self.assertIn('https://test-domain.auth0.com/oauth/token', response_text)

    @patch('requests.get')
    @patch('requests.post')
    def test_m2m_token_page_with_token(self, mock_post, mock_get):
        """Test the M2M token page when a token is successfully retrieved"""
        # Mock the metadata response
        mock_metadata_response = MagicMock()
        mock_metadata_response.json.return_value = {
            'token_endpoint': 'https://test-domain.auth0.com/oauth/token'
        }
        mock_get.return_value = mock_metadata_response
        
        # Mock the token response
        test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMj"
        mock_token_response = MagicMock()
        mock_token_response.status_code = 200
        mock_token_response.json.return_value = {
            'access_token': test_token,
            'expires_in': 86400,
            'token_type': 'Bearer',
            'scope': 'read:data write:data'
        }
        mock_post.return_value = mock_token_response
        
        # Make POST request to get token
        response = self.client.post('/auth0/m2m-token')
        response_text = response.data.decode('utf-8')
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertIn('Machine-to-Machine Token Obtained', response_text)
        self.assertIn(test_token, response_text)
        self.assertIn('Token expires in 86400 seconds', response_text)
        
        # Check for ready-to-use curl command
        self.assertIn('Ready-to-Use Curl Command', response_text)
        bearer_header = f'--header "authorization: Bearer'
        self.assertIn(bearer_header, response_text)
        self.assertIn(test_token, response_text)
        self.assertIn('id="copyBtn"', response_text)
        
        # Check session
        with self.client.session_transaction() as sess:
            self.assertEqual(sess['auth0_api_token'], test_token)
            self.assertEqual(sess['auth0_api_token_type'], 'Machine-to-Machine')


if __name__ == '__main__':
    unittest.main() 