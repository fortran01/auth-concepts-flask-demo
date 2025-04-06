import unittest
from unittest.mock import patch, MagicMock
import os
from app import app
import fakeredis


class Auth0TestCase(unittest.TestCase):
    """Test case for Auth0 integration functionality."""

    def setUp(self):
        """Set up test client and enable testing mode."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SERVER_NAME'] = '127.0.0.1:5001'
        
        # Use fakeredis instead of real Redis
        app.config['SESSION_TYPE'] = 'redis'
        app.config['SESSION_REDIS'] = fakeredis.FakeStrictRedis()
        
        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Mock Auth0 configuration
        os.environ['AUTH0_CLIENT_ID'] = 'test_client_id'
        os.environ['AUTH0_CLIENT_SECRET'] = 'test_client_secret'
        os.environ['AUTH0_DOMAIN'] = 'test.auth0.com'
        
        # Create a mock userinfo object that Auth0 would return
        self.mock_userinfo = {
            'sub': 'auth0|123456',
            'name': 'Test User',
            'nickname': 'testuser',
            'picture': 'https://example.com/avatar.png',
            'email': 'test@example.com',
            'email_verified': True,
            'updated_at': '2023-01-01T00:00:00.000Z'
        }
        
        # Mock token response
        self.mock_token = {
            'access_token': 'mock_access_token',
            'id_token': 'mock_id_token',
            'token_type': 'Bearer',
            'expires_in': 86400,
            'userinfo': self.mock_userinfo
        }

    def tearDown(self):
        """Clean up after tests."""
        self.app_context.pop()
        
    @patch('app.oauth.auth0.authorize_redirect')
    def test_auth0_login_route(self, mock_authorize_redirect):
        """Test the auth0_login route."""
        # Setup mock
        mock_redirect = MagicMock()
        mock_authorize_redirect.return_value = mock_redirect
        
        # Call the route
        response = self.client.get('/auth0/login')
        
        # Assertions
        mock_authorize_redirect.assert_called_once()
        self.assertEqual(response.status_code, 200)
    
    @patch('app.oauth.auth0.authorize_access_token')
    def test_auth0_callback_route(self, mock_authorize_access_token):
        """Test the auth0_callback route."""
        # Setup mock
        mock_authorize_access_token.return_value = self.mock_token
        
        # Call the route
        with self.client.session_transaction() as sess:
            # Ensure session is active
            sess['_fresh'] = True
        
        response = self.client.get('/auth0/callback')
        
        # Assertions
        mock_authorize_access_token.assert_called_once()
        self.assertEqual(response.status_code, 302)  # Redirect status
        
        # Check that the user was stored in session
        with self.client.session_transaction() as sess:
            self.assertIn('auth0_user', sess)
            self.assertEqual(sess['auth0_user'], self.mock_token)
    
    def test_auth0_profile_route_not_authenticated(self):
        """Test the auth0_profile route when not authenticated."""
        response = self.client.get('/auth0/profile')
        
        # Should redirect to login page
        self.assertEqual(response.status_code, 302)
        self.assertIn('/auth0-demo', response.location)
    
    def test_auth0_profile_route_authenticated(self):
        """Test the auth0_profile route when authenticated."""
        # Setup session with mock user
        with self.client.session_transaction() as sess:
            sess['auth0_user'] = self.mock_token
        
        # Call the route
        response = self.client.get('/auth0/profile')
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Test User', response.data)
        self.assertIn(b'test@example.com', response.data)
    
    def test_auth0_logout_route(self):
        """Test the auth0_logout route."""
        # Setup session with mock user
        with self.client.session_transaction() as sess:
            sess['auth0_user'] = self.mock_token
        
        # Call the route
        response = self.client.get('/auth0/logout')
        
        # Assertions
        self.assertEqual(response.status_code, 302)  # Redirect status
        
        # Check that user was removed from session
        with self.client.session_transaction() as sess:
            self.assertNotIn('auth0_user', sess)
        
        # Check that redirect URL contains Auth0 domain
        self.assertIn('test.auth0.com/v2/logout', response.location)
    
    def test_auth0_demo_page(self):
        """Test the Auth0 demo landing page."""
        response = self.client.get('/auth0-demo')
        
        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Auth0 Universal Login Demo', response.data)
        self.assertIn(b'Login with Auth0', response.data)


if __name__ == '__main__':
    unittest.main() 