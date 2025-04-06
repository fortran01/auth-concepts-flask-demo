import unittest
from unittest.mock import patch
import os
import time
import threading
from flask import Flask, jsonify, request, redirect
from werkzeug.serving import make_server

from app import app as flask_app


class MockAuth0Server(threading.Thread):
    """A mock Auth0 server for integration testing."""
    
    def __init__(self, host='127.0.0.1', port=5050):
        super().__init__()
        self.host = host
        self.port = port
        self.app = Flask(__name__)
        self.server = make_server(host, port, self.app)
        self.ctx = self.app.app_context()
        self.ctx.push()
        
        # Auth0 mock endpoints
        @self.app.route('/.well-known/openid-configuration')
        def openid_config():
            return jsonify({
                'authorization_endpoint': f'http://{host}:{port}/authorize',
                'token_endpoint': f'http://{host}:{port}/oauth/token',
                'userinfo_endpoint': f'http://{host}:{port}/userinfo',
                'issuer': f'http://{host}:{port}/'
            })
        
        @self.app.route('/authorize')
        def authorize():
            # Simulate consent and redirect back with authorization code
            callback_url = request.args.get('redirect_uri', '')
            state = request.args.get('state', '')
            # Redirect back to the callback with a mock authorization code
            return redirect(
                f"{callback_url}?code=mock_auth_code&state={state}"
            )
        
        @self.app.route('/oauth/token', methods=['POST'])
        def token():
            # Return a mock access token
            return jsonify({
                'access_token': 'mock_access_token',
                'id_token': 'mock_id_token',
                'token_type': 'Bearer',
                'expires_in': 86400
            })
        
        @self.app.route('/userinfo')
        def userinfo():
            # Return mock user information
            return jsonify({
                'sub': 'auth0|123456789',
                'name': 'Mock User',
                'nickname': 'mockuser',
                'picture': 'https://example.com/picture.jpg',
                'email': 'mock.user@example.com',
                'email_verified': True
            })
        
        @self.app.route('/v2/logout')
        def logout():
            # Simulate logout by redirecting to the returnTo URL
            return_to = request.args.get('returnTo', '/')
            return redirect(return_to)
    
    def run(self):
        """Start the mock server."""
        self.server.serve_forever()
    
    def shutdown(self):
        """Shutdown the mock server."""
        self.server.shutdown()
        self.ctx.pop()


class Auth0IntegrationTest(unittest.TestCase):
    """Integration tests for Auth0 integration."""
    
    @classmethod
    def setUpClass(cls):
        """Start mock Auth0 server."""
        cls.mock_server = MockAuth0Server()
        cls.mock_server.daemon = True
        cls.mock_server.start()
        # Wait for server to start
        time.sleep(1)
    
    @classmethod
    def tearDownClass(cls):
        """Shutdown mock Auth0 server."""
        cls.mock_server.shutdown()
    
    def setUp(self):
        """Set up the test client."""
        flask_app.config['TESTING'] = True
        flask_app.config['SESSION_TYPE'] = 'filesystem'
        
        # Configure Auth0 to use our mock server
        self.original_domain = os.environ.get('AUTH0_DOMAIN')
        self.original_client_id = os.environ.get('AUTH0_CLIENT_ID')
        self.original_client_secret = os.environ.get('AUTH0_CLIENT_SECRET')
        
        mock_server_url = f'{self.mock_server.host}:{self.mock_server.port}'
        os.environ['AUTH0_DOMAIN'] = mock_server_url
        os.environ['AUTH0_CLIENT_ID'] = 'mock_client_id'
        os.environ['AUTH0_CLIENT_SECRET'] = 'mock_client_secret'
        
        self.client = flask_app.test_client()
    
    def tearDown(self):
        """Clean up after tests."""
        # Restore original Auth0 settings
        if self.original_domain:
            os.environ['AUTH0_DOMAIN'] = self.original_domain
        else:
            del os.environ['AUTH0_DOMAIN']
            
        if self.original_client_id:
            os.environ['AUTH0_CLIENT_ID'] = self.original_client_id
        else:
            del os.environ['AUTH0_CLIENT_ID']
            
        if self.original_client_secret:
            os.environ['AUTH0_CLIENT_SECRET'] = self.original_client_secret
        else:
            del os.environ['AUTH0_CLIENT_SECRET']
    
    def test_auth0_demo_page(self):
        """Test the Auth0 demo page loads correctly."""
        response = self.client.get('/auth0-demo')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Auth0 Universal Login', response.data)

    @patch('authlib.integrations.flask_client.OAuth.register')
    def test_auth0_profile_access(self, mock_register):
        """Test access to auth0 profile page with simulated session."""
        # Add user to session
        mock_user_data = {
            'access_token': 'mock_access_token',
            'id_token': 'mock_id_token',
            'token_type': 'Bearer',
            'expires_in': 86400,
            'userinfo': {
                'sub': 'auth0|123456789',
                'name': 'Mock User',
                'nickname': 'mockuser',
                'picture': 'https://example.com/picture.jpg',
                'email': 'mock.user@example.com',
                'email_verified': True
            }
        }
        
        with self.client.session_transaction() as sess:
            sess['auth0_user'] = mock_user_data
        
        # Visit profile page
        response = self.client.get('/auth0/profile')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Mock User', response.data)
        self.assertIn(b'mock.user@example.com', response.data)
        
        # Test logout
        response = self.client.get('/auth0/logout')
        self.assertEqual(response.status_code, 302)
        
        # Profile should redirect after logout
        response = self.client.get('/auth0/profile')
        self.assertEqual(response.status_code, 302)
        self.assertTrue('/auth0-demo' in response.location)


if __name__ == '__main__':
    unittest.main() 