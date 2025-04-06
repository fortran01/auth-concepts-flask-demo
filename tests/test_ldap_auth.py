import pytest
from unittest.mock import patch, MagicMock
from app import ldap_authenticate
import ldap


@pytest.fixture
def ldap_mock():
    """Create a mock for the ldap module"""
    with patch('app.ldap') as mock_ldap:
        # Configure basic mocking behavior
        mock_conn = MagicMock()
        mock_ldap.initialize.return_value = mock_conn
        
        # Set up VERSION3 constant that's used in the code
        mock_ldap.VERSION3 = ldap.VERSION3
        
        # Set up OPT_REFERRALS constant that's used in the code
        mock_ldap.OPT_REFERRALS = ldap.OPT_REFERRALS
        
        # Set up SCOPE_SUBTREE constant that's used in the code
        mock_ldap.SCOPE_SUBTREE = ldap.SCOPE_SUBTREE
        
        # Mock exception classes
        mock_ldap.INVALID_CREDENTIALS = ldap.INVALID_CREDENTIALS
        mock_ldap.NO_SUCH_OBJECT = ldap.NO_SUCH_OBJECT
        mock_ldap.LDAPError = ldap.LDAPError
        
        yield mock_ldap


@pytest.fixture
def mock_ldap_search_success(ldap_mock):
    """Mock a successful LDAP search result"""
    mock_conn = ldap_mock.initialize.return_value
    
    # Create mock user attributes (binary values should be bytes)
    user_attrs = {
        'uid': [b'john.doe'],
        'cn': [b'John Doe'],
        'mail': [b'john.doe@example.org'],
        'sn': [b'Doe'],
        'givenName': [b'John']
    }
    
    # Configure search_s to return a successful result
    mock_conn.search_s.return_value = [
        ('uid=john.doe,ou=users,dc=example,dc=org', user_attrs)
    ]
    
    return mock_conn


@pytest.fixture
def mock_ldap_search_empty(ldap_mock):
    """Mock an empty LDAP search result (user not found)"""
    mock_conn = ldap_mock.initialize.return_value
    mock_conn.search_s.return_value = []
    return mock_conn


@pytest.fixture
def mock_ldap_bind_failure(ldap_mock):
    """Mock a failed LDAP bind due to invalid credentials"""
    mock_conn = ldap_mock.initialize.return_value
    # First bind (admin) succeeds, second bind (user) fails
    mock_conn.simple_bind_s.side_effect = [
        None,  # Admin bind succeeds
        ldap.INVALID_CREDENTIALS()  # User bind fails
    ]
    return mock_conn


@pytest.fixture
def mock_ldap_bind_success(ldap_mock):
    """Mock a successful LDAP bind"""
    mock_conn = ldap_mock.initialize.return_value
    # simple_bind_s doesn't return anything on success
    mock_conn.simple_bind_s.return_value = None
    return mock_conn


class TestLDAPAuthentication:
    """Test LDAP authentication functionality"""
    
    def test_ldap_authenticate_success(
        self, mock_ldap_search_success, mock_ldap_bind_success
    ):
        """Test successful LDAP authentication"""
        success, user_info, dn = ldap_authenticate('john.doe', 'password123')
        
        # Verify result
        assert success is True
        assert user_info is not None
        assert 'uid' in user_info
        assert user_info['uid'][0] == 'john.doe'
        assert user_info['cn'][0] == 'John Doe'
        assert dn == 'uid=john.doe,ou=users,dc=example,dc=org'
        
        # Verify that a search and bind were performed
        mock_conn = mock_ldap_search_success
        mock_conn.search_s.assert_called_once()
        mock_conn.simple_bind_s.assert_called()
    
    def test_ldap_authenticate_user_not_found(self, mock_ldap_search_empty):
        """Test LDAP authentication when user is not found"""
        success, user_info, error = ldap_authenticate('nonexistent', 'password')
        
        # Verify result
        assert success is False
        assert user_info is None
        assert "User not found" in error
        
        # Verify that only a search was performed (no bind attempt)
        mock_conn = mock_ldap_search_empty
        mock_conn.search_s.assert_called_once()
        # Only for admin bind
        mock_conn.simple_bind_s.assert_called_once()
    
    def test_ldap_authenticate_invalid_password(
        self, mock_ldap_search_success, mock_ldap_bind_failure
    ):
        """Test LDAP authentication with invalid password"""
        success, user_info, error = ldap_authenticate(
            'john.doe', 'wrong_password'
        )
        
        # Verify result
        assert success is False
        assert user_info is None
        assert "Invalid username or password" in error
        
        # Verify that a search and bind were performed
        mock_conn = mock_ldap_search_success
        # Called twice - admin bind and user bind
        assert mock_conn.simple_bind_s.call_count == 2
        assert mock_conn.search_s.call_count == 1
    
    def test_ldap_authenticate_error(self, ldap_mock):
        """Test LDAP authentication with a server error"""
        # Mock a server error
        mock_conn = ldap_mock.initialize.return_value
        mock_conn.simple_bind_s.side_effect = [
            None,  # First call (admin bind) succeeds
            # User bind fails
            ldap.LDAPError({'desc': 'Server down', 'info': 'Connection failed'})
        ]
        mock_conn.search_s.return_value = [
            ('uid=john.doe,ou=users,dc=example,dc=org', {})
        ]
        
        success, user_info, error = ldap_authenticate('john.doe', 'password123')
        
        # Verify result
        assert success is False
        assert user_info is None
        assert "LDAP error" in error
        assert "Server down" in error


class TestLDAPRoutes:
    """Test LDAP authentication web routes"""
    
    def test_ldap_login_get(self, client):
        """Test that the LDAP login page is served correctly"""
        response = client.get('/ldap-login')
        assert response.status_code == 200
        assert b'LDAP Authentication' in response.data
    
    @patch('app.ldap_authenticate')
    def test_ldap_login_post_success(self, mock_authenticate, client):
        """Test successful LDAP login via POST"""
        # Mock successful authentication
        user_info = {
            'uid': ['john.doe'],
            'cn': ['John Doe'],
            'mail': ['john.doe@example.org']
        }
        mock_authenticate.return_value = (
            True, user_info, 'uid=john.doe,ou=users,dc=example,dc=org'
        )
        
        response = client.post('/ldap-login', data={
            'username': 'john.doe',
            'password': 'password123'
        }, follow_redirects=True)
        
        # Verify the response
        assert response.status_code == 200
        assert b'LDAP Authentication Successful' in response.data
        assert b'John Doe' in response.data
        
        # Verify that authenticate was called with the right args
        mock_authenticate.assert_called_once_with('john.doe', 'password123')
        
        # Verify that session was updated
        with client.session_transaction() as session:
            assert session['ldap_authenticated'] is True
            assert session['ldap_username'] == 'john.doe'
            assert session['ldap_user_info'] == user_info
    
    @patch('app.ldap_authenticate')
    def test_ldap_login_post_failure(self, mock_authenticate, client):
        """Test failed LDAP login via POST"""
        # Mock failed authentication
        mock_authenticate.return_value = (
            False, None, "Invalid username or password."
        )
        
        response = client.post('/ldap-login', data={
            'username': 'john.doe',
            'password': 'wrong_password'
        }, follow_redirects=True)
        
        # Verify the response
        assert response.status_code == 200
        assert b'Authentication failed' in response.data
        
        # Verify session doesn't have LDAP auth
        with client.session_transaction() as session:
            assert 'ldap_authenticated' not in session
    
    def test_ldap_protected_without_auth(self, client):
        """Test that protected page redirects when not authenticated"""
        response = client.get('/ldap-protected', follow_redirects=True)
        
        # Should redirect to login page
        assert response.status_code == 200
        assert b'LDAP Authentication' in response.data
        assert b'Please log in with LDAP' in response.data
    
    def test_ldap_protected_with_auth(self, client):
        """Test that protected page works when authenticated"""
        # Set up session to simulate logged in user
        user_info = {
            'uid': ['john.doe'],
            'cn': ['John Doe'],
            'mail': ['john.doe@example.org']
        }
        
        with client.session_transaction() as session:
            session['ldap_authenticated'] = True
            session['ldap_username'] = 'john.doe'
            session['ldap_user_info'] = user_info
            session['ldap_dn'] = 'uid=john.doe,ou=users,dc=example,dc=org'
        
        response = client.get('/ldap-protected')
        
        # Should show protected page
        assert response.status_code == 200
        assert b'LDAP Authentication Successful' in response.data
        assert b'John Doe' in response.data
    
    def test_ldap_logout(self, client):
        """Test that logout clears the session"""
        # Set up session to simulate logged in user
        with client.session_transaction() as session:
            session['ldap_authenticated'] = True
            session['ldap_username'] = 'john.doe'
            session['ldap_user_info'] = {'uid': ['john.doe']}
            session['ldap_dn'] = 'uid=john.doe,ou=users,dc=example,dc=org'
        
        response = client.get('/ldap-logout', follow_redirects=True)
        
        # Should redirect to index and clear session
        assert response.status_code == 200
        assert b'Successfully logged out' in response.data
        
        # Verify session was cleared
        with client.session_transaction() as session:
            assert 'ldap_authenticated' not in session
            assert 'ldap_username' not in session 