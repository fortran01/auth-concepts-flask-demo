import pytest
import json
from app import app, SESSION_KEY_PREFIX


def test_debug_redis_session_endpoint_accessible(client):
    """Test that the Redis session debug endpoint is accessible in debug mode."""
    response = client.get('/debug/redis-session')
    assert response.status_code == 200
    
    # Parse JSON response
    data = json.loads(response.data)
    
    # Check for expected keys in response
    assert 'current_session_id' in data
    assert 'clean_session_id' in data
    assert 'current_session_from_redis' in data
    assert 'all_sessions' in data


def test_debug_redis_session_not_accessible_in_production():
    """Test that Redis session debug page is not accessible in production mode."""
    # Create a new app instance with debug disabled
    app.config['DEBUG'] = False
    
    with app.test_client() as client:
        # Check that it redirects without follow_redirects
        response = client.get('/debug/redis-session')
        assert response.status_code == 302  # Redirect status code
        
        # Check with follow_redirects that we end up at the index page
        response = client.get('/debug/redis-session', follow_redirects=True)
        assert response.status_code == 200
        assert b'Welcome to the Authentication Demo!' in response.data
    
    # Restore debug mode
    app.config['DEBUG'] = True


def test_debug_redis_session_with_auth(client):
    """Test Redis session debug with an authenticated session."""
    # First login to create a session
    response = client.post('/login', data={
        'username': 'admin',
        'password': 'secret'
    }, follow_redirects=True)
    
    assert response.status_code == 200
    assert b'Successfully logged in!' in response.data
    
    # Now check the Redis session debug endpoint
    response = client.get('/debug/redis-session')
    assert response.status_code == 200
    
    # Parse JSON response
    data = json.loads(response.data)
    
    # There should be a current_session_id from the login
    assert data['current_session_id'] is not None
    
    # Check in multiple places for the session data - it could be in any of these
    found_session = False
    
    # Check in current_session
    if isinstance(data['current_session'], dict) and data['current_session'].get('username') == 'admin':
        found_session = True
    
    # Check in current_session_from_redis
    if isinstance(data['current_session_from_redis'], dict) and data['current_session_from_redis'].get('username') == 'admin':
        found_session = True
    
    # Check in all_sessions
    for key, session_data in data['all_sessions'].items():
        if isinstance(session_data, dict) and session_data.get('username') == 'admin':
            found_session = True
            break
    
    assert found_session, "Couldn't find the current user session anywhere in the response" 