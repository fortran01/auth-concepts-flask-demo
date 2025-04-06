import pytest
import json
from unittest.mock import patch
import sys
import os

# Add the parent directory to sys.path to import the API server module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the API server app
from api_server import app as api_app
# Import the client app
from client_app import app as client_app


@pytest.fixture
def api_client():
    """Test client for the API server"""
    with api_app.test_client() as client:
        yield client


@pytest.fixture
def web_client():
    """Test client for the client web application"""
    with client_app.test_client() as client:
        yield client


def test_api_no_cors_endpoint(api_client):
    """Test the endpoint with no CORS headers"""
    response = api_client.get('/api/data')
    
    # Verify the response status and data
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert data['message'] == 'This is data from the API server'
    assert data['data'] == [1, 2, 3, 4, 5]
    
    # Verify no CORS headers are present
    assert 'Access-Control-Allow-Origin' not in response.headers


def test_api_with_cors_endpoint(api_client):
    """Test the endpoint with CORS enabled for all origins"""
    response = api_client.get('/api/data-with-cors')
    
    # Verify the response status and data
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert data['message'] == 'This is data from the API server (with CORS enabled)'
    assert data['data'] == [1, 2, 3, 4, 5]
    
    # Verify CORS headers are present and configured correctly
    assert 'Access-Control-Allow-Origin' in response.headers
    assert response.headers['Access-Control-Allow-Origin'] == '*'


def test_api_with_specific_cors_endpoint(api_client):
    """Test the endpoint with CORS enabled for a specific origin"""
    response = api_client.get('/api/data-with-specific-cors')
    
    # Verify the response status and data
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert data['message'] == 'This is data from the API server (with specific CORS)'
    assert data['data'] == [1, 2, 3, 4, 5]
    
    # Verify CORS headers are present and configured correctly
    assert 'Access-Control-Allow-Origin' in response.headers
    assert response.headers['Access-Control-Allow-Origin'] == 'http://localhost:5003'


def test_api_with_preflight_cors_endpoint(api_client):
    """Test the endpoint that handles preflight requests"""
    # Test the preflight OPTIONS request
    preflight_response = api_client.options('/api/data-with-preflight', 
        headers={
            'Origin': 'http://example.com',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'Content-Type'
        }
    )
    
    # Verify the preflight response
    assert preflight_response.status_code == 200
    assert 'Access-Control-Allow-Origin' in preflight_response.headers
    assert preflight_response.headers['Access-Control-Allow-Origin'] == '*'
    assert 'Access-Control-Allow-Methods' in preflight_response.headers
    assert 'GET' in preflight_response.headers['Access-Control-Allow-Methods']
    assert 'Access-Control-Allow-Headers' in preflight_response.headers
    assert 'Content-Type' in preflight_response.headers['Access-Control-Allow-Headers']
    
    # Test the actual request
    response = api_client.get('/api/data-with-preflight')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert data['message'] == 'This is data from the API server (with preflight handling)'


def test_api_with_flask_cors_endpoint(api_client):
    """Test the endpoint with CORS enabled using the Flask-CORS extension"""
    response = api_client.get('/api/data-with-flask-cors')
    
    # Verify the response status and data
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['status'] == 'success'
    assert data['message'] == 'This is data from the API server (using flask-cors)'
    assert data['data'] == [1, 2, 3, 4, 5]
    
    # The Flask-CORS extension automatically adds CORS headers
    assert 'Access-Control-Allow-Origin' in response.headers


def test_client_app_route(web_client):
    """Test that the client app serves the CORS demo page"""
    response = web_client.get('/')
    
    # Verify the response status
    assert response.status_code == 200
    # Check that the content includes key elements from the CORS demo page
    assert b'Cross-Origin Resource Sharing (CORS) Demo' in response.data
    assert b'This page demonstrates CORS in action' in response.data
    assert b'No CORS Headers' in response.data
    assert b'CORS Enabled for All Origins' in response.data


def test_cross_origin_request_simulation():
    """
    Simulate a cross-origin request scenario
    
    This test mocks browser behavior to demonstrate what happens when:
    1. A request from origin A tries to access an API at origin B without CORS
    2. A request from origin A tries to access an API at origin B with proper CORS headers
    """
    # Create test clients
    api_test_client = api_app.test_client()
    client_test_client = client_app.test_client()
    
    # 1. Simulate browser behavior for endpoint without CORS headers
    # In a real browser, this would be blocked by the Same-Origin Policy
    # In a test, we can make the request directly to demonstrate server behavior
    response_no_cors = api_test_client.get('/api/data', headers={'Origin': 'http://localhost:5003'})
    
    # Server responds with the data but doesn't include CORS headers
    # Without these headers, browser would block this response from reaching the JavaScript
    assert response_no_cors.status_code == 200
    assert 'Access-Control-Allow-Origin' not in response_no_cors.headers
    
    # 2. Simulate browser behavior for endpoint with CORS headers
    response_with_cors = api_test_client.get('/api/data-with-cors', headers={'Origin': 'http://localhost:5003'})
    
    # Server responds with data AND proper CORS headers
    # Browser would allow JavaScript to access this response
    assert response_with_cors.status_code == 200
    assert 'Access-Control-Allow-Origin' in response_with_cors.headers
    assert response_with_cors.headers['Access-Control-Allow-Origin'] == '*'


def test_cors_demo_info_route():
    """Test that the main app serves the CORS demo info page"""
    # This requires importing the main app, but since it might have complex initialization,
    # we'll patch it or mock it for this test
    
    # For demonstration, we'll just assert that the route exists
    # In a real test, you'd want to verify the actual content
    with patch('app.render_template') as mock_render:
        # Import here to avoid circular imports
        from app import cors_demo_info
        
        mock_render.return_value = "Mocked template response"
        response = cors_demo_info()
        
        # Verify the render_template was called with the correct template
        mock_render.assert_called_once_with('cors_demo_info.html')


def test_different_origins():
    """
    Test how the API responds to requests from different origins
    This simulates browsers from different domains making requests
    """
    api_test_client = api_app.test_client()
    
    # Test with allowed origin
    allowed_origin = 'http://localhost:5003'
    response = api_test_client.get(
        '/api/data-with-specific-cors', 
        headers={'Origin': allowed_origin}
    )
    
    assert response.status_code == 200
    assert 'Access-Control-Allow-Origin' in response.headers
    assert response.headers['Access-Control-Allow-Origin'] == allowed_origin
    
    # Test with disallowed origin
    disallowed_origin = 'http://evil-site.com'
    response = api_test_client.get(
        '/api/data-with-specific-cors', 
        headers={'Origin': disallowed_origin}
    )
    
    # The server will still return data (CORS is enforced by browser, not server)
    assert response.status_code == 200
    # But the CORS header won't include the disallowed origin
    assert 'Access-Control-Allow-Origin' in response.headers
    assert response.headers['Access-Control-Allow-Origin'] != disallowed_origin
    
    # The browser would block this response because the origin doesn't match


def test_complex_preflight_scenarios():
    """Test different preflight scenarios with various headers and methods"""
    api_test_client = api_app.test_client()
    
    # Test preflight with complex headers
    preflight_response = api_test_client.options(
        '/api/data-with-preflight',
        headers={
            'Origin': 'http://localhost:5003',
            'Access-Control-Request-Method': 'POST',  # Method not explicitly allowed
            'Access-Control-Request-Headers': 'Content-Type, Authorization'  # Complex headers
        }
    )
    
    assert preflight_response.status_code == 200
    assert 'Access-Control-Allow-Origin' in preflight_response.headers
    assert 'Access-Control-Allow-Methods' in preflight_response.headers
    assert 'POST' in preflight_response.headers['Access-Control-Allow-Methods']
    assert 'Access-Control-Allow-Headers' in preflight_response.headers
    assert 'Content-Type' in preflight_response.headers['Access-Control-Allow-Headers']
    # The Authorization header isn't explicitly allowed, but our endpoint allows Content-Type
    
    # Test with a custom header not in the allowed list
    preflight_response = api_test_client.options(
        '/api/data-with-preflight',
        headers={
            'Origin': 'http://localhost:5003',
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'X-Custom-Header'  # Not explicitly allowed
        }
    )
    
    # In a real browser, this would be blocked for the custom header
    assert preflight_response.status_code == 200
    assert 'Access-Control-Allow-Origin' in preflight_response.headers
    assert 'Access-Control-Allow-Headers' in preflight_response.headers
    # Check if our implementation allows X-Custom-Header (implementation dependent)
    # Some CORS implementations might reject this


def test_comprehensive_cors():
    """
    Comprehensive test that simulates browser requests to all API endpoints
    Testing all CORS configurations in a way that mimics real-world browser behavior
    """
    api_client = api_app.test_client()
    
    # Define test cases for each endpoint with expected behavior
    test_cases = [
        {
            'description': 'No CORS headers endpoint',
            'endpoint': '/api/data',
            'origin': 'http://localhost:5003',
            'expect_cors_header': False,
            'expect_allowed': False  # Would be blocked in browser
        },
        {
            'description': 'CORS enabled for all origins',
            'endpoint': '/api/data-with-cors',
            'origin': 'http://localhost:5003',
            'expect_cors_header': True,
            'expect_allowed': True,
            'expected_origin_value': '*'
        },
        {
            'description': 'CORS enabled for specific origin - allowed origin',
            'endpoint': '/api/data-with-specific-cors',
            'origin': 'http://localhost:5003',
            'expect_cors_header': True,
            'expect_allowed': True,
            'expected_origin_value': 'http://localhost:5003'
        },
        {
            'description': 'CORS enabled for specific origin - disallowed origin',
            'endpoint': '/api/data-with-specific-cors',
            'origin': 'http://disallowed-site.com',
            'expect_cors_header': True,
            'expect_allowed': False,  # Would be blocked in browser
            'expected_origin_value': 'http://localhost:5003'  # Server still returns the allowed origin
        },
        {
            'description': 'CORS with preflight handling',
            'endpoint': '/api/data-with-preflight',
            'origin': 'http://localhost:5003',
            'expect_cors_header': True,
            'expect_allowed': True,
            'expected_origin_value': '*'
        },
        {
            'description': 'CORS using Flask-CORS extension',
            'endpoint': '/api/data-with-flask-cors',
            'origin': 'http://localhost:5003',
            'expect_cors_header': True,
            'expect_allowed': True,
            'expected_origin_value': 'http://localhost:5003'  # Flask-CORS reflects the actual origin
        }
    ]
    
    # Run all test cases
    for test_case in test_cases:
        print(f"\nTesting: {test_case['description']}")
        
        # Make the request with the origin header
        response = api_client.get(
            test_case['endpoint'],
            headers={'Origin': test_case['origin']}
        )
        
        # Verify response has expected status code
        assert response.status_code == 200, f"Failed for {test_case['description']}"
        
        # Verify CORS headers
        if test_case['expect_cors_header']:
            assert 'Access-Control-Allow-Origin' in response.headers, \
                f"Missing CORS header for {test_case['description']}"
            
            if 'expected_origin_value' in test_case:
                assert response.headers['Access-Control-Allow-Origin'] == test_case['expected_origin_value'], \
                    f"Wrong origin value for {test_case['description']}"
                
            # For the case where the origin is not allowed
            if not test_case['expect_allowed'] and test_case['origin'] != test_case.get('expected_origin_value'):
                # A real browser would block this response
                assert response.headers['Access-Control-Allow-Origin'] != test_case['origin'], \
                    f"Origin should not be allowed for {test_case['description']}"
        else:
            assert 'Access-Control-Allow-Origin' not in response.headers, \
                f"Should not have CORS header for {test_case['description']}"
        
        # Verify response data
        data = json.loads(response.data)
        assert data['status'] == 'success', f"Response data incorrect for {test_case['description']}"
        assert 'message' in data, f"Response missing message for {test_case['description']}"
        assert 'data' in data, f"Response missing data array for {test_case['description']}" 