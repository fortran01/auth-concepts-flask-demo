from flask import Flask, jsonify, request
from flask_cors import CORS
import os

app = Flask(__name__)
app.debug = True
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-key-for-cors-demo')

# By default, no CORS headers are set
# We'll enable/configure them through routes to demonstrate CORS behavior

@app.route('/api/data')
def get_data():
    """
    API endpoint without CORS headers
    This will be blocked by browsers when called from different origins
    """
    return jsonify({
        'message': 'This is data from the API server',
        'status': 'success',
        'data': [1, 2, 3, 4, 5]
    })

@app.route('/api/data-with-cors')
def get_data_with_cors():
    """
    API endpoint with CORS headers allowing all origins
    This will work when called from any origin
    """
    response = jsonify({
        'message': 'This is data from the API server (with CORS enabled)',
        'status': 'success',
        'data': [1, 2, 3, 4, 5]
    })
    
    # Add CORS headers manually
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

@app.route('/api/data-with-specific-cors')
def get_data_with_specific_cors():
    """
    API endpoint with CORS headers allowing only a specific origin
    Will only work when called from that specific origin
    """
    response = jsonify({
        'message': 'This is data from the API server (with specific CORS)',
        'status': 'success',
        'data': [1, 2, 3, 4, 5]
    })
    
    # Only allow requests from the client app
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:5003')
    return response

@app.route('/api/data-with-preflight', methods=['GET', 'OPTIONS'])
def get_data_with_preflight():
    """
    API endpoint that handles preflight requests
    Necessary for complex requests (non-simple requests)
    """
    if request.method == 'OPTIONS':
        # Handle the preflight request
        response = app.make_default_options_response()
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Methods', 'GET, POST')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Max-Age', '3600')
        return response
    
    # Handle the actual request
    response = jsonify({
        'message': 'This is data from the API server (with preflight handling)',
        'status': 'success',
        'data': [1, 2, 3, 4, 5]
    })
    
    # Add CORS headers to the actual response too
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response

# Create a route with CORS enabled using the flask-cors extension
cors_enabled_route = CORS(app, resources={r"/api/data-with-flask-cors": {"origins": "*"}})

@app.route('/api/data-with-flask-cors')
def get_data_with_flask_cors():
    """
    API endpoint with CORS enabled using the flask-cors extension
    """
    return jsonify({
        'message': 'This is data from the API server (using flask-cors)',
        'status': 'success',
        'data': [1, 2, 3, 4, 5]
    })

if __name__ == '__main__':
    # Run the API server on port 5002
    app.run(host='0.0.0.0', port=5002) 