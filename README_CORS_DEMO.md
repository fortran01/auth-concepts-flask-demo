# CORS (Cross-Origin Resource Sharing) Demo

This demo illustrates how CORS works in web applications by showing both restricted and allowed cross-origin requests.

## What is CORS?

CORS (Cross-Origin Resource Sharing) is a security mechanism built into web browsers that restricts web pages from making requests to a different domain than the one that served the original web page. It's an extension of the Same-Origin Policy.

## Demo Setup

This demo consists of two Flask applications:

1. **API Server** (api_server.py) - Runs on port 5002
   - Provides various API endpoints with different CORS configurations
   - Demonstrates various ways to enable and configure CORS

2. **Client Application** (client_app.py) - Runs on port 5003
   - Simple web UI that makes requests to the API Server
   - Demonstrates how browsers handle cross-origin requests

## Running the Demo

1. Install the requirements:
   ```
   pip install -r requirements.txt
   ```

2. Start the API Server (in one terminal):
   ```
   python api_server.py
   ```

3. Start the Client Application (in another terminal):
   ```
   python client_app.py
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:5003
   ```

5. Use the buttons on the page to test different CORS scenarios

## Demo Scenarios

The demo covers the following scenarios:

1. **No CORS Headers**
   - Request fails due to Same-Origin Policy
   - Browser blocks the request with CORS error

2. **CORS Enabled for All Origins**
   - API adds `Access-Control-Allow-Origin: *` header
   - Request succeeds for any origin

3. **CORS Enabled for Specific Origin**
   - API adds `Access-Control-Allow-Origin: http://localhost:5003` header
   - Request succeeds only from that specific origin

4. **Complex Request with Preflight**
   - Demonstrates preflight OPTIONS request for non-simple requests
   - API handles OPTIONS request with proper CORS headers

5. **Using Flask-CORS Extension**
   - Shows how to use the Flask-CORS extension for easier CORS configuration

## Learning Points

- CORS is a browser security mechanism (the server always processes the request)
- For cross-origin requests to succeed, the server must explicitly allow them
- Different types of requests may require different CORS configurations
- Non-simple requests trigger an automatic preflight (OPTIONS) request

## Recommended Tools for Inspection

To fully understand what's happening:

1. Open your browser's Developer Tools (F12)
2. Go to the Network tab
3. Watch the requests as you click the demo buttons
4. Inspect the request headers, response headers, and error messages 