#!/usr/bin/env python3
"""
Manual test script for Auth0 integration.

This script helps manually verify the Auth0 integration by printing diagnostic
information and guiding the tester through the login flow.

Usage:
    python manual_test_auth0.py

Requirements:
    - Auth0 account configured with a web application
    - .env file with proper Auth0 credentials
"""

import os
import sys
import webbrowser
from dotenv import load_dotenv
import requests

# Add parent directory to path so we can import app
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Load environment variables
load_dotenv()

# Check if Auth0 credentials are set
auth0_client_id = os.environ.get('AUTH0_CLIENT_ID')
auth0_client_secret = os.environ.get('AUTH0_CLIENT_SECRET')
auth0_domain = os.environ.get('AUTH0_DOMAIN')
auth0_callback_url = os.environ.get('AUTH0_CALLBACK_URL')

# Print diagnostic information
print("\n=== Auth0 Integration Manual Test ===\n")
print("Checking Auth0 configuration...")

if not auth0_client_id or auth0_client_id == 'your_client_id':
    print("❌ AUTH0_CLIENT_ID is not set or is using placeholder value")
    print("   Please set a valid Auth0 Client ID in your .env file")
else:
    print(f"✅ AUTH0_CLIENT_ID: {auth0_client_id[:5]}...{auth0_client_id[-5:]}")

if not auth0_client_secret or auth0_client_secret == 'your_client_secret':
    print("❌ AUTH0_CLIENT_SECRET is not set or is using placeholder value")
    print("   Please set a valid Auth0 Client Secret in your .env file")
else:
    secret_prefix = auth0_client_secret[:5]
    secret_suffix = auth0_client_secret[-5:]
    print(f"✅ AUTH0_CLIENT_SECRET: {secret_prefix}...{secret_suffix}")

if not auth0_domain or auth0_domain == 'your-tenant.auth0.com':
    print("❌ AUTH0_DOMAIN is not set or is using placeholder value")
    print("   Please set a valid Auth0 Domain in your .env file")
else:
    print(f"✅ AUTH0_DOMAIN: {auth0_domain}")

if not auth0_callback_url:
    valid_url = False
else:
    has_localhost = 'localhost' in auth0_callback_url
    has_local_ip = '127.0.0.1' in auth0_callback_url
    valid_url = has_localhost or has_local_ip

if not valid_url:
    print("❌ AUTH0_CALLBACK_URL is not set or doesn't contain")
    print("   'localhost' or '127.0.0.1'")
    print("   Please set a valid callback URL in your .env file")
else:
    print(f"✅ AUTH0_CALLBACK_URL: {auth0_callback_url}")

# Check if we can reach the Auth0 domain
print("\nVerifying connectivity to Auth0...")
try:
    openid_config_url = f"https://{auth0_domain}/.well-known/openid-configuration"
    response = requests.get(openid_config_url)
    if response.status_code == 200:
        print(f"✅ Successfully connected to Auth0 domain: {auth0_domain}")
        
        # Print some metadata from the configuration
        config = response.json()
        print(f"   - Authorization endpoint: {config.get('authorization_endpoint')}")
        print(f"   - Token endpoint: {config.get('token_endpoint')}")
        print(f"   - Userinfo endpoint: {config.get('userinfo_endpoint')}")
    else:
        print(f"❌ Failed to connect to Auth0 domain: {auth0_domain}")
        print(f"   Status code: {response.status_code}")
except Exception as e:
    print(f"❌ Error connecting to Auth0 domain: {str(e)}")

# Verification steps for the tester
print("\n=== Manual Verification Steps ===\n")
print("1. Start the Flask application:")
print("   ./run_demo.sh")
print("\n2. Navigate to the Auth0 Demo page:")
print("   http://127.0.0.1:5001/auth0-demo")
print("\n3. Click 'Login with Auth0' and authenticate")
print("\n4. After logging in, you should be redirected to your profile page")
print("   Verify that your user information is displayed correctly")
print("\n5. Click 'Logout' and verify you're logged out")
print("   Try accessing the profile page directly and confirm you're redirected")

# Offer to open the application in a browser
print("\nWould you like to open the Auth0 demo page in your browser? (y/n)")
choice = input().strip().lower()
if choice == 'y':
    url = "http://127.0.0.1:5001/auth0-demo"
    print(f"Opening {url} in your browser...")
    webbrowser.open(url)
    print("If the page doesn't load, make sure the app is running.")

print("\nManual test guide completed.")


if __name__ == "__main__":
    pass 