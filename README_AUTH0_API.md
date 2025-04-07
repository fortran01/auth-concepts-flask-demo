# Auth0 API Authentication Demo

This document provides instructions for setting up the Auth0 API authentication demo (Demo 4) from the external authentication plan.

## Overview

This demo shows how to:
1. Set up an API in Auth0
2. Configure the audience and scopes
3. Obtain an access token from Auth0 (via both user-centric and machine-to-machine flows)
4. Validate tokens for API access

## Auth0 Setup Instructions

### 1. Create an API in Auth0

1. Log in to your [Auth0 Dashboard](https://manage.auth0.com/)
2. Navigate to **APIs** in the sidebar
3. Click **Create API**
4. Fill in the following details:
   - **Name**: `Auth Concepts API Demo`
   - **Identifier (audience)**: `https://api.example.com` (or your own URI)
   - **Signing Algorithm**: `RS256` (recommended)
5. Click **Create**

### 2. Define API Permissions (Optional)

1. In your new API settings, go to the **Permissions** tab
2. Add permissions like:
   - `read:data`
   - `write:data`
3. These will be available as scopes when requesting tokens

### 3. Configure the Regular Web Application

1. Go to **Applications** in the sidebar
2. Select your existing application or create a new one (Regular Web Application)
3. Ensure the application type is set to **Regular Web Application**
4. In the **Application URIs** section, add:
   - **Allowed Callback URLs**: `http://localhost:5001/auth0/callback,http://localhost:5001/auth0/token-callback`
   - **Allowed Logout URLs**: `http://localhost:5001/`
5. In the application settings, note your **Client ID** and **Client Secret**
6. Save changes

### 4. Create a Machine-to-Machine Application

1. Go to **Applications** in the sidebar
2. Click **Create Application**
3. Name it (e.g., "Auth Concepts M2M Client")
4. Select **Machine to Machine Applications** as the application type
5. Click **Create**
6. Select the API you created earlier (Auth Concepts API Demo)
7. Select the permissions (`read:data`, `write:data`) you want to grant to this application
8. Click **Authorize**
9. In the application settings, note your **Client ID** and **Client Secret**
10. Save changes

### 5. Update Environment Variables

Update your `.env` file with the following values:

```
# Auth0 Configuration (Regular Web App)
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_CALLBACK_URL=http://localhost:5001/auth0/callback

# Auth0 API Configuration
AUTH0_API_AUDIENCE=https://api.example.com

# Auth0 Machine-to-Machine Client (for API access)
AUTH0_M2M_CLIENT_ID=your-m2m-client-id
AUTH0_M2M_CLIENT_SECRET=your-m2m-client-secret
```

## Testing the Demo

1. Start the Flask application
2. Visit `http://localhost:5001/` and click on "Try Auth0 API Demo"
3. You can choose between two authentication flows:
   - **User Authentication Flow**: Redirects to Auth0 login, produces a token with user context
   - **Machine-to-Machine Flow**: Uses client credentials to get a token without user interaction
4. Use the token to call the protected API endpoint

## Testing with curl

You can also test the M2M flow directly from your terminal using curl commands.

### Using the Test Script

For convenience, you can use the included test script to quickly test the machine-to-machine flow:

```bash
# Make the script executable (if needed)
chmod +x test_auth0_api.sh

# Run the test
./test_auth0_api.sh
```

The script will:
1. Read your Auth0 credentials from the `.env` file
2. Request an access token from Auth0
3. Call the protected API endpoint with the token
4. Display the results in a formatted way

### Manual Testing with curl

If you prefer to test manually, you can use the following curl commands:

#### 1. Getting an Access Token

```bash
curl --request POST \
  --url "https://your-domain.auth0.com/oauth/token" \
  --header "content-type: application/json" \
  --data '{
    "client_id": "your-m2m-client-id",
    "client_secret": "your-m2m-client-secret",
    "audience": "https://api.example.com",
    "grant_type": "client_credentials"
}'
```

This will return a JSON response with your access token:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvbWVrZXkifQ...",
  "expires_in": 86400,
  "token_type": "Bearer"
}
```

#### 2. Calling the Protected API

```bash
curl --request GET \
  --url "http://localhost:5001/api/auth0-protected" \
  --header "authorization: Bearer YOUR_ACCESS_TOKEN"
```

Replace `YOUR_ACCESS_TOKEN` with the token from the previous step.

#### One-liner for Testing

To get a token and immediately use it to call the API in one command:

```bash
TOKEN=$(curl --silent --request POST \
  --url "https://your-domain.auth0.com/oauth/token" \
  --header "content-type: application/json" \
  --data '{
    "client_id": "your-m2m-client-id",
    "client_secret": "your-m2m-client-secret", 
    "audience": "https://api.example.com",
    "grant_type": "client_credentials"
}' | jq -r .access_token) && \
curl --request GET \
  --url "http://localhost:5001/api/auth0-protected" \
  --header "authorization: Bearer $TOKEN"
```

Note: This requires the `jq` command to be installed.

## How It Works

### User Authentication Flow
1. User initiates the authorization code flow by clicking "Get User Token"
2. User authenticates with Auth0 through the Universal Login page
3. Auth0 redirects back with an authorization code
4. Your application exchanges the code for tokens (access, ID, refresh)
5. The access token is used to call the API

### Machine-to-Machine Flow
1. Your application makes a direct request to Auth0's token endpoint
2. The request includes client ID, client secret, audience, and grant type
3. Auth0 validates the credentials and returns an access token
4. The access token is used to call the API

### API Protection
1. The API receives a request with a Bearer token
2. It validates the token signature using Auth0's JWKS endpoint
3. It checks the token's audience, issuer, and expiration
4. If valid, it processes the request and returns a response

## Security Considerations

- Always validate tokens on the server-side
- Verify the token's signature, issuer, audience, and expiration
- Use HTTPS in production to protect tokens in transit
- Set appropriate token expiration times
- Define and enforce proper scopes for API actions
- Keep client secrets secured and never expose them in client-side code 