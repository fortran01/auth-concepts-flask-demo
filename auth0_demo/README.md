# Auth0 Universal Login Demo

This is a simple Flask application that demonstrates Auth0's Universal Login feature, as referenced in section 4.4.2 of the design document.

## Features

- Auth0 Universal Login integration
- User profile display
- Session management with Flask
- OpenID Connect (OIDC) compliant authentication

## Prerequisites

- Python 3.7 or higher
- An Auth0 account (free tier is sufficient)
- Git (optional, for cloning the repo)

## Setup Auth0

1. **Create an Auth0 Account**:
   - Go to [Auth0's website](https://auth0.com/) and sign up for a free account
   - Create a new tenant (or use the default one)

2. **Create a New Application**:
   - In the Auth0 Dashboard, go to "Applications" → "Applications"
   - Click "Create Application"
   - Name it (e.g., "Flask Demo")
   - Select "Regular Web Applications"
   - Click "Create"

3. **Configure Application Settings**:
   - In your new application settings, note your "Domain", "Client ID", and "Client Secret"
   - Under "Application URIs" configure:
     - Allowed Callback URLs: `http://localhost:3000/callback`
     - Allowed Logout URLs: `http://localhost:3000`
   - Scroll down and click "Save Changes"

## Installation

1. Clone or download this repository
2. Navigate to the project directory
3. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
5. Create a `.env` file:
   ```
   cp .env.example .env
   ```
6. Edit the `.env` file with your Auth0 credentials:
   ```
   AUTH0_CLIENT_ID=your_client_id
   AUTH0_CLIENT_SECRET=your_client_secret
   AUTH0_DOMAIN=your-tenant.auth0.com
   APP_SECRET_KEY=your_secret_key
   ```

## Running the Application

1. With your virtual environment activated, run:
   ```
   python app.py
   ```
2. Open your browser and navigate to `http://localhost:3000`
3. Click the "Login" button to try the Auth0 Universal Login

## Understanding the Flow

1. User clicks "Login" and is redirected to Auth0's Universal Login page
2. User authenticates with Auth0 (using username/password or social providers)
3. Auth0 redirects back to your app with an authorization code
4. Your app exchanges this code for tokens in the callback route
5. The ID token contains user profile information that is displayed on the profile page

## Additional Resources

- [Auth0 Documentation](https://auth0.com/docs)
- [Python SDK for Auth0](https://auth0.com/docs/quickstart/webapp/python) 