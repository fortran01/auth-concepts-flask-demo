# Auth0 Universal Login Integration Guide

This guide describes how to set up Auth0 Universal Login for the Flask Auth Demo application, as referenced in section 4.4.2 of the external authentication design document.

## Prerequisites

- A free Auth0 account (sign up at [auth0.com](https://auth0.com))
- This Flask application running locally

## Step 1: Create an Auth0 Account

1. Go to [Auth0's website](https://auth0.com/) and sign up for a free account
2. After signing up, you'll create a tenant - this is your Auth0 domain and will be used in your app

## Step 2: Create a Regular Web Application in Auth0

1. In the Auth0 Dashboard, navigate to **Applications → Applications**
2. Click the **Create Application** button
3. Enter a name for your application (e.g., "Flask Auth Demo")
4. Select **Regular Web Applications** as the application type
5. Click **Create**

## Step 3: Configure Application Settings

1. In your new application settings, note the following values:
   - **Domain** (e.g., `your-tenant.auth0.com`)
   - **Client ID**
   - **Client Secret**

2. Scroll down to the **Application URIs** section and configure:
   - **Allowed Callback URLs**: `http://127.0.0.1:5001/auth0/callback`
   - **Allowed Logout URLs**: `http://127.0.0.1:5001`
   - **Allowed Web Origins**: `http://127.0.0.1:5001`

3. Scroll down and click **Save Changes**

## Step 4: Update Application Environment Variables

1. Open the `.env` file in the root directory of this application
2. Update the Auth0 configuration section with your Auth0 credentials:

```
# Auth0 Configuration
AUTH0_CLIENT_ID=your_client_id
AUTH0_CLIENT_SECRET=your_client_secret
AUTH0_DOMAIN=your-tenant.auth0.com
AUTH0_CALLBACK_URL=http://127.0.0.1:5001/auth0/callback
```

## Step 5: Start the Application

1. Make sure all dependencies are installed:
   ```
   pip install -r requirements.txt
   ```

2. Start the Flask application:
   ```
   flask run
   ```

3. Access the application at http://127.0.0.1:5001

## Step 6: Test the Auth0 Integration

1. On the homepage, click on the **Try Auth0 Login** button
2. You'll be redirected to Auth0's Universal Login page
3. Sign up or log in 
4. After successful authentication, you'll be redirected back to the application profile page

## Understanding the Auth0 OAuth/OIDC Flow

This implementation uses the Authorization Code Flow with PKCE, which is recommended for regular web applications. Here's how it works:

1. **Initiate Login**: When the user clicks "Login with Auth0", the application redirects to Auth0's `/authorize` endpoint
2. **Authentication**: Auth0 displays the Universal Login page, and the user authenticates
3. **Authorization**: After successful authentication, Auth0 redirects back to your application's callback URL with an authorization code
4. **Token Exchange**: Your application exchanges this code for tokens (ID token, access token)
5. **User Information**: The application uses the access token to get user profile information from the `/userinfo` endpoint
6. **Session Management**: The application stores this information in a session for future requests

## Optional: Enabling Social Connections

One of the benefits of using Auth0 is the ability to easily add social login options:

1. In the Auth0 Dashboard, go to **Authentication → Social**
2. Select a provider (e.g., Google, Facebook, GitHub)
3. Configure the provider with the necessary credentials
4. Enable the connection for your application

No changes to your application code are needed - the new social login options will automatically appear on the Auth0 login page.

## Optional: Enterprise Connections

For enterprise authentication (like LDAP, Active Directory, or SAML):

1. In the Auth0 Dashboard, go to **Authentication → Enterprise**
2. Select and configure the appropriate enterprise connection
3. Enable the connection for your application

## Security Considerations

- Keep your Auth0 Client Secret secure and never expose it in client-side code
- Use environment variables for all Auth0 configuration
- For production, enable additional security features in Auth0 like:
  - Brute Force Protection
  - Multi-factor Authentication
  - Contextual MFA based on risk assessments 