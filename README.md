# Flask Authentication Demo

This demo shows how to implement Basic and Digest Authentication in Flask.

## Features

- Basic Authentication implementation with password hashing
- Digest Authentication with nonce-based challenge-response
- Form-based Authentication with session management
- Token-based Authentication using JWT
- Multi-Factor Authentication (MFA) using TOTP
- Secure password storage using Werkzeug's password hashing
- Decorator-based authentication for route protection
- In-memory nonce management for Digest Authentication
- Type-annotated Python code for better maintainability
- Simple demo endpoints to showcase all auth methods
- Modern responsive UI with Bootstrap 5
- Persistent navigation bar with login state
- Clean and user-friendly login interface
- Flash messages for user feedback
- Built-in TOTP code generator for demo purposes
- Comprehensive test suite with 96% coverage

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

The application will start on http://localhost:5001

## Testing

Run the test suite with coverage report:
```bash
pytest
```

The tests verify:
- Basic Authentication functionality
  - No credentials
  - Invalid credentials
  - Valid credentials
- Digest Authentication functionality
  - No credentials
  - Invalid nonce
  - Valid credentials with proper nonce
- Token Authentication functionality
  - Token generation
  - Protected endpoint access
  - Token validation and expiration
- Form-based Authentication
  - Login/logout flow
  - Session management
  - Protected page access
- Welcome page accessibility

## Usage

The demo provides these endpoints:

- `/` - Welcome page (no authentication)
- `/basic` - Protected by Basic Authentication
- `/digest` - Protected by Digest Authentication
- `/form` - Protected by Form-based Authentication with session management
- `/login` - Login page for form-based authentication
- `/logout` - Logout endpoint for form-based authentication
- `/setup-mfa` - Setup Multi-Factor Authentication
- `/verify-mfa` - Verify MFA code
- `/api/token` - Get JWT token using Basic Authentication
- `/api/protected` - Protected endpoint requiring JWT token

Default credentials:
- Username: `admin`
- Password: `secret`

### Multi-Factor Authentication

The demo includes a simplified MFA implementation using Time-based One-Time Passwords (TOTP). For demonstration purposes, the app includes its own TOTP code generator, but in a real application, you would use an authenticator app like Google Authenticator or Authy.

To set up MFA:
1. Log in to the application
2. Visit the protected page
3. Click "Setup MFA"
4. You'll see your secret key and a demo TOTP generator
5. Enter the current 6-digit code to verify and enable MFA

Once MFA is enabled:
1. Login requires both password and current TOTP code
2. The demo TOTP generator can be used to generate valid codes
3. Protected pages require MFA verification

Note: In a production environment, you would:
- Use QR codes for secret sharing
- Store MFA secrets securely
- Implement backup codes
- Add MFA recovery options

### Testing Token Authentication

You can test the token-based authentication using curl:

1. Get a token using Basic Authentication:
```bash
curl -X POST http://localhost:5001/api/token -u admin:secret
```
Response:
```json
{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

2. Access protected endpoint using the token:
```bash
curl http://localhost:5001/api/protected \
    -H "Authorization: Bearer YOUR_TOKEN_HERE"
```
Response:
```json
{
    "message": "Hello admin! This endpoint is protected by JWT.",
    "expires": "2024-03-21T15:30:00"
}
```

3. Test with invalid token:
```bash
curl http://localhost:5001/api/protected \
    -H "Authorization: Bearer invalid.token.here"
```
Response:
```json
{
    "error": "Invalid or expired token"
}
```

### Testing Multi-Factor Authentication

The demo includes a built-in TOTP code generator for testing purposes. Here's how to test the MFA feature:

1. Initial Setup:
   ```
   Username: admin
   Password: secret
   ```
   - After logging in, you'll see a "Setup MFA" button on the protected page
   - Click "Setup MFA" to start the MFA setup process
   - You'll see your MFA secret key and a built-in TOTP generator
   - Use the generated code to complete the setup

2. Logging in with MFA:
   - Once MFA is enabled, the login page will require a TOTP code
   - The login page includes the same TOTP generator for convenience
   - Enter your username, password, and the current TOTP code
   - The code updates every 30 seconds

3. Testing different scenarios:
   - Try logging in without a TOTP code
   - Try an invalid TOTP code
   - Try accessing protected pages without MFA verification
   - Use an expired TOTP code (wait 30 seconds)
   - Log out and verify the TOTP generator appears on the login page

Note: In a real application, you would use an authenticator app like Google Authenticator or Authy instead of the built-in generator. The demo includes the generator on both the setup and login pages to make testing easier without requiring external apps.

## Authentication Methods

### Basic Authentication

Basic Authentication sends credentials with each request encoded in base64. While simple to implement, it should only be used over HTTPS to prevent credential exposure.

### Digest Authentication

Digest Authentication provides better security by sending a hash of the credentials instead of the credentials themselves. It uses nonces to prevent replay attacks.

### Form-based Authentication

Form-based Authentication provides a user-friendly login interface that matches the application's design. It uses session management to maintain user state and provides feedback through flash messages. This method is ideal for web applications where user experience is a priority.

### Token-based Authentication

Token-based Authentication uses JSON Web Tokens (JWT) for stateless authentication. Upon successful login, the server issues a signed JWT containing user information and claims. This token is then included in the Authorization header of subsequent requests using the Bearer scheme. Benefits include:

- Stateless authentication requiring no server-side session storage
- Built-in expiration and claim verification
- Cross-domain/CORS support
- Suitable for both web applications and APIs
- Efficient scaling in distributed systems

Key features of the JWT implementation:
- Tokens expire after 1 hour
- Uses HS256 (HMAC with SHA-256) for signing
- Includes username and expiration claims
- Requires Bearer token scheme in Authorization header