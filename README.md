# Flask Authentication Demo

This demo shows how to implement Basic and Digest Authentication in Flask.

## Features

- Basic Authentication implementation with password hashing
- Digest Authentication with nonce-based challenge-response
- Secure password storage using Werkzeug's password hashing
- Decorator-based authentication for route protection
- In-memory nonce management for Digest Authentication
- Type-annotated Python code for better maintainability
- Simple demo endpoints to showcase both auth methods
- Comprehensive test suite with 98% coverage

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
- Welcome page accessibility

## Usage

The demo provides three endpoints:

- `/` - Welcome page (no authentication)
- `/basic` - Protected by Basic Authentication
- `/digest` - Protected by Digest Authentication

Default credentials:
- Username: `admin`
- Password: `secret`

## Authentication Methods

### Basic Authentication
Basic Authentication sends credentials with each request encoded in base64. While simple to implement, it should only be used over HTTPS to prevent credential exposure.

### Digest Authentication
Digest Authentication provides better security by sending a hash of the credentials instead of the credentials themselves. It uses nonces to prevent replay attacks.