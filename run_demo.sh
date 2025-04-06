#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Flask Authentication Concepts Demo ===${NC}"
echo

# Check for required dependencies
check_dependency() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}Error: $1 is required but not installed.${NC}"
        exit 1
    fi
}

check_dependency python3
check_dependency pip

# Check if virtual environment exists, create if not
if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to create virtual environment. Please install python3-venv package.${NC}"
        exit 1
    fi
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
source venv/bin/activate

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to install dependencies.${NC}"
    exit 1
fi

# Check for Redis
echo -e "${YELLOW}Checking Redis availability...${NC}"
if ! command -v redis-cli &> /dev/null || ! redis-cli ping > /dev/null 2>&1; then
    echo -e "${RED}Redis server is not running or not available.${NC}"
    echo -e "${YELLOW}Session functionality will not work properly.${NC}"
    echo -e "${YELLOW}You can start Redis with: docker run -d -p 6379:6379 redis${NC}"
    
    echo
    read -p "Do you want to continue without Redis? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if .env file exists, create from template if not
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creating .env file from template...${NC}"
    echo -e "# Redis (session store)" > .env
    echo -e "REDIS_URL=redis://localhost:6379/0" >> .env
    echo -e "FLASK_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> .env
    echo -e "FLASK_SESSION_SALT=$(python3 -c 'import uuid; print(uuid.uuid4())')" >> .env
    echo -e "FLASK_APP=app.py" >> .env
    echo -e "FLASK_ENV=development" >> .env
    echo -e >> .env
    echo -e "# LDAP Configuration" >> .env
    echo -e "LDAP_SERVER=ldap://localhost:10389" >> .env
    echo -e "LDAP_BASE_DN=dc=example,dc=org" >> .env
    echo -e "LDAP_USER_DN_TEMPLATE=uid={username},ou=users,dc=example,dc=org" >> .env
    echo -e "LDAP_USER_FILTER=(uid={username})" >> .env
    echo -e >> .env
    echo -e "# Auth0 Configuration" >> .env
    echo -e "AUTH0_CLIENT_ID=your_client_id" >> .env
    echo -e "AUTH0_CLIENT_SECRET=your_client_secret" >> .env
    echo -e "AUTH0_DOMAIN=your-tenant.auth0.com" >> .env
    echo -e "AUTH0_CALLBACK_URL=http://127.0.0.1:5001/auth0/callback" >> .env
    
    echo -e "${YELLOW}Created default .env file.${NC}"
    echo -e "${RED}IMPORTANT:${NC} To use Auth0 functionality, edit .env and add your Auth0 credentials."
    echo -e "See auth0_setup_guide.md for instructions on setting up Auth0."
    echo
fi

# Check if LDAP container is running
echo -e "${YELLOW}Checking LDAP container...${NC}"
if ! docker ps | grep -q "osixia/openldap"; then
    echo -e "${YELLOW}LDAP container not running. Starting LDAP demo environment...${NC}"
    ./run_ldap_demo.sh setup
fi

# Start the application
echo -e "${GREEN}Starting Flask application...${NC}"
echo -e "${BLUE}Access the demo at http://127.0.0.1:5001${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo

export FLASK_APP=app.py
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5001 