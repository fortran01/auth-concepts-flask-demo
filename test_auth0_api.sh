#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
ENV_FILE=".env"
TEST_MODE=false
SHOW_TOKEN=false
API_PATH=""

# Parse command line arguments
for arg in "$@"
do
    case $arg in
        --help)
        echo -e "${BLUE}=== Auth0 M2M API Test ===${NC}"
        echo -e "Usage: $0 [options]"
        echo -e "Options:"
        echo -e "  --help                 Show this help message"
        echo -e "  --env-file FILE        Use specified environment file instead of .env"
        echo -e "  -t, --test             Run in test mode"
        echo -e "  --show-token           Display extracted access token"
        echo -e "  -a, --api PATH         Call specific API path"
        echo -e "\nExample:"
        echo -e "Step 1: Getting access token from Auth0..."
        echo -e "curl --request GET --url \"http://localhost:5001/api/auth0-protected\" --header \"authorization: Bearer TOKEN\""
        exit 0
        ;;
        --env-file=*)
        ENV_FILE="${arg#*=}"
        ;;
        --env-file)
        ENV_FILE="$2"
        shift
        ;;
        -t|--test)
        TEST_MODE=true
        ;;
        --show-token)
        SHOW_TOKEN=true
        ;;
        -a|--api)
        API_PATH="$2"
        shift
        ;;
    esac
    shift
done

# Check if .env file exists
if [ ! -f "$ENV_FILE" ]; then
  echo -e "${RED}Error: $ENV_FILE file not found. Please create it with your Auth0 credentials.${NC}"
  exit 1
fi

# Extract environment variables from .env file
source <(grep -v '^#' "$ENV_FILE" | sed -E 's/(.*)=(.*)/export \1="\2"/')

# Check if required environment variables are set
if [ -z "$AUTH0_DOMAIN" ] || [ -z "$AUTH0_M2M_CLIENT_ID" ] || [ -z "$AUTH0_M2M_CLIENT_SECRET" ] || [ -z "$AUTH0_API_AUDIENCE" ]; then
  echo -e "${RED}Error: Missing required environment variables in $ENV_FILE file.${NC}"
  echo -e "Please ensure the following variables are set:"
  echo -e "  AUTH0_DOMAIN"
  echo -e "  AUTH0_M2M_CLIENT_ID"
  echo -e "  AUTH0_M2M_CLIENT_SECRET"
  echo -e "  AUTH0_API_AUDIENCE"
  exit 1
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
  echo -e "${YELLOW}Warning: jq is not installed.${NC}"
  echo -e "To install jq on macOS, run: brew install jq"
  echo -e "To install jq on Ubuntu, run: sudo apt-get install jq"
  echo -e "${YELLOW}Proceeding without pretty-printing...${NC}"
  JQ_AVAILABLE=false
else
  JQ_AVAILABLE=true
fi

# Function to pretty print JSON if jq is available
pretty_print() {
  if [ "$JQ_AVAILABLE" = true ]; then
    echo "$1" | jq
  else
    echo "$1"
  fi
}

# Print the environment values if not in test mode
if [ "$TEST_MODE" = false ]; then
  echo -e "${BLUE}=== Auth0 M2M API Test ===${NC}"
  echo -e "Domain: $AUTH0_DOMAIN"
  echo -e "Audience: $AUTH0_API_AUDIENCE"
  echo -e "Client ID: $AUTH0_M2M_CLIENT_ID"
  echo -e "${BLUE}=========================${NC}"
fi

# Step 1: Get an access token from Auth0
echo -e "\n${YELLOW}Step 1: Getting access token from Auth0...${NC}"

TOKEN_RESPONSE=$(curl --silent --request POST \
  --url "https://$AUTH0_DOMAIN/oauth/token" \
  --header "content-type: application/json" \
  --data '{
    "client_id": "'"$AUTH0_M2M_CLIENT_ID"'",
    "client_secret": "'"$AUTH0_M2M_CLIENT_SECRET"'",
    "audience": "'"$AUTH0_API_AUDIENCE"'",
    "grant_type": "client_credentials"
}')

# Check if token request was successful
if [[ $TOKEN_RESPONSE == *"error"* ]]; then
  echo -e "${RED}Error getting access token:${NC}"
  pretty_print "$TOKEN_RESPONSE"
  exit 1
fi

echo -e "${GREEN}Successfully obtained access token:${NC}"
pretty_print "$TOKEN_RESPONSE"

# Extract the access token
if [ "$JQ_AVAILABLE" = true ]; then
  ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | jq -r .access_token)
else
  # Simple extraction without jq (might be fragile)
  ACCESS_TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*' | sed 's/"access_token":"//g')
fi

if [ -z "$ACCESS_TOKEN" ]; then
  echo -e "${RED}Failed to extract access token.${NC}"
  exit 1
fi

# Show token if requested
if [ "$SHOW_TOKEN" = true ]; then
  echo -e "${GREEN}Extracted token: $ACCESS_TOKEN${NC}"
fi

# Step 2: Call the protected API if not in test mode
if [ "$TEST_MODE" = false ]; then
  echo -e "\n${YELLOW}Step 2: Calling protected API...${NC}"

  # Determine the API URL (adjust as needed based on your setup)
  if [ -z "$API_PATH" ]; then
    API_PATH="/api/auth0-protected"
  fi
  API_URL="http://localhost:5001$API_PATH"

  API_RESPONSE=$(curl --silent --request GET \
    --url "$API_URL" \
    --header "authorization: Bearer $ACCESS_TOKEN")

  echo -e "${GREEN}API Response:${NC}"
  pretty_print "$API_RESPONSE"

  echo -e "\n${BLUE}Test complete!${NC}"
  echo -e "You can also use this token to manually test the API:"
  echo -e "${YELLOW}curl --request GET \\
    --url \"$API_URL\" \\
    --header \"authorization: Bearer $ACCESS_TOKEN\"${NC}"
fi

exit 0 