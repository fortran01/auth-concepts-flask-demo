#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Auth0 Universal Login Demo ===${NC}"
echo -e "${YELLOW}Setting up the environment...${NC}"

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

# Check if requirements are installed
echo -e "${YELLOW}Installing dependencies...${NC}"
pip install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}Failed to install dependencies.${NC}"
    exit 1
fi

# Check if .env file exists, create from example if not
if [ ! -f ".env" ]; then
    echo -e "${YELLOW}Creating .env file from example...${NC}"
    cp .env.example .env
    echo -e "${YELLOW}Please edit the .env file with your Auth0 credentials.${NC}"
    echo -e "${RED}Important: You need to set up an Auth0 account and application.${NC}"
    echo -e "${YELLOW}See README.md for detailed instructions.${NC}"
fi

# Run the application
echo -e "${GREEN}Starting Auth0 Demo application...${NC}"
echo -e "${BLUE}Access it at http://localhost:3000${NC}"
python app.py 