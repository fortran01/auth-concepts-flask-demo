#!/bin/bash

# Display banner
echo "========================================"
echo "  LDAP Authentication Demo  "
echo "========================================"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running. Please start Docker and try again."
  exit 1
fi

# Start the LDAP server and redis
echo "[1/3] Starting containers (this may take a minute)..."
docker-compose up -d
echo "✅ Containers started"

# Wait for LDAP server to be ready
echo "[2/3] Waiting for LDAP server to initialize..."
for i in {1..10}; do
  echo -n "."
  sleep 2
done
echo -e "\n✅ LDAP server should be ready now"

# Start the Flask app
echo "[3/3] Starting Flask application..."
python app.py 