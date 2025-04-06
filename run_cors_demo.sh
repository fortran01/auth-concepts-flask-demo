#!/bin/bash

echo "Starting CORS Demo - API Server & Client"
echo "---------------------------------------"
echo ""
echo "This will start both the API server and client application"
echo "needed for the CORS demo in separate terminal windows."
echo ""

# Check if the terminal supports multiple tabs/windows
if [ "$(uname)" == "Darwin" ]; then
    # macOS
    echo "Starting API Server on port 5002..."
    osascript -e 'tell application "Terminal" to do script "cd '"'$PWD'"' && python api_server.py"' > /dev/null 2>&1
    
    echo "Starting Client Application on port 5003..."
    osascript -e 'tell application "Terminal" to do script "cd '"'$PWD'"' && python client_app.py"' > /dev/null 2>&1
    
    echo "Both servers started in separate Terminal windows!"
else
    # Linux/other Unix-like systems
    if command -v gnome-terminal &> /dev/null; then
        echo "Starting API Server on port 5002..."
        gnome-terminal -- bash -c "cd \"$PWD\" && python api_server.py; exec bash" > /dev/null 2>&1
        
        echo "Starting Client Application on port 5003..."
        gnome-terminal -- bash -c "cd \"$PWD\" && python client_app.py; exec bash" > /dev/null 2>&1
        
        echo "Both servers started in separate Terminal windows!"
    else
        echo "Could not detect a supported terminal."
        echo "Please run the servers manually in separate terminals:"
        echo ""
        echo "Terminal 1: python api_server.py"
        echo "Terminal 2: python client_app.py"
    fi
fi

echo ""
echo "Once both servers are running, visit: http://localhost:5003"
echo ""
echo "Press Ctrl+C to stop this script (servers will continue running in their windows)" 