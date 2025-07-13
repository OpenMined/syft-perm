#!/bin/bash
set -e

# SyftBox app runner for syft-perm
# This script is executed by SyftBox when the app is deployed

echo "Starting syft-perm SyftBox app..."

# Get assigned port from SyftBox or use default
SYFTBOX_ASSIGNED_PORT=${SYFTBOX_ASSIGNED_PORT:-8005}
echo "Using port: $SYFTBOX_ASSIGNED_PORT"

# Save port to config file for discovery
CONFIG_DIR="$HOME/.syftperm"
mkdir -p "$CONFIG_DIR"
echo "{\"port\": $SYFTBOX_ASSIGNED_PORT}" > "$CONFIG_DIR/config.json"
echo "Saved port configuration to $CONFIG_DIR/config.json"

# Environment setup for clean installation
export ZSH_DISABLE_COMPFIX=true
export NONINTERACTIVE=1

# Create fresh virtual environment with UV
echo "Setting up Python environment..."
rm -rf .venv
uv venv --python 3.12
export VIRTUAL_ENV="$(pwd)/.venv"
export PATH="$VIRTUAL_ENV/bin:$PATH"

# Install dependencies
echo "Installing dependencies..."
uv sync

# Use fixed discovery port for debugging
DISCOVERY_PORT=62050
echo "Using discovery port: $DISCOVERY_PORT"

# Start discovery server in background
echo "Starting discovery server on port $DISCOVERY_PORT..."
uv run python -c "
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class DiscoveryHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.end_headers()
        response = {'main_server_port': $SYFTBOX_ASSIGNED_PORT, 'discovery_port': $DISCOVERY_PORT}
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress logging

server = HTTPServer(('0.0.0.0', $DISCOVERY_PORT), DiscoveryHandler)
server.serve_forever()
" &

DISCOVERY_PID=$!
echo "Discovery server started with PID $DISCOVERY_PID"

# Launch the syft-perm app server with auto-reload
echo "Launching syft-perm server on port $SYFTBOX_ASSIGNED_PORT with auto-reload..."
export SYFTBOX_PORT=$SYFTBOX_ASSIGNED_PORT
export DISCOVERY_PORT=$DISCOVERY_PORT
uv run uvicorn syft_perm.server:app --host 0.0.0.0 --port $SYFTBOX_ASSIGNED_PORT --reload
