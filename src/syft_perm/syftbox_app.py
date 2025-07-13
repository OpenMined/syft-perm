"""
SyftBox app entry point for syft-perm.

This module adapts the existing syft-perm FastAPI server to run as a SyftBox app,
following the patterns established by other SyftBox apps like syft-objects and syft-datasets.
"""

import os
import sys
import threading
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

from loguru import logger


class DiscoveryHandler(BaseHTTPRequestHandler):
    def __init__(self, main_port, *args, **kwargs):
        self.main_port = main_port
        super().__init__(*args, **kwargs)

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
        response = {'main_server_port': self.main_port, 'discovery_port': 62050}
        self.wfile.write(json.dumps(response).encode())
    
    def log_message(self, format, *args):
        pass  # Suppress logging


def start_discovery_server(main_port):
    """Start discovery server on port 62050."""
    try:
        handler = lambda *args, **kwargs: DiscoveryHandler(main_port, *args, **kwargs)
        server = HTTPServer(('0.0.0.0', 62050), handler)
        logger.info("Discovery server started on port 62050")
        server.serve_forever()
    except Exception as e:
        logger.error(f"Failed to start discovery server: {e}")


def main():
    """Main entry point for the SyftBox app."""
    try:
        # Get port from SyftBox environment or use fallback
        port = int(os.getenv("SYFTBOX_ASSIGNED_PORT", os.getenv("SYFTBOX_PORT", 8080)))
        logger.info(f"Starting syft-perm SyftBox app on port {port}")

        # Start discovery server in background thread
        discovery_thread = threading.Thread(target=start_discovery_server, args=(port,), daemon=True)
        discovery_thread.start()

        # Import the existing FastAPI app
        # Start the server using uvicorn
        import uvicorn

        from syft_perm.server import app

        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

    except ImportError as e:
        logger.error(f"Failed to import syft-perm server: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to start syft-perm SyftBox app: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
