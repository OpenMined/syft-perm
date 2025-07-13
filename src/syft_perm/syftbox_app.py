"""
SyftBox app entry point for syft-perm.

This module adapts the existing syft-perm FastAPI server to run as a SyftBox app,
following the patterns established by other SyftBox apps like syft-objects and syft-datasets.
"""

import os
import sys

from loguru import logger


def main():
    """Main entry point for the SyftBox app."""
    try:
        # Get port from SyftBox environment or use fallback
        port = int(os.getenv("SYFTBOX_ASSIGNED_PORT", os.getenv("SYFTBOX_PORT", 8080)))
        logger.info(f"Starting syft-perm SyftBox app on port {port}")

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
