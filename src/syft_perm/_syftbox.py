"""SyftBox client integration for syft_perm."""

from typing import Optional

# Global variables for client state
SYFTBOX_AVAILABLE = False
client = None
SyftBoxURL = None

def _initialize_syftbox():
    """Initialize SyftBox client classes if available"""
    global SYFTBOX_AVAILABLE, client, SyftBoxURL
    
    try:
        from syft_core import Client as _SyftBoxClient
        from syft_core.url import SyftBoxURL as _SyftBoxURL
        
        # Try to load the client
        try:
            client = _SyftBoxClient.load()
            SyftBoxURL = _SyftBoxURL
            SYFTBOX_AVAILABLE = True
        except Exception:
            client = None
            SyftBoxURL = None
            SYFTBOX_AVAILABLE = False
            
    except ImportError:
        client = None
        SyftBoxURL = None
        SYFTBOX_AVAILABLE = False

# Initialize SyftBox on module import
_initialize_syftbox() 