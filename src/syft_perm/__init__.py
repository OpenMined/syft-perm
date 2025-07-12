"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile, SyftFolder as _SyftFolder

__version__ = "0.2.30"

__all__ = [
    "open",
    "get_editor_url",
    "start_permission_server",
]

def open(path: _Union[str, _Path]) -> _Union[_SyftFile, _SyftFolder]:
    """
    Open a file or folder with SyftBox permissions.
    
    Args:
        path: Path to the file/folder (local path or syft:// URL)
    
    Returns:
        SyftFile or SyftFolder object
        
    Raises:
        ValueError: If path cannot be resolved or doesn't exist
    """
    resolved_path = _Path(path)
    if not resolved_path.exists():
        raise ValueError(f"Path does not exist: {path}")
        
    if resolved_path.is_dir():
        return _SyftFolder(path)
    return _SyftFile(path)


def get_editor_url(path: _Union[str, _Path]) -> str:
    """
    Get the URL for the Google Drive-style permission editor for a file/folder.
    
    Args:
        path: Path to the file/folder
        
    Returns:
        URL to the permission editor
    """
    from .server import get_editor_url as _get_editor_url
    return _get_editor_url(str(path))


def start_permission_server(port: int = 8765, host: str = "127.0.0.1") -> str:
    """
    Start the permission editor server.
    
    Args:
        port: Port to run the server on
        host: Host to bind to
        
    Returns:
        Server URL
    """
    from .server import start_server
    return start_server(port, host)


# Auto-start the permission server when the library is imported
try:
    from .server import start_server as _start_server
    _server_url = _start_server()
    print(f"🚀 SyftPerm permission editor started at: {_server_url}")
    print(f"   Use syft_perm.get_editor_url('/path/to/file') to get the editor URL for any file")
except ImportError:
    # FastAPI not available, skip auto-start
    print("⚠️  FastAPI not available. Install with: pip install 'syft-perm[server]' for permission editor")
except Exception as e:
    # Server failed to start, continue silently
    print(f"⚠️  Permission editor server failed to start: {e}")
    print("   You can try manually with: syft_perm.start_permission_server()")
    pass 