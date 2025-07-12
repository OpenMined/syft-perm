"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.18"

__all__ = [
    "open",
    "get_editor_url",
    "start_permission_server",
    "get_files_url",
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

    result = start_server(port, host)
    return str(result)


def get_files_url(limit: int = 50, offset: int = 0, search: _Union[str, None] = None) -> str:
    """
    Get the URL for the files API endpoint.

    Args:
        limit: Number of items per page (default: 50)
        offset: Starting index (default: 0)
        search: Optional search term for file names

    Returns:
        URL to the files API endpoint
    """
    from .server import get_server_url, start_server

    server_url = get_server_url()
    if not server_url:
        server_url = start_server()

    # Build query parameters
    params = f"?limit={limit}&offset={offset}"
    if search:
        params += f"&search={search}"

    return f"{server_url}/files{params}"


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
