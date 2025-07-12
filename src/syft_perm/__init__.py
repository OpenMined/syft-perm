"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.19"

__all__ = [
    "open",
    "get_editor_url",
    "start_permission_server",
    "get_files_url",
    "files",
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


class Files:
    """
    Access to permissioned files in SyftBox directory.

    Usage:
        import syft_perm as sp

        # Get all files
        all_files = sp.files.all()

        # Get paginated files
        page1 = sp.files.get(limit=10, offset=0)

        # Search files
        test_files = sp.files.search("test")
    """

    def __init__(self):
        self._cache = None

    def get(self, limit: int = 50, offset: int = 0, search: _Union[str, None] = None) -> dict:
        """
        Get paginated list of files with permissions.

        Args:
            limit: Number of items per page (default: 50)
            offset: Starting index (default: 0)
            search: Optional search term for file names

        Returns:
            Dictionary with files, total_count, offset, limit, has_more, syftbox_path
        """
        import requests

        url = get_files_url(limit=limit, offset=offset, search=search)
        response = requests.get(url)
        response.raise_for_status()
        return response.json()

    def all(self, search: _Union[str, None] = None) -> list:
        """
        Get all files with permissions (no pagination).

        Args:
            search: Optional search term for file names

        Returns:
            List of all files with permissions
        """
        all_files = []
        offset = 0
        limit = 100

        while True:
            data = self.get(limit=limit, offset=offset, search=search)
            all_files.extend(data["files"])

            if not data["has_more"]:
                break

            offset += limit

        return all_files

    def search(self, term: str, limit: int = 50, offset: int = 0) -> dict:
        """
        Search for files by name.

        Args:
            term: Search term for file names
            limit: Number of items per page (default: 50)
            offset: Starting index (default: 0)

        Returns:
            Dictionary with search results
        """
        return self.get(limit=limit, offset=offset, search=term)

    def __repr__(self) -> str:
        """String representation showing basic info."""
        try:
            data = self.get(limit=1)
            total = data["total_count"]
            return f"<Files: {total} permissioned files in {data['syftbox_path']}>"
        except Exception:
            return "<Files: Not connected>"

    def _repr_html_(self) -> str:
        """HTML representation for Jupyter notebooks."""
        try:
            # Get first 10 files for preview
            data = self.get(limit=10)
            total = data["total_count"]
            files = data["files"]

            html = f"""
            <div style="font-family: monospace;">
                <h3>📁 SyftBox Files ({total} total)</h3>
                <p style="color: #666;">Path: {data['syftbox_path']}</p>
                <table style="border-collapse: collapse; width: 100%;">
                    <thead>
                        <tr style="border-bottom: 2px solid #ddd;">
                            <th style="text-align: left; padding: 8px;">Name</th>
                            <th style="text-align: left; padding: 8px;">Type</th>
                            <th style="text-align: left; padding: 8px;">Permissions</th>
                        </tr>
                    </thead>
                    <tbody>
            """

            for file in files:
                file_type = "📁 dir" if file["is_dir"] else "📄 file"
                perms = []
                for perm, users in file["permissions"].items():
                    if users:
                        perms.append(f"{perm}: {len(users)}")
                perm_str = ", ".join(perms) if perms else "No permissions"

                html += f"""
                        <tr style="border-bottom: 1px solid #eee;">
                            <td style="padding: 8px;">{file['name']}</td>
                            <td style="padding: 8px;">{file_type}</td>
                            <td style="padding: 8px; color: #666;">{perm_str}</td>
                        </tr>
                """

            if total > 10:
                html += f"""
                        <tr>
                            <td colspan="3" style="padding: 8px; text-align: center; color: #666;">
                                ... and {total - 10} more files
                            </td>
                        </tr>
                """

            html += """
                    </tbody>
                </table>
            </div>
            """

            return html

        except Exception as e:
            return f"<div style='color: red;'>Error loading files: {str(e)}</div>"


# Create singleton instance
files = Files()


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
