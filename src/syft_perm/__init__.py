"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.31"

__all__ = [
    "open",
    "get_editor_url",
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

    def _scan_files(self, search: _Union[str, None] = None) -> list:
        """Scan SyftBox directory for files with permissions."""
        import os
        from pathlib import Path

        # Try to find SyftBox directory
        syftbox_dirs = [
            Path.home() / "SyftBox",
            Path.home() / ".syftbox",
            Path("/tmp/SyftBox"),
        ]

        syftbox_path = None
        for path in syftbox_dirs:
            if path.exists():
                syftbox_path = path
                break

        if not syftbox_path:
            return []

        # Only scan datasites directory
        datasites_path = syftbox_path / "datasites"
        if not datasites_path.exists():
            return []

        files = []

        # Walk through datasites directory structure
        for root, dirs, file_names in os.walk(datasites_path):
            root_path = Path(root)

            # Skip hidden directories and .git directories
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            for file_name in file_names:
                # Skip hidden files and syft.pub.yaml files
                if file_name.startswith(".") or file_name == "syft.pub.yaml":
                    continue

                file_path = root_path / file_name
                relative_path = file_path.relative_to(datasites_path)

                # Apply search filter
                if search and search.lower() not in str(relative_path).lower():
                    continue

                # Get permissions for this file
                try:
                    from ._impl import SyftFile

                    syft_file = SyftFile(file_path)
                    permissions = syft_file.permissions_dict
                except Exception:
                    permissions = {}

                files.append(
                    {
                        "name": str(relative_path),
                        "path": str(file_path),
                        "is_dir": False,
                        "permissions": permissions,
                        "size": file_path.stat().st_size if file_path.exists() else 0,
                        "modified": file_path.stat().st_mtime if file_path.exists() else 0,
                    }
                )

        # Sort by name
        files.sort(key=lambda x: x["name"])
        return files

    def get(self, limit: int = 50, offset: int = 0, search: _Union[str, None] = None) -> dict:
        """
        Get paginated list of files with permissions.

        Args:
            limit: Number of items per page (default: 50)
            offset: Starting index (default: 0)
            search: Optional search term for file names

        Returns:
            Dictionary with files, total_count, offset, limit, has_more
        """
        all_files = self._scan_files(search)
        total_count = len(all_files)

        # Apply pagination
        end = offset + limit
        page_files = all_files[offset:end]
        has_more = end < total_count

        return {
            "files": page_files,
            "total_count": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
        }

    def all(self, search: _Union[str, None] = None) -> list:
        """
        Get all files with permissions (no pagination).

        Args:
            search: Optional search term for file names

        Returns:
            List of all files with permissions
        """
        return self._scan_files(search)

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
        """Static string representation."""
        return "<Files: SyftBox permissioned files interface>"

    def _repr_html_(self) -> str:
        """Simple HTML representation for Jupyter notebooks."""
        return "<div>SyftBox Files - use sp.files.all() for full interface</div>"


# Create singleton instance
files = Files()


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
