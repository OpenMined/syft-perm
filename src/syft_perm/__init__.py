"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Optional as _Optional
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder
from ._public import Files as _Files
from ._public import FilteredFiles as _FilteredFiles
from ._public import files, files_and_folders, folders
from ._public import is_dark as _is_dark
from .fastapi_files import FastAPIFiles as _FastAPIFiles

__version__ = "0.4.0"

__all__ = ["open", "files", "folders", "files_and_folders"]


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
    from ._utils import resolve_path

    # Resolve syft:// URLs to local paths
    resolved_path = resolve_path(path)
    if resolved_path is None:
        raise ValueError(f"Could not resolve path: {path}")

    if not resolved_path.exists():
        raise ValueError(f"Path does not exist: {path} (resolved to: {resolved_path})")

    if resolved_path.is_dir():
        return _SyftFolder(resolved_path)
    return _SyftFile(resolved_path)


def _get_editor_url(path: _Union[str, _Path]) -> str:
    """
    Get the URL for the Google Drive-style permission editor for a file/folder.

    Args:
        path: Path to the file/folder

    Returns:
        URL to the permission editor
    """
    from .server import get_editor_url as _get_editor_url_from_server

    return _get_editor_url_from_server(str(path))


def _get_files_widget_url() -> str:
    """
    Get the URL for the files widget interface (identical to sp.files in Jupyter).

    Returns:
        URL to the files widget
    """
    from .server import get_files_widget_url as _get_files_widget_url_from_server

    return _get_files_widget_url_from_server()


def _get_file_editor_url(path: _Union[str, _Path] = None) -> str:
    """
    Get the URL for the file editor interface.

    Args:
        path: Optional path to open in the editor

    Returns:
        URL to the file editor
    """
    from .server import get_file_editor_url as _get_file_editor_url_from_server

    if path:
        return _get_file_editor_url_from_server(str(path))
    return _get_file_editor_url_from_server()
