"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile, SyftFolder as _SyftFolder

__version__ = "0.2.24"

__all__ = [
    "open",
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