"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path
from typing import Union, Optional

from ._impl import SyftFile, SyftFolder
from ._utils import SYFTBOX_AVAILABLE

__version__ = "0.2.12"

__all__ = [
    "open",
    "SyftFile",
    "SyftFolder",
    "SYFTBOX_AVAILABLE",
]

def open(path: Union[str, Path]) -> Union[SyftFile, SyftFolder]:
    """
    Open a file or folder with SyftBox permissions.
    
    Args:
        path: Path to the file/folder (local path or syft:// URL)
    
    Returns:
        SyftFile or SyftFolder object
        
    Raises:
        ValueError: If path cannot be resolved or doesn't exist
    """
    resolved_path = Path(path)
    if not resolved_path.exists():
        raise ValueError(f"Path does not exist: {path}")
        
    if resolved_path.is_dir():
        return SyftFolder(path)
    return SyftFile(path) 