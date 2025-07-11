"""
SyftBox File Permission Utilities

Minimal utilities for reading, setting, and removing permissions for individual files and folders in SyftBox.
"""

import yaml
from pathlib import Path
from typing import Optional, List, Dict, Any, Union, Literal

# Try to import SyftBox client for proper file management
try:
    from syft_core import Client as SyftBoxClient
    from syft_core.url import SyftBoxURL
    SYFTBOX_AVAILABLE = True
except ImportError:
    SyftBoxClient = None
    SyftBoxURL = None
    SYFTBOX_AVAILABLE = False

__version__ = "0.1.0"

def _get_syftbox_client() -> Optional[SyftBoxClient]:
    """Get SyftBox client if available, otherwise return None"""
    if not SYFTBOX_AVAILABLE:
        return None
    try:
        return SyftBoxClient.load()
    except Exception:
        return None


def _extract_local_path_from_syft_url(syft_url: str) -> Optional[Path]:
    """Extract local path from a syft:// URL if it points to a local SyftBox path"""
    if not SYFTBOX_AVAILABLE:
        return None
    
    try:
        client = SyftBoxClient.load()
        syft_url_obj = SyftBoxURL(syft_url)
        return syft_url_obj.to_local_path(datasites_path=client.datasites)
    except Exception:
        return None


def set_file_permissions(
    file_path_or_syfturl: str,
    read_users: List[str],
    write_users: List[str] = None,
    admin_users: List[str] = None,
) -> None:
    """
    Set permissions for a file (local path or syft:// URL) by updating syft.pub.yaml.
    
    Args:
        file_path_or_syfturl: Local file path or syft:// URL
        read_users: List of users who can read the file
        write_users: List of users who can write the file
        admin_users: List of users who have admin access (defaults to write_users)
    """
    if write_users is None:
        write_users = []
    if admin_users is None:
        admin_users = write_users

    # Resolve to local path if syft://
    if isinstance(file_path_or_syfturl, str) and file_path_or_syfturl.startswith("syft://"):
        file_path = _extract_local_path_from_syft_url(file_path_or_syfturl)
    else:
        file_path = Path(file_path_or_syfturl)
    
    if file_path is None:
        raise ValueError("Could not resolve file path for permissions.")

    target_path = file_path.parent
    file_pattern = file_path.name
    syftpub_path = target_path / "syft.pub.yaml"

    # Ensure target directory exists
    target_path.mkdir(parents=True, exist_ok=True)

    # Format users for SyftBox
    def format_users(users):
        return ["*" if u in ["public", "*"] else u for u in users]

    access_dict = {}
    if read_users:
        access_dict["read"] = format_users(read_users)
    if write_users:
        access_dict["write"] = format_users(write_users)
    if admin_users:
        access_dict["admin"] = format_users(admin_users)
    
    if not access_dict:
        return

    new_rule = {"pattern": file_pattern, "access": access_dict}

    # Read existing syft.pub.yaml
    existing_content = {"rules": []}
    if syftpub_path.exists():
        try:
            with open(syftpub_path, 'r') as f:
                existing_content = yaml.safe_load(f) or {"rules": []}
        except Exception:
            existing_content = {"rules": []}
    
    if "rules" not in existing_content or not isinstance(existing_content["rules"], list):
        existing_content["rules"] = []
    
    # Remove any existing rules for this pattern
    existing_content["rules"] = [
        rule for rule in existing_content["rules"] if rule.get("pattern") != new_rule["pattern"]
    ]
    existing_content["rules"].append(new_rule)
    
    with open(syftpub_path, 'w') as f:
        yaml.dump(existing_content, f, default_flow_style=False, sort_keys=False, indent=2)


def get_file_permissions(file_path_or_syfturl: str) -> Optional[Dict[str, Any]]:
    """
    Read permissions for a file (local path or syft:// URL) from syft.pub.yaml.
    
    Args:
        file_path_or_syfturl: Local file path or syft:// URL
        
    Returns:
        The access dict for the file, or None if not found.
    """
    if isinstance(file_path_or_syfturl, str) and file_path_or_syfturl.startswith("syft://"):
        file_path = _extract_local_path_from_syft_url(file_path_or_syfturl)
    else:
        file_path = Path(file_path_or_syfturl)
    
    if file_path is None:
        return None
    
    syftpub_path = file_path.parent / "syft.pub.yaml"
    if not syftpub_path.exists():
        return None
    
    try:
        with open(syftpub_path, 'r') as f:
            content = yaml.safe_load(f) or {"rules": []}
        for rule in content.get("rules", []):
            if rule.get("pattern") == file_path.name:
                return rule.get("access")
    except Exception:
        return None
    
    return None


def remove_file_permissions(file_path_or_syfturl: str) -> None:
    """
    Remove permissions for a file (local path or syft:// URL) from syft.pub.yaml.
    
    Args:
        file_path_or_syfturl: Local file path or syft:// URL
    """
    if isinstance(file_path_or_syfturl, str) and file_path_or_syfturl.startswith("syft://"):
        file_path = _extract_local_path_from_syft_url(file_path_or_syfturl)
    else:
        file_path = Path(file_path_or_syfturl)
    
    if file_path is None:
        return
    
    syftpub_path = file_path.parent / "syft.pub.yaml"
    if not syftpub_path.exists():
        return
    
    try:
        with open(syftpub_path, 'r') as f:
            content = yaml.safe_load(f) or {"rules": []}
        new_rules = [rule for rule in content.get("rules", []) if rule.get("pattern") != file_path.name]
        content["rules"] = new_rules
        with open(syftpub_path, 'w') as f:
            yaml.dump(content, f, default_flow_style=False, sort_keys=False, indent=2)
    except Exception:
        pass


def _is_file(path: Path) -> bool:
    """Check if a path points to a file."""
    return path.is_file()

def _is_directory(path: Path) -> bool:
    """Check if a path points to a directory."""
    return path.is_dir()

def set_folder_permissions(
    folder_path_or_syfturl: str,
    read_users: List[str],
    write_users: List[str] = None,
    admin_users: List[str] = None,
    including_subfolders: bool = True,
) -> None:
    """
    Set permissions for a folder (local path or syft:// URL) by creating/updating syft.pub.yaml inside it.
    
    Args:
        folder_path_or_syfturl: Local folder path or syft:// URL
        read_users: List of users who can read the folder
        write_users: List of users who can write to the folder
        admin_users: List of users who have admin access (defaults to write_users)
        including_subfolders: If True, permissions apply to all subfolders ('**' pattern), otherwise just current folder ('*' pattern)
    """
    if write_users is None:
        write_users = []
    if admin_users is None:
        admin_users = write_users

    # Resolve to local path if syft://
    if isinstance(folder_path_or_syfturl, str) and folder_path_or_syfturl.startswith("syft://"):
        folder_path = _extract_local_path_from_syft_url(folder_path_or_syfturl)
    else:
        folder_path = Path(folder_path_or_syfturl)
    
    if folder_path is None:
        raise ValueError("Could not resolve folder path for permissions.")

    if not _is_directory(folder_path):
        raise ValueError(f"Path {folder_path} is not a directory. Use set_file_permissions for files.")

    syftpub_path = folder_path / "syft.pub.yaml"

    # Format users for SyftBox
    def format_users(users):
        return ["*" if u in ["public", "*"] else u for u in users]

    access_dict = {}
    if read_users:
        access_dict["read"] = format_users(read_users)
    if write_users:
        access_dict["write"] = format_users(write_users)
    if admin_users:
        access_dict["admin"] = format_users(admin_users)
    
    if not access_dict:
        return

    # Use '**' for recursive subfolder permissions, '*' for current folder only
    pattern = "**" if including_subfolders else "*"
    new_rule = {"pattern": pattern, "access": access_dict}

    # Read existing syft.pub.yaml
    existing_content = {"rules": []}
    if syftpub_path.exists():
        try:
            with open(syftpub_path, 'r') as f:
                existing_content = yaml.safe_load(f) or {"rules": []}
        except Exception:
            existing_content = {"rules": []}
    
    if "rules" not in existing_content or not isinstance(existing_content["rules"], list):
        existing_content["rules"] = []
    
    # Remove any existing rules for this pattern
    existing_content["rules"] = [
        rule for rule in existing_content["rules"] if rule.get("pattern") != pattern
    ]
    existing_content["rules"].append(new_rule)
    
    with open(syftpub_path, 'w') as f:
        yaml.dump(existing_content, f, default_flow_style=False, sort_keys=False, indent=2)

def get_folder_permissions(folder_path_or_syfturl: str) -> Optional[Dict[str, Any]]:
    """
    Read permissions for a folder (local path or syft:// URL) from syft.pub.yaml inside it.
    
    Args:
        folder_path_or_syfturl: Local folder path or syft:// URL
        
    Returns:
        The access dict for the folder, or None if not found.
    """
    if isinstance(folder_path_or_syfturl, str) and folder_path_or_syfturl.startswith("syft://"):
        folder_path = _extract_local_path_from_syft_url(folder_path_or_syfturl)
    else:
        folder_path = Path(folder_path_or_syfturl)
    
    if folder_path is None:
        return None

    if not _is_directory(folder_path):
        raise ValueError(f"Path {folder_path} is not a directory. Use get_file_permissions for files.")
    
    syftpub_path = folder_path / "syft.pub.yaml"
    if not syftpub_path.exists():
        return None
    
    try:
        with open(syftpub_path, 'r') as f:
            content = yaml.safe_load(f) or {"rules": []}
        
        # First try to find '**' pattern (recursive)
        for rule in content.get("rules", []):
            if rule.get("pattern") == "**":
                return rule.get("access")
        
        # Then try '*' pattern (current folder only)
        for rule in content.get("rules", []):
            if rule.get("pattern") == "*":
                return rule.get("access")
    except Exception:
        return None
    
    return None

def set_permissions(
    path_or_syfturl: str,
    read_users: List[str],
    write_users: List[str] = None,
    admin_users: List[str] = None,
    including_subfolders: bool = True,
) -> None:
    """
    Set permissions for a file or folder by automatically detecting the type.
    
    Args:
        path_or_syfturl: Local path or syft:// URL
        read_users: List of users who can read
        write_users: List of users who can write
        admin_users: List of users who have admin access
        including_subfolders: For folders only - if True, permissions apply to subfolders
    """
    # Resolve path
    if isinstance(path_or_syfturl, str) and path_or_syfturl.startswith("syft://"):
        path = _extract_local_path_from_syft_url(path_or_syfturl)
    else:
        path = Path(path_or_syfturl)

    if path is None:
        raise ValueError("Could not resolve path for permissions.")

    if _is_file(path):
        set_file_permissions(path_or_syfturl, read_users, write_users, admin_users)
    elif _is_directory(path):
        set_folder_permissions(path_or_syfturl, read_users, write_users, admin_users, including_subfolders)
    else:
        raise ValueError(f"Path {path} does not exist or is neither a file nor a directory.")

def get_permissions(path_or_syfturl: str) -> Optional[Dict[str, Any]]:
    """
    Get permissions for a file or folder by automatically detecting the type.
    
    Args:
        path_or_syfturl: Local path or syft:// URL
        
    Returns:
        The access dict for the path, or None if not found.
    """
    # Resolve path
    if isinstance(path_or_syfturl, str) and path_or_syfturl.startswith("syft://"):
        path = _extract_local_path_from_syft_url(path_or_syfturl)
    else:
        path = Path(path_or_syfturl)

    if path is None:
        return None

    if _is_file(path):
        return get_file_permissions(path_or_syfturl)
    elif _is_directory(path):
        return get_folder_permissions(path_or_syfturl)
    else:
        raise ValueError(f"Path {path} does not exist or is neither a file nor a directory.")

def remove_folder_permissions(folder_path_or_syfturl: str) -> None:
    """
    Remove permissions for a folder by deleting its syft.pub.yaml file.
    
    Args:
        folder_path_or_syfturl: Local folder path or syft:// URL
    """
    if isinstance(folder_path_or_syfturl, str) and folder_path_or_syfturl.startswith("syft://"):
        folder_path = _extract_local_path_from_syft_url(folder_path_or_syfturl)
    else:
        folder_path = Path(folder_path_or_syfturl)
    
    if folder_path is None:
        return

    if not _is_directory(folder_path):
        raise ValueError(f"Path {folder_path} is not a directory. Use remove_file_permissions for files.")
    
    syftpub_path = folder_path / "syft.pub.yaml"
    if syftpub_path.exists():
        syftpub_path.unlink()

# Export the main functions
__all__ = [
    "set_file_permissions",
    "get_file_permissions", 
    "remove_file_permissions",
    "set_folder_permissions",
    "get_folder_permissions",
    "remove_folder_permissions",
    "set_permissions",
    "get_permissions",
    "SYFTBOX_AVAILABLE",
] 