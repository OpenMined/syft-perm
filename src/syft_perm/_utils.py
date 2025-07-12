"""Utility functions for syft_perm."""

import os
import yaml
from pathlib import Path
from typing import Optional, List, Dict, Any, Union, Literal

from ._syftbox import client as _syftbox_client, SYFTBOX_AVAILABLE, SyftBoxURL

__all__ = [
    "resolve_path",
    "SYFTBOX_AVAILABLE",
    "is_datasite_email",
    "get_syftbox_datasites",
]

def resolve_path(path_or_syfturl: str) -> Optional[Path]:
    """Convert any path (local or syft://) to a local Path object."""
    if not isinstance(path_or_syfturl, str):
        return Path(path_or_syfturl)
        
    if path_or_syfturl.startswith("syft://"):
        if not SYFTBOX_AVAILABLE or _syftbox_client is None:
            return None
        try:
            return SyftBoxURL(path_or_syfturl).to_local_path(datasites_path=_syftbox_client.datasites)
        except Exception:
            return None
    return Path(path_or_syfturl)

def format_users(users: List[str]) -> List[str]:
    """
    Format user list, converting 'public' or '*' to '*' and deduplicating.
    
    If '*' or 'public' is present, returns just ['*'] since it implies all users.
    Otherwise returns deduplicated list of users.
    """
    # Convert to set for deduplication
    unique_users = set(users)
    
    # Check for public access indicators
    if "*" in unique_users or "public" in unique_users:
        return ["*"]
        
    return sorted(unique_users)  # Sort for consistent order

def create_access_dict(
    read_users: List[str],
    create_users: Optional[List[str]] = None,
    write_users: Optional[List[str]] = None,
    admin_users: Optional[List[str]] = None
) -> Dict[str, List[str]]:
    """Create a standardized access dictionary from user lists"""
    create_users = create_users or []
    write_users = write_users or []
    admin_users = admin_users or write_users
    
    # Create ordered dictionary with permissions in desired order
    access_dict = {}
    if admin_users:
        access_dict["admin"] = format_users(admin_users)
    if write_users:
        access_dict["write"] = format_users(write_users)
    if create_users:
        access_dict["create"] = format_users(create_users)
    if read_users:
        access_dict["read"] = format_users(read_users)
    return access_dict

def update_syftpub_yaml(
    target_path: Path,
    pattern: str,
    access_dict: Dict[str, List[str]],
    limits_dict: Optional[Dict[str, Any]] = None
) -> None:
    """Update syft.pub.yaml with new permission rules and optional limits"""
    if not access_dict and not limits_dict:
        return
        
    syftpub_path = target_path / "syft.pub.yaml"
    target_path.mkdir(parents=True, exist_ok=True)
    
    # Read existing rules
    existing_content = {"rules": []}
    if syftpub_path.exists():
        try:
            with open(syftpub_path, 'r') as f:
                existing_content = yaml.safe_load(f) or {"rules": []}
        except Exception:
            pass
    
    if not isinstance(existing_content.get("rules"), list):
        existing_content["rules"] = []
    
    # Find existing rule for this pattern
    existing_rule = None
    for rule in existing_content["rules"]:
        if rule.get("pattern") == pattern:
            existing_rule = rule
            break
    
    # Create new rule or update existing
    if existing_rule is None:
        new_rule = {"pattern": pattern}
        existing_content["rules"].append(new_rule)
    else:
        new_rule = existing_rule
    
    # Update access permissions if provided
    if access_dict:
        # Ensure permissions are in correct order by creating new ordered dict
        ordered_access = {}
        for perm in ["admin", "write", "create", "read"]:
            if perm in access_dict:
                ordered_access[perm] = access_dict[perm]
        new_rule["access"] = ordered_access
    
    # Update limits if provided
    if limits_dict:
        new_rule["limits"] = limits_dict
    
    # Write back
    with open(syftpub_path, 'w') as f:
        yaml.dump(existing_content, f, default_flow_style=False, sort_keys=False, indent=2)

def is_datasite_email(email: str) -> bool:
    """
    Check if an email corresponds to a datasite by looking for a folder
    with that email name in SyftBox/datasites.
    
    Args:
        email: The email address to check
        
    Returns:
        bool: True if the email belongs to a datasite, False otherwise
    """
    # Handle special cases
    if email in ["*", "public"]:
        return True
        
    # Check if SyftBox client is available
    if SYFTBOX_AVAILABLE and _syftbox_client is not None:
        datasites_path = _syftbox_client.datasites
        if datasites_path and datasites_path.exists():
            datasite_folder = datasites_path / email
            return datasite_folder.exists()
    
    # Fallback: check default location ~/SyftBox/datasites
    home = Path.home()
    syftbox_datasites = home / "SyftBox" / "datasites"
    if syftbox_datasites.exists():
        datasite_folder = syftbox_datasites / email
        return datasite_folder.exists()
        
    return False

def read_syftpub_yaml(path: Path, pattern: str) -> Optional[Dict[str, List[str]]]:
    """Read permissions from syft.pub.yaml for a specific pattern"""
    syftpub_path = path / "syft.pub.yaml"
    if not syftpub_path.exists():
        return None
    
    try:
        with open(syftpub_path, 'r') as f:
            content = yaml.safe_load(f) or {"rules": []}
        for rule in content.get("rules", []):
            if rule.get("pattern") == pattern:
                return rule.get("access")
    except Exception:
        pass
    return None

def read_syftpub_yaml_full(path: Path, pattern: str) -> Optional[Dict[str, Any]]:
    """Read full rule (access and limits) from syft.pub.yaml for a specific pattern"""
    syftpub_path = path / "syft.pub.yaml"
    if not syftpub_path.exists():
        return None
    
    try:
        with open(syftpub_path, 'r') as f:
            content = yaml.safe_load(f) or {"rules": []}
        for rule in content.get("rules", []):
            if rule.get("pattern") == pattern:
                return {
                    "access": rule.get("access", {}),
                    "limits": rule.get("limits", {})
                }
    except Exception:
        pass
    return None


def get_syftbox_datasites() -> List[str]:
    """Get list of available datasites from SyftBox for autocompletion."""
    datasites = []
    
    if not SYFTBOX_AVAILABLE or _syftbox_client is None:
        return datasites
    
    try:
        # Get datasites directory from syftbox client
        datasites_path = _syftbox_client.datasites
        if datasites_path and datasites_path.exists():
            # List all subdirectories (datasites) 
            for item in datasites_path.iterdir():
                if item.is_dir() and not item.name.startswith('.'):
                    # Add the datasite name (which should be an email)
                    datasites.append(item.name)
    except Exception:
        # Fallback: try to find SyftBox directory manually
        try:
            home = Path.home()
            syftbox_datasites = home / "SyftBox" / "datasites"
            if syftbox_datasites.exists():
                for item in syftbox_datasites.iterdir():
                    if item.is_dir() and not item.name.startswith('.'):
                        datasites.append(item.name)
        except Exception:
            pass
    
    return sorted(datasites) 