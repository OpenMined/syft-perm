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
    write_users: Optional[List[str]] = None,
    admin_users: Optional[List[str]] = None
) -> Dict[str, List[str]]:
    """Create a standardized access dictionary from user lists"""
    write_users = write_users or []
    admin_users = admin_users or write_users
    
    # Create ordered dictionary with permissions in desired order
    access_dict = {}
    if admin_users:
        access_dict["admin"] = format_users(admin_users)
    if write_users:
        access_dict["write"] = format_users(write_users)
    if read_users:
        access_dict["read"] = format_users(read_users)
    return access_dict

def update_syftpub_yaml(
    target_path: Path,
    pattern: str,
    access_dict: Dict[str, List[str]]
) -> None:
    """Update syft.pub.yaml with new permission rules"""
    if not access_dict:
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
    
    # Update rules
    # Ensure permissions are in correct order by creating new ordered dict
    ordered_access = {}
    for perm in ["admin", "write", "read"]:
        if perm in access_dict:
            ordered_access[perm] = access_dict[perm]
            
    new_rule = {"pattern": pattern, "access": ordered_access}
    existing_content["rules"] = [
        rule for rule in existing_content["rules"]
        if rule.get("pattern") != pattern
    ]
    existing_content["rules"].append(new_rule)
    
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
    syftpub_path = path.parent / "syft.pub.yaml"
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