"""Wrapper class for permissions to provide a clean API."""

from typing import Dict, List, Optional


class PermissionsWrapper:
    """Wrapper for permissions dictionary to provide convenient methods."""
    
    def __init__(self, permissions_dict: Dict[str, List[str]], syft_object):
        """Initialize with permissions dictionary and parent object."""
        self._permissions = permissions_dict
        self._syft_object = syft_object
    
    def has_access(self, user: str) -> bool:
        """Check if user has any access to the file/folder."""
        # Check each permission level
        for perm_type in ["read", "create", "write", "admin"]:
            users = self._permissions.get(perm_type, [])
            if user in users or "*" in users:
                return True
        return False
    
    @property
    def is_public(self) -> bool:
        """Check if the file/folder has public access."""
        # Check if "*" is in any permission level
        for users in self._permissions.values():
            if "*" in users:
                return True
        return False
    
    def to_dict(self) -> Dict[str, List[str]]:
        """Return the permissions as a dictionary."""
        return self._permissions.copy()
    
    def summary(self) -> List[str]:
        """Get a summary of users with permissions."""
        all_users = set()
        for users in self._permissions.values():
            all_users.update(users)
        # Remove "*" and replace with "public" for clarity
        if "*" in all_users:
            all_users.remove("*")
            all_users.add("public")
        return sorted(list(all_users))
    
    def __bool__(self) -> bool:
        """Check if any permissions are set."""
        for users in self._permissions.values():
            if users:
                return True
        return False
    
    def __repr__(self) -> str:
        """String representation."""
        return f"PermissionsWrapper({self._permissions})"