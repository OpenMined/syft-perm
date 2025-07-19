"""Permission-related components for SyftPerm."""

from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from .path_matching import _acl_norm_path


class PermissionReason(Enum):
    """Reasons why a permission was granted or denied."""

    OWNER = "Owner of path"
    EXPLICIT_GRANT = "Explicitly granted {permission}"
    INHERITED = "Inherited from {path}"
    HIERARCHY = "Included via {level} permission"
    PUBLIC = "Public access (*)"
    PATTERN_MATCH = "Pattern '{pattern}' matched"
    TERMINAL_BLOCKED = "Blocked by terminal at {path}"
    NO_PERMISSION = "No permission found"
    FILE_LIMIT = "Blocked by {limit_type} limit"


@dataclass
class PermissionResult:
    """Result of a permission check with reasons."""

    has_permission: bool
    reasons: List[str]
    source_paths: List[Path] = field(default_factory=list)
    patterns: List[str] = field(default_factory=list)


# Cache implementation for permission lookups
class PermissionCache:
    """Simple LRU cache for permission lookups to match old ACL performance."""

    def __init__(self, max_size: int = 10000):
        self.cache: OrderedDict[str, Dict[str, List[str]]] = OrderedDict()
        self.max_size = max_size

    def get(self, path: str) -> Optional[Dict[str, List[str]]]:
        """Get permissions from cache if available."""
        if path in self.cache:
            # Move to end (LRU)
            self.cache.move_to_end(path)
            return self.cache[path]
        return None

    def set(self, path: str, permissions: Dict[str, List[str]]) -> None:
        """Set permissions in cache."""
        if path in self.cache:
            self.cache.move_to_end(path)
        else:
            if len(self.cache) >= self.max_size:
                # Remove oldest entry
                self.cache.popitem(last=False)
        self.cache[path] = permissions

    def invalidate(self, path_prefix: str) -> None:
        """Invalidate all cache entries starting with path_prefix."""
        keys_to_remove = [k for k in self.cache if k.startswith(path_prefix)]
        for key in keys_to_remove:
            del self.cache[key]

    def clear(self) -> None:
        """Clear all cache entries."""
        self.cache.clear()


# Global cache instance
_permission_cache = PermissionCache()


def get_cache_stats() -> Dict[str, Any]:
    """Get cache statistics for testing and debugging."""
    return {
        "size": len(_permission_cache.cache),
        "max_size": _permission_cache.max_size,
        "keys": list(_permission_cache.cache.keys()),
    }


def clear_permission_cache() -> None:
    """Clear the permission cache for testing."""
    _permission_cache.clear()


def _is_owner(path: str, user: str) -> bool:
    """
    Check if the user is the owner of the path using old syftbox logic.
    Converts absolute path to datasites-relative path, then checks prefix matching.

    Args:
        path: File/directory path (absolute or relative)
        user: User ID to check

    Returns:
        bool: True if user is owner
    """
    path_str = str(path)

    # Convert to datasites-relative path if it's an absolute path
    if "datasites" in path_str:
        # Find the datasites directory and extract the relative path from there
        parts = path_str.split("datasites")
        if len(parts) > 1:
            # Take everything after "datasites/" and normalize it
            datasites_relative = parts[-1].lstrip("/\\")
            normalized_path = _acl_norm_path(datasites_relative)
            return normalized_path.startswith(user)

    # If not under datasites, check if any path component matches the user
    # This handles both relative paths and test scenarios
    normalized_path = _acl_norm_path(path_str)
    path_parts = normalized_path.split("/")

    # Check if any path component is the user (for owner detection)
    return user in path_parts
