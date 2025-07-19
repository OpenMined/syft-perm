"""Core components for syft-perm."""

from .path_matching import (
    _acl_norm_path,
    _calculate_glob_specificity,
    _doublestar_match,
    _glob_match,
    _sort_rules_by_specificity,
)
from .permissions import (
    PermissionCache,
    PermissionReason,
    PermissionResult,
    _is_owner,
    clear_permission_cache,
    get_cache_stats,
)
from .visualization import (
    PermissionExplanation,
    ShareWidget,
)

__all__ = [
    "PermissionReason",
    "PermissionResult",
    "PermissionCache",
    "get_cache_stats",
    "clear_permission_cache",
    "_is_owner",
    "_acl_norm_path",
    "_doublestar_match",
    "_glob_match",
    "_calculate_glob_specificity",
    "_sort_rules_by_specificity",
    "PermissionExplanation",
    "ShareWidget",
]
