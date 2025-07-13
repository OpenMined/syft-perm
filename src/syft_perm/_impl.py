"""Internal implementation of SyftFile and SyftFolder classes with ACL compatibility."""

import shutil
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

import yaml

from ._utils import (
    format_users,
    is_datasite_email,
    read_syftpub_yaml,
    read_syftpub_yaml_full,
    resolve_path,
    update_syftpub_yaml,
)


# Permission reason tracking
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


def _acl_norm_path(path: str) -> str:
    """
    Normalize a file system path for use in ACL operations by:
    1. Converting all path separators to forward slashes
    2. Cleaning the path (resolving . and ..)
    3. Removing leading path separators
    This ensures consistent path handling across different operating systems
    and compatibility with glob pattern matching.
    """
    from pathlib import PurePath

    # Convert to forward slashes using pathlib for proper path handling
    normalized = str(PurePath(path).as_posix())

    # Remove leading slashes and resolve . components
    normalized = normalized.lstrip("/")

    # Handle relative path components
    if normalized.startswith("./"):
        normalized = normalized[2:]
    elif normalized == ".":
        normalized = ""

    return normalized


def _doublestar_match(pattern: str, path: str) -> bool:
    """
    Match a path against a glob pattern using doublestar algorithm.
    This implementation matches the Go doublestar library behavior used in old syftbox.

    Args:
        pattern: Glob pattern (supports *, ?, ** for recursive)
        path: Path to match against pattern (should be normalized)

    Returns:
        bool: True if path matches pattern
    """
    # Normalize inputs
    pattern = _acl_norm_path(pattern)
    path = _acl_norm_path(path)

    # Quick exact match
    if pattern == path:
        return True

    # Handle ** patterns
    if "**" in pattern:
        return _match_doublestar(pattern, path)

    # Handle single * and ? patterns
    return _match_simple_glob(pattern, path)


def _match_doublestar(pattern: str, path: str) -> bool:
    """
    Handle patterns containing ** (doublestar) recursion.

    This implements the doublestar algorithm similar to the Go library used in old syftbox.
    Key behavior: ** matches zero or more path segments (directories).
    """
    # Handle the simplest cases first
    if pattern == "**":
        return True
    if not pattern:
        return not path
    if not path:
        return pattern == "**" or pattern == ""

    # Find the first ** in the pattern
    double_star_idx = pattern.find("**")
    if double_star_idx == -1:
        # No ** in pattern, use simple glob matching
        return _match_simple_glob(pattern, path)

    # Split into prefix (before **), and suffix (after **)
    prefix = pattern[:double_star_idx].rstrip("/")
    suffix = pattern[double_star_idx + 2 :].lstrip("/")

    # Match the prefix
    if prefix:
        # For doublestar patterns, prefix should match at the beginning of the path
        # or we need to try matching the entire pattern at later positions (for leading **)
        if path == prefix:
            # Exact match
            remaining = ""
        elif path.startswith(prefix + "/"):
            # Path starts with prefix followed by separator
            remaining = path[len(prefix) + 1 :]
        elif _match_simple_glob(prefix, path):
            # Glob pattern matches entire path
            remaining = ""
        else:
            # Prefix doesn't match at start, for leading ** try at later positions
            if pattern.startswith("**/"):
                path_segments = path.split("/")
                for i in range(1, len(path_segments) + 1):
                    remaining_path = "/".join(path_segments[i:])
                    if _match_doublestar(pattern, remaining_path):
                        return True
            return False
    else:
        # No prefix, ** can match from the beginning
        remaining = path

    # Match the suffix
    if not suffix:
        # Pattern ends with **
        # Check if this came from a trailing /** (which requires something after)
        if pattern.endswith("/**"):
            # /** requires something after the prefix
            return bool(remaining)
        else:
            # ** at end matches everything remaining
            return True

    # Try matching suffix at every possible position in remaining path
    if not remaining:
        # No remaining path, but we have a suffix to match
        return suffix == ""

    # Split remaining path into segments and try matching suffix at each position
    remaining_segments = remaining.split("/")

    # Try exact match first
    if _match_doublestar(suffix, remaining):
        return True

    # Try matching suffix starting from each segment position
    for i in range(len(remaining_segments)):
        candidate = "/".join(remaining_segments[i:])
        if _match_doublestar(suffix, candidate):
            return True

    return False


def _match_suffix_recursive(suffix: str, path: str) -> bool:
    """Match suffix pattern against path, trying all possible positions."""
    if not suffix:
        return True

    if not path:
        return suffix == ""

    # Try matching suffix at current position
    if _match_simple_glob(suffix, path):
        return True

    # Try matching suffix at each segment
    path_segments = path.split("/")
    for i in range(len(path_segments)):
        test_path = "/".join(path_segments[i:])
        if _match_simple_glob(suffix, test_path):
            return True

    return False


def _match_simple_glob(pattern: str, path: str) -> bool:
    """Match simple glob patterns with *, ?, [] but no **. Case-sensitive matching."""
    if not pattern and not path:
        return True
    if not pattern:
        return False
    if not path:
        return pattern == "*" or all(c == "*" for c in pattern)

    # Handle exact match (case-sensitive)
    if pattern == path:
        return True

    # Convert glob pattern to regex-like matching (case-sensitive)
    pattern_idx = 0
    path_idx = 0
    star_pattern_idx = -1
    star_path_idx = -1

    while path_idx < len(path):
        if pattern_idx < len(pattern):
            if pattern[pattern_idx] == "*":
                # Found *, remember positions
                star_pattern_idx = pattern_idx
                star_path_idx = path_idx
                pattern_idx += 1
                continue
            elif pattern[pattern_idx] == "?":
                # ? matches any single char (case-sensitive)
                pattern_idx += 1
                path_idx += 1
                continue
            elif pattern[pattern_idx] == "[":
                # Character class matching like [0-9], [abc], etc.
                if _match_char_class(pattern, pattern_idx, path[path_idx]):
                    # Find end of character class
                    bracket_end = pattern.find("]", pattern_idx + 1)
                    if bracket_end != -1:
                        pattern_idx = bracket_end + 1
                        path_idx += 1
                        continue
                # If no matching bracket or no match, fall through to backtrack
            elif pattern[pattern_idx] == path[path_idx]:
                # Exact char match (case-sensitive)
                pattern_idx += 1
                path_idx += 1
                continue

        # No match at current position, backtrack if we have a *
        if star_pattern_idx >= 0:
            # For single *, don't match across directory boundaries
            if path[star_path_idx] == "/":
                return False
            pattern_idx = star_pattern_idx + 1
            star_path_idx += 1
            path_idx = star_path_idx
        else:
            return False

    # Skip trailing * in pattern
    while pattern_idx < len(pattern) and pattern[pattern_idx] == "*":
        pattern_idx += 1

    return pattern_idx == len(pattern)


def _match_char_class(pattern: str, start_idx: int, char: str) -> bool:
    """Match a character against a character class like [0-9], [abc], [!xyz]."""
    if start_idx >= len(pattern) or pattern[start_idx] != "[":
        return False

    # Find the end of the character class
    end_idx = pattern.find("]", start_idx + 1)
    if end_idx == -1:
        return False

    char_class = pattern[start_idx + 1 : end_idx]
    if not char_class:
        return False

    # Handle negation [!...] or [^...]
    negate = False
    if char_class[0] in "!^":
        negate = True
        char_class = char_class[1:]

    # Check for range patterns like 0-9, a-z
    i = 0
    matched = False
    while i < len(char_class):
        if i + 2 < len(char_class) and char_class[i + 1] == "-":
            # Range pattern like 0-9
            start_char = char_class[i]
            end_char = char_class[i + 2]
            if start_char <= char <= end_char:
                matched = True
                break
            i += 3
        else:
            # Single character
            if char_class[i] == char:
                matched = True
                break
            i += 1

    return matched if not negate else not matched


def _glob_match(pattern: str, path: str) -> bool:
    """
    Match a path against a glob pattern, supporting ** for recursive matching.
    This implementation uses doublestar algorithm to match old syftbox behavior.

    Args:
        pattern: Glob pattern (supports *, ?, ** for recursive)
        path: Path to match against pattern

    Returns:
        bool: True if path matches pattern
    """
    return _doublestar_match(pattern, path)


def _calculate_glob_specificity(pattern: str) -> int:
    """
    Calculate glob specificity score matching old syftbox algorithm.
    Higher scores = more specific patterns.

    Args:
        pattern: Glob pattern to score

    Returns:
        int: Specificity score (higher = more specific)
    """
    # Early return for the most specific glob patterns
    if pattern == "**":
        return -100
    elif pattern == "**/*":
        return -99

    # 2L + 10D - wildcard penalty
    # Use forward slash for glob patterns
    score = len(pattern) * 2 + pattern.count("/") * 10

    # Penalize base score for substr wildcards
    for i, c in enumerate(pattern):
        if c == "*":
            if i == 0:
                score -= 20  # Leading wildcards are very unspecific
            else:
                score -= 10  # Other wildcards are less penalized
        elif c in "?!][{":
            score -= 2  # Non * wildcards get smaller penalty

    return score


def _sort_rules_by_specificity(rules: list) -> list:
    """
    Sort rules by specificity (most specific first) matching old syftbox algorithm.

    Args:
        rules: List of rule dictionaries

    Returns:
        list: Rules sorted by specificity (descending)
    """
    # Create list of (rule, specificity) tuples
    rules_with_scores = []
    for rule in rules:
        pattern = rule.get("pattern", "")
        score = _calculate_glob_specificity(pattern)
        rules_with_scores.append((rule, score))

    # Sort by specificity (descending - higher scores first)
    rules_with_scores.sort(key=lambda x: x[1], reverse=True)

    # Return just the rules
    return [rule for rule, score in rules_with_scores]


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


def _confirm_action(message: str, force: bool = False) -> bool:
    """
    Confirm a sensitive action with the user.

    Args:
        message: The confirmation message to display
        force: Whether to skip confirmation

    Returns:
        bool: True if confirmed or forced, False otherwise
    """
    if force:
        return True

    response = input(f"{message} [y/N] ").lower().strip()
    return response in ["y", "yes"]


class SyftFile:
    """A file wrapper that manages SyftBox permissions."""

    def __init__(self, path: Union[str, Path]):
        resolved_path = resolve_path(str(path))
        if resolved_path is None:
            raise ValueError("Could not resolve path")
        self._path: Path = resolved_path

        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # File metadata for limit checks
        self._is_symlink = self._path.is_symlink() if self._path.exists() else False
        self._size = (
            self._path.stat().st_size if self._path.exists() and not self._is_symlink else 0
        )

    @property
    def _name(self) -> str:
        """Get the file name"""
        return self._path.name

    def _get_all_permissions(self) -> Dict[str, List[str]]:
        """Get all permissions for this file using old syftbox nearest-node algorithm."""
        # Check cache first
        cache_key = str(self._path)
        cached = _permission_cache.get(cache_key)
        if cached is not None:
            return cached

        # Find the nearest node with matching rules (old syftbox algorithm)
        nearest_permissions: Dict[str, List[str]] = {
            "read": [],
            "create": [],
            "write": [],
            "admin": [],
        }

        # Walk up the directory tree to find the nearest node with matching rules
        current_path = self._path
        while current_path.parent != current_path:  # Stop at root
            parent_dir = current_path.parent
            syftpub_path = parent_dir / "syft.pub.yaml"

            if syftpub_path.exists():
                try:
                    with open(syftpub_path, "r") as f:
                        content = yaml.safe_load(f) or {"rules": []}

                    # Check if this is a terminal node
                    if content.get("terminal", False):
                        # Terminal nodes stop inheritance and their rules take precedence
                        rules = content.get("rules", [])
                        sorted_rules = _sort_rules_by_specificity(rules)
                        for rule in sorted_rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our file path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path):
                                access = rule.get("access", {})
                                # Check file limits if present
                                limits = rule.get("limits", {})
                                if limits:
                                    # Check if directories are allowed
                                    if (
                                        not limits.get("allow_dirs", True)
                                        and self._path is not None
                                        and self._path.is_dir()
                                    ):
                                        continue  # Skip this rule for directories

                                    # Check if symlinks are allowed
                                    if not limits.get("allow_symlinks", True) and self._is_symlink:
                                        continue  # Skip this rule for symlinks

                                    # Check file size limits
                                    max_file_size = limits.get("max_file_size")
                                    if max_file_size is not None:
                                        if self._size > max_file_size:
                                            continue  # Skip this rule if file exceeds size limit

                                # Terminal rules: use first matching rule
                                # (most specific due to sorting)
                                result = {
                                    perm: format_users(access.get(perm, []))
                                    for perm in ["read", "create", "write", "admin"]
                                }
                                _permission_cache.set(cache_key, result)
                                return result
                        # If no match in terminal, stop inheritance with empty permissions
                        _permission_cache.set(cache_key, nearest_permissions)
                        return nearest_permissions

                    # Process rules for non-terminal nodes (sort by specificity first)
                    rules = content.get("rules", [])
                    sorted_rules = _sort_rules_by_specificity(rules)
                    found_matching_rule = False
                    for rule in sorted_rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our file path relative to this directory
                        rel_path = (
                            str(self._path.relative_to(parent_dir))
                            if self._path is not None
                            else ""
                        )
                        if _glob_match(pattern, rel_path):
                            access = rule.get("access", {})
                            # Check file limits if present
                            limits = rule.get("limits", {})
                            if limits:
                                # Check if directories are allowed
                                if not limits.get("allow_dirs", True) and self._path.is_dir():
                                    continue  # Skip this rule for directories

                                # Check if symlinks are allowed
                                if not limits.get("allow_symlinks", True) and self._is_symlink:
                                    continue  # Skip this rule for symlinks

                                # Check file size limits
                                max_file_size = limits.get("max_file_size")
                                if max_file_size is not None:
                                    if self._size > max_file_size:
                                        continue  # Skip this rule if file exceeds size limit

                            # Found a matching rule - use the first matching rule
                            # since they're sorted by specificity
                            # This becomes our nearest node
                            # (old syftbox: most specific matching rule wins)
                            nearest_permissions = {
                                perm: format_users(access.get(perm, []))
                                for perm in ["read", "create", "write", "admin"]
                            }
                            found_matching_rule = True
                            break  # Use first matching rule (most specific due to sorting)

                    # If we found a matching rule, this is our nearest node - stop searching
                    if found_matching_rule:
                        break

                except Exception:
                    pass

            current_path = parent_dir

        # Cache and return the effective permissions
        _permission_cache.set(cache_key, nearest_permissions)
        return nearest_permissions

    def _get_permission_table(self) -> List[List[str]]:
        """Get permissions formatted as a table showing effective permissions.

        Shows hierarchy and reasons.
        """
        perms = self._get_all_permissions()

        # Get all unique users
        all_users = set()
        for users in perms.values():
            all_users.update(users)

        # Create table rows
        rows = []

        # First add public if it exists
        if "*" in all_users:
            # Collect all reasons for public

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons("*", "read")
            create_has, create_reasons = self._check_permission_with_reasons("*", "create")
            write_has, write_reasons = self._check_permission_with_reasons("*", "write")
            admin_has, admin_reasons = self._check_permission_with_reasons("*", "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            rows.append(
                [
                    "public",
                    "✓" if read_has else "",
                    "✓" if create_has else "",
                    "✓" if write_has else "",
                    "✓" if admin_has else "",
                    reason_text,
                ]
            )
            all_users.remove("*")  # Remove so we don't process it again

        # Then add all other users
        for user in sorted(all_users):
            # Collect all reasons for this user

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons(user, "read")
            create_has, create_reasons = self._check_permission_with_reasons(user, "create")
            write_has, write_reasons = self._check_permission_with_reasons(user, "write")
            admin_has, admin_reasons = self._check_permission_with_reasons(user, "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            row = [
                user,
                "✓" if read_has else "",
                "✓" if create_has else "",
                "✓" if write_has else "",
                "✓" if admin_has else "",
                reason_text,
            ]
            rows.append(row)

        return rows

    def __repr__(self) -> str:
        """Return string representation showing permissions table."""
        rows = self._get_permission_table()
        if not rows:
            return f"SyftFile('{self._path}') - No permissions set"

        try:
            from tabulate import tabulate

            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="simple",
            )
            return f"SyftFile('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFile('{self._path}')\n"]
            result.append("User               Read  Create  Write  Admin  Reason")
            result.append("-" * 70)
            for row in rows:
                result.append(
                    f"{row[0]:<20} {row[1]:<5} {row[2]:<7} {row[3]:<6} "
                    f"{row[4]:<5} {row[5] if len(row) > 5 else ''}"
                )
            return "\n".join(result)

    def _ensure_server_and_get_editor_url(self) -> str:
        """Ensure the permission editor server is running and return the editor URL."""
        try:
            from ._auto_recovery import ensure_server_running
            from .server import get_editor_url, get_server_url, start_server

            # Check if server is already running
            server_url = get_server_url()
            if server_url:
                # Verify it's actually responding
                success, error = ensure_server_running(server_url)
                if not success:
                    print(f"Server health check failed: {error}")
                    server_url = None

            if not server_url:
                # Start the server
                server_url = start_server()
                print(f"🚀 SyftPerm permission editor started at: {server_url}")

            # Return the editor URL for this file
            return get_editor_url(str(self._path))

        except ImportError:
            # FastAPI not available
            return "Install 'syft-perm[server]' for permission editor"
        except Exception as e:
            # Server failed to start
            return f"Permission editor unavailable: {e}"

    def _get_loading_html(self) -> str:
        """Get static HTML to show while server is starting."""
        import threading
        import uuid

        # Generate unique ID for this instance
        instance_id = str(uuid.uuid4())

        # Start server recovery in background
        def start_server_background():
            try:
                self._ensure_server_and_get_editor_url()
            except Exception:
                pass  # Silently fail in background

        thread = threading.Thread(target=start_server_background, daemon=True)
        thread.start()

        # Return static HTML with auto-refresh
        return f"""
        <div id="syft-perm-{instance_id}" style="padding: 20px; background: #f5f5f5; border-radius: 8px; font-family: sans-serif;">  # noqa: E501
            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>
            <div style="background: white; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <p style="margin: 0;"><strong>File:</strong> {self._path}</p>
            </div>
            <div style="background: #e3f2fd; padding: 15px; border-radius: 4px; text-align: center;">  # noqa: E501
                <div style="display: inline-block;">
                    <div style="border: 3px solid #1976d2; border-radius: 50%; border-top-color: transparent;  # noqa: E501
                                width: 30px; height: 30px; animation: spin-{instance_id} 1s linear infinite;  # noqa: E501
                                margin: 0 auto 10px;"></div>
                    <p style="color: #1976d2; margin: 0;">Starting permission editor server...</p>
                    <p style="color: #666; font-size: 0.9em; margin-top: 5px;">This may take a moment if auto-recovery is needed</p>  # noqa: E501
                </div>
            </div>
            <style>
                @keyframes spin-{instance_id} {{
                    to {{ transform: rotate(360deg); }}
                }}
            </style>
            <script>
                (function() {{
                    let attempts = 0;
                    const maxAttempts = 30;
                    const checkInterval = 2000;

                    function checkServerAndReload() {{
                        attempts++;

                        // Try to fetch from the expected server
                        fetch('http://127.0.0.1:8765/')
                            .then(response => {{
                                if (response.ok) {{
                                    // Server is ready, reload the cell output
                                    if (window.Jupyter && window.Jupyter.notebook) {{
                                        // Find and re-execute this cell
                                        const cells = window.Jupyter.notebook.get_cells();
                                        for (let cell of cells) {{
                                            if (cell.output_area && cell.output_area.element) {{
                                                const output = cell.output_area.element[0];
                                                if (output && output.innerHTML.includes('syft-perm-{instance_id}')) {{  # noqa: E501
                                                    cell.execute();
                                                    return;
                                                }}
                                            }}
                                        }}
                                    }}
                                }}
                            }})
                            .catch(() => {{
                                // Server not ready yet
                                if (attempts < maxAttempts) {{
                                    setTimeout(checkServerAndReload, checkInterval);
                                }} else {{
                                    // Update the UI to show failure
                                    const elem = document.getElementById('syft-perm-{instance_id}');
                                    if (elem) {{
                                        elem.innerHTML = `
                                            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>  # noqa: E501
                                            <div style="background: #ffebee; padding: 15px; border-radius: 4px; color: #c62828;">  # noqa: E501
                                                <p style="margin: 0;"><strong>Error:</strong> Failed to start permission editor server</p>  # noqa: E501
                                                <p style="margin: 5px 0 0 0; font-size: 0.9em;">Please check your installation and try again</p>  # noqa: E501
                                            </div>
                                        `;
                                    }}
                                }}
                            }});
                    }}

                    // Start checking after a short delay
                    setTimeout(checkServerAndReload, 1000);
                }})();
            </script>
        </div>
        """

    def _repr_html_(self) -> str:
        """Return Google Drive-style permissions interface for Jupyter notebooks."""
        import hashlib
        import os

        # Get permission data
        permissions_data = self._get_all_permissions()

        # Function to generate consistent avatar colors based on email hash
        def get_avatar_color(email):
            colors = [
                "#1976d2",
                "#388e3c",
                "#f57c00",
                "#d32f2f",
                "#7b1fa2",
                "#303f9f",
                "#0288d1",
                "#0097a7",
                "#00796b",
                "#689f38",
                "#afb42b",
                "#fbc02d",
                "#ffa000",
                "#f57c00",
                "#e64a19",
                "#5d4037",
                "#616161",
                "#455a64",
            ]
            hash_obj = hashlib.md5(email.encode())
            return colors[int(hash_obj.hexdigest(), 16) % len(colors)]

        # Function to get initials from email
        def get_initials(email):
            if email == "*":
                return "PU"  # Public
            parts = email.split("@")[0].split(".")
            if len(parts) >= 2:
                return (parts[0][0] + parts[1][0]).upper()
            return email[0:2].upper()

        # Function to get highest syft permission level
        def get_highest_permission(permissions):
            if "admin" in permissions:
                return "Admin"
            elif "write" in permissions:
                return "Write"
            elif "create" in permissions:
                return "Create"
            elif "read" in permissions:
                return "Read"
            return "No access"

        # Collect all users with their permissions
        all_users = set()
        for perm_type, users in permissions_data.items():
            all_users.update(users)

        # Build user list with their highest permission level
        user_permissions = {}
        for user in all_users:
            user_perms = []
            for perm_type, users in permissions_data.items():
                if user in users:
                    user_perms.append(perm_type)
            user_permissions[user] = user_perms

        # Get current user (file owner)
        current_user = os.path.basename(os.path.expanduser("~"))

        # Create hybrid interface with syft-objects styling and Google Drive layout
        html = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    font-size: 0.75rem; background: #ffffff; border: 1px solid #e5e7eb;
                    border-radius: 0.25rem; margin: 8px 0; height: 200px;
                    display: flex; flex-direction: column;">
            <div style="background: #f8f9fa; padding: 0.375rem 0.5rem;
                        border-bottom: 1px solid #e5e7eb; flex-shrink: 0;
                        position: sticky; top: 0; z-index: 10;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="display: flex; align-items: center; gap: 0.25rem;">
                        <svg width="20" height="20" viewBox="0 0 311 360" fill="none" xmlns="http://www.w3.org/2000/svg"><g clip-path="url(#clip0)"><path d="M311.414 89.7878L155.518 179.998L-0.378906 89.7878L155.518 -0.422485L311.414 89.7878Z" fill="url(#paint0_linear)"/><path d="M311.414 89.7878V270.208L155.518 360.423V179.998L311.414 89.7878Z" fill="url(#paint1_linear)"/><path d="M155.518 179.998V360.423L-0.378906 270.208V89.7878L155.518 179.998Z" fill="url(#paint2_linear)"/></g><defs><linearGradient id="paint0_linear" x1="-0.378904" y1="89.7878" x2="311.414" y2="89.7878" gradientUnits="userSpaceOnUse"><stop stop-color="#DC7A6E"/><stop offset="0.251496" stop-color="#F6A464"/><stop offset="0.501247" stop-color="#FDC577"/><stop offset="0.753655" stop-color="#EFC381"/><stop offset="1" stop-color="#B9D599"/></linearGradient><linearGradient id="paint1_linear" x1="309.51" y1="89.7878" x2="155.275" y2="360.285" gradientUnits="userSpaceOnUse"><stop stop-color="#BFCD94"/><stop offset="0.245025" stop-color="#B2D69E"/><stop offset="0.504453" stop-color="#8DCCA6"/><stop offset="0.745734" stop-color="#5CB8B7"/><stop offset="1" stop-color="#4CA5B8"/></linearGradient><linearGradient id="paint2_linear" x1="-0.378906" y1="89.7878" x2="155.761" y2="360.282" gradientUnits="userSpaceOnUse"><stop stop-color="#D7686D"/><stop offset="0.225" stop-color="#C64B77"/><stop offset="0.485" stop-color="#A2638E"/><stop offset="0.703194" stop-color="#758AA8"/><stop offset="1" stop-color="#639EAF"/></linearGradient><clipPath id="clip0"><rect width="311" height="360" fill="white"/></clipPath></defs></svg>  # noqa: E501
                        <div>
                            <div style="font-size: 0.875rem; font-weight: 500; color: #374151;">
                                {self._path.name}
                            </div>
                            <div style="font-size: 0.75rem; color: #6b7280;">
                                Owner: {current_user}
                            </div>
                        </div>
                    </div>
                    <div style="font-size: 0.75rem; color: #6b7280; font-weight: 500;">
                        PERMISSIONS
                    </div>
                </div>
            </div>
            <div style="flex: 1; overflow-y: auto; padding: 0;">
        """

        # Add each user
        for user in sorted(user_permissions.keys()):
            permissions = user_permissions[user]
            role = get_highest_permission(permissions)
            initials = get_initials(user)
            color = get_avatar_color(user)

            # Determine if this is public access
            display_name = "Anyone with the link" if user == "*" else user

            # Get permission reasons for this user
            has_permission, reasons = self._check_permission_with_reasons(user, role.lower())
            reason_text = (
                "; ".join(reasons[:2]) if reasons else "Direct permission"
            )  # Limit to 2 reasons

            html += f"""
                <div style="display: flex; align-items: center; padding: 0.375rem 0.5rem;
                            gap: 0.5rem; border-bottom: 1px solid #f3f4f6;
                            transition: background-color 0.15s; cursor: pointer;"
                     onmouseover="this.style.background='rgba(0, 0, 0, 0.03)'"
                     onmouseout="this.style.background='transparent'">
                    <div style="width: 1.25rem; height: 1.25rem; border-radius: 50%;
                                background: {color}; display: flex; align-items: center;
                                justify-content: center; flex-shrink: 0;">
                        <span style="color: white; font-size: 0.625rem; font-weight: 500;">
                            {initials}
                        </span>
                    </div>
                    <div style="flex: 1; min-width: 0; display: flex;
                                align-items: center; gap: 0.75rem;">
                        <div style="font-size: 0.75rem; color: #374151; font-weight: 500;
                                    overflow: hidden; text-overflow: ellipsis;
                                    white-space: nowrap; min-width: 0;">
                            {display_name}
                        </div>
                        <div style="font-size: 0.625rem; color: #6b7280;
                                    overflow: hidden; text-overflow: ellipsis;
                                    white-space: nowrap; flex: 1; min-width: 0;">
                            {reason_text}
                        </div>
                    </div>
                    <div style="margin-left: 0.5rem;">
                        <span style="display: inline-flex; align-items: center;
                                     padding: 0.125rem 0.375rem; border-radius: 0.25rem;
                                     font-size: 0.625rem; font-weight: 500;
                                     background: #f3f4f6; color: #374151;">
                            {role.upper()}
                        </span>
                    </div>
                </div>
            """

        # If no users have access
        if not user_permissions:
            html += """
                <div style="text-align: center; padding: 1rem; color: #6b7280;">
                    <div style="font-size: 0.75rem; font-weight: 500;">No permissions set</div>
                    <div style="font-size: 0.75rem; margin-top: 0.125rem;">
                        Only the owner has access
                    </div>
                </div>
            """

        html += """
            </div>
        </div>
        """

        return html

    def grant_read_access(self, user: str, *, force: bool = False) -> None:
        """Grant read permission to a user."""
        self._grant_access(user, "read", force=force)

    def grant_create_access(self, user: str, *, force: bool = False) -> None:
        """Grant create permission to a user."""
        self._grant_access(user, "create", force=force)

    def grant_write_access(self, user: str, *, force: bool = False) -> None:
        """Grant write permission to a user."""
        if user in ["*", "public"] and not _confirm_action(
            f"⚠️  Warning: Granting public write access to '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "write", force=force)

    def grant_admin_access(self, user: str, *, force: bool = False) -> None:
        """Grant admin permission to a user."""
        if not _confirm_action(
            f"⚠️  Warning: Granting admin access to '{user}' for '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "admin", force=force)

    def revoke_read_access(self, user: str) -> None:
        """Revoke read permission from a user."""
        self._revoke_access(user, "read")

    def revoke_create_access(self, user: str) -> None:
        """Revoke create permission from a user."""
        self._revoke_access(user, "create")

    def revoke_write_access(self, user: str) -> None:
        """Revoke write permission from a user."""
        self._revoke_access(user, "write")

    def revoke_admin_access(self, user: str) -> None:
        """Revoke admin permission from a user."""
        self._revoke_access(user, "admin")

    def has_read_access(self, user: str) -> bool:
        """Check if a user has read permission."""
        return self._check_permission(user, "read")

    def has_create_access(self, user: str) -> bool:
        """Check if a user has create permission."""
        return self._check_permission(user, "create")

    def has_write_access(self, user: str) -> bool:
        """Check if a user has write permission."""
        return self._check_permission(user, "write")

    def has_admin_access(self, user: str) -> bool:
        """Check if a user has admin permission."""
        return self._check_permission(user, "admin")

    def _grant_access(
        self,
        user: str,
        permission: Literal["read", "create", "write", "admin"],
        *,
        force: bool = False,
    ) -> None:
        """Internal method to grant permission to a user."""
        # Validate that the email belongs to a datasite
        if not is_datasite_email(user) and not force:
            raise ValueError(
                f"'{user}' is not a valid datasite email. "
                f"Use force=True to override this check."
            )

        # Read all existing permissions for this file
        access_dict = read_syftpub_yaml(self._path.parent, self._name) or {}

        # Update the specific permission
        users = set(access_dict.get(permission, []))
        users.add(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present (even if empty)
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path.parent, self._name, access_dict)

        # Invalidate cache for this path and its parents
        _permission_cache.invalidate(str(self._path))

    def _revoke_access(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> None:
        """Internal method to revoke permission from a user."""
        access_dict = read_syftpub_yaml(self._path.parent, self._name) or {}
        users = set(access_dict.get(permission, []))
        # Handle revoking from public access
        if user in ["*", "public"]:
            users = set()  # Clear all if revoking public
        else:
            users.discard(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path.parent, self._name, access_dict)

        # Invalidate cache for this path and its parents
        _permission_cache.invalidate(str(self._path))

    def _check_permission(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            return True

        # Implement permission hierarchy following old syftbox logic: Admin > Write > Create > Read
        # Get all permission sets
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check public access for each level
        everyone_admin = "*" in admin_users
        everyone_write = "*" in write_users
        everyone_create = "*" in create_users
        everyone_read = "*" in read_users

        # Check user-specific access following old syftbox hierarchy logic
        is_admin = everyone_admin or user in admin_users
        is_writer = is_admin or everyone_write or user in write_users
        is_creator = is_writer or everyone_create or user in create_users
        is_reader = is_creator or everyone_read or user in read_users

        # Return based on requested permission level
        if permission == "admin":
            return is_admin
        elif permission == "write":
            return is_writer
        elif permission == "create":
            return is_creator
        elif permission == "read":
            return is_reader

    def _get_all_permissions_with_sources(self) -> Dict[str, Any]:
        """Get all permissions using old syftbox nearest-node algorithm with source tracking."""
        # Start with empty permissions and sources
        effective_perms: Dict[str, List[str]] = {"read": [], "create": [], "write": [], "admin": []}
        source_info: Dict[str, List[Dict[str, Any]]] = {
            "read": [],
            "create": [],
            "write": [],
            "admin": [],
        }
        terminal_path = None
        terminal_pattern = None  # Track the pattern that was matched in terminal
        matched_pattern = None  # Track any pattern that was matched (terminal or non-terminal)

        # Walk up the directory tree to find the nearest node with matching rules
        current_path = self._path
        while current_path.parent != current_path:  # Stop at root
            parent_dir = current_path.parent
            syftpub_path = parent_dir / "syft.pub.yaml"

            if syftpub_path.exists():
                try:
                    with open(syftpub_path, "r") as f:
                        content = yaml.safe_load(f) or {"rules": []}

                    # Check if this is a terminal node
                    if content.get("terminal", False):
                        terminal_path = syftpub_path
                        # Terminal nodes stop inheritance and their rules take precedence
                        rules = content.get("rules", [])
                        sorted_rules = _sort_rules_by_specificity(rules)
                        for rule in sorted_rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our file path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path):
                                matched_pattern = pattern  # Also track in general matched pattern
                                access = rule.get("access", {})

                                # Check file limits if present
                                limits = rule.get("limits", {})
                                if limits:
                                    # Check if directories are allowed
                                    if (
                                        not limits.get("allow_dirs", True)
                                        and self._path is not None
                                        and self._path.is_dir()
                                    ):
                                        continue  # Skip this rule for directories

                                    # Check if symlinks are allowed
                                    if not limits.get("allow_symlinks", True) and self._is_symlink:
                                        continue  # Skip this rule for symlinks

                                    # Check file size limits
                                    max_file_size = limits.get("max_file_size")
                                    if max_file_size is not None:
                                        if self._size > max_file_size:
                                            continue  # Skip this rule if file exceeds size limit

                                # Terminal rules override everything - return immediately
                                for perm in ["read", "create", "write", "admin"]:
                                    users = format_users(access.get(perm, []))
                                    effective_perms[perm] = users
                                    if users:
                                        source_info[perm] = [
                                            {
                                                "path": syftpub_path,
                                                "pattern": pattern,
                                                "terminal": True,
                                                "inherited": False,
                                            }
                                        ]
                                return {
                                    "permissions": effective_perms,
                                    "sources": source_info,
                                    "terminal": terminal_path,
                                    "terminal_pattern": terminal_pattern,
                                    "matched_pattern": matched_pattern,
                                }
                        # If no match in terminal, stop inheritance with empty permissions
                        return {
                            "permissions": effective_perms,
                            "sources": source_info,
                            "terminal": terminal_path,
                            "terminal_pattern": terminal_pattern,
                            "matched_pattern": matched_pattern,
                        }

                    # Process rules for non-terminal nodes (sort by specificity first)
                    rules = content.get("rules", [])
                    sorted_rules = _sort_rules_by_specificity(rules)
                    found_matching_rule = False
                    for rule in sorted_rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our file path relative to this directory
                        rel_path = (
                            str(self._path.relative_to(parent_dir))
                            if self._path is not None
                            else ""
                        )
                        if _glob_match(pattern, rel_path):
                            access = rule.get("access", {})

                            # Check file limits if present
                            limits = rule.get("limits", {})
                            if limits:
                                # Check if directories are allowed
                                if not limits.get("allow_dirs", True) and self._path.is_dir():
                                    continue  # Skip this rule for directories

                                # Check if symlinks are allowed
                                if not limits.get("allow_symlinks", True) and self._is_symlink:
                                    continue  # Skip this rule for symlinks

                                # Check file size limits
                                max_file_size = limits.get("max_file_size")
                                if max_file_size is not None:
                                    if self._size > max_file_size:
                                        continue  # Skip this rule if file exceeds size limit

                            # Found a matching rule - this becomes our nearest node
                            matched_pattern = pattern  # Track the matched pattern
                            # Use this node's permissions (not accumulate)
                            for perm in ["read", "create", "write", "admin"]:
                                users = format_users(access.get(perm, []))
                                effective_perms[perm] = users
                                if users:
                                    source_info[perm] = [
                                        {
                                            "path": syftpub_path,
                                            "pattern": pattern,
                                            "terminal": False,
                                            "inherited": parent_dir != self._path.parent,
                                        }
                                    ]
                            found_matching_rule = True
                            # Stop at first matching rule
                            # (rules should be sorted by specificity)
                            break

                    # If we found a matching rule, this is our nearest node - stop searching
                    if found_matching_rule:
                        break

                except Exception:
                    pass

            current_path = parent_dir

        return {
            "permissions": effective_perms,
            "sources": source_info,
            "terminal": terminal_path,
            "terminal_pattern": terminal_pattern,
            "matched_pattern": matched_pattern,
        }

    def _check_permission_with_reasons(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> tuple[bool, List[str]]:
        """Check if a user has a specific permission and return reasons why."""
        reasons = []

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            reasons.append("Owner of path")
            return True, reasons

        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        matched_pattern = perm_data.get("matched_pattern")

        # If blocked by terminal
        if terminal and not any(all_perms.values()):
            reasons.append(f"Blocked by terminal at {terminal.parent}")
            return False, reasons

        # Check hierarchy and build reasons
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check if user has the permission through hierarchy
        has_permission = False

        if permission == "admin":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Explicitly granted admin in {src['path'].parent}")
        elif permission == "write":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Explicitly granted write in {src['path'].parent}")
        elif permission == "create":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Explicitly granted create in {src['path'].parent}")
        elif permission == "read":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Included via create permission in {src['path'].parent}")
            elif "*" in read_users or user in read_users:
                has_permission = True
                if sources.get("read"):
                    src = sources["read"][0]
                    reasons.append(f"Explicitly granted read in {src['path'].parent}")

        # Add pattern info only for the specific permission being checked
        # (not for inherited permissions - that would be confusing)
        if sources.get(permission):
            for src in sources[permission]:
                if src["pattern"]:
                    # Show the pattern that was matched for this specific permission
                    if f"Pattern '{src['pattern']}' matched" not in reasons:
                        reasons.append(f"Pattern '{src['pattern']}' matched")
                    break

        # If we don't have permission but a pattern was matched (terminal or non-terminal),
        # it means the rule was evaluated but didn't grant this permission
        elif matched_pattern and not has_permission:
            if f"Pattern '{matched_pattern}' matched" not in reasons:
                reasons.append(f"Pattern '{matched_pattern}' matched")

        # Check for public access
        if "*" in all_perms.get(permission, []) or (
            has_permission and "*" in [admin_users, write_users, create_users, read_users]
        ):
            if "Public access (*)" not in reasons:
                reasons.append("Public access (*)")

        if not has_permission and not reasons:
            reasons.append("No permission found")

        return has_permission, reasons

    def explain_permissions(self, user: str) -> str:
        """Provide detailed explanation of why user has/lacks permissions."""
        explanation = f"Permission analysis for {user} on {self._path}:\n\n"

        for perm in ["admin", "write", "create", "read"]:
            has_perm, reasons = self._check_permission_with_reasons(user, perm)  # type: ignore
            status = "✓ GRANTED" if has_perm else "✗ DENIED"
            explanation += f"{perm.upper()}: {status}\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            explanation += "\n"

        return explanation

    def set_file_limits(
        self,
        max_size: Optional[int] = None,
        allow_dirs: Optional[bool] = None,
        allow_symlinks: Optional[bool] = None,
    ) -> None:
        """
        Set file limits for this file's permissions (compatible with old ACL).

        Args:
            max_size: Maximum file size in bytes (None to keep current, pass explicitly to change)
            allow_dirs: Whether to allow directories (None to keep current)
            allow_symlinks: Whether to allow symlinks (None to keep current)
        """
        # Read current rule to get existing limits
        rule_data = read_syftpub_yaml_full(self._path.parent, self._name)
        existing_limits = rule_data.get("limits", {}) if rule_data else {}
        access_dict = rule_data.get("access", {}) if rule_data else {}

        # Create limits dictionary by merging with existing values
        limits_dict = existing_limits.copy()

        if max_size is not None:
            limits_dict["max_file_size"] = max_size
        if allow_dirs is not None:
            limits_dict["allow_dirs"] = allow_dirs
        if allow_symlinks is not None:
            limits_dict["allow_symlinks"] = allow_symlinks

        # Set defaults for new limits
        if "allow_dirs" not in limits_dict:
            limits_dict["allow_dirs"] = True
        if "allow_symlinks" not in limits_dict:
            limits_dict["allow_symlinks"] = True

        # Update with both access and limits
        update_syftpub_yaml(self._path.parent, self._name, access_dict, limits_dict)

        # Invalidate cache
        _permission_cache.invalidate(str(self._path))

    def get_file_limits(self) -> Dict[str, Any]:
        """
        Get file limits for this file's permissions.

        Returns:
            Dict containing:
                - max_file_size: Maximum file size in bytes (None if no limit)
                - allow_dirs: Whether directories are allowed (bool)
                - allow_symlinks: Whether symlinks are allowed (bool)
                - has_limits: Whether any limits are set (bool)
        """
        # Read current rule to get limits
        rule_data = read_syftpub_yaml_full(self._path.parent, self._name)
        limits = rule_data.get("limits", {}) if rule_data else {}

        # Get limits with defaults
        max_file_size = limits.get("max_file_size")
        allow_dirs = limits.get("allow_dirs", True)
        allow_symlinks = limits.get("allow_symlinks", True)
        has_limits = bool(limits)

        return {
            "max_file_size": max_file_size,
            "allow_dirs": allow_dirs,
            "allow_symlinks": allow_symlinks,
            "has_limits": has_limits,
        }

    def move_file_and_its_permissions(self, new_path: Union[str, Path]) -> "SyftFile":
        """
        Move the file to a new location while preserving its permissions.

        Args:
            new_path: The destination path for the file

        Returns:
            SyftFile: A new SyftFile instance pointing to the moved file

        Raises:
            FileNotFoundError: If source file doesn't exist
            FileExistsError: If destination file already exists
            ValueError: If new_path is invalid
        """
        # Resolve and validate paths
        resolved_new_path = resolve_path(str(new_path))
        if resolved_new_path is None:
            raise ValueError("Could not resolve new path")
        new_path = resolved_new_path

        if not self._path.exists():
            raise FileNotFoundError(f"Source file not found: {self._path}")

        if new_path.exists():
            raise FileExistsError(f"Destination file already exists: {new_path}")

        # Get current permissions
        perms = self._get_all_permissions()

        # Create parent directory if needed
        new_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the file
        shutil.move(str(self._path), str(new_path))

        # Create new SyftFile instance
        new_file = SyftFile(new_path)

        # Apply permissions to new location
        for permission, users in perms.items():
            for user in users:
                if permission in ["read", "create", "write", "admin"]:
                    new_file._grant_access(user, permission)  # type: ignore[arg-type]

        return new_file


class SyftFolder:
    """A folder wrapper that manages SyftBox permissions."""

    def __init__(self, path: Union[str, Path]):
        self._path = Path(path)
        # Ensure folder exists
        self._path.mkdir(parents=True, exist_ok=True)

    @property
    def _name(self) -> str:
        """Get the folder name"""
        return self._path.name

    def _get_all_permissions(self) -> Dict[str, List[str]]:
        """Get all permissions for this folder using old syftbox nearest-node algorithm."""
        # Check cache first
        cache_key = str(self._path)
        cached = _permission_cache.get(cache_key)
        if cached is not None:
            return cached

        # Find the nearest node with matching rules (old syftbox algorithm)
        nearest_permissions: Dict[str, List[str]] = {
            "read": [],
            "create": [],
            "write": [],
            "admin": [],
        }

        # Walk up the directory tree to find the nearest node with matching rules
        current_path = self._path
        while current_path.parent != current_path:  # Stop at root
            parent_dir = current_path.parent
            syftpub_path = parent_dir / "syft.pub.yaml"

            if syftpub_path.exists():
                try:
                    with open(syftpub_path, "r") as f:
                        content = yaml.safe_load(f) or {"rules": []}

                    # Check if this is a terminal node
                    if content.get("terminal", False):
                        # Terminal nodes stop inheritance and their rules take precedence
                        rules = content.get("rules", [])
                        sorted_rules = _sort_rules_by_specificity(rules)
                        for rule in sorted_rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our folder path
                            # relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path) or _glob_match(
                                pattern, rel_path + "/"
                            ):
                                access = rule.get("access", {})
                                # Check file limits if present
                                limits = rule.get("limits", {})
                                if limits:
                                    # Check if directories are allowed
                                    if not limits.get("allow_dirs", True):
                                        continue  # Skip this rule for directories

                                # Terminal rules override everything - return immediately
                                result = {
                                    perm: format_users(access.get(perm, []))
                                    for perm in ["read", "create", "write", "admin"]
                                }
                                _permission_cache.set(cache_key, result)
                                return result
                        # If no match in terminal, stop inheritance with empty permissions
                        _permission_cache.set(cache_key, nearest_permissions)
                        return nearest_permissions

                    # Process rules for non-terminal nodes (sort by specificity first)
                    rules = content.get("rules", [])
                    sorted_rules = _sort_rules_by_specificity(rules)
                    found_matching_rule = False
                    for rule in sorted_rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our folder path relative to this directory
                        rel_path = str(self._path.relative_to(parent_dir))
                        if _glob_match(pattern, rel_path) or _glob_match(pattern, rel_path + "/"):
                            access = rule.get("access", {})
                            # Check file limits if present
                            limits = rule.get("limits", {})
                            if limits:
                                # Check if directories are allowed
                                if not limits.get("allow_dirs", True):
                                    continue  # Skip this rule for directories

                            # Found a matching rule - this becomes our nearest node
                            # Use this node's permissions (not accumulate)
                            nearest_permissions = {
                                perm: format_users(access.get(perm, []))
                                for perm in ["read", "create", "write", "admin"]
                            }
                            found_matching_rule = True
                            # Stop at first matching rule
                            # (rules should be sorted by specificity)
                            break

                    # If we found a matching rule, this is our nearest node - stop searching
                    if found_matching_rule:
                        break

                except Exception:
                    pass

            current_path = parent_dir

        # Cache and return the effective permissions
        _permission_cache.set(cache_key, nearest_permissions)
        return nearest_permissions

    def _get_permission_table(self) -> List[List[str]]:
        """Get permissions formatted as a table showing effective permissions.

        Shows hierarchy and reasons.
        """
        perms = self._get_all_permissions()

        # Get all unique users
        all_users = set()
        for users in perms.values():
            all_users.update(users)

        # Create table rows
        rows = []

        # First add public if it exists
        if "*" in all_users:
            # Collect all reasons for public

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons("*", "read")
            create_has, create_reasons = self._check_permission_with_reasons("*", "create")
            write_has, write_reasons = self._check_permission_with_reasons("*", "write")
            admin_has, admin_reasons = self._check_permission_with_reasons("*", "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            rows.append(
                [
                    "public",
                    "✓" if read_has else "",
                    "✓" if create_has else "",
                    "✓" if write_has else "",
                    "✓" if admin_has else "",
                    reason_text,
                ]
            )
            all_users.remove("*")  # Remove so we don't process it again

        # Then add all other users
        for user in sorted(all_users):
            # Collect all reasons for this user

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons(user, "read")
            create_has, create_reasons = self._check_permission_with_reasons(user, "create")
            write_has, write_reasons = self._check_permission_with_reasons(user, "write")
            admin_has, admin_reasons = self._check_permission_with_reasons(user, "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            row = [
                user,
                "✓" if read_has else "",
                "✓" if create_has else "",
                "✓" if write_has else "",
                "✓" if admin_has else "",
                reason_text,
            ]
            rows.append(row)

        return rows

    def __repr__(self) -> str:
        """Return string representation showing permissions table."""
        rows = self._get_permission_table()
        if not rows:
            return f"SyftFolder('{self._path}') - No permissions set"

        try:
            from tabulate import tabulate

            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="simple",
            )
            return f"SyftFolder('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFolder('{self._path}')\n"]
            result.append("User               Read  Create  Write  Admin  Reason")
            result.append("-" * 70)
            for row in rows:
                result.append(
                    f"{row[0]:<20} {row[1]:<5} {row[2]:<7} {row[3]:<6} "
                    f"{row[4]:<5} {row[5] if len(row) > 5 else ''}"
                )
            return "\n".join(result)

    def _ensure_server_and_get_editor_url(self) -> str:
        """Ensure the permission editor server is running and return the editor URL."""
        try:
            from ._auto_recovery import ensure_server_running
            from .server import get_editor_url, get_server_url, start_server

            # Check if server is already running
            server_url = get_server_url()
            if server_url:
                # Verify it's actually responding
                success, error = ensure_server_running(server_url)
                if not success:
                    print(f"Server health check failed: {error}")
                    server_url = None

            if not server_url:
                # Start the server
                server_url = start_server()
                print(f"🚀 SyftPerm permission editor started at: {server_url}")

            # Return the editor URL for this folder
            return get_editor_url(str(self._path))

        except ImportError:
            # FastAPI not available
            return "Install 'syft-perm[server]' for permission editor"
        except Exception as e:
            # Server failed to start
            return f"Permission editor unavailable: {e}"

    def _get_loading_html(self) -> str:
        """Get static HTML to show while server is starting."""
        import threading
        import uuid

        # Generate unique ID for this instance
        instance_id = str(uuid.uuid4())

        # Start server recovery in background
        def start_server_background():
            try:
                self._ensure_server_and_get_editor_url()
            except Exception:
                pass  # Silently fail in background

        thread = threading.Thread(target=start_server_background, daemon=True)
        thread.start()

        # Return static HTML with auto-refresh
        return f"""
        <div id="syft-perm-{instance_id}" style="padding: 20px; background: #f5f5f5; border-radius: 8px; font-family: sans-serif;">  # noqa: E501
            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>
            <div style="background: white; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <p style="margin: 0;"><strong>File:</strong> {self._path}</p>
            </div>
            <div style="background: #e3f2fd; padding: 15px; border-radius: 4px; text-align: center;">  # noqa: E501
                <div style="display: inline-block;">
                    <div style="border: 3px solid #1976d2; border-radius: 50%; border-top-color: transparent;  # noqa: E501
                                width: 30px; height: 30px; animation: spin-{instance_id} 1s linear infinite;  # noqa: E501
                                margin: 0 auto 10px;"></div>
                    <p style="color: #1976d2; margin: 0;">Starting permission editor server...</p>
                    <p style="color: #666; font-size: 0.9em; margin-top: 5px;">This may take a moment if auto-recovery is needed</p>  # noqa: E501
                </div>
            </div>
            <style>
                @keyframes spin-{instance_id} {{
                    to {{ transform: rotate(360deg); }}
                }}
            </style>
            <script>
                (function() {{
                    let attempts = 0;
                    const maxAttempts = 30;
                    const checkInterval = 2000;

                    function checkServerAndReload() {{
                        attempts++;

                        // Try to fetch from the expected server
                        fetch('http://127.0.0.1:8765/')
                            .then(response => {{
                                if (response.ok) {{
                                    // Server is ready, reload the cell output
                                    if (window.Jupyter && window.Jupyter.notebook) {{
                                        // Find and re-execute this cell
                                        const cells = window.Jupyter.notebook.get_cells();
                                        for (let cell of cells) {{
                                            if (cell.output_area && cell.output_area.element) {{
                                                const output = cell.output_area.element[0];
                                                if (output && output.innerHTML.includes('syft-perm-{instance_id}')) {{  # noqa: E501
                                                    cell.execute();
                                                    return;
                                                }}
                                            }}
                                        }}
                                    }}
                                }}
                            }})
                            .catch(() => {{
                                // Server not ready yet
                                if (attempts < maxAttempts) {{
                                    setTimeout(checkServerAndReload, checkInterval);
                                }} else {{
                                    // Update the UI to show failure
                                    const elem = document.getElementById('syft-perm-{instance_id}');
                                    if (elem) {{
                                        elem.innerHTML = `
                                            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>  # noqa: E501
                                            <div style="background: #ffebee; padding: 15px; border-radius: 4px; color: #c62828;">  # noqa: E501
                                                <p style="margin: 0;"><strong>Error:</strong> Failed to start permission editor server</p>  # noqa: E501
                                                <p style="margin: 5px 0 0 0; font-size: 0.9em;">Please check your installation and try again</p>  # noqa: E501
                                            </div>
                                        `;
                                    }}
                                }}
                            }});
                    }}

                    // Start checking after a short delay
                    setTimeout(checkServerAndReload, 1000);
                }})();
            </script>
        </div>
        """

    def _repr_html_(self) -> str:
        """Return Google Drive-style permissions interface for Jupyter notebooks."""
        import hashlib
        import os

        # Get permission data
        permissions_data = self._get_all_permissions()

        # Function to generate consistent avatar colors based on email hash
        def get_avatar_color(email):
            colors = [
                "#1976d2",
                "#388e3c",
                "#f57c00",
                "#d32f2f",
                "#7b1fa2",
                "#303f9f",
                "#0288d1",
                "#0097a7",
                "#00796b",
                "#689f38",
                "#afb42b",
                "#fbc02d",
                "#ffa000",
                "#f57c00",
                "#e64a19",
                "#5d4037",
                "#616161",
                "#455a64",
            ]
            hash_obj = hashlib.md5(email.encode())
            return colors[int(hash_obj.hexdigest(), 16) % len(colors)]

        # Function to get initials from email
        def get_initials(email):
            if email == "*":
                return "PU"  # Public
            parts = email.split("@")[0].split(".")
            if len(parts) >= 2:
                return (parts[0][0] + parts[1][0]).upper()
            return email[0:2].upper()

        # Function to get highest syft permission level
        def get_highest_permission(permissions):
            if "admin" in permissions:
                return "Admin"
            elif "write" in permissions:
                return "Write"
            elif "create" in permissions:
                return "Create"
            elif "read" in permissions:
                return "Read"
            return "No access"

        # Collect all users with their permissions
        all_users = set()
        for perm_type, users in permissions_data.items():
            all_users.update(users)

        # Build user list with their highest permission level
        user_permissions = {}
        for user in all_users:
            user_perms = []
            for perm_type, users in permissions_data.items():
                if user in users:
                    user_perms.append(perm_type)
            user_permissions[user] = user_perms

        # Get current user (folder owner)
        current_user = os.path.basename(os.path.expanduser("~"))

        # Create hybrid interface with syft-objects styling and Google Drive layout
        html = f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    font-size: 0.75rem; background: #ffffff; border: 1px solid #e5e7eb;
                    border-radius: 0.25rem; margin: 8px 0; height: 200px;
                    display: flex; flex-direction: column;">
            <div style="background: #f8f9fa; padding: 0.375rem 0.5rem;
                        border-bottom: 1px solid #e5e7eb; flex-shrink: 0;
                        position: sticky; top: 0; z-index: 10;">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="display: flex; align-items: center; gap: 0.25rem;">
                        <svg width="20" height="20" viewBox="0 0 311 360" fill="none" xmlns="http://www.w3.org/2000/svg"><g clip-path="url(#clip0_folder)"><path d="M311.414 89.7878L155.518 179.998L-0.378906 89.7878L155.518 -0.422485L311.414 89.7878Z" fill="url(#paint0_linear_folder)"/><path d="M311.414 89.7878V270.208L155.518 360.423V179.998L311.414 89.7878Z" fill="url(#paint1_linear_folder)"/><path d="M155.518 179.998V360.423L-0.378906 270.208V89.7878L155.518 179.998Z" fill="url(#paint2_linear_folder)"/></g><defs><linearGradient id="paint0_linear_folder" x1="-0.378904" y1="89.7878" x2="311.414" y2="89.7878" gradientUnits="userSpaceOnUse"><stop stop-color="#DC7A6E"/><stop offset="0.251496" stop-color="#F6A464"/><stop offset="0.501247" stop-color="#FDC577"/><stop offset="0.753655" stop-color="#EFC381"/><stop offset="1" stop-color="#B9D599"/></linearGradient><linearGradient id="paint1_linear_folder" x1="309.51" y1="89.7878" x2="155.275" y2="360.285" gradientUnits="userSpaceOnUse"><stop stop-color="#BFCD94"/><stop offset="0.245025" stop-color="#B2D69E"/><stop offset="0.504453" stop-color="#8DCCA6"/><stop offset="0.745734" stop-color="#5CB8B7"/><stop offset="1" stop-color="#4CA5B8"/></linearGradient><linearGradient id="paint2_linear_folder" x1="-0.378906" y1="89.7878" x2="155.761" y2="360.282" gradientUnits="userSpaceOnUse"><stop stop-color="#D7686D"/><stop offset="0.225" stop-color="#C64B77"/><stop offset="0.485" stop-color="#A2638E"/><stop offset="0.703194" stop-color="#758AA8"/><stop offset="1" stop-color="#639EAF"/></linearGradient><clipPath id="clip0_folder"><rect width="311" height="360" fill="white"/></clipPath></defs></svg>  # noqa: E501
                        <div>
                            <div style="font-size: 0.875rem; font-weight: 500; color: #374151;">
                                {self._path.name or 'Root Folder'}
                            </div>
                            <div style="font-size: 0.75rem; color: #6b7280;">
                                Owner: {current_user}
                            </div>
                        </div>
                    </div>
                    <div style="font-size: 0.75rem; color: #6b7280; font-weight: 500;">
                        PERMISSIONS
                    </div>
                </div>
            </div>
            <div style="flex: 1; overflow-y: auto; padding: 0;">
        """

        # Add each user
        for user in sorted(user_permissions.keys()):
            permissions = user_permissions[user]
            role = get_highest_permission(permissions)
            initials = get_initials(user)
            color = get_avatar_color(user)

            # Determine if this is public access
            display_name = "Anyone with the link" if user == "*" else user

            # Get permission reasons for this user
            has_permission, reasons = self._check_permission_with_reasons(user, role.lower())
            reason_text = (
                "; ".join(reasons[:2]) if reasons else "Direct permission"
            )  # Limit to 2 reasons

            html += f"""
                <div style="display: flex; align-items: center; padding: 0.375rem 0.5rem;
                            gap: 0.5rem; border-bottom: 1px solid #f3f4f6;
                            transition: background-color 0.15s; cursor: pointer;"
                     onmouseover="this.style.background='rgba(0, 0, 0, 0.03)'"
                     onmouseout="this.style.background='transparent'">
                    <div style="width: 1.25rem; height: 1.25rem; border-radius: 50%;
                                background: {color}; display: flex; align-items: center;
                                justify-content: center; flex-shrink: 0;">
                        <span style="color: white; font-size: 0.625rem; font-weight: 500;">
                            {initials}
                        </span>
                    </div>
                    <div style="flex: 1; min-width: 0; display: flex;
                                align-items: center; gap: 0.75rem;">
                        <div style="font-size: 0.75rem; color: #374151; font-weight: 500;
                                    overflow: hidden; text-overflow: ellipsis;
                                    white-space: nowrap; min-width: 0;">
                            {display_name}
                        </div>
                        <div style="font-size: 0.625rem; color: #6b7280;
                                    overflow: hidden; text-overflow: ellipsis;
                                    white-space: nowrap; flex: 1; min-width: 0;">
                            {reason_text}
                        </div>
                    </div>
                    <div style="margin-left: 0.5rem;">
                        <span style="display: inline-flex; align-items: center;
                                     padding: 0.125rem 0.375rem; border-radius: 0.25rem;
                                     font-size: 0.625rem; font-weight: 500;
                                     background: #f3f4f6; color: #374151;">
                            {role.upper()}
                        </span>
                    </div>
                </div>
            """

        # If no users have access
        if not user_permissions:
            html += """
                <div style="text-align: center; padding: 1rem; color: #6b7280;">
                    <div style="font-size: 0.75rem; font-weight: 500;">No permissions set</div>
                    <div style="font-size: 0.75rem; margin-top: 0.125rem;">
                        Only the owner has access
                    </div>
                </div>
            """

        html += """
            </div>
        </div>
        """

        return html

    def grant_read_access(self, user: str, *, force: bool = False) -> None:
        """Grant read permission to a user."""
        self._grant_access(user, "read", force=force)

    def grant_create_access(self, user: str, *, force: bool = False) -> None:
        """Grant create permission to a user."""
        self._grant_access(user, "create", force=force)

    def grant_write_access(self, user: str, *, force: bool = False) -> None:
        """Grant write permission to a user."""
        if user in ["*", "public"] and not _confirm_action(
            f"⚠️  Warning: Granting public write access to '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "write", force=force)

    def grant_admin_access(self, user: str, *, force: bool = False) -> None:
        """Grant admin permission to a user."""
        if not _confirm_action(
            f"⚠️  Warning: Granting admin access to '{user}' for '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "admin", force=force)

    def revoke_read_access(self, user: str) -> None:
        """Revoke read permission from a user."""
        self._revoke_access(user, "read")

    def revoke_create_access(self, user: str) -> None:
        """Revoke create permission from a user."""
        self._revoke_access(user, "create")

    def revoke_write_access(self, user: str) -> None:
        """Revoke write permission from a user."""
        self._revoke_access(user, "write")

    def revoke_admin_access(self, user: str) -> None:
        """Revoke admin permission from a user."""
        self._revoke_access(user, "admin")

    def has_read_access(self, user: str) -> bool:
        """Check if a user has read permission."""
        return self._check_permission(user, "read")

    def has_create_access(self, user: str) -> bool:
        """Check if a user has create permission."""
        return self._check_permission(user, "create")

    def has_write_access(self, user: str) -> bool:
        """Check if a user has write permission."""
        return self._check_permission(user, "write")

    def has_admin_access(self, user: str) -> bool:
        """Check if a user has admin permission."""
        return self._check_permission(user, "admin")

    def _grant_access(
        self,
        user: str,
        permission: Literal["read", "create", "write", "admin"],
        *,
        force: bool = False,
    ) -> None:
        """Internal method to grant permission to a user."""
        # Validate that the email belongs to a datasite
        if not is_datasite_email(user) and not force:
            raise ValueError(
                f"'{user}' is not a valid datasite email. "
                f"Use force=True to override this check."
            )

        # Read all existing permissions for this file
        access_dict = read_syftpub_yaml(self._path.parent, self._name) or {}

        # Update the specific permission
        users = set(access_dict.get(permission, []))
        users.add(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present (even if empty)
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path.parent, self._name, access_dict)

        # Invalidate cache for this path and its children
        _permission_cache.invalidate(str(self._path))

    def _revoke_access(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> None:
        """Internal method to revoke permission from a user."""
        access_dict = read_syftpub_yaml(self._path.parent, self._name) or {}
        users = set(access_dict.get(permission, []))
        # Handle revoking from public access
        if user in ["*", "public"]:
            users = set()  # Clear all if revoking public
        else:
            users.discard(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path.parent, self._name, access_dict)

        # Invalidate cache for this path and its children
        _permission_cache.invalidate(str(self._path))

    def _check_permission(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            return True

        # Implement permission hierarchy following old syftbox logic: Admin > Write > Create > Read
        # Get all permission sets
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check public access for each level
        everyone_admin = "*" in admin_users
        everyone_write = "*" in write_users
        everyone_create = "*" in create_users
        everyone_read = "*" in read_users

        # Check user-specific access following old syftbox hierarchy logic
        is_admin = everyone_admin or user in admin_users
        is_writer = is_admin or everyone_write or user in write_users
        is_creator = is_writer or everyone_create or user in create_users
        is_reader = is_creator or everyone_read or user in read_users

        # Return based on requested permission level
        if permission == "admin":
            return is_admin
        elif permission == "write":
            return is_writer
        elif permission == "create":
            return is_creator
        elif permission == "read":
            return is_reader

    def _check_permission_with_reasons(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> tuple[bool, List[str]]:
        """Check if a user has a specific permission and return reasons why."""
        reasons = []

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            reasons.append("Owner of path")
            return True, reasons

        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        matched_pattern = perm_data.get("matched_pattern")

        # If blocked by terminal
        if terminal and not any(all_perms.values()):
            reasons.append(f"Blocked by terminal at {terminal.parent}")
            return False, reasons

        # Check hierarchy and build reasons
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check if user has the permission through hierarchy
        has_permission = False

        if permission == "admin":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Explicitly granted admin in {src['path'].parent}")
        elif permission == "write":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Explicitly granted write in {src['path'].parent}")
        elif permission == "create":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Explicitly granted create in {src['path'].parent}")
        elif permission == "read":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Included via create permission in {src['path'].parent}")
            elif "*" in read_users or user in read_users:
                has_permission = True
                if sources.get("read"):
                    src = sources["read"][0]
                    reasons.append(f"Explicitly granted read in {src['path'].parent}")

        # Add pattern info only for the specific permission being checked
        # (not for inherited permissions - that would be confusing)
        if sources.get(permission):
            for src in sources[permission]:
                if src["pattern"]:
                    # Show the pattern that was matched for this specific permission
                    if f"Pattern '{src['pattern']}' matched" not in reasons:
                        reasons.append(f"Pattern '{src['pattern']}' matched")
                    break

        # If we don't have permission but a pattern was matched (terminal or non-terminal),
        # it means the rule was evaluated but didn't grant this permission
        elif matched_pattern and not has_permission:
            if f"Pattern '{matched_pattern}' matched" not in reasons:
                reasons.append(f"Pattern '{matched_pattern}' matched")

        # Check for public access
        if "*" in all_perms.get(permission, []) or (
            has_permission and "*" in [admin_users, write_users, create_users, read_users]
        ):
            if "Public access (*)" not in reasons:
                reasons.append("Public access (*)")

        if not has_permission and not reasons:
            reasons.append("No permission found")

        return has_permission, reasons

    def explain_permissions(self, user: str) -> str:
        """Provide detailed explanation of why user has/lacks permissions."""
        explanation = f"Permission analysis for {user} on {self._path}:\n\n"

        for perm in ["admin", "write", "create", "read"]:
            has_perm, reasons = self._check_permission_with_reasons(user, perm)  # type: ignore
            status = "✓ GRANTED" if has_perm else "✗ DENIED"
            explanation += f"{perm.upper()}: {status}\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            explanation += "\n"

        return explanation

    def set_file_limits(
        self,
        max_size: Optional[int] = None,
        allow_dirs: Optional[bool] = None,
        allow_symlinks: Optional[bool] = None,
    ) -> None:
        """
        Set file limits for this folder's permissions.

        Args:
            max_size: Maximum file size in bytes (None to keep current, pass explicitly to change)
            allow_dirs: Whether to allow directories (None to keep current)
            allow_symlinks: Whether to allow symlinks (None to keep current)
        """
        # Read current rule to get existing limits
        rule_data = read_syftpub_yaml_full(self._path.parent, self._name)
        existing_limits = rule_data.get("limits", {}) if rule_data else {}
        access_dict = rule_data.get("access", {}) if rule_data else {}

        # Create limits dictionary by merging with existing values
        limits_dict = existing_limits.copy()

        if max_size is not None:
            limits_dict["max_file_size"] = max_size
        if allow_dirs is not None:
            limits_dict["allow_dirs"] = allow_dirs
        if allow_symlinks is not None:
            limits_dict["allow_symlinks"] = allow_symlinks

        # Set defaults for new limits
        if "allow_dirs" not in limits_dict:
            limits_dict["allow_dirs"] = True
        if "allow_symlinks" not in limits_dict:
            limits_dict["allow_symlinks"] = True

        # Update with both access and limits
        update_syftpub_yaml(self._path.parent, self._name, access_dict, limits_dict)

        # Invalidate cache
        _permission_cache.invalidate(str(self._path))

    def get_file_limits(self) -> Dict[str, Any]:
        """
        Get file limits for this folder's permissions.

        Returns:
            Dict containing:
                - max_file_size: Maximum file size in bytes (None if no limit)
                - allow_dirs: Whether directories are allowed (bool)
                - allow_symlinks: Whether symlinks are allowed (bool)
                - has_limits: Whether any limits are set (bool)
        """
        # Read current rule to get limits
        rule_data = read_syftpub_yaml_full(self._path.parent, self._name)
        limits = rule_data.get("limits", {}) if rule_data else {}

        # Get limits with defaults
        max_file_size = limits.get("max_file_size")
        allow_dirs = limits.get("allow_dirs", True)
        allow_symlinks = limits.get("allow_symlinks", True)
        has_limits = bool(limits)

        return {
            "max_file_size": max_file_size,
            "allow_dirs": allow_dirs,
            "allow_symlinks": allow_symlinks,
            "has_limits": has_limits,
        }

    def move_folder_and_permissions(
        self, new_path: Union[str, Path], *, force: bool = False
    ) -> "SyftFolder":
        """
        Move the folder to a new location while preserving all permissions recursively.

        Args:
            new_path: The destination path for the folder
            force: Skip confirmation for moving large folders

        Returns:
            SyftFolder: A new SyftFolder instance pointing to the moved folder

        Raises:
            FileNotFoundError: If source folder doesn't exist
            FileExistsError: If destination folder already exists
            ValueError: If new_path is invalid
        """
        # Resolve and validate paths
        resolved_new_path = resolve_path(str(new_path))
        if resolved_new_path is None:
            raise ValueError("Could not resolve new path")
        new_path = resolved_new_path

        if not self._path.exists():
            raise FileNotFoundError(f"Source folder not found: {self._path}")

        if new_path.exists():
            raise FileExistsError(f"Destination folder already exists: {new_path}")

        # Count files for large folder warning
        file_count = sum(1 for _ in self._path.rglob("*"))
        if file_count > 100 and not _confirm_action(
            f"⚠️  Warning: Moving large folder with {file_count} files. "
            f"This may take a while. Continue?",
            force=force,
        ):
            print("Operation cancelled.")
            return self

        # Get permissions for all files and folders
        permission_map = {}
        for item in self._path.rglob("*"):
            if item.is_file():
                file_obj = SyftFile(item)
                permission_map[item] = file_obj._get_all_permissions()
            elif item.is_dir():
                folder_obj = SyftFolder(item)
                permission_map[item] = folder_obj._get_all_permissions()

        # Also store root folder permissions
        permission_map[self._path] = self._get_all_permissions()

        # Create parent directory if needed
        new_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the folder
        shutil.move(str(self._path), str(new_path))

        # Create new SyftFolder instance
        new_folder = SyftFolder(new_path)

        # Reapply all permissions
        for old_path, perms in permission_map.items():
            # Calculate new path
            rel_path = old_path.relative_to(self._path)
            new_item_path = new_path / rel_path

            # Apply permissions
            if new_item_path.is_file():
                file_obj = SyftFile(new_item_path)
                for permission, users in perms.items():
                    for user in users:
                        if permission in ["read", "create", "write", "admin"]:
                            file_obj._grant_access(user, permission)  # type: ignore[arg-type]
            elif new_item_path.is_dir():
                folder_obj = SyftFolder(new_item_path)
                for permission, users in perms.items():
                    for user in users:
                        if permission in ["read", "create", "write", "admin"]:
                            folder_obj._grant_access(user, permission)  # type: ignore[arg-type]

        return new_folder

    def _get_all_permissions_with_sources(self) -> Dict[str, Any]:
        # Temporary: delegate to SyftFile logic for folder
        from ._impl import SyftFile

        file_obj = SyftFile(self._path)
        return file_obj._get_all_permissions_with_sources()
