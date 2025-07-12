"""Internal implementation of SyftFile and SyftFolder classes with ACL compatibility."""

from pathlib import Path
from typing import Optional, List, Dict, Union, Iterator, Literal, Any
import shutil
import time
from collections import OrderedDict

from ._utils import (
    resolve_path,
    create_access_dict,
    update_syftpub_yaml,
    read_syftpub_yaml,
    read_syftpub_yaml_full,
    format_users,
    is_datasite_email,
)
import yaml
from pathlib import PurePath
from enum import Enum
from dataclasses import dataclass

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
    source_paths: List[Path] = None
    patterns: List[str] = None

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
        "keys": list(_permission_cache.cache.keys())
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
    import os
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
    suffix = pattern[double_star_idx + 2:].lstrip("/")
    
    # Match the prefix
    if prefix:
        # For doublestar patterns, prefix should match at the beginning of the path
        # or we need to try matching the entire pattern at later positions (for leading **)
        if path == prefix:
            # Exact match
            remaining = ""
        elif path.startswith(prefix + "/"):
            # Path starts with prefix followed by separator
            remaining = path[len(prefix) + 1:]
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
    
    char_class = pattern[start_idx + 1:end_idx]
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
    return response in ['y', 'yes']

class SyftFile:
    """A file wrapper that manages SyftBox permissions."""
    
    def __init__(self, path: Union[str, Path]):
        self._path = resolve_path(path)
        if self._path is None:
            raise ValueError("Could not resolve path")
            
        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)
        
        # File metadata for limit checks
        self._is_symlink = self._path.is_symlink() if self._path.exists() else False
        self._size = self._path.stat().st_size if self._path.exists() and not self._is_symlink else 0
    
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
        nearest_permissions = {"read": [], "create": [], "write": [], "admin": []}
        
        # Walk up the directory tree to find the nearest node with matching rules
        current_path = self._path
        while current_path.parent != current_path:  # Stop at root
            parent_dir = current_path.parent
            syftpub_path = parent_dir / "syft.pub.yaml"
            
            if syftpub_path.exists():
                try:
                    with open(syftpub_path, 'r') as f:
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
                                
                                # Terminal rules: use first matching rule (most specific due to sorting)
                                result = {perm: format_users(access.get(perm, [])) for perm in ["read", "create", "write", "admin"]}
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
                        rel_path = str(self._path.relative_to(parent_dir))
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
                            
                            # Found a matching rule - use the first matching rule since they're sorted by specificity
                            # This becomes our nearest node (old syftbox: most specific matching rule wins)
                            nearest_permissions = {perm: format_users(access.get(perm, [])) for perm in ["read", "create", "write", "admin"]}
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
        """Get permissions formatted as a table showing effective permissions with hierarchy and reasons."""
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
            all_reasons = set()
            
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
                    if "Included via write permission" not in reason and "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Create] {reason}")
            
            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if ("Included via create permission" not in reason and 
                        "Included via write permission" not in reason and 
                        "Included via admin permission" not in reason):
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
            
            rows.append([
                "public",
                "✓" if read_has else "",
                "✓" if create_has else "",
                "✓" if write_has else "",
                "✓" if admin_has else "",
                reason_text
            ])
            all_users.remove("*")  # Remove so we don't process it again
        
        # Then add all other users
        for user in sorted(all_users):
            # Collect all reasons for this user
            all_reasons = set()
            
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
                    if "Included via write permission" not in reason and "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Create] {reason}")
            
            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if ("Included via create permission" not in reason and 
                        "Included via write permission" not in reason and 
                        "Included via admin permission" not in reason):
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
                reason_text
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
                tablefmt="simple"
            )
            return f"SyftFile('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFile('{self._path}')\n"]
            result.append("User               Read  Create  Write  Admin  Reason")
            result.append("-" * 70)
            for row in rows:
                result.append(f"{row[0]:<20} {row[1]:<5} {row[2]:<7} {row[3]:<6} {row[4]:<5} {row[5] if len(row) > 5 else ''}")
            return "\n".join(result)

    def _ensure_server_and_get_editor_url(self) -> str:
        """Ensure the permission editor server is running and return the editor URL."""
        try:
            from .server import get_server_url, start_server, get_editor_url
            
            # Check if server is already running
            server_url = get_server_url()
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

    def _repr_html_(self) -> str:
        """Return HTML representation for Jupyter notebooks."""
        # Auto-start permission editor server for Jupyter notebook integration
        editor_url = self._ensure_server_and_get_editor_url()
        
        rows = self._get_permission_table()
        
        # Create compliance table showing current state vs limits
        limits = self.get_file_limits()
        
        # File size comparison
        file_size = self._size
        if file_size >= 1024 * 1024 * 1024:
            size_display = f"{file_size / (1024 * 1024 * 1024):.2f} GB"
        elif file_size >= 1024 * 1024:
            size_display = f"{file_size / (1024 * 1024):.2f} MB"
        elif file_size >= 1024:
            size_display = f"{file_size / 1024:.2f} KB"
        else:
            size_display = f"{file_size} bytes"
        
        # Size limit comparison
        if limits["max_file_size"] is not None:
            if limits["max_file_size"] >= 1024 * 1024:
                limit_display = f"{limits['max_file_size'] / (1024 * 1024):.2f} MB"
            elif limits["max_file_size"] >= 1024:
                limit_display = f"{limits['max_file_size'] / 1024:.2f} KB"
            else:
                limit_display = f"{limits['max_file_size']} bytes"
            
            size_status = "✓ OK" if file_size <= limits["max_file_size"] else "✗ EXCEEDS"
        else:
            limit_display = "No limit"
            size_status = "✓ OK"
        
        # Check if this file type is allowed by the limits
        is_dir = self._path.is_dir()
        is_symlink = self._is_symlink
        
        # For files: check if the file itself would be blocked
        type_status = "✓ OK"
        if is_dir and not limits["allow_dirs"]:
            type_status = "✗ BLOCKED (directories not allowed)"
        elif is_symlink and not limits["allow_symlinks"]:
            type_status = "✗ BLOCKED (symlinks not allowed)"
        
        # Overall compliance
        all_ok = size_status.startswith("✓") and type_status.startswith("✓")
        overall_status = "✓ COMPLIANT" if all_ok else "✗ NON-COMPLIANT"
        
        # Build compliance table
        file_type = "Directory" if is_dir else ("Symlink" if is_symlink else "Regular File")
        compliance_html = f'''<p><b>File Compliance Check:</b></p>
<table border="1" style="border-collapse: collapse; margin: 10px 0;">
<tr><th style="padding: 5px;">Property</th><th style="padding: 5px;">Current</th><th style="padding: 5px;">Limit/Setting</th><th style="padding: 5px;">Status</th></tr>
<tr><td style="padding: 5px;">File Size</td><td style="padding: 5px;">{size_display}</td><td style="padding: 5px;">{limit_display}</td><td style="padding: 5px;">{size_status}</td></tr>
<tr><td style="padding: 5px;">File Type</td><td style="padding: 5px;">{file_type}</td><td style="padding: 5px;">Dirs: {'✓' if limits['allow_dirs'] else '✗'} | Symlinks: {'✓' if limits['allow_symlinks'] else '✗'}</td><td style="padding: 5px;">{type_status}</td></tr>
<tr><td style="padding: 5px;"><b>Overall</b></td><td style="padding: 5px;" colspan="2"><b>File access compliance</b></td><td style="padding: 5px;"><b>{overall_status}</b></td></tr>
</table>\n'''
        
        # Add editor link
        editor_link = f'<p style="margin: 10px 0;"><a href="{editor_url}" target="_blank" style="background: #1976d2; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; font-size: 14px;">🖊️ Edit Permissions</a></p>\n'
        
        if not rows:
            return f"<p><b>SyftFile('{self._path}')</b> - No permissions set</p>\n{editor_link}{compliance_html}"
            
        try:
            from tabulate import tabulate
            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="html"
            )
            return f"<p><b>SyftFile('{self._path}')</b></p>\n{editor_link}{compliance_html}{table}"
        except ImportError:
            # Fallback to simple HTML table if tabulate not available
            result = [f"<p><b>SyftFile('{self._path}')</b></p>"]
            result.append(editor_link.strip())
            result.append(compliance_html.strip())
            result.append("<table>")
            result.append("<tr><th>User</th><th>Read</th><th>Create</th><th>Write</th><th>Admin</th><th>Reason</th></tr>")
            for row in rows:
                result.append(f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td><td>{row[4]}</td><td>{row[5] if len(row) > 5 else ''}</td></tr>")
            result.append("</table>")
            return "\n".join(result)

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
            force=force
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "write", force=force)
    
    def grant_admin_access(self, user: str, *, force: bool = False) -> None:
        """Grant admin permission to a user."""
        if not _confirm_action(
            f"⚠️  Warning: Granting admin access to '{user}' for '{self._path}'. Are you sure?",
            force=force
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

    def _grant_access(self, user: str, permission: Literal["read", "create", "write", "admin"], *, force: bool = False) -> None:
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
    
    def _revoke_access(self, user: str, permission: Literal["read", "create", "write", "admin"]) -> None:
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
    
    def _check_permission(self, user: str, permission: Literal["read", "create", "write", "admin"]) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()
        
        # Check if user is the owner using old syftbox logic
        if _is_owner(self._path, user):
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
        else:
            return False
    
    def _get_all_permissions_with_sources(self) -> Dict[str, Any]:
        """Get all permissions using old syftbox nearest-node algorithm with source tracking."""
        # Start with empty permissions and sources
        effective_perms = {"read": [], "create": [], "write": [], "admin": []}
        source_info = {"read": [], "create": [], "write": [], "admin": []}
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
                    with open(syftpub_path, 'r') as f:
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
                                terminal_pattern = pattern  # Track the matched pattern
                                matched_pattern = pattern  # Also track in general matched pattern
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
                                
                                # Terminal rules override everything - return immediately
                                for perm in ["read", "create", "write", "admin"]:
                                    users = format_users(access.get(perm, []))
                                    effective_perms[perm] = users
                                    if users:
                                        source_info[perm] = [{
                                            "path": syftpub_path,
                                            "pattern": pattern,
                                            "terminal": True,
                                            "inherited": False
                                        }]
                                return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path, "terminal_pattern": terminal_pattern, "matched_pattern": matched_pattern}
                        # If no match in terminal, stop inheritance with empty permissions
                        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path, "terminal_pattern": terminal_pattern, "matched_pattern": matched_pattern}
                    
                    # Process rules for non-terminal nodes (sort by specificity first)
                    rules = content.get("rules", [])
                    sorted_rules = _sort_rules_by_specificity(rules)
                    found_matching_rule = False
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
                                    source_info[perm] = [{
                                        "path": syftpub_path,
                                        "pattern": pattern,
                                        "terminal": False,
                                        "inherited": parent_dir != self._path.parent
                                    }]
                            found_matching_rule = True
                            break  # Stop at first matching rule (rules should be sorted by specificity)
                    
                    # If we found a matching rule, this is our nearest node - stop searching
                    if found_matching_rule:
                        break
                        
                except Exception:
                    pass
            
            current_path = parent_dir
        
        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path, "terminal_pattern": terminal_pattern, "matched_pattern": matched_pattern}
    
    def _check_permission_with_reasons(self, user: str, permission: Literal["read", "create", "write", "admin"]) -> tuple[bool, List[str]]:
        """Check if a user has a specific permission and return reasons why."""
        reasons = []
        
        # Check if user is the owner using old syftbox logic
        if _is_owner(self._path, user):
            reasons.append("Owner of path")
            return True, reasons
        
        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        terminal_pattern = perm_data.get("terminal_pattern")
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
        if "*" in all_perms.get(permission, []) or (has_permission and "*" in [admin_users, write_users, create_users, read_users]):
            if "Public access (*)" not in reasons:
                reasons.append("Public access (*)")
        
        if not has_permission and not reasons:
            reasons.append("No permission found")
        
        return has_permission, reasons
    
    def explain_permissions(self, user: str) -> str:
        """Provide detailed explanation of why user has/lacks permissions."""
        explanation = f"Permission analysis for {user} on {self._path}:\n\n"
        
        for perm in ["admin", "write", "create", "read"]:
            has_perm, reasons = self._check_permission_with_reasons(user, perm)
            status = "✓ GRANTED" if has_perm else "✗ DENIED"
            explanation += f"{perm.upper()}: {status}\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            explanation += "\n"
        
        return explanation
    
    def set_file_limits(self, max_size: Optional[int] = None, 
                       allow_dirs: Optional[bool] = None, 
                       allow_symlinks: Optional[bool] = None) -> None:
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
            "has_limits": has_limits
        }

    def move_file_and_its_permissions(self, new_path: Union[str, Path]) -> 'SyftFile':
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
        new_path = resolve_path(new_path)
        if new_path is None:
            raise ValueError("Could not resolve new path")
            
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
                new_file._grant_access(user, permission)
        
        return new_file

class SyftFolder:
    """A folder wrapper that manages SyftBox permissions."""
    
    def __init__(self, path: Union[str, Path]):
        self._path = resolve_path(path)
        if self._path is None:
            raise ValueError("Could not resolve path")
            
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
        nearest_permissions = {"read": [], "create": [], "write": [], "admin": []}
        
        # Walk up the directory tree to find the nearest node with matching rules
        current_path = self._path
        while current_path.parent != current_path:  # Stop at root
            parent_dir = current_path.parent
            syftpub_path = parent_dir / "syft.pub.yaml"
            
            if syftpub_path.exists():
                try:
                    with open(syftpub_path, 'r') as f:
                        content = yaml.safe_load(f) or {"rules": []}
                    
                    # Check if this is a terminal node
                    if content.get("terminal", False):
                        # Terminal nodes stop inheritance and their rules take precedence
                        rules = content.get("rules", [])
                        sorted_rules = _sort_rules_by_specificity(rules)
                        for rule in sorted_rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our folder path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path) or _glob_match(pattern, rel_path + "/"):
                                terminal_pattern = pattern  # Track the matched pattern
                                access = rule.get("access", {})
                                # Check file limits if present
                                limits = rule.get("limits", {})
                                if limits:
                                    # Check if directories are allowed
                                    if not limits.get("allow_dirs", True):
                                        continue  # Skip this rule for directories
                                
                                # Terminal rules override everything - return immediately
                                result = {perm: format_users(access.get(perm, [])) for perm in ["read", "create", "write", "admin"]}
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
                            nearest_permissions = {perm: format_users(access.get(perm, [])) for perm in ["read", "create", "write", "admin"]}
                            found_matching_rule = True
                            break  # Stop at first matching rule (rules should be sorted by specificity)
                    
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
        """Get permissions formatted as a table showing effective permissions with hierarchy and reasons."""
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
            all_reasons = set()
            
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
                    if "Included via write permission" not in reason and "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Create] {reason}")
            
            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if ("Included via create permission" not in reason and 
                        "Included via write permission" not in reason and 
                        "Included via admin permission" not in reason):
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
            
            rows.append([
                "public",
                "✓" if read_has else "",
                "✓" if create_has else "",
                "✓" if write_has else "",
                "✓" if admin_has else "",
                reason_text
            ])
            all_users.remove("*")  # Remove so we don't process it again
        
        # Then add all other users
        for user in sorted(all_users):
            # Collect all reasons for this user
            all_reasons = set()
            
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
                    if "Included via write permission" not in reason and "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Create] {reason}")
            
            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if ("Included via create permission" not in reason and 
                        "Included via write permission" not in reason and 
                        "Included via admin permission" not in reason):
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
                reason_text
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
                tablefmt="simple"
            )
            return f"SyftFolder('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFolder('{self._path}')\n"]
            result.append("User               Read  Create  Write  Admin  Reason")
            result.append("-" * 70)
            for row in rows:
                result.append(f"{row[0]:<20} {row[1]:<5} {row[2]:<7} {row[3]:<6} {row[4]:<5} {row[5] if len(row) > 5 else ''}")
            return "\n".join(result)

    def _ensure_server_and_get_editor_url(self) -> str:
        """Ensure the permission editor server is running and return the editor URL."""
        try:
            from .server import get_server_url, start_server, get_editor_url
            
            # Check if server is already running
            server_url = get_server_url()
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

    def _repr_html_(self) -> str:
        """Return HTML representation for Jupyter notebooks."""
        # Auto-start permission editor server for Jupyter notebook integration
        editor_url = self._ensure_server_and_get_editor_url()
        
        rows = self._get_permission_table()
        limits = self.get_file_limits()
        
        # Create compliance table for folder
        limits = self.get_file_limits()
        
        # Analyze folder contents
        total_files = 0
        oversized_files = 0
        largest_file_size = 0
        largest_file_name = ""
        subdirs = 0
        symlinks = 0
        
        try:
            for item in self._path.rglob('*'):
                if item.is_file():
                    total_files += 1
                    file_size = item.stat().st_size
                    if file_size > largest_file_size:
                        largest_file_size = file_size
                        largest_file_name = item.name
                    if limits["max_file_size"] is not None:
                        if file_size > limits["max_file_size"]:
                            oversized_files += 1
                elif item.is_dir() and item != self._path:
                    subdirs += 1
                elif item.is_symlink():
                    symlinks += 1
        except (OSError, PermissionError):
            pass
        
        # Format largest file size
        if largest_file_size >= 1024 * 1024:
            largest_display = f"{largest_file_size / (1024 * 1024):.2f} MB ({largest_file_name})"
        elif largest_file_size >= 1024:
            largest_display = f"{largest_file_size / 1024:.2f} KB ({largest_file_name})"
        else:
            largest_display = f"{largest_file_size} bytes ({largest_file_name})" if largest_file_name else "No files"
        
        # Size limit comparison
        if limits["max_file_size"] is not None:
            if limits["max_file_size"] >= 1024 * 1024:
                limit_display = f"{limits['max_file_size'] / (1024 * 1024):.2f} MB"
            elif limits["max_file_size"] >= 1024:
                limit_display = f"{limits['max_file_size'] / 1024:.2f} KB"
            else:
                limit_display = f"{limits['max_file_size']} bytes"
            
            if oversized_files > 0:
                size_status = f"✗ {oversized_files}/{total_files} files exceed limit"
            else:
                size_status = f"✓ All {total_files} files within limit"
        else:
            limit_display = "No limit"
            size_status = f"✓ All {total_files} files OK"
        
        # Directory policy status
        if subdirs == 0:
            dir_status = "✓ No subdirectories"
        elif limits["allow_dirs"]:
            dir_status = f"✓ {subdirs} subdirectories allowed"
        else:
            dir_status = f"✗ {subdirs} subdirectories would be blocked"
        
        # Symlink policy status
        if symlinks == 0:
            symlink_status = "✓ No symlinks"
        elif limits["allow_symlinks"]:
            symlink_status = f"✓ {symlinks} symlinks allowed"
        else:
            symlink_status = f"✗ {symlinks} symlinks would be blocked"
        
        # Overall compliance
        size_ok = oversized_files == 0
        dirs_ok = limits["allow_dirs"] or subdirs == 0
        symlinks_ok = limits["allow_symlinks"] or symlinks == 0
        all_ok = size_ok and dirs_ok and symlinks_ok
        overall_status = "✓ COMPLIANT" if all_ok else "✗ NON-COMPLIANT"
        
        # Build compliance table
        compliance_html = f'''<p><b>Folder Compliance Check:</b></p>
<table border="1" style="border-collapse: collapse; margin: 10px 0;">
<tr><th style="padding: 5px;">Property</th><th style="padding: 5px;">Current State</th><th style="padding: 5px;">Policy/Limit</th><th style="padding: 5px;">Status</th></tr>
<tr><td style="padding: 5px;">Largest File</td><td style="padding: 5px;">{largest_display}</td><td style="padding: 5px;">{limit_display}</td><td style="padding: 5px;">{size_status}</td></tr>
<tr><td style="padding: 5px;">Subdirectories</td><td style="padding: 5px;">{subdirs} subdirectories</td><td style="padding: 5px;">{'Allowed' if limits['allow_dirs'] else 'Blocked'}</td><td style="padding: 5px;">{dir_status}</td></tr>
<tr><td style="padding: 5px;">Symlinks</td><td style="padding: 5px;">{symlinks} symlinks</td><td style="padding: 5px;">{'Allowed' if limits['allow_symlinks'] else 'Blocked'}</td><td style="padding: 5px;">{symlink_status}</td></tr>
<tr><td style="padding: 5px;"><b>Overall</b></td><td style="padding: 5px;" colspan="2"><b>Folder access compliance</b></td><td style="padding: 5px;"><b>{overall_status}</b></td></tr>
</table>\n'''
        
        # Add editor link
        editor_link = f'<p style="margin: 10px 0;"><a href="{editor_url}" target="_blank" style="background: #1976d2; color: white; padding: 8px 16px; text-decoration: none; border-radius: 4px; font-size: 14px;">🖊️ Edit Permissions</a></p>'
        
        # Build the HTML output
        result = [f"<p><b>SyftFolder('{self._path}')</b></p>", editor_link, compliance_html.strip()]
        
        # File limits are now shown in the compliance table above
        
        if not rows:
            result.append("<p>No permissions set</p>")
            return "\n".join(result)
            
        try:
            from tabulate import tabulate
            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="html"
            )
            result.append(table)
            return "\n".join(result)
        except ImportError:
            # Fallback to simple HTML table if tabulate not available
            result.append("<table>")
            result.append("<tr><th>User</th><th>Read</th><th>Create</th><th>Write</th><th>Admin</th><th>Reason</th></tr>")
            for row in rows:
                result.append(f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td><td>{row[4]}</td><td>{row[5] if len(row) > 5 else ''}</td></tr>")
            result.append("</table>")
            return "\n".join(result)
    
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
            force=force
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "write", force=force)
    
    def grant_admin_access(self, user: str, *, force: bool = False) -> None:
        """Grant admin permission to a user."""
        if not _confirm_action(
            f"⚠️  Warning: Granting admin access to '{user}' for '{self._path}'. Are you sure?",
            force=force
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

    def _grant_access(self, user: str, permission: Literal["read", "create", "write", "admin"], *, force: bool = False) -> None:
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
    
    def _revoke_access(self, user: str, permission: Literal["read", "create", "write", "admin"]) -> None:
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
    
    def _check_permission(self, user: str, permission: Literal["read", "create", "write", "admin"]) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()
        
        # Check if user is the owner using old syftbox logic
        if _is_owner(self._path, user):
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
        else:
            return False

    def _check_permission_with_reasons(self, user: str, permission: Literal["read", "create", "write", "admin"]) -> tuple[bool, List[str]]:
        """Check if a user has a specific permission and return reasons why."""
        reasons = []
        
        # Check if user is the owner using old syftbox logic
        if _is_owner(self._path, user):
            reasons.append("Owner of path")
            return True, reasons
        
        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        terminal_pattern = perm_data.get("terminal_pattern")
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
        if "*" in all_perms.get(permission, []) or (has_permission and "*" in [admin_users, write_users, create_users, read_users]):
            if "Public access (*)" not in reasons:
                reasons.append("Public access (*)")
        
        if not has_permission and not reasons:
            reasons.append("No permission found")
        
        return has_permission, reasons

    def _get_all_permissions_with_sources(self) -> Dict[str, Any]:
        """Get all permissions using old syftbox nearest-node algorithm with source tracking."""
        # Start with empty permissions and sources
        effective_perms = {"read": [], "create": [], "write": [], "admin": []}
        source_info = {"read": [], "create": [], "write": [], "admin": []}
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
                    with open(syftpub_path, 'r') as f:
                        content = yaml.safe_load(f) or {"rules": []}
                    
                    # Check if this is a terminal node
                    if content.get("terminal", False):
                        terminal_path = syftpub_path
                        # Terminal nodes stop inheritance and their rules take precedence
                        rules = content.get("rules", [])
                        sorted_rules = _sort_rules_by_specificity(rules)
                        for rule in sorted_rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our folder path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path) or _glob_match(pattern, rel_path + "/"):
                                terminal_pattern = pattern  # Track the matched pattern
                                matched_pattern = pattern  # Also track in general matched pattern
                                access = rule.get("access", {})
                                # Terminal rules override everything - return immediately
                                for perm in ["read", "create", "write", "admin"]:
                                    users = format_users(access.get(perm, []))
                                    effective_perms[perm] = users
                                    if users:
                                        source_info[perm] = [{
                                            "path": syftpub_path,
                                            "pattern": pattern,
                                            "terminal": True,
                                            "inherited": False
                                        }]
                                return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path, "terminal_pattern": terminal_pattern, "matched_pattern": matched_pattern}
                        # If no match in terminal, stop inheritance with empty permissions
                        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path, "terminal_pattern": terminal_pattern, "matched_pattern": matched_pattern}
                    
                    # Process rules for non-terminal nodes (sort by specificity first)
                    rules = content.get("rules", [])
                    sorted_rules = _sort_rules_by_specificity(rules)
                    found_matching_rule = False
                    for rule in sorted_rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our folder path relative to this directory
                        rel_path = str(self._path.relative_to(parent_dir))
                        if _glob_match(pattern, rel_path) or _glob_match(pattern, rel_path + "/"):
                            matched_pattern = pattern  # Track the matched pattern
                            access = rule.get("access", {})
                            # Found a matching rule - this becomes our nearest node
                            # Use this node's permissions (not accumulate)
                            # File limits are checked at write time, not permission resolution time
                            for perm in ["read", "create", "write", "admin"]:
                                users = format_users(access.get(perm, []))
                                effective_perms[perm] = users
                                if users:
                                    source_info[perm] = [{
                                        "path": syftpub_path,
                                        "pattern": pattern,
                                        "terminal": False,
                                        "inherited": parent_dir != self._path.parent
                                    }]
                            found_matching_rule = True
                            break  # Stop at first matching rule (rules should be sorted by specificity)
                    
                    # If we found a matching rule, this is our nearest node - stop searching
                    if found_matching_rule:
                        break
                        
                except Exception:
                    pass
            
            current_path = parent_dir
        
        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path, "terminal_pattern": terminal_pattern, "matched_pattern": matched_pattern}
    
    def explain_permissions(self, user: str) -> str:
        """Provide detailed explanation of why user has/lacks permissions."""
        explanation = f"Permission analysis for {user} on {self._path}:\n\n"
        
        for perm in ["admin", "write", "create", "read"]:
            has_perm, reasons = self._check_permission_with_reasons(user, perm)
            status = "✓ GRANTED" if has_perm else "✗ DENIED"
            explanation += f"{perm.upper()}: {status}\n"
            for reason in reasons:
                explanation += f"  • {reason}\n"
            explanation += "\n"
        
        return explanation

    def set_file_limits(self, max_size: Optional[int] = None, 
                       allow_dirs: Optional[bool] = None, 
                       allow_symlinks: Optional[bool] = None) -> None:
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
            "has_limits": has_limits
        }

    def move_folder_and_permissions(self, new_path: Union[str, Path], *, force: bool = False) -> 'SyftFolder':
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
        new_path = resolve_path(new_path)
        if new_path is None:
            raise ValueError("Could not resolve new path")
            
        if not self._path.exists():
            raise FileNotFoundError(f"Source folder not found: {self._path}")
            
        if new_path.exists():
            raise FileExistsError(f"Destination folder already exists: {new_path}")
            
        # Count files for large folder warning
        file_count = sum(1 for _ in self._path.rglob('*'))
        if file_count > 100 and not _confirm_action(
            f"⚠️  Warning: Moving large folder with {file_count} files. This may take a while. Continue?",
            force=force
        ):
            print("Operation cancelled.")
            return self
            
        # Get permissions for all files and folders
        permission_map = {}
        for item in self._path.rglob('*'):
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
                        file_obj._grant_access(user, permission)
            elif new_item_path.is_dir():
                folder_obj = SyftFolder(new_item_path)
                for permission, users in perms.items():
                    for user in users:
                        folder_obj._grant_access(user, permission)
        
        return new_folder

# Utility function to clear the permission cache
def clear_permission_cache() -> None:
    """Clear the global permission cache."""
    _permission_cache.clear()

# Utility function to get cache statistics
def get_cache_stats() -> Dict[str, Any]:
    """Get statistics about the permission cache."""
    return {
        "size": len(_permission_cache.cache),
        "max_size": _permission_cache.max_size,
        "entries": list(_permission_cache.cache.keys())
    }