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

def _glob_match(pattern: str, path: str) -> bool:
    """
    Match a path against a glob pattern, supporting ** for recursive matching.
    This implementation aims to match the doublestar library behavior from Go.
    
    Args:
        pattern: Glob pattern (supports *, ?, ** for recursive)
        path: Path to match against pattern
        
    Returns:
        bool: True if path matches pattern
    """
    # Handle the ** pattern specially
    if "**" in pattern:
        # Convert pattern to regex-like parts
        parts = pattern.split("**")
        
        # Handle patterns like "**/*.txt" or "dir/**/*.py"
        if len(parts) == 2:
            prefix, suffix = parts
            prefix = prefix.rstrip("/")
            suffix = suffix.lstrip("/")
            
            # Check prefix match
            if prefix and not path.startswith(prefix):
                return False
            
            # Remove prefix from path for suffix matching
            if prefix:
                remaining = path[len(prefix):].lstrip("/")
            else:
                remaining = path
            
            # For suffix, we need to check if it matches anywhere in the remaining path
            if suffix:
                # Simple patterns like "*.txt"
                if suffix.startswith("*") and "." in suffix:
                    # Extension matching
                    return remaining.endswith(suffix[1:])
                else:
                    # More complex suffix patterns
                    from fnmatch import fnmatch
                    # Check if suffix matches any part of the path
                    path_parts = remaining.split("/")
                    for i in range(len(path_parts)):
                        subpath = "/".join(path_parts[i:])
                        if fnmatch(subpath, suffix):
                            return True
                    return False
            else:
                # Pattern ends with **, matches everything under prefix
                return True
        
        # Multiple ** patterns - more complex handling
        elif len(parts) > 2:
            # For now, fall back to simpler logic
            # This could be enhanced to handle more complex patterns
            from fnmatch import fnmatch
            # Replace ** with * for simple matching
            simple_pattern = pattern.replace("**", "*")
            return fnmatch(path, simple_pattern)
        
        # Single "**" matches everything
        elif pattern == "**":
            return True
    
    # For non-** patterns, use standard fnmatch
    from fnmatch import fnmatch
    
    # Special handling for * patterns that shouldn't match across directories
    if "*" in pattern and "/" not in pattern and "/" in path:
        # Pattern like "*.txt" shouldn't match "subdir/file.txt"
        return False
    
    return fnmatch(path, pattern)

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
        """Get all permissions for this file, including inherited permissions."""
        # Check cache first
        cache_key = str(self._path)
        cached = _permission_cache.get(cache_key)
        if cached is not None:
            return cached
        
        # Start with empty permissions
        effective_perms = {"read": [], "create": [], "write": [], "admin": []}
        
        # Walk up the directory tree collecting permissions
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
                        # Terminal nodes stop inheritance
                        rules = content.get("rules", [])
                        for rule in rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our file path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path):
                                access = rule.get("access", {})
                                # Terminal rules override everything
                                result = {perm: format_users(access.get(perm, [])) for perm in ["read", "create", "write", "admin"]}
                                _permission_cache.set(cache_key, result)
                                return result
                        # If no match in terminal, stop inheritance with empty permissions
                        _permission_cache.set(cache_key, effective_perms)
                        return effective_perms
                    
                    # Process rules for non-terminal nodes
                    rules = content.get("rules", [])
                    for rule in rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our file path relative to this directory
                        rel_path = str(self._path.relative_to(parent_dir))
                        if _glob_match(pattern, rel_path):
                            access = rule.get("access", {})
                            # Check file limits if present
                            limits = rule.get("limits", {})
                            if limits:
                                # Check file size limit
                                max_size = limits.get("max_file_size")
                                if max_size is not None and self._size > max_size:
                                    continue  # Skip this rule due to size limit
                                
                                # Check if directories are allowed
                                if not limits.get("allow_dirs", True) and self._path.is_dir():
                                    continue  # Skip this rule for directories
                                
                                # Check if symlinks are allowed
                                if not limits.get("allow_symlinks", True) and self._is_symlink:
                                    continue  # Skip this rule for symlinks
                            
                            # Merge permissions (inheritance)
                            for perm in ["read", "create", "write", "admin"]:
                                users = access.get(perm, [])
                                if users and not effective_perms[perm]:
                                    # Only inherit if we don't have more specific permissions
                                    effective_perms[perm] = format_users(users)
                except Exception:
                    pass
            
            current_path = parent_dir
        
        # Cache and return the effective permissions
        _permission_cache.set(cache_key, effective_perms)
        return effective_perms

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
            
            # Combine all unique reasons
            for reasons in [read_reasons, create_reasons, write_reasons, admin_reasons]:
                all_reasons.update(reasons)
            
            # Format reasons for display - always show all reasons
            reason_list = sorted(list(all_reasons))
            reason_text = "; ".join(reason_list)
            
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
            
            # Combine all unique reasons
            for reasons in [read_reasons, create_reasons, write_reasons, admin_reasons]:
                all_reasons.update(reasons)
            
            # Format reasons for display - always show all reasons
            reason_list = sorted(list(all_reasons))
            reason_text = "; ".join(reason_list)
            
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

    def _repr_html_(self) -> str:
        """Return HTML representation for Jupyter notebooks."""
        rows = self._get_permission_table()
        if not rows:
            return f"<p><b>SyftFile('{self._path}')</b> - No permissions set</p>"
            
        try:
            from tabulate import tabulate
            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="html"
            )
            return f"<p><b>SyftFile('{self._path}')</b></p>\n{table}"
        except ImportError:
            # Fallback to simple HTML table if tabulate not available
            result = [f"<p><b>SyftFile('{self._path}')</b></p>"]
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
        
        # Check if user is the owner (first part of path after datasites/)
        path_parts = self._path.parts
        try:
            datasites_idx = path_parts.index("datasites")
            if datasites_idx + 1 < len(path_parts):
                owner = path_parts[datasites_idx + 1]
                if owner == user:
                    return True  # Owner has all permissions
        except (ValueError, IndexError):
            pass
        
        # Also check simple prefix matching (like old ACL)
        path_str = str(self._path)
        if path_str.startswith(user + "/") or path_str.startswith("/" + user + "/"):
            return True
        
        # Implement permission hierarchy: Admin > Write > Create > Read
        # Check if user has admin permission
        admin_users = all_perms.get("admin", [])
        is_admin = "*" in admin_users or user in admin_users
        
        # Check if user has write permission (includes admin)
        write_users = all_perms.get("write", [])
        is_writer = is_admin or "*" in write_users or user in write_users
        
        # Check if user has create permission (includes write and admin)
        create_users = all_perms.get("create", [])
        is_creator = is_writer or "*" in create_users or user in create_users
        
        # Check if user has read permission (includes all higher permissions)
        read_users = all_perms.get("read", [])
        is_reader = is_creator or "*" in read_users or user in read_users
        
        # Return based on requested permission
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
        """Get all permissions including inherited ones with source tracking."""
        # Start with empty permissions and sources
        effective_perms = {"read": [], "create": [], "write": [], "admin": []}
        source_info = {"read": [], "create": [], "write": [], "admin": []}
        terminal_path = None
        
        # Walk up the directory tree collecting permissions
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
                        # Terminal nodes stop inheritance
                        rules = content.get("rules", [])
                        for rule in rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our file path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path):
                                access = rule.get("access", {})
                                # Terminal rules override everything
                                for perm in ["read", "create", "write", "admin"]:
                                    users = format_users(access.get(perm, []))
                                    if users:
                                        effective_perms[perm] = users
                                        source_info[perm] = [{
                                            "path": syftpub_path,
                                            "pattern": pattern,
                                            "terminal": True,
                                            "inherited": False
                                        }]
                                return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path}
                        # If no match in terminal, stop inheritance
                        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path}
                    
                    # Process rules for non-terminal nodes
                    rules = content.get("rules", [])
                    for rule in rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our file path relative to this directory
                        rel_path = str(self._path.relative_to(parent_dir))
                        if _glob_match(pattern, rel_path):
                            access = rule.get("access", {})
                            # Check file limits if present
                            limits = rule.get("limits", {})
                            if limits:
                                # Check file size limit
                                max_size = limits.get("max_file_size")
                                if max_size is not None and self._size > max_size:
                                    continue  # Skip this rule due to size limit
                                
                                # Check if directories are allowed
                                if not limits.get("allow_dirs", True) and self._path.is_dir():
                                    continue  # Skip this rule for directories
                                
                                # Check if symlinks are allowed
                                if not limits.get("allow_symlinks", True) and self._is_symlink:
                                    continue  # Skip this rule for symlinks
                            
                            # Merge permissions (inheritance)
                            for perm in ["read", "create", "write", "admin"]:
                                users = access.get(perm, [])
                                if users and not effective_perms[perm]:
                                    # Only inherit if we don't have more specific permissions
                                    effective_perms[perm] = format_users(users)
                                    source_info[perm].append({
                                        "path": syftpub_path,
                                        "pattern": pattern,
                                        "terminal": False,
                                        "inherited": parent_dir != self._path.parent
                                    })
                except Exception:
                    pass
            
            current_path = parent_dir
        
        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path}
    
    def _check_permission_with_reasons(self, user: str, permission: Literal["read", "create", "write", "admin"]) -> tuple[bool, List[str]]:
        """Check if a user has a specific permission and return reasons why."""
        reasons = []
        
        # Check if user is the owner
        path_parts = self._path.parts
        try:
            datasites_idx = path_parts.index("datasites")
            if datasites_idx + 1 < len(path_parts):
                owner = path_parts[datasites_idx + 1]
                if owner == user:
                    reasons.append("Owner of path")
                    return True, reasons
        except (ValueError, IndexError):
            pass
        
        # Also check simple prefix matching (like old ACL)
        path_str = str(self._path)
        if path_str.startswith(user + "/") or path_str.startswith("/" + user + "/"):
            reasons.append("Owner of path (prefix match)")
            return True, reasons
        
        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        
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
        
        # Add pattern info if available
        for perm_type in ["admin", "write", "create", "read"]:
            if sources.get(perm_type):
                for src in sources[perm_type]:
                    if src["pattern"] and src["pattern"] != self._name:
                        # User has permission and pattern is not just the filename
                        if (perm_type == permission or 
                            (perm_type == "admin") or
                            (perm_type == "write" and permission in ["create", "read"]) or
                            (perm_type == "create" and permission == "read")):
                            if f"Pattern '{src['pattern']}' matched" not in reasons:
                                reasons.append(f"Pattern '{src['pattern']}' matched")
                            break
        
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
                       allow_dirs: bool = True, 
                       allow_symlinks: bool = True) -> None:
        """
        Set file limits for this file's permissions (compatible with old ACL).
        
        Args:
            max_size: Maximum file size in bytes (None for no limit)
            allow_dirs: Whether to allow directories
            allow_symlinks: Whether to allow symlinks
        """
        # Read current permissions
        access_dict = read_syftpub_yaml(self._path.parent, self._name) or {}
        
        # Add limits to the rule
        if "limits" not in access_dict:
            access_dict["limits"] = {}
        
        if max_size is not None:
            access_dict["limits"]["max_file_size"] = max_size
        access_dict["limits"]["allow_dirs"] = allow_dirs
        access_dict["limits"]["allow_symlinks"] = allow_symlinks
        
        update_syftpub_yaml(self._path.parent, self._name, access_dict)
        
        # Invalidate cache
        _permission_cache.invalidate(str(self._path))

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
        """Get all permissions for this folder, including inherited permissions."""
        # Check cache first
        cache_key = str(self._path)
        cached = _permission_cache.get(cache_key)
        if cached is not None:
            return cached
        
        # Start with empty permissions
        effective_perms = {"read": [], "create": [], "write": [], "admin": []}
        
        # Walk up the directory tree collecting permissions
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
                        # Terminal nodes stop inheritance
                        rules = content.get("rules", [])
                        for rule in rules:
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
                                
                                # Terminal rules override everything
                                result = {perm: format_users(access.get(perm, [])) for perm in ["read", "create", "write", "admin"]}
                                _permission_cache.set(cache_key, result)
                                return result
                        # If no match in terminal, stop inheritance with empty permissions
                        _permission_cache.set(cache_key, effective_perms)
                        return effective_perms
                    
                    # Process rules for non-terminal nodes
                    rules = content.get("rules", [])
                    for rule in rules:
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
                            
                            # Merge permissions (inheritance)
                            for perm in ["read", "create", "write", "admin"]:
                                users = access.get(perm, [])
                                if users and not effective_perms[perm]:
                                    # Only inherit if we don't have more specific permissions
                                    effective_perms[perm] = format_users(users)
                except Exception:
                    pass
            
            current_path = parent_dir
        
        # Cache and return the effective permissions
        _permission_cache.set(cache_key, effective_perms)
        return effective_perms

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
            
            # Combine all unique reasons
            for reasons in [read_reasons, create_reasons, write_reasons, admin_reasons]:
                all_reasons.update(reasons)
            
            # Format reasons for display - always show all reasons
            reason_list = sorted(list(all_reasons))
            reason_text = "; ".join(reason_list)
            
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
            
            # Combine all unique reasons
            for reasons in [read_reasons, create_reasons, write_reasons, admin_reasons]:
                all_reasons.update(reasons)
            
            # Format reasons for display - always show all reasons
            reason_list = sorted(list(all_reasons))
            reason_text = "; ".join(reason_list)
            
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

    def _repr_html_(self) -> str:
        """Return HTML representation for Jupyter notebooks."""
        rows = self._get_permission_table()
        if not rows:
            return f"<p><b>SyftFolder('{self._path}')</b> - No permissions set</p>"
            
        try:
            from tabulate import tabulate
            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="html"
            )
            return f"<p><b>SyftFolder('{self._path}')</b></p>\n{table}"
        except ImportError:
            # Fallback to simple HTML table if tabulate not available
            result = [f"<p><b>SyftFolder('{self._path}')</b></p>"]
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
        
        # Check if user is the owner (first part of path after datasites/)
        path_parts = self._path.parts
        try:
            datasites_idx = path_parts.index("datasites")
            if datasites_idx + 1 < len(path_parts):
                owner = path_parts[datasites_idx + 1]
                if owner == user:
                    return True  # Owner has all permissions
        except (ValueError, IndexError):
            pass
        
        # Also check simple prefix matching (like old ACL)
        path_str = str(self._path)
        if path_str.startswith(user + "/") or path_str.startswith("/" + user + "/"):
            return True
        
        # Implement permission hierarchy: Admin > Write > Create > Read
        # Check if user has admin permission
        admin_users = all_perms.get("admin", [])
        is_admin = "*" in admin_users or user in admin_users
        
        # Check if user has write permission (includes admin)
        write_users = all_perms.get("write", [])
        is_writer = is_admin or "*" in write_users or user in write_users
        
        # Check if user has create permission (includes write and admin)
        create_users = all_perms.get("create", [])
        is_creator = is_writer or "*" in create_users or user in create_users
        
        # Check if user has read permission (includes all higher permissions)
        read_users = all_perms.get("read", [])
        is_reader = is_creator or "*" in read_users or user in read_users
        
        # Return based on requested permission
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
        
        # Check if user is the owner
        path_parts = self._path.parts
        try:
            datasites_idx = path_parts.index("datasites")
            if datasites_idx + 1 < len(path_parts):
                owner = path_parts[datasites_idx + 1]
                if owner == user:
                    reasons.append("Owner of path")
                    return True, reasons
        except (ValueError, IndexError):
            pass
        
        # Also check simple prefix matching (like old ACL)
        path_str = str(self._path)
        if path_str.startswith(user + "/") or path_str.startswith("/" + user + "/"):
            reasons.append("Owner of path (prefix match)")
            return True, reasons
        
        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        
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
        
        # Add pattern info if available
        for perm_type in ["admin", "write", "create", "read"]:
            if sources.get(perm_type):
                for src in sources[perm_type]:
                    if src["pattern"] and src["pattern"] != self._name:
                        # User has permission and pattern is not just the folder name
                        if (perm_type == permission or 
                            (perm_type == "admin") or
                            (perm_type == "write" and permission in ["create", "read"]) or
                            (perm_type == "create" and permission == "read")):
                            if f"Pattern '{src['pattern']}' matched" not in reasons:
                                reasons.append(f"Pattern '{src['pattern']}' matched")
                            break
        
        # Check for public access
        if "*" in all_perms.get(permission, []) or (has_permission and "*" in [admin_users, write_users, create_users, read_users]):
            if "Public access (*)" not in reasons:
                reasons.append("Public access (*)")
        
        if not has_permission and not reasons:
            reasons.append("No permission found")
        
        return has_permission, reasons

    def _get_all_permissions_with_sources(self) -> Dict[str, Any]:
        """Get all permissions including inherited ones with source tracking."""
        # Start with empty permissions and sources
        effective_perms = {"read": [], "create": [], "write": [], "admin": []}
        source_info = {"read": [], "create": [], "write": [], "admin": []}
        terminal_path = None
        
        # Walk up the directory tree collecting permissions
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
                        # Terminal nodes stop inheritance
                        rules = content.get("rules", [])
                        for rule in rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our folder path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path) or _glob_match(pattern, rel_path + "/"):
                                access = rule.get("access", {})
                                # Terminal rules override everything
                                for perm in ["read", "create", "write", "admin"]:
                                    users = format_users(access.get(perm, []))
                                    if users:
                                        effective_perms[perm] = users
                                        source_info[perm] = [{
                                            "path": syftpub_path,
                                            "pattern": pattern,
                                            "terminal": True,
                                            "inherited": False
                                        }]
                                return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path}
                        # If no match in terminal, stop inheritance
                        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path}
                    
                    # Process rules for non-terminal nodes
                    rules = content.get("rules", [])
                    for rule in rules:
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
                            
                            # Merge permissions (inheritance)
                            for perm in ["read", "create", "write", "admin"]:
                                users = access.get(perm, [])
                                if users and not effective_perms[perm]:
                                    # Only inherit if we don't have more specific permissions
                                    effective_perms[perm] = format_users(users)
                                    source_info[perm].append({
                                        "path": syftpub_path,
                                        "pattern": pattern,
                                        "terminal": False,
                                        "inherited": parent_dir != self._path.parent
                                    })
                except Exception:
                    pass
            
            current_path = parent_dir
        
        return {"permissions": effective_perms, "sources": source_info, "terminal": terminal_path}
    
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