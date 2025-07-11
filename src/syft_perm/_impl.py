"""Internal implementation of SyftFile and SyftFolder classes."""

from pathlib import Path
from typing import Optional, List, Dict, Union, Iterator, Literal
import shutil

from ._utils import (
    resolve_path,
    create_access_dict,
    update_syftpub_yaml,
    read_syftpub_yaml,
    format_users,
    is_datasite_email,
)
import fnmatch
import yaml

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
    
    @property
    def _name(self) -> str:
        """Get the file name"""
        return self._path.name

    def _get_all_permissions(self) -> Dict[str, List[str]]:
        """Get all permissions for this file, including inherited permissions."""
        # Start with empty permissions
        effective_perms = {"read": [], "write": [], "admin": []}
        
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
                            if fnmatch.fnmatch(rel_path, pattern):
                                access = rule.get("access", {})
                                # Terminal rules override everything
                                return {perm: format_users(access.get(perm, [])) for perm in ["read", "write", "admin"]}
                        # If no match in terminal, stop inheritance with empty permissions
                        return effective_perms
                    
                    # Process rules for non-terminal nodes
                    rules = content.get("rules", [])
                    for rule in rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our file path relative to this directory
                        rel_path = str(self._path.relative_to(parent_dir))
                        if fnmatch.fnmatch(rel_path, pattern):
                            access = rule.get("access", {})
                            # Merge permissions (inheritance)
                            for perm in ["read", "write", "admin"]:
                                users = access.get(perm, [])
                                if users and not effective_perms[perm]:
                                    # Only inherit if we don't have more specific permissions
                                    effective_perms[perm] = format_users(users)
                except Exception:
                    pass
            
            current_path = parent_dir
        
        # Return the effective permissions
        return effective_perms

    def _get_permission_table(self) -> List[List[str]]:
        """Get permissions formatted as a table."""
        perms = self._get_all_permissions()
        
        # Get all unique users
        all_users = set()
        for users in perms.values():
            all_users.update(users)
        
        # Create table rows
        rows = []
        
        # First add public if it exists
        if "*" in all_users:
            rows.append([
                "public",
                "✓" if "*" in perms.get("read", []) else "",
                "✓" if "*" in perms.get("write", []) else "",
                "✓" if "*" in perms.get("admin", []) else ""
            ])
            all_users.remove("*")  # Remove so we don't process it again
        
        # Then add all other users
        for user in sorted(all_users):
            row = [
                user,
                "✓" if user in perms.get("read", []) else "",
                "✓" if user in perms.get("write", []) else "",
                "✓" if user in perms.get("admin", []) else ""
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
                headers=["User", "Read", "Write", "Admin"],
                tablefmt="simple"
            )
            return f"SyftFile('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFile('{self._path}')\n"]
            result.append("User               Read  Write  Admin")
            result.append("-" * 40)
            for row in rows:
                result.append(f"{row[0]:<20} {row[1]:<5} {row[2]:<5} {row[3]:<5}")
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
                headers=["User", "Read", "Write", "Admin"],
                tablefmt="html"
            )
            return f"<p><b>SyftFile('{self._path}')</b></p>\n{table}"
        except ImportError:
            # Fallback to simple HTML table if tabulate not available
            result = [f"<p><b>SyftFile('{self._path}')</b></p>"]
            result.append("<table>")
            result.append("<tr><th>User</th><th>Read</th><th>Write</th><th>Admin</th></tr>")
            for row in rows:
                result.append(f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>")
            result.append("</table>")
            return "\n".join(result)

    def grant_read_access(self, user: str, *, force: bool = False) -> None:
        """Grant read permission to a user."""
        self._grant_access(user, "read", force=force)
    
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
    
    def revoke_write_access(self, user: str) -> None:
        """Revoke write permission from a user."""
        self._revoke_access(user, "write")
    
    def revoke_admin_access(self, user: str) -> None:
        """Revoke admin permission from a user."""
        self._revoke_access(user, "admin")
    
    def has_read_access(self, user: str) -> bool:
        """Check if a user has read permission."""
        return self._check_permission(user, "read")
    
    def has_write_access(self, user: str) -> bool:
        """Check if a user has write permission."""
        return self._check_permission(user, "write")
    
    def has_admin_access(self, user: str) -> bool:
        """Check if a user has admin permission."""
        return self._check_permission(user, "admin")

    def _grant_access(self, user: str, permission: Literal["read", "write", "admin"], *, force: bool = False) -> None:
        """Internal method to grant permission to a user."""
        # Validate that the email belongs to a datasite
        if not is_datasite_email(user) and not force:
            raise ValueError(
                f"'{user}' is not a valid datasite email. "
                f"Use force=True to override this check."
            )
            
        perms = read_syftpub_yaml(self._path.parent, self._name) or {}
        users = set(perms.get(permission, []))
        users.add(user)
        perms[permission] = format_users(list(users))  # Use format_users for consistent handling
        update_syftpub_yaml(self._path.parent, self._name, perms)
    
    def _revoke_access(self, user: str, permission: Literal["read", "write", "admin"]) -> None:
        """Internal method to revoke permission from a user."""
        perms = read_syftpub_yaml(self._path.parent, self._name) or {}
        users = set(perms.get(permission, []))
        # Handle revoking from public access
        if "*" in users or "public" in users:
            users = set()  # Reset to empty if revoking from public
        users.discard(user)
        users.discard("*")  # Also remove "*" if present
        users.discard("public")  # Also remove "public" if present
        perms[permission] = format_users(list(users))
        update_syftpub_yaml(self._path.parent, self._name, perms)
    
    def _check_permission(self, user: str, permission: Literal["read", "write", "admin"]) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()
        users = all_perms.get(permission, [])
        
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
        
        # Check regular permissions
        return "*" in users or user in users

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
        # Start with empty permissions
        effective_perms = {"read": [], "write": [], "admin": []}
        
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
                            if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path + "/", pattern):
                                access = rule.get("access", {})
                                # Terminal rules override everything
                                return {perm: format_users(access.get(perm, [])) for perm in ["read", "write", "admin"]}
                        # If no match in terminal, stop inheritance with empty permissions
                        return effective_perms
                    
                    # Process rules for non-terminal nodes
                    rules = content.get("rules", [])
                    for rule in rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our folder path relative to this directory
                        rel_path = str(self._path.relative_to(parent_dir))
                        if fnmatch.fnmatch(rel_path, pattern) or fnmatch.fnmatch(rel_path + "/", pattern):
                            access = rule.get("access", {})
                            # Merge permissions (inheritance)
                            for perm in ["read", "write", "admin"]:
                                users = access.get(perm, [])
                                if users and not effective_perms[perm]:
                                    # Only inherit if we don't have more specific permissions
                                    effective_perms[perm] = format_users(users)
                except Exception:
                    pass
            
            current_path = parent_dir
        
        # Return the effective permissions
        return effective_perms

    def _get_permission_table(self) -> List[List[str]]:
        """Get permissions formatted as a table."""
        perms = self._get_all_permissions()
        
        # Get all unique users
        all_users = set()
        for users in perms.values():
            all_users.update(users)
        
        # Create table rows
        rows = []
        
        # First add public if it exists
        if "*" in all_users:
            rows.append([
                "public",
                "✓" if "*" in perms.get("read", []) else "",
                "✓" if "*" in perms.get("write", []) else "",
                "✓" if "*" in perms.get("admin", []) else ""
            ])
            all_users.remove("*")  # Remove so we don't process it again
        
        # Then add all other users
        for user in sorted(all_users):
            row = [
                user,
                "✓" if user in perms.get("read", []) else "",
                "✓" if user in perms.get("write", []) else "",
                "✓" if user in perms.get("admin", []) else ""
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
                headers=["User", "Read", "Write", "Admin"],
                tablefmt="simple"
            )
            return f"SyftFolder('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFolder('{self._path}')\n"]
            result.append("User               Read  Write  Admin")
            result.append("-" * 40)
            for row in rows:
                result.append(f"{row[0]:<20} {row[1]:<5} {row[2]:<5} {row[3]:<5}")
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
                headers=["User", "Read", "Write", "Admin"],
                tablefmt="html"
            )
            return f"<p><b>SyftFolder('{self._path}')</b></p>\n{table}"
        except ImportError:
            # Fallback to simple HTML table if tabulate not available
            result = [f"<p><b>SyftFolder('{self._path}')</b></p>"]
            result.append("<table>")
            result.append("<tr><th>User</th><th>Read</th><th>Write</th><th>Admin</th></tr>")
            for row in rows:
                result.append(f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td><td>{row[3]}</td></tr>")
            result.append("</table>")
            return "\n".join(result)
    
    def grant_read_access(self, user: str, *, force: bool = False) -> None:
        """Grant read permission to a user."""
        self._grant_access(user, "read", force=force)
    
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
    
    def revoke_write_access(self, user: str) -> None:
        """Revoke write permission from a user."""
        self._revoke_access(user, "write")
    
    def revoke_admin_access(self, user: str) -> None:
        """Revoke admin permission from a user."""
        self._revoke_access(user, "admin")
    
    def has_read_access(self, user: str) -> bool:
        """Check if a user has read permission."""
        return self._check_permission(user, "read")
    
    def has_write_access(self, user: str) -> bool:
        """Check if a user has write permission."""
        return self._check_permission(user, "write")
    
    def has_admin_access(self, user: str) -> bool:
        """Check if a user has admin permission."""
        return self._check_permission(user, "admin")

    def _grant_access(self, user: str, permission: Literal["read", "write", "admin"], *, force: bool = False) -> None:
        """Internal method to grant permission to a user."""
        # Validate that the email belongs to a datasite
        if not is_datasite_email(user) and not force:
            raise ValueError(
                f"'{user}' is not a valid datasite email. "
                f"Use force=True to override this check."
            )
            
        perms = read_syftpub_yaml(self._path.parent, self._name) or {}
        users = set(perms.get(permission, []))
        users.add(user)
        perms[permission] = format_users(list(users))  # Use format_users for consistent handling
        update_syftpub_yaml(self._path.parent, self._name, perms)
    
    def _revoke_access(self, user: str, permission: Literal["read", "write", "admin"]) -> None:
        """Internal method to revoke permission from a user."""
        perms = read_syftpub_yaml(self._path.parent, self._name) or {}
        users = set(perms.get(permission, []))
        # Handle revoking from public access
        if "*" in users or "public" in users:
            users = set()  # Reset to empty if revoking from public
        users.discard(user)
        users.discard("*")  # Also remove "*" if present
        users.discard("public")  # Also remove "public" if present
        perms[permission] = format_users(list(users))
        update_syftpub_yaml(self._path.parent, self._name, perms)
    
    def _check_permission(self, user: str, permission: Literal["read", "write", "admin"]) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()
        users = all_perms.get(permission, [])
        
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
        
        # Check regular permissions
        return "*" in users or user in users

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