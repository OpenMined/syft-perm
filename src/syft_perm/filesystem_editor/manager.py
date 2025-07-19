import mimetypes
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import HTTPException


def get_current_user_email():
    """Helper function to get current user email - you may need to implement this."""
    # This is a placeholder - implement according to your authentication system
    return None


class FileSystemManager:
    """Manages filesystem operations for the code editor."""

    ALLOWED_EXTENSIONS = {
        # Text files
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".html",
        ".css",
        ".scss",
        ".sass",
        ".json",
        ".yaml",
        ".yml",
        ".xml",
        ".md",
        ".txt",
        ".csv",
        ".log",
        ".sql",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".bat",
        ".cmd",
        # Config files
        ".ini",
        ".cfg",
        ".conf",
        ".toml",
        ".env",
        ".gitignore",
        ".dockerignore",
        # Code files
        ".c",
        ".cpp",
        ".h",
        ".hpp",
        ".java",
        ".php",
        ".rb",
        ".go",
        ".rs",
        ".swift",
        ".kt",
        ".scala",
        ".clj",
        ".lisp",
        ".hs",
        ".elm",
        ".dart",
        ".r",
        ".m",
        ".mm",
        # Web files
        ".vue",
        ".svelte",
        ".astro",
        ".htmx",
        ".mustache",
        ".handlebars",
        # Data files
        ".jsonl",
        ".ndjson",
        ".tsv",
        ".properties",
        ".lock",
        # Documentation
        ".rst",
        ".tex",
        ".latex",
        ".adoc",
        ".org",
    }

    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limit

    def __init__(self, base_path: str = None):
        """Initialize with optional base path restriction."""

        self.base_path = Path(base_path).resolve() if base_path else None

    def _validate_path(self, path: str) -> Path:
        """Validate and resolve a path, ensuring it's within allowed bounds."""

        try:

            resolved_path = Path(path).resolve()

            # If we have a base path, ensure the resolved path is within it

            if self.base_path and not str(resolved_path).startswith(str(self.base_path)):

                raise HTTPException(
                    status_code=403, detail="Access denied: Path outside allowed directory"
                )

            return resolved_path

        except Exception as e:

            raise HTTPException(status_code=400, detail=f"Invalid path: {str(e)}")

    def _is_text_file(self, file_path: Path) -> bool:
        """Check if a file is a text file that can be edited."""

        if file_path.suffix.lower() in self.ALLOWED_EXTENSIONS:

            return True

        # Check MIME type

        mime_type, _ = mimetypes.guess_type(str(file_path))

        if mime_type and mime_type.startswith("text/"):

            return True

        # Try to read a small portion to detect if it's text

        try:

            with open(file_path, "rb") as f:

                chunk = f.read(1024)

                return chunk.decode("utf-8", errors="strict") is not None

        except (UnicodeDecodeError, PermissionError):

            return False

    def list_directory(self, path: str, user_email: Optional[str] = None) -> Dict[str, Any]:
        """List directory contents."""

        dir_path = self._validate_path(path)

        if not dir_path.exists():

            raise HTTPException(status_code=404, detail="Directory not found")

        if not dir_path.is_dir():

            raise HTTPException(status_code=400, detail="Path is not a directory")

        try:

            items = []

            for item_path in sorted(
                dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
            ):

                try:

                    stat = item_path.stat()

                    is_directory = item_path.is_dir()

                    item_info = {
                        "name": item_path.name,
                        "path": str(item_path),
                        "is_directory": is_directory,
                        "size": stat.st_size if not is_directory else None,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "is_editable": not is_directory and self._is_text_file(item_path),
                        "extension": item_path.suffix.lower() if not is_directory else None,
                    }

                    items.append(item_info)

                except (PermissionError, OSError):

                    # Skip items we can't access

                    continue

            # Get parent directory if not at root

            parent_path = None

            if dir_path.parent != dir_path:

                parent_path = str(dir_path.parent)

            # Check admin permissions for the directory itself

            current_user = user_email or get_current_user_email()

            can_admin = True  # Default to true for non-SyftBox directories

            # Check if directory is within SyftBox

            syftbox_path = os.path.expanduser("~/SyftBox")

            if str(dir_path).startswith(syftbox_path) and current_user:

                try:

                    # Use syft-perm to check admin permissions

                    from . import open as syft_open

                    syft_folder = syft_open(dir_path)

                    can_admin = syft_folder.has_admin_access(current_user)

                except Exception:

                    # If syft-perm check fails, assume no admin access

                    can_admin = False

            return {
                "path": str(dir_path),
                "parent": parent_path,
                "items": items,
                "total_items": len(items),
                "can_admin": can_admin,
            }

        except PermissionError:

            raise HTTPException(status_code=403, detail="Permission denied")

    def read_file(self, path: str, user_email: str = None) -> Dict[str, Any]:
        """Read file contents."""

        file_path = self._validate_path(path)

        if not file_path.exists():

            raise HTTPException(status_code=404, detail="File not found")

        if file_path.is_dir():

            raise HTTPException(status_code=400, detail="Path is a directory")

        if file_path.stat().st_size > self.MAX_FILE_SIZE:

            raise HTTPException(status_code=413, detail="File too large to edit")

        if not self._is_text_file(file_path):

            raise HTTPException(status_code=415, detail="File type not supported for editing")

        # Check write permissions using syft-perm

        current_user = user_email or get_current_user_email()

        can_write = True  # Default to true for non-SyftBox files

        can_admin = True  # Default to true for non-SyftBox files

        write_users = []

        # Check if file is within SyftBox - use syft-perm for proper permission checking

        syftbox_path = os.path.expanduser("~/SyftBox")

        if str(file_path).startswith(syftbox_path):

            if current_user:

                try:

                    # Use syft-perm to check actual permissions

                    from . import open as syft_open

                    syft_file = syft_open(file_path)

                    can_write = syft_file.has_write_access(current_user)

                    can_admin = syft_file.has_admin_access(current_user)

                    # Get write users from the permission system

                    permissions = syft_file._get_all_permissions()

                    write_users = permissions.get("write", [])

                except Exception:

                    # If syft-perm check fails, fall back to conservative approach

                    can_write = False

                    can_admin = False

                    write_users = []

            else:

                # No current user identified, assume no write access for SyftBox files

                can_write = False

                can_admin = False

                write_users = []

        try:

            with open(file_path, "r", encoding="utf-8") as f:

                content = f.read()

            stat = file_path.stat()

            return {
                "path": str(file_path),
                "content": content,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "extension": file_path.suffix.lower(),
                "encoding": "utf-8",
                "can_write": can_write,
                "can_admin": can_admin,
                "write_users": write_users,
            }

        except UnicodeDecodeError:

            raise HTTPException(status_code=415, detail="File encoding not supported")

        except PermissionError:

            raise HTTPException(status_code=403, detail="Permission denied")

    def write_file(
        self, path: str, content: str, create_dirs: bool = False, user_email: str = None
    ) -> Dict[str, Any]:
        """Write content to a file."""

        file_path = self._validate_path(path)

        # Check write permissions using syft-perm before attempting to write

        current_user = user_email or get_current_user_email()

        syftbox_path = os.path.expanduser("~/SyftBox")

        permission_warning = None

        if str(file_path).startswith(syftbox_path) and current_user:

            try:

                # Use syft-perm to check actual permissions

                from . import open as syft_open

                syft_file = syft_open(file_path.parent if not file_path.exists() else file_path)

                if not syft_file.has_write_access(current_user):

                    permission_warning = "You can edit this file but the permission system indicates it's likely to be rejected"

            except Exception:

                # If permission check fails, proceed but note the uncertainty

                pass

        # Create parent directories if requested

        if create_dirs:

            file_path.parent.mkdir(parents=True, exist_ok=True)

        # Check if parent directory exists

        if not file_path.parent.exists():

            raise HTTPException(status_code=400, detail="Parent directory does not exist")

        # Check if we can write to this file type

        if file_path.suffix.lower() not in self.ALLOWED_EXTENSIONS:

            raise HTTPException(status_code=415, detail="File type not allowed for editing")

        try:

            with open(file_path, "w", encoding="utf-8") as f:

                f.write(content)

            stat = file_path.stat()

            response = {
                "path": str(file_path),
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "message": "File saved successfully",
            }

            if permission_warning:

                response["permission_warning"] = permission_warning

            return response

        except PermissionError:

            raise HTTPException(status_code=403, detail="Permission denied")

        except OSError as e:

            raise HTTPException(status_code=500, detail=f"Error writing file: {str(e)}")

    def create_directory(self, path: str, user_email: str = None) -> Dict[str, Any]:
        """Create a new directory."""

        dir_path = self._validate_path(path)

        if dir_path.exists():

            raise HTTPException(status_code=400, detail="Directory already exists")

        # Check write permissions on parent directory using syft-perm

        current_user = user_email or get_current_user_email()

        syftbox_path = os.path.expanduser("~/SyftBox")

        if str(dir_path).startswith(syftbox_path) and current_user:

            try:

                # Use syft-perm to check actual permissions on parent directory

                from . import open as syft_open

                parent_dir = syft_open(dir_path.parent)

                if not parent_dir.has_write_access(current_user):

                    raise HTTPException(
                        status_code=403, detail="No write permission on parent directory"
                    )

            except Exception:

                # If permission check fails, log but proceed

                pass

        try:

            dir_path.mkdir(parents=True, exist_ok=False)

            return {"path": str(dir_path), "message": "Directory created successfully"}

        except PermissionError:

            raise HTTPException(status_code=403, detail="Permission denied")

        except OSError as e:

            raise HTTPException(status_code=500, detail=f"Error creating directory: {str(e)}")

    def delete_item(self, path: str, recursive: bool = False) -> Dict[str, Any]:
        """Delete a file or directory."""

        item_path = self._validate_path(path)

        if not item_path.exists():

            raise HTTPException(status_code=404, detail="Item not found")

        try:

            if item_path.is_dir():

                if recursive:

                    import shutil

                    shutil.rmtree(item_path)

                else:

                    item_path.rmdir()

            else:

                item_path.unlink()

            return {"path": str(item_path), "message": "Item deleted successfully"}

        except PermissionError:

            raise HTTPException(status_code=403, detail="Permission denied")

        except OSError as e:

            raise HTTPException(status_code=500, detail=f"Error deleting item: {str(e)}")

    def rename_item(self, old_path: str, new_path: str, user_email: str = None) -> Dict[str, Any]:
        """Rename a file or directory."""
        # Validate old path
        old_item_path = self._validate_path(old_path)

        if not old_item_path.exists():
            raise HTTPException(status_code=404, detail="Item not found")

        # Validate new path
        new_item_path = self._validate_path(new_path)

        if new_item_path.exists():
            raise HTTPException(status_code=409, detail="An item with that name already exists")

        # Check if parent directory exists
        if not new_item_path.parent.exists():
            raise HTTPException(status_code=400, detail="Parent directory does not exist")

        # Check write permissions on parent directory
        current_user = user_email or get_current_user_email()

        if current_user:
            try:
                from . import open as syft_open

                parent_folder = syft_open(old_item_path.parent)

                # Check if user has write or admin permissions
                if not parent_folder.has_permission(current_user, "write"):
                    # Check if it's their own datasite
                    import re

                    datasite_match = re.search(r"/datasites/([^/]+)/", str(old_item_path))
                    if not (datasite_match and datasite_match.group(1) == current_user):
                        raise HTTPException(
                            status_code=403,
                            detail="You don't have write permissions to rename items in this directory",
                        )
            except Exception:
                # If syft-perm check fails, continue with basic checks
                pass

        try:
            # Perform the rename
            old_item_path.rename(new_item_path)

            return {
                "old_path": str(old_item_path),
                "new_path": str(new_item_path),
                "message": f"{'Directory' if new_item_path.is_dir() else 'File'} renamed successfully",
            }

        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"Error renaming item: {str(e)}")
