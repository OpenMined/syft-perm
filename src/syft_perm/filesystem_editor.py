"""

Filesystem Code Editor Module

A fully featured file system browser and code editor for the FastAPI server.

Completely decoupled from syft-objects functionality.

"""

import json
import mimetypes
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import HTTPException


def get_current_user_email() -> Optional[str]:
    """Get current user email from environment or local datasite."""

    # Try environment variable first

    user_email = os.environ.get("SYFTBOX_USER_EMAIL")

    # If not found, try to read from syftbox config

    if not user_email:

        try:

            config_path = Path(os.path.expanduser("~/.syftbox/config.json"))

            if config_path.exists():

                with open(config_path, "r") as f:

                    config = json.load(f)

                    user_email = config.get("email")

        except Exception:

            pass

    # If still not found, try to detect from local datasite

    if not user_email:

        datasites_path = Path(os.path.expanduser("~/SyftBox/datasites"))

        if datasites_path.exists():

            for datasite_dir in datasites_path.iterdir():

                if datasite_dir.is_dir() and "@" in datasite_dir.name:

                    yaml_files = list(datasite_dir.glob("**/syft.pub.yaml"))

                    if yaml_files:

                        user_email = datasite_dir.name

                        break

    return user_email


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


def generate_editor_html(
    initial_path: str = None,
    is_dark_mode: bool = False,
    syft_user: Optional[str] = None,
    is_new_file: bool = False,
) -> str:
    """Generate the HTML for the filesystem code editor."""

    initial_path = initial_path or str(Path.home())

    # Check if initial_path is a file or directory

    is_initial_file = False

    if is_new_file:

        # For new files, treat as a file and set parent directory

        is_initial_file = True

        try:

            path_obj = Path(initial_path)

            initial_dir = str(path_obj.parent)

        except Exception:

            # If path parsing fails, use home directory as fallback

            initial_dir = str(Path.home())

    else:

        try:

            path_obj = Path(initial_path)

            if path_obj.exists() and path_obj.is_file():

                is_initial_file = True

                # For files, we'll pass the parent directory as the current path

                initial_dir = str(path_obj.parent)

            else:

                initial_dir = initial_path

        except Exception:

            initial_dir = initial_path

    # Define theme colors based on dark/light mode

    if is_dark_mode:

        # Dark mode colors

        bg_color = "#1e1e1e"

        text_color = "#d4d4d4"

        border_color = "#3e3e42"

        panel_bg = "#252526"

        panel_header_bg = "#2d2d30"

        accent_bg = "#2d2d30"

        muted_color = "#9ca3af"

        btn_primary_bg = "rgba(59, 130, 246, 0.2)"

        btn_primary_border = "rgba(59, 130, 246, 0.4)"

        btn_secondary_bg = "#2d2d30"

        btn_secondary_hover = "#3e3e42"

        editor_bg = "#1e1e1e"

        status_bar_bg = "#252526"

        status_bar_border = "#3e3e42"

        breadcrumb_bg = "#252526"

        file_item_hover = "#2d2d30"

        empty_state_color = "#9ca3af"

        error_bg = "rgba(239, 68, 68, 0.1)"

        error_color = "#ef4444"

        success_bg = "#065f46"

        success_border = "#10b981"

    else:

        # Light mode colors

        bg_color = "#ffffff"

        text_color = "#374151"

        border_color = "#e5e7eb"

        panel_bg = "#ffffff"

        panel_header_bg = "#f8f9fa"

        accent_bg = "#f3f4f6"

        muted_color = "#6b7280"

        btn_primary_bg = "rgba(147, 197, 253, 0.25)"

        btn_primary_border = "rgba(147, 197, 253, 0.4)"

        btn_secondary_bg = "#f3f4f6"

        btn_secondary_hover = "#e5e7eb"

        editor_bg = "#ffffff"

        status_bar_bg = "#ffffff"

        status_bar_border = "#e5e7eb"

        breadcrumb_bg = "#ffffff"

        file_item_hover = "#f3f4f6"

        empty_state_color = "#6b7280"

        error_bg = "rgba(254, 226, 226, 0.5)"

        error_color = "#dc2626"

        success_bg = "#dcfce7"

        success_border = "#bbf7d0"

    html_content = f"""

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>SyftBox File Editor</title>

    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/{('prism-tomorrow' if is_dark_mode else 'prism')}.min.css" rel="stylesheet">

    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-core.min.js"></script>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js"></script>

    <style>

        body {{

            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;

            margin: 0;

            padding: 0;

            background: {bg_color};

            color: {text_color};

            font-size: 13px;

            line-height: 1.5;

            height: 100vh;

            overflow: hidden;

        }}

        .container {{

            width: 100%;

            height: 100vh;

            margin: 0;

            padding: 0;

            display: flex;

            flex-direction: column;

        }}

        .main-content {{

            display: grid;

            grid-template-columns: 1fr 2fr;

            gap: 24px;

            flex: 1;

            overflow: hidden;

        }}

        .panel {{

            background: {panel_bg};

            border: none;

            border-radius: 0;

            overflow: hidden;

            box-shadow: none;

            display: flex;

            flex-direction: column;

            min-height: 0;

        }}

        .panel-header {{

            background: {panel_header_bg};

            padding: 8px 12px;

            border-bottom: 1px solid {border_color};

            font-weight: 600;

            color: {text_color};

            font-size: 12px;

        }}

        .panel-content {{

            flex: 1;

            overflow: auto;

            background: {panel_bg};

        }}

        .breadcrumb {{

            display: flex;

            flex-wrap: wrap;

            align-items: center;

            gap: 6px;

            padding: 8px 12px;

            background: {breadcrumb_bg};

            border-bottom: 1px solid {border_color};

            font-size: 11px;

            max-height: 150px;

            overflow-y: auto;

        }}

        .breadcrumb-item {{

            display: flex;

            align-items: center;

            gap: 8px;

            max-width: 200px;

        }}

        .breadcrumb-link {{

            color: {muted_color};

            text-decoration: none;

            padding: 4px 8px;

            border-radius: 4px;

            transition: all 0.2s;

            white-space: nowrap;

            overflow: hidden;

            text-overflow: ellipsis;

            max-width: 150px;

            font-weight: 500;

        }}

        .breadcrumb-link:hover {{

            background: {accent_bg};

            color: {text_color};

            max-width: none;

        }}

        .breadcrumb-current {{

            color: {text_color};

            font-weight: 500;

            background: {accent_bg};

            padding: 4px 8px;

            border-radius: 4px;

            max-width: 150px;

            white-space: nowrap;

            overflow: hidden;

            text-overflow: ellipsis;

        }}

        .breadcrumb-separator {{

            color: {muted_color};

            font-size: 0.8rem;

        }}

        .file-list {{

            padding: 8px 0;

        }}

        .file-item {{

            display: flex;

            align-items: center;

            gap: 12px;

            padding: 10px 16px;

            border-radius: 4px;

            cursor: pointer;

            transition: all 0.2s;

            border: 1px solid transparent;

            background: transparent;

        }}

        .file-item:hover {{

            background: {file_item_hover};

        }}

        .file-item.selected {{

            background: {accent_bg};

            border-color: {border_color};

        }}

        .file-icon {{

            width: 16px;

            height: 16px;

            font-size: 14px;

            display: flex;

            align-items: center;

            justify-content: center;

            color: {muted_color};

        }}

        .file-details {{

            flex: 1;

            min-width: 0;

        }}

        .file-name {{

            font-weight: 500;

            color: {text_color};

            white-space: nowrap;

            overflow: hidden;

            text-overflow: ellipsis;

            font-size: 12px;

        }}

        .file-meta {{

            font-size: 10px;

            color: {muted_color};

            margin-top: 1px;

        }}

        .editor-container {{

            flex: 1;

            display: flex;

            flex-direction: column;

            min-height: 0;

        }}

        .editor-header {{

            display: flex;

            align-items: center;

            justify-content: space-between;

            gap: 12px;

            padding: 12px 16px;

            background: {panel_bg};

            border-bottom: none;

            flex-shrink: 0;

        }}

        .editor-title {{

            font-weight: 500;

            color: {text_color};

            white-space: nowrap;

            overflow: hidden;

            text-overflow: ellipsis;

            flex: 1;

            font-size: 0.95rem;

            text-align: left;

        }}

        .editor-actions {{

            display: flex;

            gap: 6px;

            flex-shrink: 0;

            margin-left: auto;

        }}

        .btn {{

            padding: 5px 12px;

            border: none;

            border-radius: 4px;

            font-size: 11px;

            font-weight: 500;

            cursor: pointer;

            transition: all 0.15s;

            display: inline-flex;

            align-items: center;

            gap: 4px;

            line-height: 1.4;

        }}

        .btn-primary {{

            background: {btn_primary_bg};

            color: #3b82f6;

            border: 1px solid {btn_primary_border};

            backdrop-filter: blur(4px);

        }}

        .btn-primary:hover {{

            background: {btn_primary_bg};

            border-color: {btn_primary_border};

            transform: translateY(-1px);

            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.2);

            opacity: 0.8;

        }}

        .btn-primary.saving {{

            animation: buttonRainbow 1s ease-in-out;

        }}

        @keyframes buttonRainbow {{

            0% {{ background: rgba(255, 204, 204, 0.5); border-color: rgba(255, 179, 179, 0.7); }}

            14% {{ background: rgba(255, 217, 179, 0.5); border-color: rgba(255, 194, 153, 0.7); }}

            28% {{ background: rgba(255, 255, 204, 0.5); border-color: rgba(255, 255, 179, 0.7); }}

            42% {{ background: rgba(204, 255, 204, 0.5); border-color: rgba(179, 255, 179, 0.7); }}

            57% {{ background: rgba(204, 255, 255, 0.5); border-color: rgba(179, 255, 255, 0.7); }}

            71% {{ background: rgba(204, 204, 255, 0.5); border-color: rgba(179, 179, 255, 0.7); }}

            85% {{ background: rgba(255, 204, 255, 0.5); border-color: rgba(255, 179, 255, 0.7); }}

            100% {{ background: rgba(147, 197, 253, 0.25); border-color: rgba(147, 197, 253, 0.4); }}

        }}

        .btn-secondary {{

            background: {btn_secondary_bg};

            color: {text_color};

        }}

        .btn-secondary:hover {{

            background: {btn_secondary_hover};

        }}

        .btn-purple {{

            background: {'#3b2e4d' if is_dark_mode else '#e9d5ff'};

            color: {'#c084fc' if is_dark_mode else '#a855f7'};

            border: 1px solid {'rgba(192, 132, 252, 0.3)' if is_dark_mode else 'rgba(168, 85, 247, 0.3)'};

        }}

        .btn-purple:hover {{

            background: {'#4a3861' if is_dark_mode else '#ddd5ff'};

            transform: translateY(-1px);

            box-shadow: 0 2px 8px rgba(168, 85, 247, 0.2);

        }}

        /* Additional button colors with better harmony */

        .btn-mint {{

            background: {btn_secondary_bg};

            color: {text_color};

        }}

        .btn-mint:hover {{

            background: {btn_secondary_hover};

        }}

        .btn-lavender {{

            background: {btn_secondary_bg};

            color: {text_color};

        }}

        .btn-lavender:hover {{

            background: {btn_secondary_hover};

        }}

        .btn:disabled {{

            opacity: 0.5;

            cursor: not-allowed;

        }}

        .editor-textarea {{

            flex: 1;

            resize: none;

            border: none;

            outline: none;

            padding: 16px;

            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;

            font-size: 14px;

            line-height: 1.6;

            background: {editor_bg};

            color: {text_color};

            tab-size: 4;

            width: 100%;

            height: 100%;

        }}

        .editor-textarea:focus {{

            box-shadow: none;

        }}

        #editor-container {{

            flex: 1;

            position: relative;

            overflow: hidden;

            display: none;

        }}

        #syntax-highlight {{

            position: absolute;

            top: 0;

            left: 0;

            right: 0;

            bottom: 0;

            padding: 16px;

            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;

            font-size: 14px;

            line-height: 1.6;

            white-space: pre-wrap;

            word-wrap: break-word;

            overflow: auto;

            pointer-events: none;

            background: transparent;

        }}

        #editor-input {{

            position: absolute;

            top: 0;

            left: 0;

            right: 0;

            bottom: 0;

            padding: 16px;

            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;

            font-size: 14px;

            line-height: 1.6;

            background: transparent;

            color: transparent;

            caret-color: {text_color};

            resize: none;

            border: none;

            outline: none;

            white-space: pre-wrap;

            word-wrap: break-word;

            overflow: auto;

        }}

        .status-bar {{

            display: flex;

            align-items: center;

            justify-content: space-between;

            padding: 8px 16px;

            background: {status_bar_bg};

            border-top: 1px solid {status_bar_border};

            font-size: 0.85rem;

            color: {muted_color};

            flex-shrink: 0;

        }}

        .status-left {{

            display: flex;

            align-items: center;

            gap: 16px;

        }}

        .status-right {{

            display: flex;

            align-items: center;

            gap: 16px;

        }}

        .loading {{

            text-align: center;

            padding: 40px;

            color: {muted_color};

        }}

        .error {{

            background: {error_bg};

            color: {error_color};

            padding: 12px;

            border-radius: 0;

            margin: 12px;

            border: none;

        }}

        .success {{

            background: {success_bg};

            color: {('white' if is_dark_mode else '#065f46')};

            padding: 12px 20px;

            border-radius: 8px;

            margin: 12px;

            border: 1px solid {success_border};

            position: fixed;

            top: 20px;

            right: 20px;

            z-index: 1000;

            font-weight: 500;

            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);

            animation: slideIn 0.3s ease-out, rainbowPastel 3s ease-in-out;

        }}

        @keyframes slideIn {{

            from {{

                transform: translateX(400px);

                opacity: 0;

            }}

            to {{

                transform: translateX(0);

                opacity: 1;

            }}

        }}

        @keyframes slideOut {{

            to {{

                transform: translateX(400px);

                opacity: 0;

            }}

        }}

        @keyframes rainbowPastel {{

            0% {{ background: #ffcccc; border-color: #ffb3b3; }} /* Pastel Pink */

            14% {{ background: #ffd9b3; border-color: #ffc299; }} /* Pastel Orange */

            28% {{ background: #ffffcc; border-color: #ffffb3; }} /* Pastel Yellow */

            42% {{ background: #ccffcc; border-color: #b3ffb3; }} /* Pastel Green */

            57% {{ background: #ccffff; border-color: #b3ffff; }} /* Pastel Cyan */

            71% {{ background: #ccccff; border-color: #b3b3ff; }} /* Pastel Blue */

            85% {{ background: #ffccff; border-color: #ffb3ff; }} /* Pastel Purple */

            100% {{ background: #dcfce7; border-color: #bbf7d0; }} /* Final teal */

        }}

        .empty-state {{

            text-align: center;

            padding: 60px 20px;

            color: {empty_state_color};

        }}

        .empty-state h3 {{

            font-size: 1.1rem;

            margin-bottom: 8px;

            color: {text_color};

            font-weight: 500;

        }}

        .empty-state p {{

            color: {empty_state_color};

            font-size: 0.9rem;

        }}

        .logo {{

            width: 48px;

            height: 48px;

            margin: 0 auto 16px;

        }}

        @media (max-width: 900px) {{

            .main-content {{

                grid-template-columns: 1fr;

                gap: 16px;

            }}

            .editor-header {{

                flex-direction: column;

                gap: 8px;

            }}

            .editor-actions {{

                width: 100%;

                justify-content: flex-start;

            }}

            .breadcrumb {{

                padding: 8px 12px;

            }}

            .breadcrumb-item {{

                max-width: 120px;

            }}

            .breadcrumb-link,

            .breadcrumb-current {{

                max-width: 100px;

                font-size: 0.85rem;

            }}

        }}

        /* Embedded mode detection */

        .embedded-mode {{

            height: 100vh !important;

        }}

        .embedded-mode .container {{

            height: 100% !important;

        }}

        .embedded-mode .main-content {{

            height: 100% !important;

        }}

        .embedded-mode .panel {{

            height: 100% !important;

        }}

        .embedded-mode .editor-container {{

            height: 100% !important;

        }}

        @media (max-width: 600px) {{

            .container {{

                padding: 8px;

            }}

            .panel-header {{

                padding: 10px 12px;

            }}

            .breadcrumb {{

                padding: 8px;

            }}

            .file-item {{

                padding: 8px 10px;

            }}

            .editor-textarea {{

                padding: 10px;

                font-size: 13px;

            }}

        }}

        /* File-only mode styles */

        .file-only-mode .panel:first-child {{

            display: none;

        }}

        .file-only-mode .main-content {{

            grid-template-columns: 1fr;

        }}

        .file-only-mode .editor-panel {{

            border-radius: 0;

        }}

        .toggle-explorer-btn {{

            margin-right: 8px;

        }}

        /* Syntax highlighting editor styles */

        #editor-container {{

            position: relative;

            width: 100%;

            height: 100%;

            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;

        }}

        #syntax-highlight {{

            position: absolute;

            top: 0;

            left: 0;

            width: 100%;

            height: 100%;

            margin: 0;

            padding: 12px;

            border: none;

            background: transparent;

            color: transparent;

            font-family: inherit;

            font-size: 13px;

            line-height: 1.5;

            white-space: pre-wrap;

            overflow: auto;

            box-sizing: border-box;

            pointer-events: none;

            z-index: 1;

        }}

        #editor-input {{

            position: absolute;

            top: 0;

            left: 0;

            width: 100%;

            height: 100%;

            margin: 0;

            padding: 12px;

            border: none;

            background: transparent;

            color: {text_color};

            font-family: inherit;

            font-size: 13px;

            line-height: 1.5;

            white-space: pre-wrap;

            overflow: auto;

            resize: none;

            outline: none;

            box-sizing: border-box;

            z-index: 2;

            caret-color: {text_color};

        }}

        #editor-input::selection {{

            background: rgba(59, 130, 246, 0.3);

        }}

        /* Modal styles */
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(4px);
            animation: fadeIn 0.2s ease-out;
        }}

        .modal-content {{
            background-color: {panel_bg};
            margin: 15% auto;
            padding: 24px;
            border: 1px solid {border_color};
            border-radius: 8px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            animation: slideIn 0.2s ease-out;
        }}

        @keyframes fadeIn {{
            from {{
                opacity: 0;
            }}
            to {{
                opacity: 1;
            }}
        }}

        @keyframes slideIn {{
            from {{
                transform: translateY(-20px);
                opacity: 0;
            }}
            to {{
                transform: translateY(0);
                opacity: 1;
            }}
        }}

    </style>

</head>

<body>

    <div class="container">

        <div class="main-content">

            <div class="panel">

                <div class="panel-header">

                    File Explorer

                </div>

                <div class="breadcrumb" id="breadcrumb">

                    <div class="loading">Loading...</div>

                </div>

                <div class="panel-content">

                    <div class="file-list" id="fileList">

                        <div class="loading">Loading files...</div>

                    </div>

                </div>

            </div>

            <div class="panel">

                <div class="editor-container">

                    <div class="editor-header">

                        <div class="editor-title" id="editorTitle">No file selected</div>

                        <div class="editor-actions">

                            <button class="btn btn-secondary toggle-explorer-btn" id="toggleExplorerBtn" title="Toggle File Explorer">

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/>

                                </svg>

                            </button>

                            <button class="btn btn-lavender" id="newFileBtn">

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>

                                    <polyline points="14 2 14 8 20 8"/>

                                    <line x1="12" y1="18" x2="12" y2="12"/>

                                    <line x1="9" y1="15" x2="15" y2="15"/>

                                </svg>

                                New File

                            </button>

                            <button class="btn btn-mint" id="newFolderBtn">

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>

                                    <line x1="12" y1="11" x2="12" y2="17"/>

                                    <line x1="9" y1="14" x2="15" y2="14"/>

                                </svg>

                                New Folder

                            </button>

                            <button class="btn btn-secondary" id="shareBtn" title="Share file/folder">

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M16 3h5v5M21 3l-7 7m1 4v4h-5M14 21l7-7"/>

                                </svg>

                                Share

                            </button>

                            <button class="btn btn-secondary" id="renameBtn" title="Rename file/folder" style="display: none;">

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M12 20h9"/>

                                    <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>

                                </svg>

                                Rename

                            </button>

                            <button class="btn btn-secondary" id="closeFileBtn" title="Close file" style="display: none;">

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <line x1="18" y1="6" x2="6" y2="18"/>

                                    <line x1="6" y1="6" x2="18" y2="18"/>

                                </svg>

                                Close

                            </button>

                            <button class="btn btn-purple" id="openInWindowBtn" title="Open in new window">

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>

                                    <polyline points="15 3 21 3 21 9"/>

                                    <line x1="10" y1="14" x2="21" y2="3"/>

                                </svg>

                                Open in Window

                            </button>

                            <button class="btn btn-primary" id="saveBtn" disabled>

                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2v16z"/>

                                </svg>

                                Save

                            </button>

                        </div>

                    </div>

                    <div class="panel-content">

                        <div class="empty-state" id="emptyState">

                            <svg class="logo" xmlns="http://www.w3.org/2000/svg" width="311" height="360" viewBox="0 0 311 360" fill="none">

                                <g clip-path="url(#clip0_7523_4240)">

                                    <path d="M311.414 89.7878L155.518 179.998L-0.378906 89.7878L155.518 -0.422485L311.414 89.7878Z" fill="url(#paint0_linear_7523_4240)"></path>

                                    <path d="M311.414 89.7878V270.208L155.518 360.423V179.998L311.414 89.7878Z" fill="url(#paint1_linear_7523_4240)"></path>

                                    <path d="M155.518 179.998V360.423L-0.378906 270.208V89.7878L155.518 179.998Z" fill="url(#paint2_linear_7523_4240)"></path>

                                </g>

                                <defs>

                                    <linearGradient id="paint0_linear_7523_4240" x1="-0.378904" y1="89.7878" x2="311.414" y2="89.7878" gradientUnits="userSpaceOnUse">

                                        <stop stop-color="#DC7A6E"></stop>

                                        <stop offset="0.251496" stop-color="#F6A464"></stop>

                                        <stop offset="0.501247" stop-color="#FDC577"></stop>

                                        <stop offset="0.753655" stop-color="#EFC381"></stop>

                                        <stop offset="1" stop-color="#B9D599"></stop>

                                    </linearGradient>

                                    <linearGradient id="paint1_linear_7523_4240" x1="309.51" y1="89.7878" x2="155.275" y2="360.285" gradientUnits="userSpaceOnUse">

                                        <stop stop-color="#BFCD94"></stop>

                                        <stop offset="0.245025" stop-color="#B2D69E"></stop>

                                        <stop offset="0.504453" stop-color="#8DCCA6"></stop>

                                        <stop offset="0.745734" stop-color="#5CB8B7"></stop>

                                        <stop offset="1" stop-color="#4CA5B8"></stop>

                                    </linearGradient>

                                    <linearGradient id="paint2_linear_7523_4240" x1="-0.378906" y1="89.7878" x2="155.761" y2="360.282" gradientUnits="userSpaceOnUse">

                                        <stop stop-color="#D7686D"></stop>

                                        <stop offset="0.225" stop-color="#C64B77"></stop>

                                        <stop offset="0.485" stop-color="#A2638E"></stop>

                                        <stop offset="0.703194" stop-color="#758AA8"></stop>

                                        <stop offset="1" stop-color="#639EAF"></stop>

                                    </linearGradient>

                                    <clipPath id="clip0_7523_4240">

                                        <rect width="311" height="360" fill="white"></rect>

                                    </clipPath>

                                </defs>

                            </svg>

                            <h3>Welcome to SyftBox Editor</h3>

                            <p>Select a file from the explorer to start editing</p>

                        </div>

                        <div id="editor-container" style="display: none;">

                            <pre id="syntax-highlight"><code class="language-text"></code></pre>

                            <textarea id="editor-input" spellcheck="false"></textarea>

                        </div>

                        <textarea class="editor-textarea" id="editor" style="display: none;" placeholder="Start typing..."></textarea>

                    </div>

                    <div class="status-bar">

                        <div class="status-left">

                            <span id="fileInfo">Ready</span>

                        </div>

                        <div class="status-right">

                            <span id="readOnlyIndicator" style="color: #dc2626; font-weight: 600; margin-right: 10px; display: none;">READ-ONLY</span>

                            <span id="cursorPosition">Ln 1, Col 1</span>

                            <span id="fileSize">0 bytes</span>

                            <a href="https://github.com/OpenMined/syft-perm/issues" target="_blank" style="margin-left: 20px; color: {muted_color}; text-decoration: none; font-size: 11px;">

                                Report a Bug

                            </a>

                        </div>

                    </div>

                </div>

            </div>

        </div>

    </div>

    <script>

        // Detect if we're in an iframe and add embedded-mode class

        if (window.self !== window.top) {{

            document.body.classList.add('embedded-mode');

        }}

        // Also check for URL parameter

        const urlParams = new URLSearchParams(window.location.search);

        if (urlParams.get('embedded') === 'true') {{

            document.body.classList.add('embedded-mode');

        }}

        // Theme colors for JavaScript

        const themeColors = {{

            editor_bg: '{editor_bg}',

            editor_readonly_bg: '{('#2d2d30' if is_dark_mode else '#f9fafb')}',

            editor_uncertain_bg: '{('#3d3d30' if is_dark_mode else '#fffbeb')}',

            text_color: '{text_color}',

            muted_color: '{muted_color}'

        }};

        class FileSystemEditor {{

            constructor() {{

                // Check for path parameter in URL

                const urlParams = new URLSearchParams(window.location.search);

                const pathParam = urlParams.get('path');

                // Get syft_user from URL parameter if present

                this.syftUser = urlParams.get('syft_user') || null;

                // Check if this is a new file

                this.isNewFile = urlParams.get('new') === 'true';

                this.currentPath = pathParam || '{initial_dir}';

                this.initialFilePath = {'`' + initial_path + '`' if is_initial_file else 'null'};

                this.isInitialFile = {str(is_initial_file).lower()};

                this.currentFile = null;

                this.selectedFolder = null;

                this.isModified = false;

                this.isAdmin = false;  // Default to false until we load a file/directory

                this.fileOnlyMode = this.isInitialFile || this.isNewFile;

                this.isDarkMode = {str(is_dark_mode).lower()};

                this.initializeElements();

                this.setupEventListeners();

                if (this.isInitialFile || this.isNewFile) {{

                    if (this.isNewFile) {{

                        // For new files, create an empty file in memory

                        const filePath = this.currentPath;

                        const fileName = filePath.split('/').pop();

                        const parentDir = filePath.substring(0, filePath.lastIndexOf('/'));

                        console.log('Creating new file:', filePath);

                        console.log('File name:', fileName);

                        console.log('Parent directory:', parentDir);

                        // Set up for a new file

                        this.currentFile = {{

                            path: filePath,

                            content: '',

                            size: 0,

                            modified: new Date().toISOString(),

                            extension: fileName.includes('.') ? '.' + fileName.split('.').pop() : '',

                            encoding: 'utf-8',

                            can_write: true,

                            can_admin: true,

                            write_users: [this.syftUser || 'unknown']

                        }};

                        this.isModified = true;  // Mark as modified since it's new

                        this.isReadOnly = false;

                        this.isAdmin = true;

                        // Update UI for the new file

                        this.editorTitle.textContent = fileName + ' (new)';

                        // Show the editor

                        this.toggleFileOnlyMode(true);

                        this.toggleExplorerBtn.style.display = 'none';

                        // Hide empty state and show editor

                        this.emptyState.style.display = 'none';

                        this.editorContainer.style.display = 'none';

                        this.editor.style.display = 'block';

                        // Set editor content

                        this.editor.value = '';

                        this.editorInput.value = '';

                        // Update status

                        this.fileInfo.innerHTML = `<strong>${{fileName}}</strong> (new file - unsaved)`;

                        this.fileSize.textContent = '0 bytes';

                        this.updateCursorPosition();

                        // Focus the editor

                        this.editor.focus();

                        // Update the file browser to show parent directory

                        // Only load directory if we're not in file-only mode

                        this.currentPath = parentDir;

                        if (parentDir && !this.fileOnlyMode) {{

                            this.loadDirectory(parentDir);

                        }}

                    }} else {{

                        // If initial path is an existing file, load it directly

                        this.loadFile(this.initialFilePath);

                        this.toggleFileOnlyMode(true);

                        // Hide toggle button when viewing a single file

                        this.toggleExplorerBtn.style.display = 'none';

                    }}

                }} else {{

                    // Otherwise load the directory

                    this.loadDirectory(this.currentPath);

                }}

            }}

            initializeElements() {{

                this.fileList = document.getElementById('fileList');

                this.editor = document.getElementById('editor');

                this.editorContainer = document.getElementById('editor-container');

                this.editorInput = document.getElementById('editor-input');

                this.syntaxHighlight = document.getElementById('syntax-highlight').querySelector('code');

                this.saveBtn = document.getElementById('saveBtn');

                this.shareBtn = document.getElementById('shareBtn');
                
                this.renameBtn = document.getElementById('renameBtn');

                this.closeFileBtn = document.getElementById('closeFileBtn');

                this.newFileBtn = document.getElementById('newFileBtn');

                this.newFolderBtn = document.getElementById('newFolderBtn');

                this.editorTitle = document.getElementById('editorTitle');

                this.emptyState = document.getElementById('emptyState');

                this.breadcrumb = document.getElementById('breadcrumb');

                this.fileInfo = document.getElementById('fileInfo');

                this.cursorPosition = document.getElementById('cursorPosition');

                this.fileSize = document.getElementById('fileSize');

                this.toggleExplorerBtn = document.getElementById('toggleExplorerBtn');

                this.readOnlyIndicator = document.getElementById('readOnlyIndicator');

            }}

            getLanguageFromExtension(extension) {{

                const ext = extension.toLowerCase();

                const langMap = {{

                    '.js': 'javascript',

                    '.jsx': 'jsx',

                    '.ts': 'typescript',

                    '.tsx': 'tsx',

                    '.py': 'python',

                    '.html': 'html',

                    '.htm': 'html',

                    '.css': 'css',

                    '.scss': 'scss',

                    '.sass': 'sass',

                    '.json': 'json',

                    '.md': 'markdown',

                    '.xml': 'xml',

                    '.svg': 'svg',

                    '.sql': 'sql',

                    '.c': 'c',

                    '.cpp': 'cpp',

                    '.cc': 'cpp',

                    '.cxx': 'cpp',

                    '.h': 'c',

                    '.hpp': 'cpp',

                    '.java': 'java',

                    '.rs': 'rust',

                    '.php': 'php',

                    '.yaml': 'yaml',

                    '.yml': 'yaml',

                    '.toml': 'toml',

                    '.ini': 'ini',

                    '.cfg': 'ini',

                    '.conf': 'ini',

                    '.sh': 'bash',

                    '.bash': 'bash',

                    '.zsh': 'bash',

                    '.fish': 'bash',

                    '.ps1': 'powershell',

                    '.bat': 'batch',

                    '.cmd': 'batch',

                    '.rb': 'ruby',

                    '.go': 'go',

                    '.swift': 'swift',

                    '.kt': 'kotlin',

                    '.r': 'r',

                    '.R': 'r'

                }};

                return langMap[ext] || 'plaintext';

            }}

            updateSyntaxHighlighting() {{

                const content = this.editorInput.value;

                const language = this.currentFile ? this.getLanguageFromExtension(this.currentFile.extension || '') : 'plaintext';

                // Update language class

                this.syntaxHighlight.className = `language-${{language}}`;

                this.syntaxHighlight.textContent = content;

                // Re-highlight

                if (window.Prism) {{

                    Prism.highlightElement(this.syntaxHighlight);

                }}

            }}

            syncScroll() {{

                const syntaxPre = document.getElementById('syntax-highlight');

                syntaxPre.scrollTop = this.editorInput.scrollTop;

                syntaxPre.scrollLeft = this.editorInput.scrollLeft;

            }}

            setupEventListeners() {{

                this.saveBtn.addEventListener('click', () => this.saveFile());

                this.shareBtn.addEventListener('click', () => this.showShareModal());
                
                this.renameBtn.addEventListener('click', () => this.showRenameModal());

                this.closeFileBtn.addEventListener('click', () => this.closeFile());

                this.newFileBtn.addEventListener('click', () => this.createNewFile());

                this.newFolderBtn.addEventListener('click', () => this.createNewFolder());

                // Open in Window button

                const openInWindowBtn = document.getElementById('openInWindowBtn');

                if (openInWindowBtn) {{

                    openInWindowBtn.addEventListener('click', () => {{

                        const currentUrl = window.location.href;

                        window.open(currentUrl, '_blank');

                    }});

                }}

                this.toggleExplorerBtn.addEventListener('click', () => this.toggleFileOnlyMode());

                // Editor input listeners

                this.editorInput.addEventListener('input', () => {{

                    this.isModified = true;

                    this.updateUI();

                    this.updateSyntaxHighlighting();

                }});

                this.editorInput.addEventListener('scroll', () => this.syncScroll());

                this.editorInput.addEventListener('keyup', () => this.updateCursorPosition());

                this.editorInput.addEventListener('click', () => this.updateCursorPosition());

                // Fallback textarea listeners

                this.editor.addEventListener('input', () => {{

                    this.isModified = true;

                    this.updateUI();

                }});

                this.editor.addEventListener('keyup', () => this.updateCursorPosition());

                this.editor.addEventListener('click', () => this.updateCursorPosition());

                // Auto-save on Ctrl+S

                document.addEventListener('keydown', (e) => {{

                    if (e.ctrlKey && e.key === 's') {{

                        e.preventDefault();

                        if (this.currentFile) {{

                            this.saveFile();

                        }}

                    }}

                }});

            }}

            async loadDirectory(path) {{

                try {{

                    let url = `/api/filesystem/list?path=${{encodeURIComponent(path)}}`;

                    if (this.syftUser) {{

                        url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;

                    }}

                    const response = await fetch(url);

                    const data = await response.json();

                    if (!response.ok) {{

                        // Handle permission denied or directory not found gracefully

                        if (response.status === 403 || response.status === 404) {{

                            // Show permission denied message instead of error alert

                            const title = response.status === 403 ? 'Permission Denied' : 'Directory Not Found';

                            const message = response.status === 403 ?

                                'You do not have permission to access this directory. It may not exist locally or you may need to request access.' :

                                'The requested directory could not be found. It may have been moved or deleted.';

                            this.fileList.innerHTML = `

                                <div class="empty-state" style="text-align: center; padding: 40px;">

                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="${{themeColors.muted_color}}" stroke-width="1.5" style="margin: 0 auto 16px;">

                                        <path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>

                                    </svg>

                                    <h3 style="color: ${{themeColors.text_color}}; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">

                                        ${{title}}

                                    </h3>

                                    <p style="color: ${{themeColors.muted_color}}; font-size: 14px; margin: 0; max-width: 400px;">

                                        ${{message}}

                                    </p>

                                </div>

                            `;

                            // Clear breadcrumb navigation for permission denied directories

                            this.breadcrumb.innerHTML = `<div class="breadcrumb-current">${{title}}</div>`;

                            return;

                        }}

                        throw new Error(data.detail || 'Failed to load directory');

                    }}

                    this.currentPath = data.path;

                    this.isAdmin = data.can_admin || false;  // Update admin status for the directory

                    this.renderFileList(data.items);

                    this.renderBreadcrumb(data.path, data.parent);

                    this.updateUI();  // Update UI to reflect admin status

                }} catch (error) {{

                    this.showError('Failed to load directory: ' + error.message);

                }}

            }}

            renderFileList(items) {{

                if (items.length === 0) {{

                    this.fileList.innerHTML = '<div class="empty-state"><h3>Empty Directory</h3><p>No files or folders found</p></div>';

                    return;

                }}

                this.fileList.innerHTML = items.map(item => {{

                    const icon = item.is_directory

                        ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/></svg>'

                        : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>';

                    const sizeText = item.is_directory ? 'Directory' : this.formatFileSize(item.size);

                    const modifiedText = new Date(item.modified).toLocaleString();

                    return `

                        <div class="file-item" data-path="${{item.path}}" data-is-directory="${{item.is_directory}}" data-is-editable="${{item.is_editable}}">

                            <div class="file-icon ${{item.is_directory ? 'directory' : (item.is_editable ? 'editable' : '')}}">${{icon}}</div>

                            <div class="file-details">

                                <div class="file-name">${{item.name}}</div>

                                <div class="file-meta">${{sizeText}} • ${{modifiedText}}</div>

                            </div>

                        </div>

                    `;

                }}).join('');

                // Add click handlers

                this.fileList.querySelectorAll('.file-item').forEach(item => {{

                    item.addEventListener('click', () => {{

                        const path = item.dataset.path;

                        const isDirectory = item.dataset.isDirectory === 'true';

                        const isEditable = item.dataset.isEditable === 'true';

                        // Clear previous selections

                        this.fileList.querySelectorAll('.file-item').forEach(el => el.classList.remove('selected'));

                        // Add selection to current item

                        item.classList.add('selected');

                        if (isDirectory) {{

                            // For directories, just select them (don't navigate)

                            // This allows users to configure permissions for folders

                            this.selectedFolder = path;

                            this.currentFile = null;

                            // Check admin permissions for the selected folder

                            this.checkFolderPermissions(path);

                            // Update the editor title to show selected folder

                            this.editorTitle.textContent = `Selected: ${{path.split('/').pop()}} (folder)`;

                            // Show empty state with folder selected message

                            this.emptyState.style.display = 'flex';

                            this.emptyState.innerHTML = `

                                <div style="text-align: center;">

                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="${{themeColors.muted_color}}" stroke-width="1.5" style="margin: 0 auto 16px;">

                                        <path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/>

                                    </svg>

                                    <h3 style="color: ${{themeColors.text_color}}; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">

                                        Folder Selected

                                    </h3>

                                    <p style="color: ${{themeColors.muted_color}}; font-size: 14px; margin: 0;">

                                        ${{path.split('/').pop()}} - Use the Share button to configure permissions

                                    </p>

                                    <p style="color: ${{themeColors.muted_color}}; font-size: 13px; margin: 8px 0 0 0;">

                                        Double-click to open the folder

                                    </p>

                                </div>

                            `;

                            // Hide editors

                            this.editor.style.display = 'none';

                            this.editorContainer.style.display = 'none';

                            // Enable share button if user has permissions

                            this.updateUI();

                        }} else if (isEditable) {{

                            this.loadFile(path);

                            this.selectedFolder = null;

                        }}

                    }});

                    // Add double-click handler for folders to navigate

                    item.addEventListener('dblclick', () => {{

                        const isDirectory = item.dataset.isDirectory === 'true';

                        if (isDirectory) {{

                            this.loadDirectory(item.dataset.path);

                        }}

                    }});

                    item.addEventListener('contextmenu', (e) => {{

                        e.preventDefault();

                        this.showContextMenu(e, item.dataset.path, item.dataset.isDirectory === 'true');

                    }});

                }});

            }}

            renderBreadcrumb(currentPath, parentPath) {{

                const pathParts = currentPath.split('/').filter(part => part !== '');

                const isRoot = pathParts.length === 0;

                let breadcrumbHtml = '';

                if (isRoot) {{

                    breadcrumbHtml = '<div class="breadcrumb-current">Root</div>';

                }} else {{

                    // Build path parts

                    let currentBuildPath = '';

                    pathParts.forEach((part, index) => {{

                        currentBuildPath += '/' + part;

                        const isLast = index === pathParts.length - 1;

                        if (isLast) {{

                            breadcrumbHtml += `<div class="breadcrumb-current">${{part}}</div>`;

                        }} else {{

                            breadcrumbHtml += `

                                <div class="breadcrumb-item">

                                    <a href="#" class="breadcrumb-link" data-path="${{currentBuildPath}}">${{part}}</a>

                                    <span class="breadcrumb-separator">›</span>

                                </div>

                            `;

                        }}

                    }});

                    // Add home link at beginning

                    breadcrumbHtml = `

                        <div class="breadcrumb-item">

                            <a href="#" class="breadcrumb-link" data-path="/">Home</a>

                            <span class="breadcrumb-separator">›</span>

                        </div>

                    ` + breadcrumbHtml;

                }}

                this.breadcrumb.innerHTML = breadcrumbHtml;

                // Add click handlers for breadcrumb navigation

                this.breadcrumb.querySelectorAll('.breadcrumb-link').forEach(link => {{

                    link.addEventListener('click', (e) => {{

                        e.preventDefault();

                        const path = link.dataset.path;

                        this.loadDirectory(path);

                    }});

                }});

            }}

            async loadFile(path) {{

                try {{

                    let url = `/api/filesystem/read?path=${{encodeURIComponent(path)}}`;

                    if (this.syftUser) {{

                        url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;

                    }}

                    const response = await fetch(url);

                    const data = await response.json();

                    if (!response.ok) {{

                        // Handle permission denied or file not found

                        if (response.status === 403 || response.status === 404) {{

                            // Show permission denied message instead of editor

                            this.currentFile = null;

                            this.editor.value = '';

                            this.isModified = false;

                            this.updateUI();

                            // Hide editor, show empty state with custom message

                            this.editor.style.display = 'none';

                            this.emptyState.style.display = 'flex';

                            const title = response.status === 403 ? 'Permission Denied' : 'File Not Found';

                            const message = response.status === 403 ?

                                'You do not have permission to access this file. It may not exist locally or you may need to request access.' :

                                'The requested file could not be found. It may have been moved or deleted.';

                            this.emptyState.innerHTML = `

                                <div style="text-align: center; padding: 40px;">

                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="${{themeColors.muted_color}}" stroke-width="1.5" style="margin: 0 auto 16px;">

                                        <path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>

                                    </svg>

                                    <h3 style="color: ${{themeColors.text_color}}; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">

                                        ${{title}}

                                    </h3>

                                    <p style="color: ${{themeColors.muted_color}}; font-size: 14px; margin: 0; max-width: 400px;">

                                        ${{message}}

                                    </p>

                                </div>

                            `;

                            return;

                        }}

                        throw new Error(data.detail || 'Failed to load file');

                    }}

                    this.currentFile = data;

                    this.isModified = false;

                    this.isReadOnly = !data.can_write;

                    this.isAdmin = data.can_admin || false;

                    this.isUncertainPermissions = false;

                    // Backend now uses syft-perm for proper permission checking

                    // can_write reflects the actual syft-perm decision

                    // No more "uncertain permissions" guesswork needed

                    // Decide which editor to use

                    const useSimpleEditor = true; // For now, always use simple editor

                    if (useSimpleEditor) {{

                        // Use syntax highlighting editor

                        this.editorInput.value = data.content;

                        this.editorInput.readOnly = this.isReadOnly;

                        // Set background color based on permissions

                        if (this.isReadOnly) {{

                            this.editorInput.style.backgroundColor = themeColors.editor_readonly_bg;

                        }} else if (this.isUncertainPermissions) {{

                            this.editorInput.style.backgroundColor = themeColors.editor_uncertain_bg;

                        }} else {{

                            this.editorInput.style.backgroundColor = themeColors.editor_bg;

                        }}

                        // Update syntax highlighting

                        this.updateSyntaxHighlighting();

                        // Show editor container

                        this.emptyState.style.display = 'none';

                        this.editorContainer.style.display = 'block';

                        this.editor.style.display = 'none';

                    }} else {{

                        // Fallback to simple textarea

                        this.editor.value = data.content;

                        this.editor.readOnly = this.isReadOnly;

                        if (this.isReadOnly) {{

                            this.editor.style.backgroundColor = themeColors.editor_readonly_bg;

                        }} else if (this.isUncertainPermissions) {{

                            this.editor.style.backgroundColor = themeColors.editor_uncertain_bg;

                        }} else {{

                            this.editor.style.backgroundColor = themeColors.editor_bg;

                        }}

                        this.emptyState.style.display = 'none';

                        this.editorContainer.style.display = 'none';

                        this.editor.style.display = 'block';

                    }}

                    this.updateUI();

                    // Update file info with appropriate indicator

                    let badge = '';

                    if (this.isReadOnly) {{

                        badge = ' <span style="color: #dc2626; font-weight: 600;">[READ-ONLY]</span>';

                    }} else if (this.isUncertainPermissions) {{

                        badge = ' <span style="color: #f59e0b; font-weight: 600;">[UNCERTAIN PERMISSIONS]</span>';

                    }}

                    this.fileInfo.innerHTML = `${{path.split('/').pop()}} (${{data.extension}})${{badge}}`;

                    this.fileSize.textContent = this.formatFileSize(data.size);

                    // Remove any existing permission warnings

                    const existingWarnings = this.editorContainer.parentElement.querySelectorAll('.permission-warning');

                    existingWarnings.forEach(w => w.remove());

                    // Show permission info

                    if (this.isReadOnly && data.write_users && data.write_users.length > 0) {{

                        const permissionInfo = document.createElement('div');

                        permissionInfo.className = 'permission-warning';

                        permissionInfo.style.cssText = `

                            background: #fef2f2;

                            border: 1px solid #fecaca;

                            border-radius: 6px;

                            padding: 12px;

                            margin: 10px 0;

                            font-size: 13px;

                            color: #dc2626;

                        `;

                        permissionInfo.innerHTML = `

                            <strong>⚠️ Read-Only:</strong> The permission system indicates you don't have write access to this file.

                            Only <strong>${{data.write_users.join(', ')}}</strong> can edit this file.

                        `;

                        this.editorContainer.parentElement.insertBefore(permissionInfo, this.editorContainer);

                    }} else if (this.isUncertainPermissions) {{

                        const permissionInfo = document.createElement('div');

                        permissionInfo.className = 'permission-warning';

                        permissionInfo.id = 'uncertain-permissions-warning';

                        permissionInfo.style.cssText = `

                            background: #fef3c7;

                            border: 1px solid #fcd34d;

                            border-radius: 6px;

                            padding: 12px;

                            margin: 10px 0;

                            font-size: 13px;

                            color: #d97706;

                        `;

                        permissionInfo.innerHTML = `

                            <strong>⚠️ Uncertain Permissions:</strong> This file is in another user's datasite.

                            We can't verify your write permissions until the server processes your changes.

                            If you don't have permission, a conflict file will be created.

                        `;

                        this.editorContainer.parentElement.insertBefore(permissionInfo, this.editorContainer);

                    }}

                    // Update read-only indicator in footer

                    if (this.readOnlyIndicator) {{

                        if (this.isReadOnly) {{

                            this.readOnlyIndicator.textContent = 'READ-ONLY';

                            this.readOnlyIndicator.style.color = '#dc2626';

                            this.readOnlyIndicator.style.display = 'inline';

                        }} else if (this.isUncertainPermissions) {{

                            this.readOnlyIndicator.textContent = 'UNCERTAIN PERMISSIONS';

                            this.readOnlyIndicator.style.color = '#f59e0b';

                            this.readOnlyIndicator.style.display = 'inline';

                        }} else {{

                            this.readOnlyIndicator.style.display = 'none';

                        }}

                    }}

                    // Focus the active editor

                    if (this.editorContainer.style.display !== 'none') {{

                        this.editorInput.focus();

                    }} else {{

                        this.editor.focus();

                    }}

                }} catch (error) {{

                    this.showError('Failed to load file: ' + error.message);

                }}

            }}

            async saveFile() {{

                if (!this.currentFile) return;

                // Check if file is read-only

                if (this.isReadOnly) {{

                    this.showError('Cannot save: This file is read-only. You don\\'t have write permission.');

                    return;

                }}

                // Check if we have uncertain permissions

                if (this.isUncertainPermissions) {{

                    // Show modal to confirm save attempt

                    const userConfirmed = await this.showPermissionModal();

                    if (!userConfirmed) return; // User cancelled

                }}

                // Animate the save button with rainbow effect

                this.saveBtn.classList.add('saving');

                this.saveBtn.style.transform = 'scale(0.95)';

                // Create a more visible notification

                const notification = document.createElement('div');

                notification.style.cssText = `

                    position: fixed;

                    top: 50%;

                    left: 50%;

                    transform: translate(-50%, -50%);

                    padding: 20px 40px;

                    border-radius: 12px;

                    font-weight: 600;

                    font-size: 16px;

                    color: #065f46;

                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);

                    z-index: 10000;

                    animation: saveNotification 2s ease-in-out forwards;

                `;

                notification.textContent = '✨ Saving...';

                document.body.appendChild(notification);

                // Add the animation style if not already present

                if (!document.getElementById('save-animation-style')) {{

                    const style = document.createElement('style');

                    style.id = 'save-animation-style';

                    style.textContent = `

                        @keyframes saveNotification {{

                            0% {{

                                background: #ffcccc;

                                border: 2px solid #ffb3b3;

                                opacity: 0;

                                transform: translate(-50%, -50%) scale(0.8);

                            }}

                            10% {{

                                opacity: 1;

                                transform: translate(-50%, -50%) scale(1);

                            }}

                            20% {{ background: #ffd9b3; border-color: #ffc299; }}

                            30% {{ background: #ffffcc; border-color: #ffffb3; }}

                            40% {{ background: #ccffcc; border-color: #b3ffb3; }}

                            50% {{ background: #ccffff; border-color: #b3ffff; }}

                            60% {{ background: #ccccff; border-color: #b3b3ff; }}

                            70% {{ background: #ffccff; border-color: #ffb3ff; }}

                            80% {{ background: #dcfce7; border-color: #bbf7d0; }}

                            90% {{

                                opacity: 1;

                                transform: translate(-50%, -50%) scale(1);

                            }}

                            100% {{

                                background: #dcfce7;

                                border-color: #bbf7d0;

                                opacity: 0;

                                transform: translate(-50%, -50%) scale(1.1);

                            }}

                        }}

                    `;

                    document.head.appendChild(style);

                }}

                setTimeout(() => {{

                    this.saveBtn.style.transform = '';

                    this.saveBtn.classList.remove('saving');

                }}, 1000);

                try {{

                    // Get content from the active editor

                    let content = '';

                    if (this.editorContainer.style.display !== 'none') {{

                        content = this.editorInput.value;

                    }} else {{

                        content = this.editor.value;

                    }}

                    // Strip syft:// prefix if present

                    let filePath = this.currentFile.path;

                    if (filePath.startsWith('syft://')) {{

                        filePath = filePath.substring(7); // Remove 'syft://' prefix

                    }}

                    const requestBody = {{

                        path: filePath,

                        content: content

                    }};

                    // Add syft_user if present

                    if (this.syftUser) {{

                        requestBody.syft_user = this.syftUser;

                    }}

                    const response = await fetch('/api/filesystem/write', {{

                        method: 'POST',

                        headers: {{

                            'Content-Type': 'application/json',

                        }},

                        body: JSON.stringify(requestBody)

                    }});

                    const data = await response.json();

                    if (!response.ok) {{

                        throw new Error(data.detail || 'Failed to save file');

                    }}

                    this.isModified = false;

                    this.updateUI();

                    // Update notification to show success

                    const notification = document.querySelector('div[style*="saveNotification"]');

                    if (notification) {{

                        notification.textContent = '✅ Saved!';

                        setTimeout(() => notification.remove(), 500);

                    }}

                    this.showSuccess('File saved successfully');

                    // Update file info

                    this.fileSize.textContent = this.formatFileSize(data.size);

                }} catch (error) {{

                    this.showError('Failed to save file: ' + error.message);

                }}

            }}

            updateUI() {{

                const title = this.currentFile ?

                    `${{this.currentFile.path.split('/').pop()}}${{this.isModified ? ' •' : ''}}${{this.isReadOnly ? ' [READ-ONLY]' : ''}}` :

                    'No file selected';

                this.editorTitle.textContent = title;

                // Disable save button if no file, not modified, or read-only

                this.saveBtn.disabled = !this.currentFile || !this.isModified || this.isReadOnly;

                // Update save button appearance for read-only

                if (this.isReadOnly) {{

                    this.saveBtn.style.opacity = '0.5';

                    this.saveBtn.style.cursor = 'not-allowed';

                    this.saveBtn.title = 'File is read-only';

                }} else {{

                    this.saveBtn.style.opacity = '';

                    this.saveBtn.style.cursor = '';

                    this.saveBtn.title = 'Save file (Ctrl+S)';

                }}

                // Show/hide close button based on whether a file is open

                this.closeFileBtn.style.display = this.currentFile ? 'inline-flex' : 'none';
                
                // Show/hide rename button based on whether a file/folder is selected
                
                const hasSelection = this.currentFile || this.selectedFolder;
                this.renameBtn.style.display = hasSelection ? 'inline-flex' : 'none';
                
                // Enable rename button only if user has write permissions
                if (this.renameBtn) {{
                    const canRename = hasSelection && (this.isAdmin || !this.isReadOnly);
                    this.renameBtn.disabled = !canRename;
                    
                    if (!canRename) {{
                        this.renameBtn.style.opacity = '0.5';
                        this.renameBtn.style.cursor = 'not-allowed';
                        this.renameBtn.title = this.isReadOnly ? 'Read-only - cannot rename' : 'Select a file or folder first';
                    }} else {{
                        this.renameBtn.style.opacity = '';
                        this.renameBtn.style.cursor = '';
                        this.renameBtn.title = 'Rename file/folder';
                    }}
                }}

                // Update share button - only enabled if user has admin permissions

                if (this.shareBtn) {{

                    const hasFile = this.currentFile || this.selectedFolder || this.currentPath;

                    const canShare = hasFile && this.isAdmin;

                    this.shareBtn.disabled = !canShare;

                    if (!hasFile) {{

                        this.shareBtn.style.opacity = '0.5';

                        this.shareBtn.style.cursor = 'not-allowed';

                        this.shareBtn.title = 'Select a file or folder first';

                    }} else if (!this.isAdmin) {{

                        this.shareBtn.style.opacity = '0.5';

                        this.shareBtn.style.cursor = 'not-allowed';

                        this.shareBtn.title = 'You need admin permissions to share this item';

                    }} else {{

                        this.shareBtn.style.opacity = '';

                        this.shareBtn.style.cursor = '';

                        this.shareBtn.title = 'Share file/folder';

                    }}

                }}

            }}

            closeFile() {{

                // Close the current file and return to directory view

                this.currentFile = null;

                this.selectedFolder = null;

                this.isModified = false;

                this.isReadOnly = false;

                this.isUncertainPermissions = false;

                // Clear editors

                this.editor.value = '';

                this.editorInput.value = '';

                // Hide editors and show empty state

                this.editor.style.display = 'none';

                this.editorContainer.style.display = 'none';

                this.emptyState.style.display = 'flex';

                // Restore default empty state content

                this.emptyState.innerHTML = `

                    <svg class="logo" xmlns="http://www.w3.org/2000/svg" width="311" height="360" viewBox="0 0 311 360" fill="none">

                        <g clip-path="url(#clip0_7523_4240)">

                            <path d="M311.414 89.7878L155.518 179.998L-0.378906 89.7878L155.518 -0.422485L311.414 89.7878Z" fill="url(#paint0_linear_7523_4240)"></path>

                            <path d="M311.414 89.7878V270.208L155.518 360.423V179.998L311.414 89.7878Z" fill="url(#paint1_linear_7523_4240)"></path>

                            <path d="M155.518 179.998V360.423L-0.378906 270.208V89.7878L155.518 179.998Z" fill="url(#paint2_linear_7523_4240)"></path>

                        </g>

                        <defs>

                            <linearGradient id="paint0_linear_7523_4240" x1="-0.378904" y1="89.7878" x2="311.414" y2="89.7878" gradientUnits="userSpaceOnUse">

                                <stop stop-color="#DC7A6E"></stop>

                                <stop offset="0.251496" stop-color="#F6A464"></stop>

                                <stop offset="0.501247" stop-color="#FDC577"></stop>

                                <stop offset="0.753655" stop-color="#EFC381"></stop>

                                <stop offset="1" stop-color="#B9D599"></stop>

                            </linearGradient>

                            <linearGradient id="paint1_linear_7523_4240" x1="309.51" y1="89.7878" x2="155.275" y2="360.285" gradientUnits="userSpaceOnUse">

                                <stop stop-color="#BFCD94"></stop>

                                <stop offset="0.245025" stop-color="#B2D69E"></stop>

                                <stop offset="0.504453" stop-color="#8DCCA6"></stop>

                                <stop offset="0.745734" stop-color="#5CB8B7"></stop>

                                <stop offset="1" stop-color="#4CA5B8"></stop>

                            </linearGradient>

                            <linearGradient id="paint2_linear_7523_4240" x1="-0.378906" y1="89.7878" x2="155.761" y2="360.282" gradientUnits="userSpaceOnUse">

                                <stop stop-color="#D7686D"></stop>

                                <stop offset="0.225" stop-color="#C64B77"></stop>

                                <stop offset="0.485" stop-color="#A2638E"></stop>

                                <stop offset="0.703194" stop-color="#758AA8"></stop>

                                <stop offset="1" stop-color="#639EAF"></stop>

                            </linearGradient>

                            <clipPath id="clip0_7523_4240">

                                <rect width="311" height="360" fill="white"></rect>

                            </clipPath>

                        </defs>

                    </svg>

                    <h3>Welcome to SyftBox Editor</h3>

                    <p>Select a file from the explorer to start editing</p>

                `;

                // Remove any permission warnings

                const existingWarnings = this.editorContainer.parentElement.querySelectorAll('.permission-warning');

                existingWarnings.forEach(w => w.remove());

                // Update UI

                this.updateUI();

                // Clear file info

                this.fileInfo.innerHTML = 'Ready';

                this.fileSize.textContent = '0 bytes';

                // Reset read-only indicator

                if (this.readOnlyIndicator) {{

                    this.readOnlyIndicator.style.display = 'none';

                }}

                // Clear any selected file styling in the file list

                this.fileList.querySelectorAll('.file-item').forEach(item => {{

                    item.classList.remove('selected');

                }});

            }}

            updateCursorPosition() {{

                let textarea;

                if (this.editorContainer.style.display !== 'none') {{

                    textarea = this.editorInput;

                }} else {{

                    textarea = this.editor;

                }}

                const text = textarea.value;

                const cursorPos = textarea.selectionStart;

                // Calculate line and column

                const lines = text.substring(0, cursorPos).split('\\n');

                const line = lines.length;

                const col = lines[lines.length - 1].length + 1;

                this.cursorPosition.textContent = `Ln ${{line}}, Col ${{col}}`;

            }}

            formatFileSize(bytes) {{

                if (bytes === 0) return '0 bytes';

                const k = 1024;

                const sizes = ['bytes', 'KB', 'MB', 'GB'];

                const i = Math.floor(Math.log(bytes) / Math.log(k));

                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];

            }}

            showContextMenu(event, path, isDirectory) {{

                // Simple context menu - for now just prevent the default browser menu

                // Could be extended later to show options like delete, rename, etc.

                event.preventDefault();

                console.log('Context menu for:', path, 'isDirectory:', isDirectory);

            }}

            showError(message) {{

                const errorDiv = document.createElement('div');

                errorDiv.className = 'error';

                errorDiv.textContent = message;

                document.body.appendChild(errorDiv);

                setTimeout(() => {{

                    errorDiv.remove();

                }}, 5000);

            }}

            showSuccess(message) {{

                const successDiv = document.createElement('div');

                successDiv.className = 'success';

                successDiv.textContent = message;

                document.body.appendChild(successDiv);

                setTimeout(() => {{

                    successDiv.style.animation = 'slideOut 0.3s ease-in forwards';

                    setTimeout(() => successDiv.remove(), 300);

                }}, 3500);  // Show for 3.5 seconds to see full animation

            }}

            createNewFile() {{

                const filename = prompt('Enter filename:', 'untitled.txt');

                if (!filename) return;

                const newPath = this.currentPath + '/' + filename;

                // Strip syft:// prefix if present

                let filePath = newPath;

                if (filePath.startsWith('syft://')) {{

                    filePath = filePath.substring(7); // Remove 'syft://' prefix

                }}

                const requestBody = {{

                    path: filePath,

                    content: '',

                    create_dirs: true

                }};

                // Add syft_user if present

                if (this.syftUser) {{

                    requestBody.syft_user = this.syftUser;

                }}

                // Create empty file

                fetch('/api/filesystem/write', {{

                    method: 'POST',

                    headers: {{

                        'Content-Type': 'application/json',

                    }},

                    body: JSON.stringify(requestBody)

                }})

                .then(response => response.json())

                .then(data => {{

                    if (data.message) {{

                        this.showSuccess(data.message);

                        this.loadDirectory(this.currentPath);

                    }}

                }})

                .catch(error => {{

                    this.showError('Failed to create file: ' + error.message);

                }});

            }}

            createNewFolder() {{

                const foldername = prompt('Enter folder name:', 'New Folder');

                if (!foldername) return;

                const newPath = this.currentPath + '/' + foldername;

                const requestBody = {{

                    path: newPath

                }};

                // Add syft_user if present

                if (this.syftUser) {{

                    requestBody.syft_user = this.syftUser;

                }}

                fetch('/api/filesystem/create-directory', {{

                    method: 'POST',

                    headers: {{

                        'Content-Type': 'application/json',

                    }},

                    body: JSON.stringify(requestBody)

                }})

                .then(response => response.json())

                .then(data => {{

                    if (data.message) {{

                        this.showSuccess(data.message);

                        this.loadDirectory(this.currentPath);

                    }}

                }})

                .catch(error => {{

                    this.showError('Failed to create folder: ' + error.message);

                }});

            }}

            toggleFileOnlyMode(forceState = null) {{

                if (forceState !== null) {{

                    this.fileOnlyMode = forceState;

                }} else {{

                    this.fileOnlyMode = !this.fileOnlyMode;

                }}

                if (this.fileOnlyMode) {{

                    document.body.classList.add('file-only-mode');

                    this.toggleExplorerBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/></svg> Show';

                }} else {{

                    document.body.classList.remove('file-only-mode');

                    this.toggleExplorerBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/></svg>';

                }}

            }}

            showError(message) {{

                alert('Error: ' + message);

            }}

            showSuccess(message) {{

                console.log('Success: ' + message);

            }}

            async showPermissionModal() {{

                return new Promise((resolve) => {{

                    // Create modal overlay

                    const overlay = document.createElement('div');

                    overlay.style.cssText = `

                        position: fixed;

                        top: 0;

                        left: 0;

                        right: 0;

                        bottom: 0;

                        background: rgba(0, 0, 0, 0.5);

                        z-index: 9999;

                        display: flex;

                        align-items: center;

                        justify-content: center;

                        animation: fadeIn 0.2s ease-out;

                    `;

                    // Create modal content

                    const modal = document.createElement('div');

                    modal.style.cssText = `

                        background: white;

                        border-radius: 8px;

                        padding: 24px;

                        max-width: 500px;

                        width: 90%;

                        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);

                        animation: slideIn 0.3s ease-out;

                    `;

                    const fileName = this.currentFile.path.split('/').pop();

                    const fileExt = this.currentFile.extension || '.txt';

                    modal.innerHTML = `

                        <h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600; color: #111827;">

                            ⚠️ Uncertain Write Permissions

                        </h3>

                        <div style="color: #374151; font-size: 14px; line-height: 1.6; margin-bottom: 20px;">

                            <p style="margin: 0 0 12px 0;">

                                This file is in another user's datasite. We can't verify your write permissions

                                until the server processes your changes.

                            </p>

                            <p style="margin: 0 0 12px 0;">

                                <strong>If you have permission:</strong> Your changes will be saved normally.

                            </p>

                            <p style="margin: 0;">

                                <strong>If you don't have permission:</strong> A conflict file

                                (<code style="background: #f3f4f6; padding: 2px 4px; border-radius: 3px;">${{fileName}}.syftconflict${{fileExt}}</code>)

                                will be created with your changes.

                            </p>

                        </div>

                        <div style="display: flex; gap: 12px; justify-content: flex-end;">

                            <button id="cancelSave" style="

                                padding: 8px 16px;

                                border: 1px solid #d1d5db;

                                background: white;

                                color: #374151;

                                border-radius: 6px;

                                font-size: 14px;

                                font-weight: 500;

                                cursor: pointer;

                                transition: all 0.2s;

                            " onmouseover="this.style.background='#f9fafb'" onmouseout="this.style.background='white'">

                                Cancel

                            </button>

                            <button id="confirmSave" style="

                                padding: 8px 16px;

                                border: 1px solid #fbbf24;

                                background: #fbbf24;

                                color: #78350f;

                                border-radius: 6px;

                                font-size: 14px;

                                font-weight: 500;

                                cursor: pointer;

                                transition: all 0.2s;

                            " onmouseover="this.style.background='#f59e0b'" onmouseout="this.style.background='#fbbf24'">

                                Save Anyway

                            </button>

                        </div>

                    `;

                    overlay.appendChild(modal);

                    document.body.appendChild(overlay);

                    // Add animation styles if not present

                    if (!document.getElementById('modal-animations')) {{

                        const style = document.createElement('style');

                        style.id = 'modal-animations';

                        style.textContent = `

                            @keyframes fadeIn {{

                                from {{ opacity: 0; }}

                                to {{ opacity: 1; }}

                            }}

                            @keyframes slideIn {{

                                from {{ transform: translateY(-20px); opacity: 0; }}

                                to {{ transform: translateY(0); opacity: 1; }}

                            }}

                        `;

                        document.head.appendChild(style);

                    }}

                    // Handle button clicks

                    const cancelBtn = modal.querySelector('#cancelSave');

                    const confirmBtn = modal.querySelector('#confirmSave');

                    const cleanup = () => {{

                        overlay.style.animation = 'fadeIn 0.2s ease-out reverse';

                        modal.style.animation = 'slideIn 0.2s ease-out reverse';

                        setTimeout(() => overlay.remove(), 200);

                    }};

                    cancelBtn.addEventListener('click', () => {{

                        cleanup();

                        resolve(false);

                    }});

                    confirmBtn.addEventListener('click', () => {{

                        cleanup();

                        resolve(true);

                    }});

                    // Close on escape key

                    const escHandler = (e) => {{

                        if (e.key === 'Escape') {{

                            cleanup();

                            resolve(false);

                            document.removeEventListener('keydown', escHandler);

                        }}

                    }};

                    document.addEventListener('keydown', escHandler);

                }});

            }}

            async showShareModal() {{

                // Determine the path to share - could be current file, selected folder, or current directory

                let pathToShare;

                if (this.currentFile) {{

                    pathToShare = this.currentFile.path;

                }} else if (this.selectedFolder) {{

                    pathToShare = this.selectedFolder;

                }} else {{

                    pathToShare = this.currentPath;

                }}

                if (!pathToShare) {{

                    this.showError('No file or folder selected');

                    return;

                }}

                // Create modal overlay

                const overlay = document.createElement('div');

                overlay.style.cssText = `

                    position: fixed;

                    top: 0;

                    left: 0;

                    right: 0;

                    bottom: 0;

                    background: rgba(0, 0, 0, 0.5);

                    z-index: 10000;

                    display: flex;

                    align-items: center;

                    justify-content: center;

                    animation: fadeIn 0.3s ease-out;

                `;

                // Create modal container with iframe

                const modal = document.createElement('div');

                modal.style.cssText = `

                    background: transparent;

                    border-radius: 12px;

                    width: 90%;

                    max-width: 640px;

                    height: 600px;

                    max-height: 80vh;

                    overflow: hidden;

                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);

                    animation: slideIn 0.3s ease-out;

                `;

                // Create iframe

                const iframe = document.createElement('iframe');

                const shareUrl = `/share-modal?path=${{encodeURIComponent(pathToShare)}}`;

                iframe.src = shareUrl;

                iframe.style.cssText = `

                    width: 100%;

                    height: 100%;

                    border: none;

                    border-radius: 12px;

                `;

                modal.appendChild(iframe);

                overlay.appendChild(modal);

                document.body.appendChild(overlay);

                // Handle messages from iframe

                const messageHandler = (event) => {{

                    if (event.data && event.data.action === 'closeShareModal') {{

                        document.body.removeChild(overlay);

                        window.removeEventListener('message', messageHandler);

                    }}

                }};

                window.addEventListener('message', messageHandler);

                // Allow closing by clicking overlay

                overlay.addEventListener('click', (e) => {{

                    if (e.target === overlay) {{

                        document.body.removeChild(overlay);

                        window.removeEventListener('message', messageHandler);

                    }}

                }});

            }}
            
            async showRenameModal() {{
                // Determine what to rename
                let pathToRename;
                let itemName;
                let isDirectory = false;
                
                if (this.currentFile) {{
                    pathToRename = this.currentFile.path;
                    itemName = pathToRename.split('/').pop() || 'file';
                    isDirectory = false;
                }} else if (this.selectedFolder) {{
                    pathToRename = this.selectedFolder;
                    itemName = pathToRename.split('/').pop() || pathToRename;
                    isDirectory = true;
                }} else {{
                    this.showError('No file or folder selected to rename');
                    return;
                }}
                
                // Create modal dialog
                const modal = document.createElement('div');
                modal.className = 'modal';
                modal.style.display = 'block';
                
                const modalContent = document.createElement('div');
                modalContent.className = 'modal-content';
                
                modalContent.innerHTML = `
                    <h2 style="margin: 0 0 16px 0;">Rename ${{isDirectory ? 'Folder' : 'File'}}</h2>
                    <p style="margin: 0 0 16px 0; opacity: 0.8;">Current name: <strong>${{itemName}}</strong></p>
                    <input type="text" id="newNameInput" value="${{itemName}}" 
                        style="width: 100%; padding: 12px 80px 12px 16px; margin-bottom: 16px; 
                               border: 1px solid var(--border-color); border-radius: 4px;
                               background: var(--input-bg); color: var(--text-color);
                               font-size: 14px; box-sizing: border-box;">
                    <div style="display: flex; justify-content: flex-end; gap: 8px;">
                        <button class="btn btn-secondary" id="cancelRename">Cancel</button>
                        <button class="btn btn-primary" id="confirmRename">Rename</button>
                    </div>
                `;
                
                modal.appendChild(modalContent);
                document.body.appendChild(modal);
                
                // Focus input and select text
                const input = modalContent.querySelector('#newNameInput');
                input.focus();
                input.select();
                
                // Handle rename
                const doRename = async () => {{
                    const newName = input.value.trim();
                    if (!newName) {{
                        this.showError('Name cannot be empty');
                        return;
                    }}
                    
                    if (newName === itemName) {{
                        document.body.removeChild(modal);
                        return;
                    }}
                    
                    try {{
                        // Calculate new path
                        const pathParts = pathToRename.split('/');
                        pathParts[pathParts.length - 1] = newName;
                        const newPath = pathParts.join('/');
                        
                        // Call rename API
                        let url = `/api/filesystem/rename?old_path=${{encodeURIComponent(pathToRename)}}&new_path=${{encodeURIComponent(newPath)}}`;
                        if (this.syftUser) {{
                            url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;
                        }}
                        
                        const response = await fetch(url, {{ method: 'POST' }});
                        const result = await response.json();
                        
                        if (response.ok) {{
                            this.showSuccess(`${{isDirectory ? 'Folder' : 'File'}} renamed successfully`);
                            document.body.removeChild(modal);
                            
                            // Update UI
                            if (this.currentFile && !isDirectory) {{
                                // If we renamed the current file, load the new file
                                this.loadFile(newPath);
                            }} else {{
                                // Refresh the directory listing
                                this.loadDirectory(this.currentPath);
                                
                                // If we renamed a folder and it was selected, update the selection
                                if (this.selectedFolder === pathToRename) {{
                                    this.selectedFolder = newPath;
                                }}
                            }}
                        }} else {{
                            this.showError(result.detail || 'Failed to rename');
                        }}
                    }} catch (error) {{
                        this.showError('Error renaming: ' + error.message);
                    }}
                }};
                
                // Event listeners
                modalContent.querySelector('#confirmRename').addEventListener('click', doRename);
                modalContent.querySelector('#cancelRename').addEventListener('click', () => {{
                    document.body.removeChild(modal);
                }});
                
                input.addEventListener('keydown', (e) => {{
                    if (e.key === 'Enter') {{
                        doRename();
                    }} else if (e.key === 'Escape') {{
                        document.body.removeChild(modal);
                    }}
                }});
                
                // Close on outside click
                modal.addEventListener('click', (e) => {{
                    if (e.target === modal) {{
                        document.body.removeChild(modal);
                    }}
                }});
            }}

            async getCurrentUser() {{

                // If we have a syft user from the URL, use that

                if (this.syftUser) {{

                    return this.syftUser;

                }}

                // Try to get current user from the backend or environment

                try {{

                    const response = await fetch('/api/current-user');

                    if (response.ok) {{

                        const data = await response.json();

                        return data.email;

                    }}

                }} catch (e) {{

                    // Fallback: try to extract from local path or use a default

                    const pathParts = window.location.pathname.split('/');

                    const datasitesIndex = pathParts.indexOf('datasites');

                    if (datasitesIndex >= 0 && pathParts.length > datasitesIndex + 1) {{

                        return pathParts[datasitesIndex + 1];

                    }}

                }}

                return null;

            }}

            async checkFolderPermissions(folderPath) {{

                // Check admin permissions for a selected folder

                try {{

                    let url = `/api/filesystem/read?path=${{encodeURIComponent(folderPath + '/.syft_folder_check')}}`;

                    if (this.syftUser) {{

                        url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;

                    }}

                    // We'll use a trick: try to read a non-existent file in the folder

                    // This will trigger permission checks for the folder itself

                    const response = await fetch(url);

                    if (response.status === 404) {{

                        // File not found is expected, but we got permission info

                        const data = await response.json();

                        // The backend should still check permissions even for non-existent files

                    }}

                    // For now, let's use a simpler approach: when a folder is selected,

                    // we already have its parent's admin status from loadDirectory

                    // So we'll inherit that status

                    // This is a reasonable assumption since folder permissions are inherited

                    // The isAdmin status was already set by loadDirectory for the current directory

                    // We'll keep that status for selected folders within that directory

                    this.updateUI();

                }} catch (error) {{

                    console.error('Error checking folder permissions:', error);

                    // On error, assume no admin access

                    this.isAdmin = false;

                    this.updateUI();

                }}

            }}

            createShareModal(path, isDirectory, permData) {{

                // Create modal overlay

                const overlay = document.createElement('div');

                overlay.style.cssText = `

                    position: fixed;

                    top: 0;

                    left: 0;

                    right: 0;

                    bottom: 0;

                    background: rgba(0, 0, 0, 0.5);

                    z-index: 10000;

                    display: flex;

                    align-items: center;

                    justify-content: center;

                    animation: fadeIn 0.3s ease-out;

                `;

                // Create modal content

                const modal = document.createElement('div');

                const isDark = this.isDarkMode;

                modal.style.cssText = `

                    background: ${{isDark ? '#2d2d30' : 'white'}};

                    color: ${{isDark ? '#d4d4d4' : '#374151'}};

                    border-radius: 12px;

                    padding: 0;

                    max-width: 640px;

                    width: 90%;

                    max-height: 80vh;

                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);

                    animation: slideIn 0.3s ease-out;

                    overflow: hidden;

                `;

                const fileName = path.split('/').pop();

                const itemType = isDirectory ? 'folder' : 'file';

                // Generate user list HTML

                const permissions = permData.permissions || {{}};

                const allUsers = new Set();

                Object.values(permissions).forEach(userList => {{

                    userList.forEach(user => allUsers.add(user));

                }});

                const userListHtml = Array.from(allUsers).map(user => {{

                    const userPerms = {{}};

                    ['read', 'create', 'write', 'admin'].forEach(perm => {{

                        userPerms[perm] = permissions[perm]?.includes(user) || false;

                    }});

                    return `

                        <div class="user-row" data-user="${{user}}" style="

                            display: flex;

                            align-items: center;

                            padding: 12px 16px;

                            border-bottom: 1px solid ${{isDark ? '#3e3e42' : '#e5e7eb'}};

                            gap: 12px;

                        ">

                            <div class="user-info" style="flex: 1; min-width: 0;">

                                <div class="user-email" style="

                                    font-weight: 500;

                                    font-size: 14px;

                                    color: ${{isDark ? '#d4d4d4' : '#111827'}};

                                    overflow: hidden;

                                    text-overflow: ellipsis;

                                    white-space: nowrap;

                                ">${{user}}</div>

                                <div class="user-role" style="

                                    font-size: 12px;

                                    color: ${{isDark ? '#9ca3af' : '#6b7280'}};

                                    margin-top: 2px;

                                ">${{this.getUserRoleText(userPerms)}}</div>

                            </div>

                            <select class="permission-select" data-user="${{user}}" style="

                                padding: 6px 8px;

                                border: 1px solid ${{isDark ? '#3e3e42' : '#d1d5db'}};

                                border-radius: 6px;

                                background: ${{isDark ? '#1e1e1e' : 'white'}};

                                color: ${{isDark ? '#d4d4d4' : '#374151'}};

                                font-size: 13px;

                                cursor: pointer;

                            ">

                                <option value="none" ${{!userPerms.read ? 'selected' : ''}}>No access</option>

                                <option value="read" ${{userPerms.read && !userPerms.write && !userPerms.admin ? 'selected' : ''}}>Read</option>

                                <option value="write" ${{userPerms.write && !userPerms.admin ? 'selected' : ''}}>Write</option>

                                <option value="admin" ${{userPerms.admin ? 'selected' : ''}}>Admin</option>

                            </select>

                            <button class="remove-user-btn" data-user="${{user}}" style="

                                padding: 6px;

                                border: none;

                                background: none;

                                color: ${{isDark ? '#9ca3af' : '#6b7280'}};

                                cursor: pointer;

                                border-radius: 4px;

                                transition: all 0.2s;

                            " title="Remove user">

                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                    <path d="M3 6h18M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6m3 0V4c0-1 1-2 2-2h4c-1 0 2 1 2 2v2"/>

                                </svg>

                            </button>

                        </div>

                    `;

                }}).join('');

                modal.innerHTML = `

                    <div class="modal-header" style="

                        padding: 20px 24px;

                        border-bottom: 1px solid ${{isDark ? '#3e3e42' : '#e5e7eb'}};

                        display: flex;

                        align-items: center;

                        justify-content: space-between;

                    ">

                        <div>

                            <h2 style="

                                margin: 0;

                                font-size: 18px;

                                font-weight: 600;

                                color: ${{isDark ? '#d4d4d4' : '#111827'}};

                            ">Share "${{fileName}}"</h2>

                            <p style="

                                margin: 4px 0 0 0;

                                font-size: 14px;

                                color: ${{isDark ? '#9ca3af' : '#6b7280'}};

                            ">Manage who can access this ${{itemType}}</p>

                        </div>

                        <button id="closeModal" style="

                            background: none;

                            border: none;

                            color: ${{isDark ? '#9ca3af' : '#6b7280'}};

                            cursor: pointer;

                            padding: 8px;

                            border-radius: 6px;

                            transition: all 0.2s;

                        " title="Close">

                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                <line x1="18" y1="6" x2="6" y2="18"/>

                                <line x1="6" y1="6" x2="18" y2="18"/>

                            </svg>

                        </button>

                    </div>

                    <div class="modal-body" style="

                        padding: 20px 0;

                        max-height: 400px;

                        overflow-y: auto;

                    ">

                        <div class="add-user-section" style="

                            padding: 0 24px 16px;

                            border-bottom: 1px solid ${{isDark ? '#3e3e42' : '#e5e7eb'}};

                            margin-bottom: 16px;

                        ">

                            <div style="display: flex; gap: 8px; align-items: flex-end;">

                                <div style="flex: 1;">

                                    <label style="

                                        display: block;

                                        font-size: 13px;

                                        font-weight: 500;

                                        color: ${{isDark ? '#d4d4d4' : '#374151'}};

                                        margin-bottom: 6px;

                                    ">Add person</label>

                                    <input

                                        type="email"

                                        id="userEmailInput"

                                        placeholder="Enter email address"

                                        style="

                                            width: 100%;

                                            padding: 8px 12px;

                                            border: 1px solid ${{isDark ? '#3e3e42' : '#d1d5db'}};

                                            border-radius: 6px;

                                            background: ${{isDark ? '#1e1e1e' : 'white'}};

                                            color: ${{isDark ? '#d4d4d4' : '#374151'}};

                                            font-size: 14px;

                                            box-sizing: border-box;

                                        "

                                    />

                                </div>

                                <select id="newUserPermission" style="

                                    padding: 8px 12px;

                                    border: 1px solid ${{isDark ? '#3e3e42' : '#d1d5db'}};

                                    border-radius: 6px;

                                    background: ${{isDark ? '#1e1e1e' : 'white'}};

                                    color: ${{isDark ? '#d4d4d4' : '#374151'}};

                                    font-size: 14px;

                                    cursor: pointer;

                                ">

                                    <option value="read">Read</option>

                                    <option value="write">Write</option>

                                    <option value="admin">Admin</option>

                                </select>

                                <button id="addUserBtn" style="

                                    padding: 8px 16px;

                                    background: #3b82f6;

                                    color: white;

                                    border: none;

                                    border-radius: 6px;

                                    font-size: 14px;

                                    font-weight: 500;

                                    cursor: pointer;

                                    transition: all 0.2s;

                                    white-space: nowrap;

                                ">Add</button>

                            </div>

                        </div>

                        <div class="users-list">

                            ${{userListHtml || '<div style="padding: 20px; text-align: center; color: ' + (isDark ? '#9ca3af' : '#6b7280') + ';">No users have access yet</div>'}}

                        </div>

                    </div>

                    <div class="modal-footer" style="

                        padding: 16px 24px;

                        border-top: 1px solid ${{isDark ? '#3e3e42' : '#e5e7eb'}};

                        display: flex;

                        justify-content: flex-end;

                        gap: 12px;

                        background: ${{isDark ? '#252526' : '#f9fafb'}};

                    ">

                        <button id="cancelShare" style="

                            padding: 8px 16px;

                            border: 1px solid ${{isDark ? '#3e3e42' : '#d1d5db'}};

                            background: ${{isDark ? '#2d2d30' : 'white'}};

                            color: ${{isDark ? '#d4d4d4' : '#374151'}};

                            border-radius: 6px;

                            font-size: 14px;

                            font-weight: 500;

                            cursor: pointer;

                            transition: all 0.2s;

                        ">Cancel</button>

                        <button id="saveShare" style="

                            padding: 8px 16px;

                            background: #10b981;

                            color: white;

                            border: none;

                            border-radius: 6px;

                            font-size: 14px;

                            font-weight: 500;

                            cursor: pointer;

                            transition: all 0.2s;

                        ">Save Changes</button>

                    </div>

                `;

                overlay.appendChild(modal);

                document.body.appendChild(overlay);

                // Add modal event listeners

                this.setupShareModalEventListeners(overlay, modal, path, isDirectory, permData);

            }}

            getUserRoleText(userPerms) {{

                if (userPerms.admin) return 'Admin';

                if (userPerms.write) return 'Can edit';

                if (userPerms.read) return 'Can view';

                return 'No access';

            }}

            setupShareModalEventListeners(overlay, modal, path, isDirectory, permData) {{

                const closeModal = () => {{

                    overlay.style.animation = 'fadeIn 0.2s ease-out reverse';

                    modal.style.animation = 'slideIn 0.2s ease-out reverse';

                    setTimeout(() => overlay.remove(), 200);

                }};

                // Close modal handlers

                modal.querySelector('#closeModal').addEventListener('click', closeModal);

                modal.querySelector('#cancelShare').addEventListener('click', closeModal);

                // Close on escape

                const escHandler = (e) => {{

                    if (e.key === 'Escape') {{

                        closeModal();

                        document.removeEventListener('keydown', escHandler);

                    }}

                }};

                document.addEventListener('keydown', escHandler);

                // Add user handler

                const addUserBtn = modal.querySelector('#addUserBtn');

                const userEmailInput = modal.querySelector('#userEmailInput');

                const newUserPermission = modal.querySelector('#newUserPermission');

                const addUser = () => {{

                    const email = userEmailInput.value.trim();

                    const permission = newUserPermission.value;

                    if (!email) {{

                        this.showError('Please enter an email address');

                        return;

                    }}

                    if (!email.includes('@')) {{

                        this.showError('Please enter a valid email address');

                        return;

                    }}

                    this.addUserToModal(modal, email, permission, path);

                    userEmailInput.value = '';

                }};

                addUserBtn.addEventListener('click', addUser);

                userEmailInput.addEventListener('keypress', (e) => {{

                    if (e.key === 'Enter') addUser();

                }});

                // Permission change handlers

                modal.addEventListener('change', (e) => {{

                    if (e.target.classList.contains('permission-select')) {{

                        const user = e.target.dataset.user;

                        const permission = e.target.value;

                        this.updateUserPermission(e.target.closest('.user-row'), user, permission);

                    }}

                }});

                // Remove user handlers

                modal.addEventListener('click', (e) => {{

                    if (e.target.closest('.remove-user-btn')) {{

                        const userRow = e.target.closest('.user-row');

                        const user = userRow.dataset.user;

                        if (confirm(`Remove access for ${{user}}?`)) {{

                            userRow.remove();

                        }}

                    }}

                }});

                // Save changes handler

                modal.querySelector('#saveShare').addEventListener('click', () => {{

                    this.savePermissionChanges(modal, path, closeModal);

                }});

            }}

            addUserToModal(modal, email, permission, path) {{

                const usersList = modal.querySelector('.users-list');

                const isDark = this.isDarkMode;

                // Check if user already exists

                if (modal.querySelector(`[data-user="${{email}}"]`)) {{

                    this.showError('User already has access');

                    return;

                }}

                // Remove "no users" message if present

                const noUsersMsg = usersList.querySelector('div[style*="text-align: center"]');

                if (noUsersMsg) noUsersMsg.remove();

                const userRow = document.createElement('div');

                userRow.className = 'user-row';

                userRow.dataset.user = email;

                userRow.style.cssText = `

                    display: flex;

                    align-items: center;

                    padding: 12px 16px;

                    border-bottom: 1px solid ${{isDark ? '#3e3e42' : '#e5e7eb'}};

                    gap: 12px;

                `;

                userRow.innerHTML = `

                    <div class="user-info" style="flex: 1; min-width: 0;">

                        <div class="user-email" style="

                            font-weight: 500;

                            font-size: 14px;

                            color: ${{isDark ? '#d4d4d4' : '#111827'}};

                            overflow: hidden;

                            text-overflow: ellipsis;

                            white-space: nowrap;

                        ">${{email}}</div>

                        <div class="user-role" style="

                            font-size: 12px;

                            color: ${{isDark ? '#9ca3af' : '#6b7280'}};

                            margin-top: 2px;

                        ">${{this.getPermissionText(permission)}}</div>

                    </div>

                    <select class="permission-select" data-user="${{email}}" style="

                        padding: 6px 8px;

                        border: 1px solid ${{isDark ? '#3e3e42' : '#d1d5db'}};

                        border-radius: 6px;

                        background: ${{isDark ? '#1e1e1e' : 'white'}};

                        color: ${{isDark ? '#d4d4d4' : '#374151'}};

                        font-size: 13px;

                        cursor: pointer;

                    ">

                        <option value="none">No access</option>

                        <option value="read" ${{permission === 'read' ? 'selected' : ''}}>Read</option>

                        <option value="write" ${{permission === 'write' ? 'selected' : ''}}>Write</option>

                        <option value="admin" ${{permission === 'admin' ? 'selected' : ''}}>Admin</option>

                    </select>

                    <button class="remove-user-btn" data-user="${{email}}" style="

                        padding: 6px;

                        border: none;

                        background: none;

                        color: ${{isDark ? '#9ca3af' : '#6b7280'}};

                        cursor: pointer;

                        border-radius: 4px;

                        transition: all 0.2s;

                    " title="Remove user">

                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                            <path d="M3 6h18M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6m3 0V4c0-1 1-2 2-2h4c-1 0 2 1 2 2v2"/>

                        </svg>

                    </button>

                `;

                usersList.appendChild(userRow);

            }}

            getPermissionText(permission) {{

                switch (permission) {{

                    case 'admin': return 'Admin';

                    case 'write': return 'Can edit';

                    case 'read': return 'Can view';

                    default: return 'No access';

                }}

            }}

            updateUserPermission(userRow, user, permission) {{

                const userRole = userRow.querySelector('.user-role');

                userRole.textContent = this.getPermissionText(permission);

            }}

            async savePermissionChanges(modal, path, closeModal) {{

                const userRows = modal.querySelectorAll('.user-row');

                const changes = [];

                // Collect all current permissions from the modal

                userRows.forEach(row => {{

                    const user = row.dataset.user;

                    const permission = row.querySelector('.permission-select').value;

                    if (permission !== 'none') {{

                        changes.push({{ user, permission, action: 'grant' }});

                    }}

                }});

                try {{

                    // Apply changes via API

                    for (const change of changes) {{

                        const response = await fetch('/permissions/update', {{

                            method: 'POST',

                            headers: {{ 'Content-Type': 'application/json' }},

                            body: JSON.stringify({{

                                path: path,

                                user: change.user,

                                permission: change.permission,

                                action: change.action

                            }})

                        }});

                        if (!response.ok) {{

                            const error = await response.json();

                            throw new Error(error.detail || 'Failed to update permissions');

                        }}

                    }}

                    this.showSuccess('Permissions updated successfully');

                    closeModal();

                }} catch (error) {{

                    this.showError('Failed to save permissions: ' + error.message);

                }}

            }}

        }}

        // Initialize the editor when DOM is loaded

        document.addEventListener('DOMContentLoaded', () => {{

            new FileSystemEditor();

        }});

    </script>

</body>

</html>"""

    return html_content


def generate_share_modal_html(
    path: str, is_dark_mode: bool = False, syft_user: Optional[str] = None
) -> str:
    """Generate standalone share modal HTML."""

    import json
    from pathlib import Path

    path_obj = Path(path)

    file_name = path_obj.name

    is_directory = path_obj.is_dir() if path_obj.exists() else False

    item_type = "folder" if is_directory else "file"

    # Define theme colors

    if is_dark_mode:

        bg_color = "#2d2d30"

        text_color = "#d4d4d4"

        border_color = "#3e3e42"

        input_bg = "#1e1e1e"

        hover_bg = "#3e3e42"

        muted_color = "#9ca3af"

        modal_bg = "#252526"

    else:

        bg_color = "white"

        text_color = "#374151"

        border_color = "#e5e7eb"

        input_bg = "white"

        hover_bg = "#f3f4f6"

        muted_color = "#6b7280"

        modal_bg = "#f9fafb"

    return f"""

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Share {file_name}</title>

    <style>

        body {{

            margin: 0;

            padding: 20px;

            background: {bg_color};

            color: {text_color};

            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;

            display: flex;

            align-items: center;

            justify-content: center;

            min-height: 100vh;

        }}

        .container {{

            background: {bg_color};

            border-radius: 12px;

            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);

            width: 100%;

            max-width: 640px;

            overflow: hidden;

        }}

        .header {{

            padding: 20px 24px;

            border-bottom: 1px solid {border_color};

        }}

        .header h1 {{

            margin: 0;

            font-size: 18px;

            font-weight: 600;

        }}

        .header p {{

            margin: 4px 0 0 0;

            font-size: 14px;

            color: {muted_color};

        }}

        .body {{

            padding: 20px 0;

            max-height: 400px;

            overflow-y: auto;

        }}

        .add-section {{

            padding: 0 24px 16px;

            border-bottom: 1px solid {border_color};

            margin-bottom: 16px;

        }}

        .add-form {{

            display: flex;

            gap: 8px;

            align-items: flex-end;

        }}

        .form-group {{

            flex: 1;

        }}

        .form-label {{

            display: block;

            font-size: 13px;

            font-weight: 500;

            margin-bottom: 6px;

        }}

        .form-input {{

            width: 100%;

            padding: 8px 40px 8px 12px;

            border: 1px solid {border_color};

            border-radius: 6px;

            background: {input_bg};

            color: {text_color};

            font-size: 14px;

            box-sizing: border-box;

        }}

        .form-select {{

            padding: 8px 12px;

            border: 1px solid {border_color};

            border-radius: 6px;

            background: {input_bg};

            color: {text_color};

            font-size: 14px;

            cursor: pointer;

        }}

        .btn {{

            padding: 8px 16px;

            border: none;

            border-radius: 6px;

            font-size: 14px;

            font-weight: 500;

            cursor: pointer;

            transition: all 0.2s;

            white-space: nowrap;

        }}

        .btn-primary {{

            background: #3b82f6;

            color: white;

        }}

        .btn-primary:hover {{

            background: #2563eb;

        }}

        .btn-secondary {{

            background: {modal_bg};

            color: {text_color};

            border: 1px solid {border_color};

        }}

        .btn-secondary:hover {{

            background: {hover_bg};

        }}

        .user-row {{

            display: flex;

            align-items: center;

            padding: 12px 24px;

            border-bottom: 1px solid {border_color};

            gap: 12px;

        }}

        .user-row:hover {{

            background: {hover_bg};

        }}

        .user-info {{

            flex: 1;

            min-width: 0;

        }}

        .user-email {{

            font-weight: 500;

            font-size: 14px;

            overflow: hidden;

            text-overflow: ellipsis;

            white-space: nowrap;

        }}

        .user-role {{

            font-size: 12px;

            color: {muted_color};

            margin-top: 2px;

        }}

        .permission-reasons {{
            margin-top: 4px;
            padding: 6px 0;
            font-size: 11px;
            color: {muted_color};
            font-style: italic;
        }}

        .reason-item {{
            margin: 0;
            display: flex;
            align-items: center;
            gap: 6px;
            line-height: 1.3;
        }}

        .reason-perm {{
            font-weight: 500;
            color: {f'#1d4ed8' if not is_dark_mode else '#60a5fa'};
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.3px;
        }}

        .reason-text {{
            flex: 1;
            opacity: 0.85;
            font-weight: 400;
            word-break: break-word;
        }}

        .reason-icon {{
            margin-right: 2px;
            opacity: 0.8;
            font-size: 10px;
        }}

        .permission-select {{

            padding: 6px 8px;

            border: 1px solid {border_color};

            border-radius: 6px;

            background: {input_bg};

            color: {text_color};

            font-size: 13px;

            cursor: pointer;

        }}

        .remove-btn {{

            padding: 6px;

            border: none;

            background: none;

            color: {muted_color};

            cursor: pointer;

            border-radius: 4px;

            transition: all 0.2s;

        }}

        .remove-btn:hover {{

            background: {hover_bg};

            color: #ef4444;

        }}

        .footer {{

            padding: 16px 24px;

            border-top: 1px solid {border_color};

            display: flex;

            justify-content: flex-end;

            gap: 12px;

            background: {modal_bg};

        }}

        .loading {{

            text-align: center;

            padding: 40px;

            color: {muted_color};

        }}

        .error {{

            background: #fee2e2;

            color: #dc2626;

            padding: 12px 16px;

            border-radius: 8px;

            margin: 16px 24px;

            font-size: 14px;

        }}

        .success {{

            background: #d1fae5;

            color: #065f46;

            padding: 12px 16px;

            border-radius: 8px;

            margin: 16px 24px;

            font-size: 14px;

        }}

        .empty {{

            padding: 40px;

            text-align: center;

            color: {muted_color};

            font-size: 14px;

        }}

    </style>

</head>

<body>

    <div class="container">

        <div class="header">

            <h1>Share "{file_name}"</h1>

            <p>Manage who can access this {item_type}</p>

        </div>

        <div id="messageArea"></div>

        <div class="body">

            <div class="add-section">

                <div class="add-form">

                    <div class="form-group">

                        <label class="form-label">Add person</label>

                        <input

                            type="email"

                            id="userEmailInput"

                            class="form-input"

                            placeholder="Enter email address"

                        />

                    </div>

                    <select id="newUserPermission" class="form-select">

                        <option value="read">Read</option>

                        <option value="write">Write</option>

                        <option value="admin">Admin</option>

                    </select>

                    <button class="btn btn-primary" onclick="addUser()">Add</button>

                </div>

            </div>

            <div id="usersList" class="loading">Loading permissions...</div>

        </div>

        <div class="footer">

            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>

            <button class="btn btn-primary" onclick="saveChanges()">Save Changes</button>

        </div>

    </div>

    <script>

        const path = {json.dumps(path)};

        const syftUser = {json.dumps(syft_user) if syft_user else 'null'};

        let currentPermissions = {{}};

        let pendingChanges = {{}};

        async function loadPermissions() {{

            try {{

                const response = await fetch(`/permissions/${{encodeURIComponent(path)}}?include_reasons=true`);

                if (!response.ok) {{

                    throw new Error('Failed to load permissions');

                }}

                const data = await response.json();

                currentPermissions = data.permissions || {{}};

                renderUsersList();

                // Check if current user has admin permissions

                const currentUser = await getCurrentUser();

                if (currentUser) {{

                    let hasAdmin = false;

                    // Check if we have permission reasons (new format) or simple permissions (old format)

                    const hasReasons = currentPermissions && Object.values(currentPermissions).some(userPerm =>

                        userPerm && typeof userPerm === 'object' && userPerm.reasons

                    );

                    if (hasReasons) {{

                        // New format with reasons - check user's admin permission directly

                        const userData = currentPermissions[currentUser];

                        if (userData && userData.reasons && userData.reasons.admin) {{

                            hasAdmin = userData.reasons.admin.granted;

                        }}

                    }} else {{

                        // Old format without reasons

                        if (currentPermissions.admin) {{

                            hasAdmin = currentPermissions.admin.includes(currentUser) ||

                                     currentPermissions.admin.includes('*');

                        }}

                    }}

                    if (!hasAdmin) {{

                        showError('You need admin permissions to share this {item_type}');

                        document.querySelector('.add-section').style.display = 'none';

                        document.querySelector('.footer').style.display = 'none';

                    }}

                }}

            }} catch (error) {{

                showError('Failed to load permissions: ' + error.message);

            }}

        }}

        async function getCurrentUser() {{

            if (syftUser) return syftUser;

            try {{

                const response = await fetch('/api/current-user');

                if (response.ok) {{

                    const data = await response.json();

                    return data.email;

                }}

            }} catch (e) {{

                console.error('Failed to get current user:', e);

            }}

            return null;

        }}

        function renderUsersList() {{

            const container = document.getElementById('usersList');

            const allUsers = new Set();

            // Check if we have permission reasons (new format) or simple permissions (old format)

            const hasReasons = currentPermissions && Object.values(currentPermissions).some(userPerm =>

                userPerm && typeof userPerm === 'object' && userPerm.reasons

            );

            if (hasReasons) {{

                // New format with reasons

                Object.keys(currentPermissions).forEach(user => {{

                    allUsers.add(user);

                }});

            }} else {{

                // Old format without reasons

                Object.values(currentPermissions).forEach(userList => {{

                    userList.forEach(user => allUsers.add(user));

                }});

            }}

            if (allUsers.size === 0) {{

                container.innerHTML = '<div class="empty">No users have access yet</div>';

                return;

            }}

            const html = Array.from(allUsers).map(user => {{

                let userPerms = {{}};

                let reasons = {{}};

                if (hasReasons) {{

                    // New format with reasons

                    const userData = currentPermissions[user];

                    if (userData && userData.permissions) {{

                        ['read', 'create', 'write', 'admin'].forEach(perm => {{

                            userPerms[perm] = userData.permissions[perm]?.includes(user) || false;

                        }});

                        reasons = userData.reasons || {{}};

                    }}

                }} else {{

                    // Old format without reasons

                    ['read', 'create', 'write', 'admin'].forEach(perm => {{

                        userPerms[perm] = currentPermissions[perm]?.includes(user) || false;

                    }});

                }}

                const role = getUserRole(userPerms);

                const reasonsHtml = hasReasons ? generateReasonsHtml(user, reasons) : '';

                return `

                    <div class="user-row">

                        <div class="user-info">

                            <div class="user-email">${{user}}</div>

                            <div class="user-role">${{role}}</div>

                            ${{reasonsHtml}}

                        </div>

                        <select class="permission-select" onchange="updatePermission('${{user}}', this.value)">

                            <option value="none" ${{!userPerms.read ? 'selected' : ''}}>No access</option>

                            <option value="read" ${{userPerms.read && !userPerms.write && !userPerms.admin ? 'selected' : ''}}>Read</option>

                            <option value="write" ${{userPerms.write && !userPerms.admin ? 'selected' : ''}}>Write</option>

                            <option value="admin" ${{userPerms.admin ? 'selected' : ''}}>Admin</option>

                        </select>

                        <button class="remove-btn" onclick="removeUser('${{user}}')" title="Remove user">

                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                <path d="M3 6h18M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6m3 0V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>

                            </svg>

                        </button>

                    </div>

                `;

            }}).join('');

            container.innerHTML = html;

        }}

        function generateReasonsHtml(user, reasons) {{

            if (!reasons || Object.keys(reasons).length === 0) {{

                return '';

            }}

            let reasonsHtml = '<div class="permission-reasons">';
            
            // Find the highest granted permission level
            let highestPerm = null;
            ['admin', 'write', 'create', 'read'].forEach(perm => {{
                const permData = reasons[perm];
                if (permData && permData.granted && permData.reasons && permData.reasons.length > 0 && !highestPerm) {{
                    highestPerm = {{ level: perm, data: permData }};
                }}
            }});
            
            if (highestPerm) {{
                const icons = {{
                    'admin': '👑',
                    'write': '✏️', 
                    'create': '📝',
                    'read': '👁️'
                }};
                
                // Clean up the reason text - remove path prefix if it's too long
                let reasonText = highestPerm.data.reasons[0];
                if (reasonText.includes('/Users/') && reasonText.length > 50) {{
                    reasonText = reasonText.replace(/\\/Users\\/[^\\/]+\\/SyftBox\\/datasites\\/[^\\/]+\\//, '...');
                }}
                
                reasonsHtml += `<div class="reason-item">
                    <span class="reason-perm">
                        <span class="reason-icon">${{icons[highestPerm.level] || '📋'}}</span>${{highestPerm.level.toUpperCase()}}:
                    </span>
                    <span class="reason-text">${{reasonText}}</span>
                </div>`;
            }}

            reasonsHtml += '</div>';

            return reasonsHtml;

        }}

        function getUserRole(perms) {{

            if (perms.admin) return 'Admin (can manage permissions)';

            if (perms.write) return 'Write (can edit {item_type})';

            if (perms.read) return 'Read (can view {item_type})';

            return 'No access';

        }}

        function updatePermission(user, level) {{

            if (!pendingChanges[user]) {{

                pendingChanges[user] = {{}};

            }}

            pendingChanges[user].level = level;

        }}

        function removeUser(user) {{

            if (!pendingChanges[user]) {{

                pendingChanges[user] = {{}};

            }}

            pendingChanges[user].remove = true;

            // Update UI immediately

            const newPerms = JSON.parse(JSON.stringify(currentPermissions));

            ['read', 'create', 'write', 'admin'].forEach(perm => {{

                if (newPerms[perm]) {{

                    newPerms[perm] = newPerms[perm].filter(u => u !== user);

                }}

            }});

            currentPermissions = newPerms;

            renderUsersList();

        }}

        async function addUser() {{

            const email = document.getElementById('userEmailInput').value.trim();

            const permission = document.getElementById('newUserPermission').value;

            if (!email) {{

                showError('Please enter an email address');

                return;

            }}

            if (!email.includes('@')) {{

                showError('Please enter a valid email address');

                return;

            }}

            // Add to pending changes

            if (!pendingChanges[email]) {{

                pendingChanges[email] = {{}};

            }}

            pendingChanges[email].level = permission;

            // Update UI immediately

            const newPerms = JSON.parse(JSON.stringify(currentPermissions));

            ['read', 'create', 'write', 'admin'].forEach(perm => {{

                if (!newPerms[perm]) newPerms[perm] = [];

                newPerms[perm] = newPerms[perm].filter(u => u !== email);

            }});

            if (permission === 'read') {{

                newPerms.read.push(email);

            }} else if (permission === 'write') {{

                newPerms.read.push(email);

                newPerms.create.push(email);

                newPerms.write.push(email);

            }} else if (permission === 'admin') {{

                newPerms.read.push(email);

                newPerms.create.push(email);

                newPerms.write.push(email);

                newPerms.admin.push(email);

            }}

            currentPermissions = newPerms;

            renderUsersList();

            // Clear input

            document.getElementById('userEmailInput').value = '';

        }}

        async function saveChanges() {{

            const updates = [];

            for (const [user, changes] of Object.entries(pendingChanges)) {{

                if (changes.remove) {{

                    // Remove all permissions

                    ['read', 'create', 'write', 'admin'].forEach(perm => {{

                        updates.push({{

                            path: path,

                            user: user,

                            permission: perm,

                            action: 'revoke'

                        }});

                    }});

                }} else if (changes.level) {{

                    // First remove all permissions

                    ['read', 'create', 'write', 'admin'].forEach(perm => {{

                        updates.push({{

                            path: path,

                            user: user,

                            permission: perm,

                            action: 'revoke'

                        }});

                    }});

                    // Then grant appropriate permissions

                    if (changes.level === 'read') {{

                        updates.push({{

                            path: path,

                            user: user,

                            permission: 'read',

                            action: 'grant'

                        }});

                    }} else if (changes.level === 'write') {{

                        ['read', 'create', 'write'].forEach(perm => {{

                            updates.push({{

                                path: path,

                                user: user,

                                permission: perm,

                                action: 'grant'

                            }});

                        }});

                    }} else if (changes.level === 'admin') {{

                        ['read', 'create', 'write', 'admin'].forEach(perm => {{

                            updates.push({{

                                path: path,

                                user: user,

                                permission: perm,

                                action: 'grant'

                            }});

                        }});

                    }}

                }}

            }}

            try {{

                for (const update of updates) {{

                    const response = await fetch('/permissions/update', {{

                        method: 'POST',

                        headers: {{ 'Content-Type': 'application/json' }},

                        body: JSON.stringify(update)

                    }});

                    if (!response.ok) {{

                        throw new Error('Failed to update permissions');

                    }}

                }}

                showSuccess('Permissions updated successfully');

                pendingChanges = {{}};

                // Close modal after success

                setTimeout(() => {{

                    if (window.parent !== window) {{

                        window.parent.postMessage({{ action: 'closeShareModal' }}, '*');

                    }} else {{

                        window.close();

                    }}

                }}, 1500);

            }} catch (error) {{

                showError('Failed to save permissions: ' + error.message);

            }}

        }}

        function closeModal() {{

            if (window.parent !== window) {{

                window.parent.postMessage({{ action: 'closeShareModal' }}, '*');

            }} else {{

                window.close();

            }}

        }}

        function showError(message) {{

            const area = document.getElementById('messageArea');

            area.innerHTML = `<div class="error">${{message}}</div>`;

            setTimeout(() => area.innerHTML = '', 5000);

        }}

        function showSuccess(message) {{

            const area = document.getElementById('messageArea');

            area.innerHTML = `<div class="success">${{message}}</div>`;

        }}

        // Load permissions on page load

        loadPermissions();

    </script>

</body>

</html>

"""
