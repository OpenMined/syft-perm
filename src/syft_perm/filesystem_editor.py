"""
Filesystem Code Editor Module
A fully featured file system browser and code editor for the FastAPI server.
Completely decoupled from syft-objects functionality.
"""

import os
import mimetypes
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import HTTPException
from fastapi.responses import HTMLResponse
import json


class FileSystemManager:
    """Manages filesystem operations for the code editor."""
    
    ALLOWED_EXTENSIONS = {
        # Text files
        '.py', '.js', '.ts', '.jsx', '.tsx', '.html', '.css', '.scss', '.sass',
        '.json', '.yaml', '.yml', '.xml', '.md', '.txt', '.csv', '.log',
        '.sql', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd',
        # Config files
        '.ini', '.cfg', '.conf', '.toml', '.env', '.gitignore', '.dockerignore',
        # Code files
        '.c', '.cpp', '.h', '.hpp', '.java', '.php', '.rb', '.go', '.rs', '.swift',
        '.kt', '.scala', '.clj', '.lisp', '.hs', '.elm', '.dart', '.r', '.m', '.mm',
        # Web files
        '.vue', '.svelte', '.astro', '.htmx', '.mustache', '.handlebars',
        # Data files
        '.jsonl', '.ndjson', '.tsv', '.properties', '.lock',
        # Documentation
        '.rst', '.tex', '.latex', '.adoc', '.org',
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
                raise HTTPException(status_code=403, detail="Access denied: Path outside allowed directory")
            
            return resolved_path
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid path: {str(e)}")
    
    def _is_text_file(self, file_path: Path) -> bool:
        """Check if a file is a text file that can be edited."""
        if file_path.suffix.lower() in self.ALLOWED_EXTENSIONS:
            return True
        
        # Check MIME type
        mime_type, _ = mimetypes.guess_type(str(file_path))
        if mime_type and mime_type.startswith('text/'):
            return True
        
        # Try to read a small portion to detect if it's text
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                return chunk.decode('utf-8', errors='strict') is not None
        except (UnicodeDecodeError, PermissionError):
            return False
    
    def list_directory(self, path: str) -> Dict[str, Any]:
        """List directory contents."""
        dir_path = self._validate_path(path)
        
        if not dir_path.exists():
            raise HTTPException(status_code=404, detail="Directory not found")
        
        if not dir_path.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")
        
        try:
            items = []
            
            for item_path in sorted(dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
                try:
                    stat = item_path.stat()
                    is_directory = item_path.is_dir()
                    
                    item_info = {
                        'name': item_path.name,
                        'path': str(item_path),
                        'is_directory': is_directory,
                        'size': stat.st_size if not is_directory else None,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'is_editable': not is_directory and self._is_text_file(item_path),
                        'extension': item_path.suffix.lower() if not is_directory else None
                    }
                    items.append(item_info)
                    
                except (PermissionError, OSError):
                    # Skip items we can't access
                    continue
            
            # Get parent directory if not at root
            parent_path = None
            if dir_path.parent != dir_path:
                parent_path = str(dir_path.parent)
            
            return {
                'path': str(dir_path),
                'parent': parent_path,
                'items': items,
                'total_items': len(items)
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
        
        # Check write permissions
        # IMPORTANT: Non-admins don't have access to syft.pub.yaml files, so we can't
        # reliably check write permissions for files in other people's datasites.
        # The best we can do is:
        # 1. If it's in the user's own datasite, they can write
        # 2. If it's in someone else's datasite, assume read-only
        # 3. For non-SyftBox files, allow writes
        
        can_write = True  # Default to true for non-SyftBox files
        write_users = []
        
        # Check if file is within SyftBox
        syftbox_path = os.path.expanduser("~/SyftBox")
        if str(file_path).startswith(syftbox_path):
            # For SyftBox files, check if user owns the datasite
            try:
                # Extract the datasite from the path
                # Format: ~/SyftBox/datasites/<email>/...
                path_parts = str(file_path).split('/')
                if 'datasites' in path_parts:
                    ds_idx = path_parts.index('datasites')
                    if len(path_parts) > ds_idx + 1:
                        datasite_owner = path_parts[ds_idx + 1]
                        
                        # Simple check: user can write if they own the datasite
                        if user_email and user_email == datasite_owner:
                            can_write = True
                            write_users = [datasite_owner]
                        else:
                            # File is in someone else's datasite
                            # We can't know the real permissions without syft.pub.yaml
                            # So assume read-only to be safe
                            can_write = False
                            write_users = [datasite_owner]  # Show the owner at least
            except Exception:
                # On error, be conservative - assume no write access for SyftBox files
                can_write = False
                write_users = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            stat = file_path.stat()
            return {
                'path': str(file_path),
                'content': content,
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'extension': file_path.suffix.lower(),
                'encoding': 'utf-8',
                'can_write': can_write,
                'write_users': write_users
            }
        except UnicodeDecodeError:
            raise HTTPException(status_code=415, detail="File encoding not supported")
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
    
    def write_file(self, path: str, content: str, create_dirs: bool = False, user_email: str = None) -> Dict[str, Any]:
        """Write content to a file."""
        file_path = self._validate_path(path)
        
        # For SyftBox files in other people's datasites, we allow the write attempt
        # but warn that it might fail. The server will handle the actual permission check
        # and create a .syftconflict file if the user doesn't have permission.
        
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
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            stat = file_path.stat()
            return {
                'path': str(file_path),
                'size': stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'message': 'File saved successfully'
            }
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"Error writing file: {str(e)}")
    
    def create_directory(self, path: str) -> Dict[str, Any]:
        """Create a new directory."""
        dir_path = self._validate_path(path)
        
        if dir_path.exists():
            raise HTTPException(status_code=400, detail="Directory already exists")
        
        try:
            dir_path.mkdir(parents=True, exist_ok=False)
            return {
                'path': str(dir_path),
                'message': 'Directory created successfully'
            }
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
            
            return {
                'path': str(item_path),
                'message': 'Item deleted successfully'
            }
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
        except OSError as e:
            raise HTTPException(status_code=500, detail=f"Error deleting item: {str(e)}")


def generate_editor_html(initial_path: str = None, is_dark_mode: bool = False) -> str:
    """Generate the HTML for the filesystem code editor."""
    initial_path = initial_path or str(Path.home())
    
    # Check if initial_path is a file or directory
    is_initial_file = False
    initial_file_content = ""
    try:
        path_obj = Path(initial_path)
        if path_obj.exists() and path_obj.is_file():
            is_initial_file = True
            # For files, we'll pass the parent directory as the current path
            initial_dir = str(path_obj.parent)
        else:
            initial_dir = initial_path
    except:
        initial_dir = initial_path
    
    # Define theme colors based on dark/light mode
    if is_dark_mode:
        # Dark mode colors
        bg_color = "#1e1e1e"
        text_color = "#d4d4d4"
        border_color = "#3e3e42"
        panel_bg = "#252526"
        panel_header_bg = "#2d2d30"
        input_bg = "#1e1e1e"
        input_border = "#3e3e42"
        hover_bg = "rgba(255, 255, 255, 0.05)"
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
        input_bg = "#ffffff"
        input_border = "#e5e7eb"
        hover_bg = "rgba(0, 0, 0, 0.03)"
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
        
        class FileSystemEditor {{
            constructor() {{
                this.currentPath = '{initial_dir}';
                this.initialFilePath = {'`' + initial_path + '`' if is_initial_file else 'null'};
                this.isInitialFile = {str(is_initial_file).lower()};
                this.currentFile = null;
                this.isModified = false;
                this.fileOnlyMode = this.isInitialFile;
                this.initializeElements();
                this.setupEventListeners();
                
                if (this.isInitialFile) {{
                    // If initial path is a file, load it directly
                    this.loadFile(this.initialFilePath);
                    this.toggleFileOnlyMode(true);
                    // Hide toggle button when viewing a single file
                    this.toggleExplorerBtn.style.display = 'none';
                }} else {{
                    // Otherwise load the directory
                    this.loadDirectory(this.currentPath);
                }}
            }}
            
            initializeElements() {{
                this.fileList = document.getElementById('fileList');
                this.editor = document.getElementById('editor');
                this.saveBtn = document.getElementById('saveBtn');
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
            
            setupEventListeners() {{
                this.saveBtn.addEventListener('click', () => this.saveFile());
                this.newFileBtn.addEventListener('click', () => this.createNewFile());
                this.newFolderBtn.addEventListener('click', () => this.createNewFolder());
                this.toggleExplorerBtn.addEventListener('click', () => this.toggleFileOnlyMode());
                
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
                    const response = await fetch(`/api/filesystem/list?path=${{encodeURIComponent(path)}}`);
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
                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" stroke-width="1.5" style="margin: 0 auto 16px;">
                                        <path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                    </svg>
                                    <h3 style="color: #374151; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">
                                        ${{title}}
                                    </h3>
                                    <p style="color: #6b7280; font-size: 14px; margin: 0; max-width: 400px;">
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
                    this.renderFileList(data.items);
                    this.renderBreadcrumb(data.path, data.parent);
                    
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
                        
                        if (isDirectory) {{
                            this.loadDirectory(path);
                        }} else if (isEditable) {{
                            this.loadFile(path);
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
                    const response = await fetch(`/api/filesystem/read?path=${{encodeURIComponent(path)}}`);
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
                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" stroke-width="1.5" style="margin: 0 auto 16px;">
                                        <path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                    </svg>
                                    <h3 style="color: #374151; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">
                                        ${{title}}
                                    </h3>
                                    <p style="color: #6b7280; font-size: 14px; margin: 0; max-width: 400px;">
                                        ${{message}}
                                    </p>
                                </div>
                            `;
                            return;
                        }}
                        throw new Error(data.detail || 'Failed to load file');
                    }}
                    
                    this.currentFile = data;
                    this.editor.value = data.content;
                    this.isModified = false;
                    this.isReadOnly = !data.can_write;
                    this.isUncertainPermissions = false;
                    
                    // Check if this is a file in someone else datasite (uncertain permissions)
                    const pathStr = data.path || path;
                    if (pathStr.includes('/SyftBox/datasites/') && data.write_users && data.write_users.length > 0) {{
                        // If we marked it as read-only but it is not our datasite, we are uncertain
                        const pathParts = pathStr.split('/');
                        const dsIdx = pathParts.indexOf('datasites');
                        if (dsIdx >= 0 && pathParts.length > dsIdx + 1) {{
                            const datasite = pathParts[dsIdx + 1];
                            // Get current user email from somewhere (might need to add this to API)
                            // For now, if it is marked read-only and has write_users, it is uncertain
                            if (this.isReadOnly && !data.write_users.includes('*')) {{
                                this.isUncertainPermissions = true;
                                this.isReadOnly = false; // Allow editing, but with warning
                            }}
                        }}
                    }}
                    
                    // Set editor state based on permissions
                    this.editor.readOnly = this.isReadOnly;
                    if (this.isReadOnly) {{
                        this.editor.style.backgroundColor = '#f9fafb';
                    }} else if (this.isUncertainPermissions) {{
                        this.editor.style.backgroundColor = '#fffbeb'; // Light yellow warning color
                    }} else {{
                        this.editor.style.backgroundColor = '#ffffff';
                    }}
                    
                    this.updateUI();
                    
                    // Show editor, hide empty state
                    this.emptyState.style.display = 'none';
                    this.editor.style.display = 'block';
                    
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
                    const existingWarnings = this.editor.parentElement.querySelectorAll('.permission-warning');
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
                            <strong>⚠️ Read-Only:</strong> You don't have write permission for this file. 
                            Only <strong>${{data.write_users.join(', ')}}</strong> can edit this file.
                        `;
                        this.editor.parentElement.insertBefore(permissionInfo, this.editor);
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
                        this.editor.parentElement.insertBefore(permissionInfo, this.editor);
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
                    
                    // Focus editor
                    this.editor.focus();
                    
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
                    const response = await fetch('/api/filesystem/write', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            path: this.currentFile.path,
                            content: this.editor.value
                        }})
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
            }}
            
            updateCursorPosition() {{
                const textarea = this.editor;
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
                
                // Create empty file
                fetch('/api/filesystem/write', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        path: newPath,
                        content: '',
                        create_dirs: true
                    }})
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
                
                fetch('/api/filesystem/create-directory', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        path: newPath
                    }})
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
        }}
        
        // Initialize the editor when DOM is loaded
        document.addEventListener('DOMContentLoaded', () => {{
            new FileSystemEditor();
        }});
    </script>
</body>
</html>"""
    
    return html_content