"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.75"

__all__ = [
    "open",
    "get_editor_url",
    "files",
]


def open(path: _Union[str, _Path]) -> _Union[_SyftFile, _SyftFolder]:
    """
    Open a file or folder with SyftBox permissions.

    Args:
        path: Path to the file/folder (local path or syft:// URL)

    Returns:
        SyftFile or SyftFolder object

    Raises:
        ValueError: If path cannot be resolved or doesn't exist
    """
    from ._utils import resolve_path

    # Resolve syft:// URLs to local paths
    resolved_path = resolve_path(path)
    if resolved_path is None:
        raise ValueError(f"Could not resolve path: {path}")

    if not resolved_path.exists():
        raise ValueError(f"Path does not exist: {path} (resolved to: {resolved_path})")

    if resolved_path.is_dir():
        return _SyftFolder(resolved_path)
    return _SyftFile(resolved_path)


def get_editor_url(path: _Union[str, _Path]) -> str:
    """
    Get the URL for the Google Drive-style permission editor for a file/folder.

    Args:
        path: Path to the file/folder

    Returns:
        URL to the permission editor
    """
    from .server import get_editor_url as _get_editor_url

    return _get_editor_url(str(path))


class Files:
    """
    Access to permissioned files in SyftBox directory.

    Usage:
        import syft_perm as sp

        # Get all files
        all_files = sp.files.all()

        # Get paginated files
        page1 = sp.files.get(limit=10, offset=0)

        # Search files
        test_files = sp.files.search("test")
    """

    def __init__(self):
        self._cache = None

    def _scan_files(self, search: _Union[str, None] = None) -> list:
        """Scan SyftBox directory for files with permissions."""
        import os
        from pathlib import Path

        # Try to find SyftBox directory
        syftbox_dirs = [
            Path.home() / "SyftBox",
            Path.home() / ".syftbox",
            Path("/tmp/SyftBox"),
        ]

        syftbox_path = None
        for path in syftbox_dirs:
            if path.exists():
                syftbox_path = path
                break

        if not syftbox_path:
            return []

        # Only scan datasites directory
        datasites_path = syftbox_path / "datasites"
        if not datasites_path.exists():
            return []

        files = []
        all_paths = set()  # Track all paths to avoid duplicates

        # Try to detect current user's email from environment or config
        user_email = None
        try:
            # Try environment variable first
            user_email = os.environ.get("SYFTBOX_USER_EMAIL")

            # If not found, try to detect from local datasite
            if not user_email and datasites_path.exists():
                # Look for a local datasite with actual permissions
                for datasite_dir in datasites_path.iterdir():
                    if datasite_dir.is_dir() and "@" in datasite_dir.name:
                        # Check if this datasite has permission files we can read
                        yaml_files = list(datasite_dir.glob("**/syft.pub.yaml"))
                        if yaml_files:
                            user_email = datasite_dir.name
                            break
        except Exception:
            pass

        # First pass: collect all unique paths (files and folders)
        for root, dirs, file_names in os.walk(datasites_path):
            root_path = Path(root)
            
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            
            # Add current directory
            if root_path != datasites_path:  # Don't add the datasites folder itself
                all_paths.add(root_path)
            
            # Add all files
            for file_name in file_names:
                if not file_name.startswith(".") and file_name != "syft.pub.yaml":
                    all_paths.add(root_path / file_name)
        
        # Second pass: process all paths and create entries
        for path in sorted(all_paths):
            relative_path = path.relative_to(datasites_path)
            
            # Apply search filter
            if search and search.lower() not in str(relative_path).lower():
                continue
                
            # Process the path (either file or folder)
            if path.is_dir():
                # It's a folder
                datasite_owner = (
                    str(relative_path).split("/")[0] if "/" in str(relative_path) else str(relative_path)
                )
                
                is_user_datasite = user_email and datasite_owner == user_email
                
                # Get permissions for this folder
                permissions_summary = []
                try:
                    syft_obj = open(path)
                    permissions = syft_obj.permissions_dict.copy()
                    
                    # Build permissions summary
                    user_highest_perm = {}
                    for perm_level in ["admin", "write", "create", "read"]:
                        users = permissions.get(perm_level, [])
                        for user in users:
                            if user not in user_highest_perm:
                                user_highest_perm[user] = perm_level
                    
                    perm_groups = {}
                    for user, perm in user_highest_perm.items():
                        if perm not in perm_groups:
                            perm_groups[perm] = []
                        perm_groups[perm].append(user)
                    
                    for perm_level in ["admin", "write", "create", "read"]:
                        if perm_level in perm_groups:
                            users = perm_groups[perm_level]
                            if len(users) > 2:
                                user_list = f"{users[0]}, {users[1]}, +{len(users)-2}"
                            else:
                                user_list = ", ".join(users)
                            permissions_summary.append(f"{perm_level}: {user_list}")
                except Exception:
                    permissions_summary = []
                
                # Calculate folder size
                folder_size = 0
                try:
                    for item in path.rglob("*"):
                        if item.is_file() and not item.name.startswith("."):
                            folder_size += item.stat().st_size
                except Exception:
                    folder_size = 0
                
                files.append(
                    {
                        "name": str(relative_path),
                        "path": str(path),
                        "is_dir": True,
                        "permissions": {},
                        "is_user_datasite": is_user_datasite,
                        "has_yaml": path.joinpath("syft.pub.yaml").exists(),
                        "size": folder_size,
                        "modified": path.stat().st_mtime if path.exists() else 0,
                        "extension": "folder",
                        "datasite_owner": datasite_owner,
                        "permissions_summary": permissions_summary,
                    }
                )
            else:
                # It's a file
                datasite_owner = (
                    str(relative_path).split("/")[0] if "/" in str(relative_path) else ""
                )
                
                is_user_datasite = user_email and datasite_owner == user_email
                
                # Get permissions for this file
                has_yaml = False
                permissions_summary = []
                try:
                    syft_obj = open(path)
                    permissions = syft_obj.permissions_dict.copy()
                    
                    if hasattr(syft_obj, "has_yaml"):
                        has_yaml = syft_obj.has_yaml
                    elif any(users for users in permissions.values()):
                        has_yaml = True
                    
                    # Build permissions summary
                    user_highest_perm = {}
                    for perm_level in ["admin", "write", "create", "read"]:
                        users = permissions.get(perm_level, [])
                        for user in users:
                            if user not in user_highest_perm:
                                user_highest_perm[user] = perm_level
                    
                    perm_groups = {}
                    for user, perm in user_highest_perm.items():
                        if perm not in perm_groups:
                            perm_groups[perm] = []
                        perm_groups[perm].append(user)
                    
                    for perm_level in ["admin", "write", "create", "read"]:
                        if perm_level in perm_groups:
                            users = perm_groups[perm_level]
                            if len(users) > 2:
                                user_list = f"{users[0]}, {users[1]}, +{len(users)-2}"
                            else:
                                user_list = ", ".join(users)
                            permissions_summary.append(f"{perm_level}: {user_list}")
                except Exception:
                    permissions = {}
                    has_yaml = False
                    permissions_summary = []
                
                # Get file extension
                file_ext = path.suffix if path.suffix else ".txt"
                
                files.append(
                    {
                        "name": str(relative_path),
                        "path": str(path),
                        "is_dir": False,
                        "permissions": permissions,
                        "is_user_datasite": is_user_datasite,
                        "has_yaml": has_yaml,
                        "size": path.stat().st_size if path.exists() else 0,
                        "modified": path.stat().st_mtime if path.exists() else 0,
                        "extension": file_ext,
                        "datasite_owner": datasite_owner,
                        "permissions_summary": permissions_summary,
                    }
                )
        
        # Sort by name
        files.sort(key=lambda x: x["name"])
        return files

    def get(self, limit: int = 50, offset: int = 0, search: _Union[str, None] = None) -> dict:
        """
        Get paginated list of files with permissions.

        Args:
            limit: Number of items per page (default: 50)
            offset: Starting index (default: 0)
            search: Optional search term for file names

        Returns:
            Dictionary with files, total_count, offset, limit, has_more
        """
        all_files = self._scan_files(search)
        total_count = len(all_files)

        # Apply pagination
        end = offset + limit
        page_files = all_files[offset:end]
        has_more = end < total_count

        return {
            "files": page_files,
            "total_count": total_count,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
        }

    def all(self, search: _Union[str, None] = None) -> list:
        """
        Get all files with permissions (no pagination).

        Args:
            search: Optional search term for file names

        Returns:
            List of all files with permissions
        """
        return self._scan_files(search)

    def search(self, term: str, limit: int = 50, offset: int = 0) -> dict:
        """
        Search for files by name.

        Args:
            term: Search term for file names
            limit: Number of items per page (default: 50)
            offset: Starting index (default: 0)

        Returns:
            Dictionary with search results
        """
        return self.get(limit=limit, offset=offset, search=term)

    def __repr__(self) -> str:
        """Static string representation."""
        return "<Files: SyftBox permissioned files interface>"

    def _repr_html_(self) -> str:
        """Generate SyftObjects-style widget for Jupyter."""
        import html as html_module
        import json
        import uuid
        from datetime import datetime

        container_id = f"syft_files_{uuid.uuid4().hex[:8]}"
        data = self.get(limit=100)  # Get more files initially
        files = data["files"]
        total = data["total_count"]

        if not files:
            return (
                "<div style='padding: 40px; text-align: center; color: #666; "
                "font-family: -apple-system, BlinkMacSystemFont, sans-serif;'>"
                "No files found in SyftBox/datasites directory</div>"
            )

        # Get all files for search
        all_files = self._scan_files()

        # Build HTML template with SyftObjects styling
        html = f"""
        <style>
        #{container_id} * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        #{container_id} {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 12px;
            background: #ffffff;
            overflow: hidden;
            display: flex;
            flex-direction: column;
            width: 100%;
            margin: 0;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }}

        #{container_id} .search-controls {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            padding: 0.75rem;
            background: #f8f9fa;
            border-bottom: 1px solid #e5e7eb;
            flex-shrink: 0;
        }}

        #{container_id} .search-controls input {{
            flex: 1;
            min-width: 200px;
            padding: 0.5rem;
            border: 1px solid #d1d5db;
            border-radius: 0.25rem;
            font-size: 0.875rem;
        }}

        #{container_id} .table-container {{
            flex: 1;
            overflow-y: auto;
            overflow-x: auto;
            background: #ffffff;
            min-height: 0;
            max-height: 600px;
        }}

        #{container_id} table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75rem;
        }}

        #{container_id} thead {{
            background: #f8f9fa;
            border-bottom: 1px solid #e5e7eb;
        }}

        #{container_id} th {{
            text-align: left;
            padding: 0.375rem 0.25rem;
            font-weight: 500;
            font-size: 0.75rem;
            border-bottom: 1px solid #e5e7eb;
            position: sticky;
            top: 0;
            background: #f8f9fa;
            z-index: 10;
        }}

        #{container_id} td {{
            padding: 0.375rem 0.25rem;
            border-bottom: 1px solid #f3f4f6;
            vertical-align: top;
            font-size: 0.75rem;
            text-align: left;
        }}

        #{container_id} tbody tr {{
            transition: background-color 0.15s;
            cursor: pointer;
        }}

        #{container_id} tbody tr:hover {{
            background: rgba(0, 0, 0, 0.03);
        }}

        @keyframes rainbow {{
            0% {{ background-color: #ffe9ec; }}
            14.28% {{ background-color: #fff4ea; }}
            28.57% {{ background-color: #ffffea; }}
            42.86% {{ background-color: #eaffef; }}
            57.14% {{ background-color: #eaf6ff; }}
            71.43% {{ background-color: #f5eaff; }}
            85.71% {{ background-color: #ffeaff; }}
            100% {{ background-color: #ffe9ec; }}
        }}

        #{container_id} .rainbow-flash {{
            animation: rainbow 0.8s ease-in-out;
        }}

        #{container_id} .pagination {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            border-top: 1px solid #e5e7eb;
            background: rgba(0, 0, 0, 0.02);
            flex-shrink: 0;
        }}

        #{container_id} .pagination button {{
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            border: 1px solid #e5e7eb;
            background: white;
            cursor: pointer;
            transition: all 0.15s;
        }}

        #{container_id} .pagination button:hover:not(:disabled) {{
            background: #f3f4f6;
        }}

        #{container_id} .pagination button:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        #{container_id} .pagination .page-info {{
            font-size: 0.75rem;
            color: #6b7280;
        }}

        #{container_id} .pagination .status {{
            font-size: 0.75rem;
            color: #9ca3af;
            font-style: italic;
            opacity: 0.8;
            text-align: center;
            flex: 1;
        }}

        #{container_id} .pagination .pagination-controls {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        #{container_id} .truncate {{
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}

        #{container_id} .btn {{
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            border: none;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 0.125rem;
            transition: all 0.15s;
        }}

        #{container_id} .btn:hover {{
            opacity: 0.8;
        }}

        #{container_id} .btn-blue {{
            background: #dbeafe;
            color: #3b82f6;
        }}

        #{container_id} .btn-purple {{
            background: #e9d5ff;
            color: #a855f7;
        }}

        #{container_id} .btn-red {{
            background: #fee2e2;
            color: #ef4444;
        }}

        #{container_id} .btn-green {{
            background: #d1fae5;
            color: #10b981;
        }}

        #{container_id} .btn-gray {{
            background: #f3f4f6;
            color: #6b7280;
        }}

        #{container_id} .icon {{
            width: 0.5rem;
            height: 0.5rem;
        }}
        
        #{container_id} .autocomplete-dropdown {{
            position: absolute;
            background: white;
            border: 1px solid #e5e7eb;
            border-radius: 0.25rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            display: none;
        }}
        
        #{container_id} .autocomplete-dropdown.show {{
            display: block;
        }}
        
        #{container_id} .autocomplete-option {{
            padding: 0.5rem;
            cursor: pointer;
            font-size: 0.875rem;
        }}
        
        #{container_id} .autocomplete-option:hover,
        #{container_id} .autocomplete-option.selected {{
            background: #f3f4f6;
        }}

        #{container_id} .type-badge {{
            display: inline-block;
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 500;
            background: #f3f4f6;
            color: #374151;
            text-align: center;
            white-space: nowrap;
        }}

        #{container_id} .admin-email {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-family: monospace;
            font-size: 0.75rem;
            color: #374151;
        }}

        #{container_id} .date-text {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-size: 0.75rem;
            color: #6b7280;
        }}
        </style>

        <div id="{container_id}">
            <div class="search-controls">
                <input id="{container_id}-search" placeholder="🔍 Search files..." style="flex: 1;">
                <input id="{container_id}-admin-filter" placeholder="Filter by Admin..." style="flex: 1;">
                <button class="btn btn-blue" 
                        onclick="searchFiles_{container_id}()">Search</button>
                <button class="btn btn-gray" onclick="clearSearch_{container_id}()">Clear</button>
                <button class="btn btn-green" 
                        onclick="newFile_{container_id}()">New</button>
                <button class="btn btn-blue" 
                        onclick="selectAll_{container_id}()">Select All</button>
                <button class="btn btn-gray" onclick="refreshFiles_{container_id}()">Refresh</button>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 1.5rem;"><input type="checkbox" id="{container_id}-select-all" onclick="toggleSelectAll_{container_id}()"></th>
                            <th style="width: 2rem; cursor: pointer;" onclick="sortTable_{container_id}('index')"># ↕</th>
                            <th style="width: 20rem; cursor: pointer;" onclick="sortTable_{container_id}('name')">Name ↕</th>
                            <th style="width: 8rem; cursor: pointer;" onclick="sortTable_{container_id}('admin')">Admin ↕</th>
                            <th style="width: 7rem; cursor: pointer;" onclick="sortTable_{container_id}('modified')">Modified ↕</th>
                            <th style="width: 5rem; cursor: pointer;" onclick="sortTable_{container_id}('type')">Type ↕</th>
                            <th style="width: 4rem; cursor: pointer;" onclick="sortTable_{container_id}('size')">Size ↕</th>
                            <th style="width: 10rem; cursor: pointer;" onclick="sortTable_{container_id}('permissions')">Permissions ↕</th>
                            <th style="width: 15rem;">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="{container_id}-tbody">
        """

        # Initial table rows - show first 50 files
        for i, file in enumerate(files[:50]):
            # Format file info
            file_name = file["name"].split("/")[-1]  # Just the filename
            file_path = file["name"]
            full_syft_path = f"syft://{file_path}"  # Full syft:// path
            datasite_owner = file.get("datasite_owner", "unknown")
            modified = datetime.fromtimestamp(file.get("modified", 0)).strftime("%m/%d/%Y")
            file_ext = file.get("extension", ".txt")
            size = file.get("size", 0)
            is_dir = file.get("is_dir", False)

            # Format size
            if size > 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"

            html += f"""
                    <tr onclick="copyPath_{container_id}('syft://{html_module.escape(file_path)}', this)">
                        <td><input type="checkbox" onclick="event.stopPropagation(); updateSelectAllState_{container_id}()"></td>
                        <td>{i}</td>
                        <td><div class="truncate" style="font-weight: 500;" title="{html_module.escape(full_syft_path)}">{html_module.escape(full_syft_path)}</div></td>
                        <td>
                            <div class="admin-email">
                                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"></path>
                                    <circle cx="12" cy="7" r="4"></circle>
                                </svg>
                                <span class="truncate">{html_module.escape(datasite_owner)}</span>
                            </div>
                        </td>
                        <td>
                            <div class="date-text">
                                <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect width="18" height="18" x="3" y="4" rx="2" ry="2"></rect>
                                    <line x1="16" x2="16" y1="2" y2="6"></line>
                                    <line x1="8" x2="8" y1="2" y2="6"></line>
                                    <line x1="3" x2="21" y1="10" y2="10"></line>
                                </svg>
                                <span class="truncate">{modified}</span>
                            </div>
                        </td>
                        <td><span class="type-badge">{file_ext if not is_dir else 'folder'}</span></td>
                        <td><span style="color: #6b7280;">{size_str}</span></td>
                        <td>
                            <div style="display: flex; flex-direction: column; gap: 0.125rem; font-size: 0.625rem; color: #6b7280;">
            """
            
            # Add each permission line
            perms = file.get('permissions_summary', [])
            if perms:
                for perm_line in perms[:3]:  # Limit to 3 lines
                    html += f'                                <span>{html_module.escape(perm_line)}</span>\n'
                if len(perms) > 3:
                    html += f'                                <span>+{len(perms) - 3} more...</span>\n'
            else:
                html += '                                <span style="color: #9ca3af;">No permissions</span>\n'
                
            html += """
                            </div>
                        </td>
                        <td>
                            <div style="display: flex; gap: 0.125rem;">
                                <button class="btn btn-gray" onclick="event.stopPropagation(); editFile_{container_id}('{html_module.escape(file_path)}')" title="Open in editor">File</button>
                                <button class="btn btn-blue" onclick="event.stopPropagation(); viewInfo_{container_id}('{html_module.escape(file_path)}')" title="View file info">Info</button>
                                <button class="btn btn-purple" onclick="event.stopPropagation(); copyPath_{container_id}('syft://{html_module.escape(file_path)}')" title="Copy path">Copy</button>
                                <button class="btn btn-red" onclick="event.stopPropagation(); deleteFile_{container_id}('{html_module.escape(file_path)}')" title="Delete file">
                                    <svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <path d="M3 6h18"></path>
                                        <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>
                                        <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>
                                        <line x1="10" x2="10" y1="11" y2="17"></line>
                                        <line x1="14" x2="14" y1="11" y2="17"></line>
                                    </svg>
                                </button>
                            </div>
                        </td>
                    </tr>
            """

        html += f"""
                    </tbody>
                </table>
            </div>

            <div class="pagination">
                <div></div>
                <span class="status" id="{container_id}-status">Loading...</span>
                <div class="pagination-controls">
                    <button onclick="changePage_{container_id}(-1)" id="{container_id}-prev-btn" disabled>Previous</button>
                    <span class="page-info" id="{container_id}-page-info">Page 1 of {(total + 49) // 50}</span>
                    <button onclick="changePage_{container_id}(1)" id="{container_id}-next-btn">Next</button>
                </div>
            </div>
        </div>

        <script>
        (function() {{
            // Store all files data
            var allFiles = {json.dumps(all_files)};
            var filteredFiles = allFiles.slice();
            var currentPage = 1;
            var itemsPerPage = 50;
            var sortColumn = 'name';
            var sortDirection = 'asc';
            var searchHistory = [];
            var adminHistory = [];

            // Helper function to escape HTML
            function escapeHtml(text) {{
                var div = document.createElement('div');
                div.textContent = text || '';
                return div.innerHTML;
            }}

            // Format date
            function formatDate(timestamp) {{
                var date = new Date(timestamp * 1000);
                return (date.getMonth() + 1).toString().padStart(2, '0') + '/' +
                       date.getDate().toString().padStart(2, '0') + '/' +
                       date.getFullYear();
            }}

            // Format size
            function formatSize(size) {{
                if (size > 1024 * 1024) {{
                    return (size / (1024 * 1024)).toFixed(1) + ' MB';
                }} else if (size > 1024) {{
                    return (size / 1024).toFixed(1) + ' KB';
                }} else {{
                    return size + ' B';
                }}
            }}

            // Show status message
            function showStatus(message) {{
                var statusEl = document.getElementById('{container_id}-status');
                if (statusEl) statusEl.textContent = message;
            }}
            
            // Calculate total size (files only)
            function calculateTotalSize() {{
                var totalSize = 0;
                filteredFiles.forEach(function(file) {{
                    if (!file.is_dir) {{
                        totalSize += file.size || 0;
                    }}
                }});
                return totalSize;
            }}
            
            // Update status with file and folder counts and size
            function updateStatus() {{
                var fileCount = 0;
                var folderCount = 0;
                
                filteredFiles.forEach(function(item) {{
                    if (item.is_dir) {{
                        folderCount++;
                    }} else {{
                        fileCount++;
                    }}
                }});
                
                var totalSize = calculateTotalSize();
                var sizeStr = formatSize(totalSize);
                
                var statusText = fileCount + ' files';
                if (folderCount > 0) {{
                    statusText += ', ' + folderCount + ' folders';
                }}
                statusText += ', ' + sizeStr + ' total';
                
                showStatus(statusText);
            }}

            // Render table
            function renderTable() {{
                var tbody = document.getElementById('{container_id}-tbody');
                var totalFiles = filteredFiles.length;
                var totalPages = Math.max(1, Math.ceil(totalFiles / itemsPerPage));
                
                // Ensure currentPage is valid
                if (currentPage > totalPages) currentPage = totalPages;
                if (currentPage < 1) currentPage = 1;
                
                // Update pagination controls
                document.getElementById('{container_id}-prev-btn').disabled = currentPage === 1;
                document.getElementById('{container_id}-next-btn').disabled = currentPage === totalPages;
                document.getElementById('{container_id}-page-info').textContent = 'Page ' + currentPage + ' of ' + totalPages;
                
                if (totalFiles === 0) {{
                    tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 40px;">No files found</td></tr>';
                    return;
                }}
                
                // Calculate start and end indices
                var start = (currentPage - 1) * itemsPerPage;
                var end = Math.min(start + itemsPerPage, totalFiles);
                
                // Generate table rows
                var html = '';
                for (var i = start; i < end; i++) {{
                    var file = filteredFiles[i];
                    var fileName = file.name.split('/').pop();
                    var filePath = file.name;
                    var fullSyftPath = 'syft://' + filePath;  // Full syft:// path
                    var datasiteOwner = file.datasite_owner || 'unknown';
                    var modified = formatDate(file.modified || 0);
                    var fileExt = file.extension || '.txt';
                    var sizeStr = formatSize(file.size || 0);
                    var isDir = file.is_dir || false;
                    
                    html += '<tr onclick="copyPath_{container_id}(\\'syft://' + filePath + '\\', this)">' +
                        '<td><input type="checkbox" onclick="event.stopPropagation(); updateSelectAllState_{container_id}()"></td>' +
                        '<td>' + (totalFiles - i - 1) + '</td>' +
                        '<td><div class="truncate" style="font-weight: 500;" title="' + escapeHtml(fullSyftPath) + '">' + escapeHtml(fullSyftPath) + '</div></td>' +
                        '<td>' +
                            '<div class="admin-email">' +
                                '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                                    '<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"></path>' +
                                    '<circle cx="12" cy="7" r="4"></circle>' +
                                '</svg>' +
                                '<span class="truncate">' + escapeHtml(datasiteOwner) + '</span>' +
                            '</div>' +
                        '</td>' +
                        '<td>' +
                            '<div class="date-text">' +
                                '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                                    '<rect width="18" height="18" x="3" y="4" rx="2" ry="2"></rect>' +
                                    '<line x1="16" x2="16" y1="2" y2="6"></line>' +
                                    '<line x1="8" x2="8" y1="2" y2="6"></line>' +
                                    '<line x1="3" x2="21" y1="10" y2="10"></line>' +
                                '</svg>' +
                                '<span class="truncate">' + modified + '</span>' +
                            '</div>' +
                        '</td>' +
                        '<td><span class="type-badge">' + (isDir ? 'folder' : fileExt) + '</span></td>' +
                        '<td><span style="color: #6b7280;">' + sizeStr + '</span></td>' +
                        '<td>' +
                            '<div style="display: flex; flex-direction: column; gap: 0.125rem; font-size: 0.625rem; color: #6b7280;">';
                    
                    // Add permission lines
                    var perms = file.permissions_summary || [];
                    if (perms.length > 0) {{
                        for (var j = 0; j < Math.min(perms.length, 3); j++) {{
                            html += '<span>' + escapeHtml(perms[j]) + '</span>';
                        }}
                        if (perms.length > 3) {{
                            html += '<span>+' + (perms.length - 3) + ' more...</span>';
                        }}
                    }} else {{
                        html += '<span style="color: #9ca3af;">No permissions</span>';
                    }}
                    
                    html += '</div>' +
                        '</td>' +
                        '<td>' +
                            '<div style="display: flex; gap: 0.125rem;">' +
                                '<button class="btn btn-gray" onclick="event.stopPropagation(); editFile_{container_id}(\\'' + escapeHtml(filePath) + '\\')" title="Open in editor">File</button>' +
                                '<button class="btn btn-blue" onclick="event.stopPropagation(); viewInfo_{container_id}(\\'' + escapeHtml(filePath) + '\\')" title="View file info">Info</button>' +
                                '<button class="btn btn-purple" onclick="event.stopPropagation(); copyPath_{container_id}(\\'syft://' + filePath + '\\')" title="Copy path">Copy</button>' +
                                '<button class="btn btn-red" onclick="event.stopPropagation(); deleteFile_{container_id}(\\'' + escapeHtml(filePath) + '\\')" title="Delete file">' +
                                    '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                                        '<path d="M3 6h18"></path>' +
                                        '<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>' +
                                        '<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>' +
                                        '<line x1="10" x2="10" y1="11" y2="17"></line>' +
                                        '<line x1="14" x2="14" y1="11" y2="17"></line>' +
                                    '</svg>' +
                                '</button>' +
                            '</div>' +
                        '</td>' +
                    '</tr>';
                }}
                
                tbody.innerHTML = html;
            }}

            // Search files
            window.searchFiles_{container_id} = function() {{
                var searchTerm = document.getElementById('{container_id}-search').value.toLowerCase();
                var adminFilter = document.getElementById('{container_id}-admin-filter').value.toLowerCase();
                
                filteredFiles = allFiles.filter(function(file) {{
                    var nameMatch = file.name.toLowerCase().includes(searchTerm);
                    var adminMatch = adminFilter === '' || (file.datasite_owner || '').toLowerCase().includes(adminFilter);
                    return (searchTerm === '' || nameMatch) && adminMatch;
                }});
                
                currentPage = 1;
                renderTable();
                updateStatus();
            }};

            // Clear search
            window.clearSearch_{container_id} = function() {{
                document.getElementById('{container_id}-search').value = '';
                document.getElementById('{container_id}-admin-filter').value = '';
                filteredFiles = allFiles.slice();
                currentPage = 1;
                renderTable();
                updateStatus();
            }};

            // Change page
            window.changePage_{container_id} = function(direction) {{
                var totalPages = Math.max(1, Math.ceil(filteredFiles.length / itemsPerPage));
                currentPage += direction;
                if (currentPage < 1) currentPage = 1;
                if (currentPage > totalPages) currentPage = totalPages;
                renderTable();
            }};

            // Copy path with rainbow animation
            window.copyPath_{container_id} = function(path, rowElement) {{
                var command = 'sp.open("' + path + '")';
                
                // Copy to clipboard
                navigator.clipboard.writeText(command).then(function() {{
                    // Add rainbow animation
                    if (rowElement) {{
                        rowElement.classList.add('rainbow-flash');
                        setTimeout(function() {{
                            rowElement.classList.remove('rainbow-flash');
                        }}, 800);
                    }}
                    
                    showStatus('Copied to clipboard: ' + command);
                    setTimeout(function() {{
                        updateStatus();
                    }}, 2000);
                }}).catch(function() {{
                    showStatus('Failed to copy to clipboard');
                }});
            }};

            // Edit file
            window.editFile_{container_id} = function(filePath) {{
                // In Jupyter, this would open the file editor
                console.log('Edit file:', filePath);
                showStatus('Opening file editor for: ' + filePath);
            }};

            // View file info
            window.viewInfo_{container_id} = function(filePath) {{
                // In Jupyter, this would show file permissions and metadata
                console.log('View info for:', filePath);
                showStatus('Viewing info for: ' + filePath);
            }};

            // Delete file
            window.deleteFile_{container_id} = function(filePath) {{
                if (confirm('Are you sure you want to delete this file?\\n\\n' + filePath)) {{
                    console.log('Delete file:', filePath);
                    showStatus('File deleted: ' + filePath);
                    // In real implementation, would remove from list and refresh
                }}
            }};

            // New file
            window.newFile_{container_id} = function() {{
                console.log('Create new file');
                showStatus('Creating new file...');
            }};

            // Toggle select all
            window.toggleSelectAll_{container_id} = function() {{
                var selectAllCheckbox = document.getElementById('{container_id}-select-all');
                var checkboxes = document.querySelectorAll('#{container_id} tbody input[type="checkbox"]');
                checkboxes.forEach(function(cb) {{ 
                    cb.checked = selectAllCheckbox.checked; 
                }});
                showStatus(selectAllCheckbox.checked ? 'All visible files selected' : 'Selection cleared');
            }};
            
            // Update select all checkbox state based on individual checkboxes
            window.updateSelectAllState_{container_id} = function() {{
                var checkboxes = document.querySelectorAll('#{container_id} tbody input[type="checkbox"]');
                var selectAllCheckbox = document.getElementById('{container_id}-select-all');
                var allChecked = true;
                var someChecked = false;
                
                checkboxes.forEach(function(cb) {{
                    if (!cb.checked) allChecked = false;
                    if (cb.checked) someChecked = true;
                }});
                
                selectAllCheckbox.checked = allChecked;
                selectAllCheckbox.indeterminate = !allChecked && someChecked;
            }};
            
            // Select all button (legacy)
            window.selectAll_{container_id} = function() {{
                var selectAllCheckbox = document.getElementById('{container_id}-select-all');
                selectAllCheckbox.checked = true;
                toggleSelectAll_{container_id}();
            }};

            // Refresh files
            window.refreshFiles_{container_id} = function() {{
                showStatus('Refreshing files...');
                // In real implementation, would reload file list
                setTimeout(function() {{
                    showStatus('Files refreshed');
                }}, 1000);
            }};

            // Sort table
            window.sortTable_{container_id} = function(column) {{
                if (sortColumn === column) {{
                    sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
                }} else {{
                    sortColumn = column;
                    sortDirection = 'asc';
                }}
                
                filteredFiles.sort(function(a, b) {{
                    var aVal, bVal;
                    
                    switch(column) {{
                        case 'index':
                            aVal = allFiles.indexOf(a);
                            bVal = allFiles.indexOf(b);
                            break;
                        case 'name':
                            aVal = a.name.toLowerCase();
                            bVal = b.name.toLowerCase();
                            break;
                        case 'admin':
                            aVal = (a.datasite_owner || '').toLowerCase();
                            bVal = (b.datasite_owner || '').toLowerCase();
                            break;
                        case 'modified':
                            aVal = a.modified || 0;
                            bVal = b.modified || 0;
                            break;
                        case 'type':
                            aVal = (a.extension || '').toLowerCase();
                            bVal = (b.extension || '').toLowerCase();
                            break;
                        case 'size':
                            aVal = a.size || 0;
                            bVal = b.size || 0;
                            break;
                        case 'permissions':
                            aVal = (a.permissions_summary || []).length;
                            bVal = (b.permissions_summary || []).length;
                            break;
                        default:
                            return 0;
                    }}
                    
                    if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
                    if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
                    return 0;
                }});
                
                currentPage = 1;
                renderTable();
            }};
            
            // Tab completion with dropdown
            function setupTabCompletion(inputEl, getOptions) {{
                var dropdown = document.createElement('div');
                dropdown.className = 'autocomplete-dropdown';
                dropdown.id = inputEl.id + '-dropdown';
                inputEl.parentNode.style.position = 'relative';
                inputEl.parentNode.appendChild(dropdown);
                
                var currentIndex = -1;
                var currentOptions = [];
                var isDropdownOpen = false;
                
                function updateDropdown() {{
                    dropdown.innerHTML = '';
                    currentOptions.forEach(function(option, index) {{
                        var div = document.createElement('div');
                        div.className = 'autocomplete-option';
                        if (index === currentIndex) div.classList.add('selected');
                        div.textContent = option;
                        div.onclick = function() {{
                            inputEl.value = option;
                            hideDropdown();
                        }};
                        dropdown.appendChild(div);
                    }});
                    
                    // Position dropdown
                    var rect = inputEl.getBoundingClientRect();
                    var parentRect = inputEl.parentNode.getBoundingClientRect();
                    dropdown.style.top = (rect.bottom - parentRect.top) + 'px';
                    dropdown.style.left = '0px';
                    dropdown.style.width = rect.width + 'px';
                }}
                
                function showDropdown() {{
                    if (currentOptions.length > 0) {{
                        dropdown.classList.add('show');
                        isDropdownOpen = true;
                        updateDropdown();
                    }}
                }}
                
                function hideDropdown() {{
                    dropdown.classList.remove('show');
                    isDropdownOpen = false;
                    currentIndex = -1;
                }}
                
                inputEl.addEventListener('keydown', function(e) {{
                    if (e.key === 'Tab' || (e.key === 'ArrowDown' && !isDropdownOpen)) {{
                        e.preventDefault();
                        
                        var value = inputEl.value.toLowerCase();
                        currentOptions = getOptions().filter(function(opt) {{
                            return opt.toLowerCase().includes(value);
                        }}).slice(0, 10); // Limit to 10 options
                        
                        if (currentOptions.length > 0) {{
                            currentIndex = 0;
                            showDropdown();
                        }}
                    }} else if (e.key === 'ArrowDown' && isDropdownOpen) {{
                        e.preventDefault();
                        currentIndex = Math.min(currentIndex + 1, currentOptions.length - 1);
                        updateDropdown();
                    }} else if (e.key === 'ArrowUp' && isDropdownOpen) {{
                        e.preventDefault();
                        currentIndex = Math.max(currentIndex - 1, 0);
                        updateDropdown();
                    }} else if (e.key === 'Enter' && isDropdownOpen && currentIndex >= 0) {{
                        e.preventDefault();
                        inputEl.value = currentOptions[currentIndex];
                        hideDropdown();
                    }} else if (e.key === 'Escape') {{
                        hideDropdown();
                    }}
                }});
                
                inputEl.addEventListener('blur', function() {{
                    setTimeout(hideDropdown, 200); // Delay to allow click on dropdown
                }});
                
                inputEl.addEventListener('input', function() {{
                    // Don't hide dropdown on input to allow real-time search
                    // hideDropdown();
                }});
            }}
            
            // Get unique file names and paths for tab completion
            function getFileNames() {{
                var names = [];
                var seen = {{}};;
                allFiles.forEach(function(file) {{
                    // Add the full path
                    if (!seen[file.name]) {{
                        seen[file.name] = true;
                        names.push(file.name);
                    }}
                    
                    // Also add individual parts for convenience
                    var parts = file.name.split('/');
                    parts.forEach(function(part) {{
                        if (part && !seen[part]) {{
                            seen[part] = true;
                            names.push(part);
                        }}
                    }});
                }});
                return names.sort();
            }}
            
            // Get unique admins for tab completion
            function getAdmins() {{
                var admins = [];
                var seen = {{}};;
                allFiles.forEach(function(file) {{
                    var admin = file.datasite_owner;
                    if (admin && !seen[admin]) {{
                        seen[admin] = true;
                        admins.push(admin);
                    }}
                }});
                return admins.sort();
            }}
            
            // Setup tab completion for search inputs
            setupTabCompletion(document.getElementById('{container_id}-search'), getFileNames);
            setupTabCompletion(document.getElementById('{container_id}-admin-filter'), getAdmins);
            
            // Add real-time search on every keystroke
            document.getElementById('{container_id}-search').addEventListener('input', function() {{
                searchFiles_{container_id}();
            }});
            document.getElementById('{container_id}-admin-filter').addEventListener('input', function() {{
                searchFiles_{container_id}();
            }});
            
            // Add enter key support for search (redundant but kept for compatibility)
            document.getElementById('{container_id}-search').addEventListener('keypress', function(e) {{
                if (e.key === 'Enter') searchFiles_{container_id}();
            }});
            document.getElementById('{container_id}-admin-filter').addEventListener('keypress', function(e) {{
                if (e.key === 'Enter') searchFiles_{container_id}();
            }});
            
            // Initial status update
            updateStatus();
        }})();
        </script>
        """

        return html


# Create singleton instance
files = Files()


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
