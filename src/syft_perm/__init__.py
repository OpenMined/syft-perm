"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.35"

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
    resolved_path = _Path(path)
    if not resolved_path.exists():
        raise ValueError(f"Path does not exist: {path}")

    if resolved_path.is_dir():
        return _SyftFolder(path)
    return _SyftFile(path)


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

        # Walk through datasites directory structure
        for root, dirs, file_names in os.walk(datasites_path):
            root_path = Path(root)

            # Skip hidden directories and .git directories
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            for file_name in file_names:
                # Skip hidden files and syft.pub.yaml files
                if file_name.startswith(".") or file_name == "syft.pub.yaml":
                    continue

                file_path = root_path / file_name
                relative_path = file_path.relative_to(datasites_path)

                # Apply search filter
                if search and search.lower() not in str(relative_path).lower():
                    continue

                # Get permissions for this file
                try:
                    from ._impl import SyftFile

                    syft_file = SyftFile(file_path)
                    permissions = syft_file.permissions_dict
                except Exception:
                    permissions = {}

                files.append(
                    {
                        "name": str(relative_path),
                        "path": str(file_path),
                        "is_dir": False,
                        "permissions": permissions,
                        "size": file_path.stat().st_size if file_path.exists() else 0,
                        "modified": file_path.stat().st_mtime if file_path.exists() else 0,
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
        """Generate fallback widget with working search functionality."""
        import uuid
        import html as html_module
        import json
        
        container_id = f"syft_files_{uuid.uuid4().hex[:8]}"
        data = self.get(limit=50)  # Get first 50 files
        files = data["files"]
        total = data["total_count"]
        
        if not files:
            return "<div style='padding: 20px; color: #666;'>No files found in SyftBox/datasites directory</div>"
        
        # Get more files for search (up to 1000)
        all_files = self._scan_files()[:1000]
        
        # CSS similar to syft-objects
        html = f"""
        <style>
        #{container_id} {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 12px;
            background: #ffffff;
        }}
        #{container_id} .widget-container {{
            border: 1px solid #e5e7eb;
            border-radius: 0.375rem;
            overflow: hidden;
            height: 400px;
            display: flex;
            flex-direction: column;
        }}
        #{container_id} .header {{
            background: #ffffff;
            border-bottom: 1px solid #e5e7eb;
            padding: 0.5rem;
            flex-shrink: 0;
        }}
        #{container_id} .search-controls {{
            display: flex;
            gap: 0.25rem;
            flex-wrap: wrap;
            padding: 0.5rem;
            background: #ffffff;
        }}
        #{container_id} .table-container {{
            flex: 1;
            overflow-y: auto;
            overflow-x: auto;
            background: #ffffff;
            min-height: 0;
        }}
        #{container_id} table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75rem;
        }}
        #{container_id} thead {{
            background: rgba(0, 0, 0, 0.03);
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
            background: rgba(0, 0, 0, 0.03);
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
        }}
        #{container_id} tbody tr:hover {{
            background: rgba(0, 0, 0, 0.03);
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
        #{container_id} .page-info {{
            font-size: 0.75rem;
            color: #6b7280;
        }}
        #{container_id} .status {{
            font-size: 0.75rem;
            color: #9ca3af;
            font-style: italic;
            opacity: 0.8;
            text-align: center;
            flex: 1;
        }}
        </style>
        
        <div id="{container_id}">
            <div class="widget-container">
                <div class="header">
                    <div class="search-controls">
                        <input id="{container_id}-search" placeholder="🔍 Search files..." 
                               style="flex: 1; padding: 0.25rem 0.5rem; border: 1px solid #d1d5db; border-radius: 0.25rem; font-size: 0.75rem;">
                        <button onclick="clearSearch_{container_id}()" style="padding: 0.25rem 0.5rem; border: 1px solid #e5e7eb; background: white; border-radius: 0.25rem; font-size: 0.75rem; cursor: pointer;">Clear</button>
                    </div>
                </div>
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th style="width: 50%;">File Path</th>
                                <th style="width: 15%;">Size</th>
                                <th style="width: 35%;">Permissions</th>
                            </tr>
                        </thead>
                        <tbody id="{container_id}-tbody">
        """
        
        # Initial table rows
        items_per_page = 20
        for i, file in enumerate(files[:items_per_page]):
            # Format file size
            size = file.get("size", 0)
            if size > 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.1f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"

            # Format permissions
            perms = file.get("permissions", {})
            perm_items = []
            for perm_type, users in perms.items():
                if users:
                    if len(users) > 2:
                        user_str = f"{', '.join(users[:2])}... (+{len(users)-2})"
                    else:
                        user_str = ', '.join(users)
                    perm_items.append(f"<strong>{perm_type}:</strong> {html_module.escape(user_str)}")

            perm_str = "<br>".join(perm_items) if perm_items else "<em>No permissions</em>"
            
            html += f"""
                        <tr>
                            <td style="font-family: 'SF Mono', Monaco, monospace; word-break: break-all;">
                                {html_module.escape(file['name'])}
                            </td>
                            <td style="color: #6b7280;">
                                {size_str}
                            </td>
                            <td style="font-size: 0.7rem; line-height: 1.3;">
                                {perm_str}
                            </td>
                        </tr>
            """
        
        total_pages = max(1, (total + items_per_page - 1) // items_per_page)
        
        html += f"""
                        </tbody>
                    </table>
                </div>
                <div class="pagination">
                    <div></div>
                    <span class="status" id="{container_id}-status">Showing {len(files[:items_per_page])} of {total} files in datasites</span>
                    <div>
                        <button onclick="changePage_{container_id}(-1)" id="{container_id}-prev" disabled>Previous</button>
                        <span class="page-info" id="{container_id}-page-info">Page 1 of {total_pages}</span>
                        <button onclick="changePage_{container_id}(1)" id="{container_id}-next" {'disabled' if total_pages <= 1 else ''}>Next</button>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
        // Store files data
        window['{container_id}_files'] = {json.dumps(all_files)};
        window['{container_id}_filteredFiles'] = window['{container_id}_files'];
        window['{container_id}_currentPage'] = 1;
        window['{container_id}_itemsPerPage'] = {items_per_page};
        window['{container_id}_totalFiles'] = {len(all_files)};
        
        function escapeHtml_{container_id}(text) {{
            var div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }}
        
        function filterFiles_{container_id}() {{
            var searchTerm = document.getElementById('{container_id}-search').value.toLowerCase();
            var allFiles = window['{container_id}_files'];
            
            var filtered = allFiles.filter(function(file) {{
                return !searchTerm || file.name.toLowerCase().includes(searchTerm);
            }});
            
            window['{container_id}_filteredFiles'] = filtered;
            window['{container_id}_totalFiles'] = filtered.length;
            window['{container_id}_currentPage'] = 1;
            
            updateDisplay_{container_id}();
        }}
        
        function clearSearch_{container_id}() {{
            document.getElementById('{container_id}-search').value = '';
            filterFiles_{container_id}();
        }}
        
        function changePage_{container_id}(direction) {{
            var currentPage = window['{container_id}_currentPage'];
            var itemsPerPage = window['{container_id}_itemsPerPage'];
            var totalFiles = window['{container_id}_totalFiles'];
            var totalPages = Math.max(1, Math.ceil(totalFiles / itemsPerPage));
            
            currentPage += direction;
            if (currentPage < 1) currentPage = 1;
            if (currentPage > totalPages) currentPage = totalPages;
            
            window['{container_id}_currentPage'] = currentPage;
            updateDisplay_{container_id}();
        }}
        
        function updateDisplay_{container_id}() {{
            var currentPage = window['{container_id}_currentPage'];
            var itemsPerPage = window['{container_id}_itemsPerPage'];
            var totalFiles = window['{container_id}_totalFiles'];
            var totalPages = Math.max(1, Math.ceil(totalFiles / itemsPerPage));
            var files = window['{container_id}_filteredFiles'];
            
            // Update page info
            document.getElementById('{container_id}-page-info').textContent = 'Page ' + currentPage + ' of ' + totalPages;
            document.getElementById('{container_id}-status').textContent = 'Showing ' + Math.min(itemsPerPage, totalFiles - (currentPage-1)*itemsPerPage) + ' of ' + totalFiles + ' files in datasites';
            
            // Update buttons
            document.getElementById('{container_id}-prev').disabled = currentPage === 1;
            document.getElementById('{container_id}-next').disabled = currentPage === totalPages;
            
            // Update table
            var tbody = document.getElementById('{container_id}-tbody');
            tbody.innerHTML = '';
            
            var start = (currentPage - 1) * itemsPerPage;
            var end = Math.min(start + itemsPerPage, totalFiles);
            
            for (var i = start; i < end; i++) {{
                var file = files[i];
                if (!file) continue;
                
                // Format file size
                var size = file.size || 0;
                var sizeStr;
                if (size > 1024 * 1024) {{
                    sizeStr = (size / (1024 * 1024)).toFixed(1) + ' MB';
                }} else if (size > 1024) {{
                    sizeStr = (size / 1024).toFixed(1) + ' KB';
                }} else {{
                    sizeStr = size + ' B';
                }}
                
                // Format permissions
                var perms = file.permissions || {{}};
                var permItems = [];
                for (var permType in perms) {{
                    var users = perms[permType];
                    if (users && users.length > 0) {{
                        var userStr;
                        if (users.length > 2) {{
                            userStr = users.slice(0, 2).join(', ') + '... (+' + (users.length - 2) + ')';
                        }} else {{
                            userStr = users.join(', ');
                        }}
                        permItems.push('<strong>' + permType + ':</strong> ' + escapeHtml_{container_id}(userStr));
                    }}
                }}
                var permStr = permItems.length > 0 ? permItems.join('<br>') : '<em>No permissions</em>';
                
                var tr = document.createElement('tr');
                tr.innerHTML = 
                    '<td style="font-family: \\'SF Mono\\', Monaco, monospace; word-break: break-all;">' + escapeHtml_{container_id}(file.name) + '</td>' +
                    '<td style="color: #6b7280;">' + sizeStr + '</td>' +
                    '<td style="font-size: 0.7rem; line-height: 1.3;">' + permStr + '</td>';
                tbody.appendChild(tr);
            }}
        }}
        
        // Add search event listener
        document.getElementById('{container_id}-search').addEventListener('input', filterFiles_{container_id});
        </script>
        """
        
        return html


# Create singleton instance
files = Files()


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
