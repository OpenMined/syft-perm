"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.34"

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
        """Interactive HTML representation with search and pagination."""
        try:
            data = self.get(limit=20)  # Show first 20 files
            files = data["files"]
            total = data["total_count"]

            if not files:
                return "<div style='padding: 20px; color: #666;'>No files found in SyftBox/datasites directory</div>"

            # Generate unique IDs for this instance
            widget_id = f"syft_files_{id(self)}"

            html = f"""
            <div id="{widget_id}" style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                        border: 1px solid #e1e5e9; border-radius: 8px; overflow: hidden; max-width: 100%;">
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                            color: white; padding: 16px 20px; display: flex; align-items: center; gap: 12px;">
                    <div style="font-size: 24px;">📁</div>
                    <div>
                        <div style="font-size: 18px; font-weight: 600; margin-bottom: 2px;">SyftBox Datasites</div>
                        <div style="font-size: 14px; opacity: 0.9;">Showing <span id="{widget_id}_count">{len(files)}</span> of <span id="{widget_id}_total">{total}</span> files</div>
                    </div>
                </div>
                
                <!-- Search Bar -->
                <div style="padding: 16px 20px; background: #f8f9fa; border-bottom: 1px solid #e1e5e9;">
                    <input id="{widget_id}_search" type="text" placeholder="🔍 Search files..." 
                           style="width: 100%; padding: 8px 12px; border: 1px solid #d1d5db; border-radius: 6px; 
                                  font-size: 14px; outline: none;" oninput="searchFiles_{widget_id}(this.value)">
                </div>
                
                <!-- Table -->
                <div style="overflow-x: auto;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
                        <thead>
                            <tr style="background: #f8f9fa; border-bottom: 2px solid #e1e5e9;">
                                <th style="text-align: left; padding: 12px; font-weight: 600; width: 40%;">File Path</th>
                                <th style="text-align: left; padding: 12px; font-weight: 600; width: 15%;">Size</th>
                                <th style="text-align: left; padding: 12px; font-weight: 600; width: 45%;">Permissions</th>
                            </tr>
                        </thead>
                        <tbody id="{widget_id}_tbody">
            """

            for file in files:
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
                        if len(users) > 3:
                            user_str = f"{', '.join(users[:3])}... (+{len(users)-3})"
                        else:
                            user_str = ", ".join(users)
                        perm_items.append(f"<strong>{perm_type}:</strong> {user_str}")

                perm_str = "<br>".join(perm_items) if perm_items else "<em>No permissions</em>"

                html += f"""
                        <tr>
                            <td style="padding: 12px; font-family: 'SF Mono', Monaco, monospace; font-size: 13px; 
                                       text-align: left; word-break: break-all;">
                                {file['name']}
                            </td>
                            <td style="padding: 12px; color: #586069; text-align: left;">
                                {size_str}
                            </td>
                            <td style="padding: 12px; font-size: 12px; line-height: 1.4; text-align: left;">
                                {perm_str}
                            </td>
                        </tr>
                """

            html += f"""
                        </tbody>
                    </table>
                </div>
                
                <!-- Pagination -->
                <div style="padding: 12px 20px; background: #f8f9fa; border-top: 1px solid #e1e5e9; 
                            display: flex; justify-content: space-between; align-items: center;">
                    <div style="font-size: 14px; color: #586069;">
                        Page <span id="{widget_id}_page">1</span> of <span id="{widget_id}_pages">{max(1, (total + 19) // 20)}</span>
                    </div>
                    <div>
                        <button id="{widget_id}_prev" onclick="changePage_{widget_id}(-1)" 
                                style="padding: 6px 12px; margin-right: 8px; border: 1px solid #d1d5db; 
                                       background: white; border-radius: 4px; font-size: 14px; cursor: pointer;"
                                disabled>Previous</button>
                        <button id="{widget_id}_next" onclick="changePage_{widget_id}(1)" 
                                style="padding: 6px 12px; border: 1px solid #d1d5db; background: white; 
                                       border-radius: 4px; font-size: 14px; cursor: pointer;"
                                {'disabled' if total <= 20 else ''}>Next</button>
                    </div>
                </div>
            </div>
            
            <script>
            (function() {{
                // Get all files for this widget
                const allFiles = {str(data["files"] + self._scan_files()[len(data["files"]):][:1000])};  // Get more files for search
                let currentPage = 1;
                let currentSearch = "";
                
                window.searchFiles_{widget_id} = function(searchTerm) {{
                    currentSearch = searchTerm.toLowerCase();
                    currentPage = 1;
                    updateTable();
                }};
                
                window.changePage_{widget_id} = function(direction) {{
                    const filteredFiles = allFiles.filter(f => 
                        f.name.toLowerCase().includes(currentSearch)
                    );
                    const totalPages = Math.max(1, Math.ceil(filteredFiles.length / 20));
                    const newPage = currentPage + direction;
                    
                    if (newPage >= 1 && newPage <= totalPages) {{
                        currentPage = newPage;
                        updateTable();
                    }}
                }};
                
                function updateTable() {{
                    const filteredFiles = allFiles.filter(f => 
                        f.name.toLowerCase().includes(currentSearch)
                    );
                    const totalPages = Math.max(1, Math.ceil(filteredFiles.length / 20));
                    const startIdx = (currentPage - 1) * 20;
                    const endIdx = Math.min(startIdx + 20, filteredFiles.length);
                    const pageFiles = filteredFiles.slice(startIdx, endIdx);
                    
                    // Update table body
                    const tbody = document.getElementById('{widget_id}_tbody');
                    if (!tbody) return;
                    
                    tbody.innerHTML = pageFiles.map(file => {{
                        const size = file.size || 0;
                        let sizeStr;
                        if (size > 1024 * 1024) {{
                            sizeStr = (size / (1024 * 1024)).toFixed(1) + ' MB';
                        }} else if (size > 1024) {{
                            sizeStr = (size / 1024).toFixed(1) + ' KB';
                        }} else {{
                            sizeStr = size + ' B';
                        }}
                        
                        const perms = file.permissions || {{}};
                        const permItems = [];
                        for (const [permType, users] of Object.entries(perms)) {{
                            if (users && users.length > 0) {{
                                let userStr;
                                if (users.length > 3) {{
                                    userStr = users.slice(0, 3).join(', ') + '... (+' + (users.length - 3) + ')';
                                }} else {{
                                    userStr = users.join(', ');
                                }}
                                permItems.push('<strong>' + permType + ':</strong> ' + userStr);
                            }}
                        }}
                        const permStr = permItems.length > 0 ? permItems.join('<br>') : '<em>No permissions</em>';
                        
                        return `
                            <tr>
                                <td style="padding: 12px; font-family: 'SF Mono', Monaco, monospace; font-size: 13px; 
                                           text-align: left; word-break: break-all;">${{file.name}}</td>
                                <td style="padding: 12px; color: #586069; text-align: left;">${{sizeStr}}</td>
                                <td style="padding: 12px; font-size: 12px; line-height: 1.4; text-align: left;">${{permStr}}</td>
                            </tr>
                        `;
                    }}).join('');
                    
                    // Update counters
                    const countEl = document.getElementById('{widget_id}_count');
                    const totalEl = document.getElementById('{widget_id}_total');
                    const pageEl = document.getElementById('{widget_id}_page');
                    const pagesEl = document.getElementById('{widget_id}_pages');
                    
                    if (countEl) countEl.textContent = pageFiles.length;
                    if (totalEl) totalEl.textContent = filteredFiles.length;
                    if (pageEl) pageEl.textContent = currentPage;
                    if (pagesEl) pagesEl.textContent = totalPages;
                    
                    // Update pagination buttons
                    const prevBtn = document.getElementById('{widget_id}_prev');
                    const nextBtn = document.getElementById('{widget_id}_next');
                    
                    if (prevBtn) prevBtn.disabled = currentPage <= 1;
                    if (nextBtn) nextBtn.disabled = currentPage >= totalPages;
                }}
            }})();
            </script>
            """

            return html

        except Exception as e:
            return f"<div style='color: red; padding: 20px;'>Error loading files: {str(e)}</div>"


# Create singleton instance
files = Files()


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
