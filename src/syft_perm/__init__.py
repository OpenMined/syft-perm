"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.37"

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
        """Generate simple widget with working search functionality for Jupyter."""
        import html as html_module
        import json
        import uuid

        container_id = f"syft_files_{uuid.uuid4().hex[:8]}"
        data = self.get(limit=100)  # Get more files initially
        files = data["files"]
        total = data["total_count"]

        if not files:
            return (
                "<div style='padding: 20px; color: #666;'>"
                "No files found in SyftBox/datasites directory</div>"
            )

        # Get all files for search
        all_files = self._scan_files()

        # Build HTML template
        div_style = (
            "font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, "
            "sans-serif; border: 1px solid #e5e7eb; border-radius: 8px; "
            "overflow: hidden; max-width: 100%;"
        )
        input_style = (
            "width: 100%; padding: 8px 12px; border: 1px solid #d1d5db; "
            "border-radius: 6px; font-size: 14px; outline: none;"
        )
        th_style = (
            "text-align: left; padding: 10px; font-weight: 600; "
            "border-bottom: 1px solid #e5e7eb;"
        )

        html = f"""
        <div id="{container_id}" style="{div_style}">
            <!-- Search Header -->
            <div style="background: #f8f9fa; padding: 12px; border-bottom: 1px solid #e5e7eb; position: relative;">
                <input id="{container_id}-search" type="text" placeholder="🔍 Search files... (use Tab for autocomplete)"
                       style="{input_style}"
                       oninput="searchFiles_{container_id}(this.value)"
                       onkeydown="handleKeyDown_{container_id}(event)"
                       autocomplete="off">
                <div id="{container_id}-suggestions" style="display: none; position: absolute; top: 100%; left: 12px; right: 12px;
                                                              background: white; border: 1px solid #d1d5db; border-top: none;
                                                              border-radius: 0 0 6px 6px; max-height: 200px; overflow-y: auto;
                                                              z-index: 1000; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"></div>
            </div>

            <!-- Table Container -->
            <div style="max-height: 400px; overflow-y: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead style="background: #f8f9fa; position: sticky; top: 0; z-index: 10;">
                        <tr>
                            <th style="{th_style} width: 50%;">File Path</th>
                            <th style="{th_style} width: 15%;">Size</th>
                            <th style="{th_style} width: 35%;">Permissions</th>
                        </tr>
                    </thead>
                    <tbody id="{container_id}-tbody">
        """

        # Initial table rows - show first 20 files
        for file in files[:20]:
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
                        user_str = f"{', '.join(users[:2])}... (+{len(users) - 2})"
                    else:
                        user_str = ", ".join(users)
                    perm_items.append(
                        f"<strong>{perm_type}:</strong> {html_module.escape(user_str)}"
                    )

            perm_str = "<br>".join(perm_items) if perm_items else "<em>No permissions</em>"

            html += f"""
                    <tr style="border-bottom: 1px solid #f3f4f6;">
                        <td style="padding: 10px; font-family: 'SF Mono', Monaco, monospace;
                                   word-break: break-all;">
                            {html_module.escape(file['name'])}
                        </td>
                        <td style="padding: 10px; color: #6b7280;">
                            {size_str}
                        </td>
                        <td style="padding: 10px; font-size: 12px; line-height: 1.4;">
                            {perm_str}
                        </td>
                    </tr>
            """

        html += f"""
                    </tbody>
                </table>
            </div>

            <!-- Footer -->
            <div style="background: #f8f9fa; padding: 10px; border-top: 1px solid #e5e7eb;
                        font-size: 12px; color: #6b7280; text-align: center;">
                <span id="{container_id}-status">Showing 20 of {total} files in datasites</span>
            </div>
        </div>

        <script>
        (function() {{
            // Store all files data in a way that's compatible with Jupyter
            var allFiles = {json.dumps(all_files)};
            var container = document.getElementById('{container_id}');

            function escapeHtml(text) {{
                var div = document.createElement('div');
                div.textContent = text || '';
                return div.innerHTML;
            }}

            function formatSize(size) {{
                if (size > 1024 * 1024) {{
                    return (size / (1024 * 1024)).toFixed(1) + ' MB';
                }} else if (size > 1024) {{
                    return (size / 1024).toFixed(1) + ' KB';
                }} else {{
                    return size + ' B';
                }}
            }}

            function formatPermissions(perms) {{
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
                        permItems.push('<strong>' + permType + ':</strong> ' + escapeHtml(userStr));
                    }}
                }}
                return permItems.length > 0 ? permItems.join('<br>') : '<em>No permissions</em>';
            }}

            window.searchFiles_{container_id} = function(searchTerm) {{
                var tbody = document.getElementById('{container_id}-tbody');
                var status = document.getElementById('{container_id}-status');

                if (!tbody || !status) return;

                searchTerm = searchTerm.toLowerCase();
                var filteredFiles = allFiles.filter(function(file) {{
                    return !searchTerm || file.name.toLowerCase().includes(searchTerm);
                }});

                // Clear current table
                tbody.innerHTML = '';

                // Show first 50 filtered results
                var displayFiles = filteredFiles.slice(0, 50);

                for (var i = 0; i < displayFiles.length; i++) {{
                    var file = displayFiles[i];
                    var sizeStr = formatSize(file.size || 0);
                    var permStr = formatPermissions(file.permissions || {{}});

                    var tr = document.createElement('tr');
                    tr.style.borderBottom = '1px solid #f3f4f6';
                    tr.innerHTML =
                        '<td style="padding: 10px; font-family: \\'SF Mono\\', Monaco, monospace; ' +
                        'word-break: break-all;">' + escapeHtml(file.name) + '</td>' +
                        '<td style="padding: 10px; color: #6b7280;">' + sizeStr + '</td>' +
                        '<td style="padding: 10px; font-size: 12px; line-height: 1.4;">' + permStr + '</td>';
                    tbody.appendChild(tr);
                }}

                // Update status
                var statusText = searchTerm ?
                    'Showing ' + displayFiles.length + ' of ' + filteredFiles.length + ' matching files' :
                    'Showing ' + displayFiles.length + ' of ' + allFiles.length + ' files in datasites';
                status.textContent = statusText;
            }};
        }})();
        </script>
        """

        return html


# Create singleton instance
files = Files()


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
