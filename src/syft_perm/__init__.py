"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.54"

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

                # Check if this file is in the user's datasite
                is_user_datasite = False
                if user_email:
                    datasite_owner = (
                        str(relative_path).split("/")[0] if "/" in str(relative_path) else ""
                    )
                    is_user_datasite = datasite_owner == user_email

                # Get permissions for this file using sp.open()
                has_yaml = False
                try:
                    # Use open() to get the file object with all permissions
                    syft_obj = open(file_path)
                    permissions = syft_obj.permissions_dict

                    # Check if syft-perm found any yaml files
                    # If has_yaml property exists and returns True, yaml files were found
                    if hasattr(syft_obj, "has_yaml"):
                        has_yaml = syft_obj.has_yaml
                    # Fallback: if we have any permissions with actual users, yaml files must exist
                    elif any(users for users in permissions.values()):
                        has_yaml = True

                except Exception:
                    permissions = {}
                    has_yaml = False

                files.append(
                    {
                        "name": str(relative_path),
                        "path": str(file_path),
                        "is_dir": False,
                        "permissions": permissions,
                        "is_user_datasite": is_user_datasite,
                        "has_yaml": has_yaml,
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
            "width: calc(100% - 24px); padding: 8px 12px; border: 1px solid #d1d5db; "
            "border-radius: 6px; font-size: 14px; outline: none; box-sizing: border-box;"
        )
        th_style = (
            "text-align: left; padding: 10px; font-weight: 600; "
            "border-bottom: 1px solid #e5e7eb;"
        )

        html = f"""
        <div id="{container_id}" style="{div_style}">
            <!-- Search Header -->
            <div style="background: #f8f9fa; padding: 12px; border-bottom: 1px solid #e5e7eb;
                        position: relative;">
                <input id="{container_id}-search" type="text"
                       placeholder="🔍 Search files... (use Tab for autocomplete)"
                       style="{input_style}"
                       oninput="searchFiles_{container_id}(this.value)"
                       onkeydown="handleKeyDown_{container_id}(event)"
                       autocomplete="off">
                <div id="{container_id}-suggestions"
                     style="display: none; position: absolute; top: 100%; left: 12px; right: 12px;
                            background: white; border: 1px solid #d1d5db; border-top: none;
                            border-radius: 0 0 6px 6px; max-height: 200px; overflow-y: auto;
                            z-index: 1000; box-shadow: 0 4px 6px rgba(0,0,0,0.1);"></div>
            </div>

            <!-- Table Container -->
            <div style="max-height: 400px; overflow-y: auto;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead style="background: #f8f9fa; position: sticky; top: 0; z-index: 10;">
                        <tr>
                            <th style="{th_style} width: 65%;">File Path</th>
                            <th style="{th_style} width: 10%;">Size</th>
                            <th style="{th_style} width: 25%;">Permissions</th>
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
            has_yaml = file.get("has_yaml", False)

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

            if perm_items:
                perm_str = "<br>".join(perm_items)
            else:
                # Show message based on whether permissions are actually unknown
                if not has_yaml:
                    perm_str = "<em style='color: #6b7280;'>Unknown — but you have read</em>"
                else:
                    perm_str = "<em style='color: #9ca3af;'>No explicit permissions</em>"

            html += f"""
                    <tr style="border-bottom: 1px solid #f3f4f6;">
                        <td style="padding: 10px; font-family: 'SF Mono', Monaco, monospace;
                                   word-break: break-all; text-align: left; cursor: pointer;"
                            onclick="copyToClipboard_{container_id}('syft://{html_module.escape(file['name'])}')"
                            title="Click to copy sp.open() command">
                            syft://{html_module.escape(file['name'])}
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
                <span id="{container_id}-size" style="margin-left: 10px;"></span>
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

            window.copyToClipboard_{container_id} = function(path) {{
                var command = 'sp.open("' + path + '")';

                // Create temporary textarea to copy text
                var textarea = document.createElement('textarea');
                textarea.value = command;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);

                // Select and copy
                textarea.select();
                try {{
                    document.execCommand('copy');
                    // Optional: Show brief feedback
                    var originalTitle = event.target.title;
                    event.target.title = 'Copied!';
                    event.target.style.color = '#10b981';
                    setTimeout(function() {{
                        event.target.title = originalTitle;
                        event.target.style.color = '';
                    }}, 1000);
                }} catch (err) {{
                    console.error('Failed to copy:', err);
                }}

                document.body.removeChild(textarea);
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

            function formatPermissions(perms, hasYaml) {{
                var permItems = [];
                for (var permType in perms) {{
                    var users = perms[permType];
                    if (users && users.length > 0) {{
                        var userStr;
                        if (users.length > 2) {{
                            userStr = users.slice(0, 2).join(', ') + '... (+' +
                                     (users.length - 2) + ')';
                        }} else {{
                            userStr = users.join(', ');
                        }}
                        permItems.push('<strong>' + permType + ':</strong> ' + escapeHtml(userStr));
                    }}
                }}
                if (permItems.length > 0) {{
                    return permItems.join('<br>');
                }} else {{
                    // Show message based on whether permissions are actually unknown
                    if (!hasYaml) {{
                        return '<em style="color: #6b7280;">Unknown — but you have read</em>';
                    }} else {{
                        return '<em style="color: #9ca3af;">No explicit permissions</em>';
                    }}
                }}
            }}

            var selectedSuggestionIndex = -1;
            var currentSuggestions = [];

            window.searchFiles_{container_id} = function(searchTerm) {{
                var tbody = document.getElementById('{container_id}-tbody');
                var status = document.getElementById('{container_id}-status');
                var sizeSpan = document.getElementById('{container_id}-size');

                if (!tbody || !status || !sizeSpan) return;

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
                    var permStr = formatPermissions(file.permissions || {{}},
                                                   file.has_yaml || false);

                    var tr = document.createElement('tr');
                    tr.style.borderBottom = '1px solid #f3f4f6';
                    tr.innerHTML =
                        '<td style="padding: 10px; font-family: monospace; ' +
                        'word-break: break-all; text-align: left; cursor: pointer;" ' +
                        'onclick="copyToClipboard_' + '{container_id}' + '(\\'' +
                        'syft://' + file.name + '\\')" ' +
                        'title="Click to copy sp.open() command">' +
                        'syft://' + escapeHtml(file.name) + '</td>' +
                        '<td style="padding: 10px; color: #6b7280;">' + sizeStr + '</td>' +
                        '<td style="padding: 10px; font-size: 12px; line-height: 1.4;">' +
                        permStr + '</td>';
                    tbody.appendChild(tr);
                }}

                // Calculate total size of displayed files
                var totalSize = 0;
                for (var i = 0; i < filteredFiles.length; i++) {{
                    totalSize += filteredFiles[i].size || 0;
                }}

                // Update status
                var statusText = searchTerm ?
                    'Showing ' + displayFiles.length + ' of ' + filteredFiles.length +
                    ' matching files' :
                    'Showing ' + displayFiles.length + ' of ' + allFiles.length +
                    ' files in datasites';
                status.textContent = statusText;

                // Update size display
                sizeSpan.textContent = '| Total size: ' + formatSize(totalSize);
            }};

            function getPathSuggestions(input) {{
                var suggestions = new Set();
                var inputLower = input.toLowerCase();

                // Get all path segments that match the input
                allFiles.forEach(function(file) {{
                    var parts = file.name.split('/');
                    var currentPath = '';

                    for (var i = 0; i < parts.length; i++) {{
                        if (i > 0) currentPath += '/';
                        currentPath += parts[i];

                        if (currentPath.toLowerCase().startsWith(inputLower) &&
                            currentPath !== input) {{
                            suggestions.add(currentPath);
                        }}
                    }}
                }});

                return Array.from(suggestions).sort().slice(0, 10);
            }}

            function showSuggestions(suggestions) {{
                var suggestionsDiv = document.getElementById('{container_id}-suggestions');
                if (!suggestionsDiv) return;

                if (suggestions.length === 0) {{
                    suggestionsDiv.style.display = 'none';
                    return;
                }}

                suggestionsDiv.innerHTML = '';
                currentSuggestions = suggestions;
                selectedSuggestionIndex = -1;

                suggestions.forEach(function(suggestion, index) {{
                    var div = document.createElement('div');
                    div.textContent = suggestion;
                    div.style.cssText = 'padding: 8px 12px; cursor: pointer; ' +
                                        'border-bottom: 1px solid #f3f4f6;';
                    div.onclick = function() {{
                        document.getElementById('{container_id}-search').value = suggestion;
                        searchFiles_{container_id}(suggestion);
                        suggestionsDiv.style.display = 'none';
                    }};
                    div.onmouseover = function() {{
                        selectedSuggestionIndex = index;
                        updateSuggestionHighlight();
                    }};
                    suggestionsDiv.appendChild(div);
                }});

                suggestionsDiv.style.display = 'block';
            }}

            function updateSuggestionHighlight() {{
                var suggestionsDiv = document.getElementById('{container_id}-suggestions');
                if (!suggestionsDiv) return;

                var items = suggestionsDiv.children;
                for (var i = 0; i < items.length; i++) {{
                    if (i === selectedSuggestionIndex) {{
                        items[i].style.backgroundColor = '#e5f3ff';
                    }} else {{
                        items[i].style.backgroundColor = 'transparent';
                    }}
                }}
            }}

            window.handleKeyDown_{container_id} = function(event) {{
                var suggestionsDiv = document.getElementById('{container_id}-suggestions');
                var isVisible = suggestionsDiv && suggestionsDiv.style.display !== 'none';

                if (event.key === 'Tab') {{
                    event.preventDefault();
                    var input = event.target;
                    var suggestions = getPathSuggestions(input.value);

                    if (suggestions.length > 0) {{
                        if (!isVisible) {{
                            showSuggestions(suggestions);
                        }} else {{
                            // Cycle through suggestions
                            selectedSuggestionIndex = (selectedSuggestionIndex + 1) %
                                                    suggestions.length;
                            updateSuggestionHighlight();
                            input.value = currentSuggestions[selectedSuggestionIndex];
                        }}
                    }}
                }} else if (isVisible) {{
                    if (event.key === 'ArrowDown') {{
                        event.preventDefault();
                        selectedSuggestionIndex = Math.min(selectedSuggestionIndex + 1,
                                                          currentSuggestions.length - 1);
                        updateSuggestionHighlight();
                    }} else if (event.key === 'ArrowUp') {{
                        event.preventDefault();
                        selectedSuggestionIndex = Math.max(selectedSuggestionIndex - 1, 0);
                        updateSuggestionHighlight();
                    }} else if (event.key === 'Enter' && selectedSuggestionIndex >= 0) {{
                        event.preventDefault();
                        var selected = currentSuggestions[selectedSuggestionIndex];
                        event.target.value = selected;
                        searchFiles_{container_id}(selected);
                        suggestionsDiv.style.display = 'none';
                    }} else if (event.key === 'Escape') {{
                        suggestionsDiv.style.display = 'none';
                    }}
                }}
            }};
        }})();

        // Initialize with total size display
        (function() {{
            var initialTotalSize = 0;
            for (var i = 0; i < allFiles.length; i++) {{
                initialTotalSize += allFiles[i].size || 0;
            }}
            var sizeSpan = document.getElementById('{container_id}-size');
            if (sizeSpan) {{
                sizeSpan.textContent = '| Total size: ' + formatSize(initialTotalSize);
            }}
        }})();
        </script>
        """

        return html


# Create singleton instance
files = Files()


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
