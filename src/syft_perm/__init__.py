"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder

__version__ = "0.3.89"

__all__ = [
    "open",
    "get_editor_url",
    "get_files_widget_url",
    "files",
    "is_dark",
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


def get_files_widget_url() -> str:
    """
    Get the URL for the files widget interface (identical to sp.files in Jupyter).
    
    Returns:
        URL to the files widget
    """
    from .server import get_files_widget_url as _get_files_widget_url
    
    return _get_files_widget_url()


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
        self._initial_page = 1  # Default to first page
        self._items_per_page = 50  # Default items per page
        self._show_ascii_progress = True  # Whether to show ASCII progress in __repr__

    def _scan_files(self, search: _Union[str, None] = None, progress_callback=None, show_ascii_progress=False) -> list:
        """Scan SyftBox directory for files with permissions."""
        import os
        import sys
        import time
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

        # Count total datasites for progress tracking
        datasite_dirs = [
            d for d in datasites_path.iterdir() if d.is_dir() and not d.name.startswith(".")
        ]
        total_datasites = len(datasite_dirs)
        processed_datasites = 0

        # Setup ASCII progress bar if requested
        if show_ascii_progress and total_datasites > 0:
            print("Scanning datasites...")
            
        def update_ascii_progress(current, total, status):
            if show_ascii_progress:
                percent = (current / max(total, 1)) * 100
                bar_length = 40
                filled_length = int(bar_length * current / max(total, 1))
                bar = '█' * filled_length + '░' * (bar_length - filled_length)
                sys.stdout.write(f'\r[{bar}] {percent:.0f}% - {status}')
                sys.stdout.flush()

        # First pass: collect all unique paths (files and folders) per datasite
        for datasite_dir in datasite_dirs:
            if progress_callback:
                progress_callback(
                    processed_datasites, total_datasites, f"Scanning {datasite_dir.name}"
                )
            elif show_ascii_progress:
                update_ascii_progress(
                    processed_datasites, total_datasites, f"Scanning {datasite_dir.name}"
                )

            for root, dirs, file_names in os.walk(datasite_dir):
                root_path = Path(root)

                # Skip hidden directories
                dirs[:] = [d for d in dirs if not d.startswith(".")]

                # Add current directory
                all_paths.add(root_path)

                # Add all files
                for file_name in file_names:
                    if not file_name.startswith(".") and file_name != "syft.pub.yaml":
                        all_paths.add(root_path / file_name)

            processed_datasites += 1

            # Update progress after each datasite is fully processed
            if progress_callback:
                progress_callback(
                    processed_datasites, total_datasites, f"Completed {datasite_dir.name}"
                )
            elif show_ascii_progress:
                update_ascii_progress(
                    processed_datasites, total_datasites, f"Completed {datasite_dir.name}"
                )

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
                    str(relative_path).split("/")[0]
                    if "/" in str(relative_path)
                    else str(relative_path)
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
        
        # Clear ASCII progress bar if it was shown
        if show_ascii_progress and total_datasites > 0:
            sys.stdout.write('\r' + ' ' * 80 + '\r')  # Clear the line
            sys.stdout.flush()
        
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

    def search(self, files: _Union[str, None] = None, admin: _Union[str, None] = None, limit: int = 50, offset: int = 0) -> "Files":
        """
        Search and filter files by query and admin.

        Args:
            files: Search term for file names (same as textbar search)
            admin: Filter by admin email
            limit: Number of items per page (default: 50)
            offset: Starting index (default: 0)

        Returns:
            New Files instance with filtered results
        """
        # Get all files first
        all_files = self._scan_files()
        
        # Apply filters
        filtered_files = self._apply_filters(all_files, files_query=files, admin=admin)
        
        # Create new Files instance with filtered data
        result = FilteredFiles(filtered_files, limit=limit, offset=offset)
        return result

    def filter(self, folders: _Union[list, None] = None) -> "Files":
        """
        Filter files by folder paths.

        Args:
            folders: List of file or folder paths to include

        Returns:
            New Files instance with filtered results
        """
        # Get all files first
        all_files = self._scan_files()
        
        # Apply folder filter
        filtered_files = self._apply_folder_filter(all_files, folders=folders)
        
        # Create new Files instance with filtered data
        result = FilteredFiles(filtered_files)
        return result

    def _apply_filters(self, files: list, files_query: _Union[str, None] = None, admin: _Union[str, None] = None) -> list:
        """Apply search and admin filters to file list."""
        filtered = files.copy()
        
        # Apply files search filter (same as textbar search)
        if files_query:
            # Parse search terms to handle quoted phrases (same logic as in JS)
            search_terms = self._parse_search_terms(files_query)
            
            filtered = [
                file for file in filtered
                if self._matches_search_terms(file, search_terms)
            ]
        
        # Apply admin filter
        if admin:
            filtered = [
                file for file in filtered
                if file.get("datasite_owner", "").lower() == admin.lower()
            ]
        
        return filtered

    def _apply_folder_filter(self, files: list, folders: _Union[list, None] = None) -> list:
        """Apply folder path filter to file list."""
        if not folders:
            return files
        
        # Normalize folder paths
        normalized_folders = []
        for folder in folders:
            # Remove syft:// prefix if present
            if isinstance(folder, str) and folder.startswith("syft://"):
                folder = folder[7:]  # Remove "syft://"
            normalized_folders.append(str(folder).strip())
        
        # Filter files that match any of the folder paths
        filtered = []
        for file in files:
            file_path = file.get("name", "")
            for folder_path in normalized_folders:
                if file_path.startswith(folder_path):
                    filtered.append(file)
                    break
        
        return filtered

    def _parse_search_terms(self, search: str) -> list:
        """Parse search string into terms, handling quoted phrases."""
        terms = []
        current_term = ''
        in_quotes = False
        quote_char = ''
        
        for char in search:
            if (char == '"' or char == "'") and not in_quotes:
                # Start of quoted string
                in_quotes = True
                quote_char = char
            elif char == quote_char and in_quotes:
                # End of quoted string
                in_quotes = False
                if current_term.strip():
                    terms.append(current_term.strip())
                    current_term = ''
                quote_char = ''
            elif char.isspace() and not in_quotes:
                # End of unquoted term
                if current_term.strip():
                    terms.append(current_term.strip())
                    current_term = ''
            else:
                current_term += char
        
        # Add final term
        if current_term.strip():
            terms.append(current_term.strip())
        
        return terms

    def _matches_search_terms(self, file: dict, search_terms: list) -> bool:
        """Check if file matches all search terms."""
        file_text = f"{file.get('name', '')} {file.get('datasite_owner', '')}".lower()
        
        for term in search_terms:
            if term.lower() not in file_text:
                return False
        
        return True

    def __getitem__(self, key) -> "Files":
        """Support slice notation sp.files[x:y] for range selection by chronological #."""
        if isinstance(key, slice):
            # Get all files first
            all_files = self._scan_files()
            
            # Sort by modified date to get chronological order (newest first)
            sorted_files = sorted(all_files, key=lambda x: x.get('modified', 0), reverse=True)
            
            # Apply slice (convert to 0-based indexing since user expects 1-based)
            start = (key.start - 1) if key.start is not None and key.start > 0 else key.start
            stop = (key.stop - 1) if key.stop is not None and key.stop > 0 else key.stop
            
            sliced_files = sorted_files[slice(start, stop, key.step)]
            
            # Create new Files instance with sliced data
            result = FilteredFiles(sliced_files)
            return result
        else:
            raise TypeError("Files indexing only supports slice notation, e.g., files[1:10]")

    def page(self, page_number: int, items_per_page: int = 50) -> "Files":
        """
        Return a Files instance that will display starting at a specific page.
        
        Args:
            page_number: The page number to jump to (1-based indexing)
            items_per_page: Number of items per page (default: 50)
        
        Returns:
            Files instance that will render starting at the requested page
        """
        if page_number < 1:
            raise ValueError("Page number must be >= 1")
            
        # Create a new Files instance with the initial page set
        new_files = Files()
        new_files._initial_page = page_number
        new_files._items_per_page = items_per_page
        return new_files

    def _repr_pretty_(self, p, cycle):
        """Called by IPython for pretty printing. We disable ASCII progress here."""
        if cycle:
            p.text('...')
            return
        # Temporarily disable ASCII progress for IPython pretty printing
        old_progress = self._show_ascii_progress
        self._show_ascii_progress = False
        try:
            p.text(str(self))
        finally:
            self._show_ascii_progress = old_progress
    
    def __repr__(self) -> str:
        """Generate ASCII table representation of files."""
        from datetime import datetime
        
        # Get files with ASCII progress bar when appropriate
        all_files = self._scan_files(show_ascii_progress=self._show_ascii_progress)
        
        if not all_files:
            return "No files found in SyftBox/datasites directory"
        
        # Sort by modified date (newest first)
        sorted_files = sorted(all_files, key=lambda x: x.get("modified", 0), reverse=True)
        
        # Calculate pagination
        total_files = len(sorted_files)
        total_pages = (total_files + self._items_per_page - 1) // self._items_per_page
        
        # Validate current page
        current_page = min(self._initial_page, total_pages)
        current_page = max(1, current_page)
        
        # Get files for current page
        start = (current_page - 1) * self._items_per_page
        end = min(start + self._items_per_page, total_files)
        page_files = sorted_files[start:end]
        
        # Create chronological index
        chronological_ids = {}
        for i, file in enumerate(sorted_files):
            file_key = f"{file['name']}|{file['path']}"
            chronological_ids[file_key] = i + 1
        
        # Define column widths
        col_widths = {
            'num': 5,
            'url': 60,
            'modified': 16,
            'type': 8,
            'size': 10,
            'perms': 12
        }
        
        # Build header
        header = (
            f"{'#':<{col_widths['num']}} "
            f"{'URL':<{col_widths['url']}} "
            f"{'Modified':<{col_widths['modified']}} "
            f"{'Type':<{col_widths['type']}} "
            f"{'Size':<{col_widths['size']}} "
            f"{'Permissions':<{col_widths['perms']}}"
        )
        
        separator = "-" * len(header)
        
        # Build rows
        rows = []
        for file in page_files:
            # Get chronological number
            file_key = f"{file['name']}|{file['path']}"
            num = chronological_ids.get(file_key, 0)
            
            # Format URL (truncate if needed)
            url = file['name']
            if len(url) > col_widths['url']:
                url = url[:col_widths['url']-3] + "..."
            
            # Format modified date
            modified_ts = file.get('modified', 0)
            if modified_ts:
                modified = datetime.fromtimestamp(modified_ts).strftime('%Y-%m-%d %H:%M')
            else:
                modified = 'Unknown'
            
            # Format file type
            file_type = file.get('extension', '').lstrip('.') or 'file'
            if len(file_type) > col_widths['type']:
                file_type = file_type[:col_widths['type']-3] + "..."
            
            # Format size
            size_bytes = file.get('size', 0)
            if size_bytes < 1024:
                size = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size = f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                size = f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                size = f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
            
            # Format permissions count
            perms = file.get('permissions_summary', [])
            perm_str = f"{len(perms)} users"
            
            # Build row
            row = (
                f"{num:<{col_widths['num']}} "
                f"{url:<{col_widths['url']}} "
                f"{modified:<{col_widths['modified']}} "
                f"{file_type:<{col_widths['type']}} "
                f"{size:>{col_widths['size']}} "
                f"{perm_str:<{col_widths['perms']}}"
            )
            rows.append(row)
        
        # Calculate totals for footer
        file_count = 0
        folder_count = 0
        total_size = 0
        
        for file in sorted_files:
            if file.get('is_dir', False):
                folder_count += 1
            else:
                file_count += 1
                total_size += file.get('size', 0)
        
        # Format total size
        if total_size < 1024:
            size_str = f"{total_size} B"
        elif total_size < 1024 * 1024:
            size_str = f"{total_size / 1024:.1f} KB"
        elif total_size < 1024 * 1024 * 1024:
            size_str = f"{total_size / (1024 * 1024):.1f} MB"
        else:
            size_str = f"{total_size / (1024 * 1024 * 1024):.1f} GB"
        
        # Build output
        output = [
            f"Files (Page {current_page} of {total_pages}, showing {start+1}-{end} of {total_files} items)",
            separator,
            header,
            separator
        ]
        output.extend(rows)
        output.append(separator)
        output.append(f"{file_count} files, {folder_count} folders • Total size: {size_str}")
        output.append(f"Use sp.files.page(n) to view other pages or sp.files in Jupyter for interactive view")
        
        return "\n".join(output)

    def _repr_html_(self) -> str:
        """Generate SyftObjects-style widget for Jupyter."""
        import html as html_module
        import json
        import threading
        import time
        import uuid
        from datetime import datetime
        from pathlib import Path

        from IPython.display import HTML, clear_output, display

        # Check if server is available
        try:
            import requests
            import os
            import json
            
            server_available = False
            server_port = None
            
            # First, try to read port from config file
            config_path = Path.home() / ".syftperm" / "config.json"
            if config_path.exists():
                try:
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                        configured_port = config.get('port')
                        if configured_port:
                            # Verify the server is actually running on this port
                            try:
                                response = requests.get(f"http://localhost:{configured_port}/", timeout=0.5)
                                if response.status_code == 200:
                                    # Check if response contains syft-perm identifier
                                    if "SyftPerm" in response.text:
                                        server_available = True
                                        server_port = configured_port
                            except:
                                pass
                except:
                    pass
            
            # If not found via config, fall back to checking common ports
            if not server_available:
                for port in [8080, 8765, 5000]:
                    try:
                        response = requests.get(f"http://localhost:{port}/", timeout=0.5)
                        if response.status_code == 200:
                            # Check if response contains syft-perm identifier
                            if "SyftPerm" in response.text:
                                server_available = True
                                server_port = port
                                break
                    except:
                        pass
            
            if server_available:
                print(f"Server available on port {server_port}")
            else:
                print("Server not available")
        except ImportError:
            # requests not available
            print("Server not available")

        container_id = f"syft_files_{uuid.uuid4().hex[:8]}"
        
        # Detect dark mode early for loading animation
        is_dark_mode = is_dark()
        
        # Non-obvious tips for users
        tips = [
            'Use quotation marks to search for exact phrases like "machine learning"',
            'Multiple words without quotes searches for files containing ALL words',
            'Press Tab in search boxes for auto-completion suggestions',
            'Tab completion in Admin filter shows all available datasite emails',
            'Use sp.files.page(5) to jump directly to page 5',
            'Click any row to copy its syft:// path to clipboard',
            'Try sp.files.search("keyword") for programmatic filtering',
            'Use sp.files.filter(extension=".csv") to find specific file types',
            'Chain filters: sp.files.filter(extension=".py").search("test")',
            'Escape special characters with backslash when searching',
            'ASCII loading bar only appears with print(sp.files), not in Jupyter',
            'Loading progress: first 10% is setup, 10-100% is file scanning',
            'Press Escape to close the tab-completion dropdown',
            'Use sp.open("syft://path") to access files programmatically',
            'Search for dates in various formats: 2024-01-15, Jan-15, etc',
            'Admin filter supports partial matching - type "gmail" for all Gmail users',
            'File sizes show as B, KB, MB, or GB automatically',
            'The # column shows files in chronological order by modified date',
            'Empty search returns all files - useful for resetting filters',
            'Search works across file names, paths, and extensions at once'
        ]
        
        # Pick a random tip for loading and footer
        import random
        loading_tip = random.choice(tips)
        footer_tip = random.choice(tips)
        show_footer_tip = random.random() < 0.5  # 50% chance

        # Variables to track progress (start with percentage-based)
        progress_data = {"current": 0, "total": 100, "status": "Initializing..."}

        # Show loading animation with real progress tracking
        loading_html = f"""
        <style>
        @keyframes float {{
            0%, 100% {{ transform: translateY(0px); }}
            50% {{ transform: translateY(-8px); }}
        }}
        .syftbox-logo {{
            animation: float 3s ease-in-out infinite;
            filter: drop-shadow(0 4px 12px rgba(0, 0, 0, 0.15));
        }}
        .progress-bar-gradient {{
            background: linear-gradient(90deg, #3b82f6 0%, #10b981 100%);
            transition: width 0.4s ease-out;
            border-radius: 3px;
        }}
        </style>
        <div id="loading-container-{container_id}" style="padding: 40px; text-align: center; font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: {'#1e1e1e' if is_dark_mode else '#ffffff'};">
            <div style="margin-bottom: 28px;">
                <svg class="syftbox-logo" xmlns="http://www.w3.org/2000/svg" width="62" height="72" viewBox="0 0 311 360" fill="none"&gt;
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
            </div>
            <div style="font-size: 20px; font-weight: 600; color: {'#cccccc' if is_dark_mode else '#666666'}; margin-bottom: 12px;">loading your view of <br />the internet of private data...</div>
            <div style="width: 340px; height: 6px; background-color: {'#3e3e42' if is_dark_mode else '#e5e7eb'}; border-radius: 3px; margin: 0 auto; overflow: hidden;">
                <div id="loading-bar-{container_id}" class="progress-bar-gradient" style="width: 0%; height: 100%;"></div>
            </div>
            <div id="loading-status-{container_id}" style="margin-top: 12px; color: {'#9ca3af' if is_dark_mode else '#6b7280'}; opacity: 0.7; font-size: 12px;">Initializing...</div>
            <div style="margin-top: 20px; padding: 12px 24px; background: {'#1e3a5f' if is_dark_mode else '#f0f9ff'}; border-radius: 6px; max-width: 600px; margin-left: auto; margin-right: auto;">
                <div style="font-size: 12px; color: {'#93c5fd' if is_dark_mode else '#0c4a6e'}; line-height: 1.4; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                    <span style="font-weight: 600; color: {'#60a5fa' if is_dark_mode else '#0369a1'};">💡 TIP:</span> {html_module.escape(loading_tip)}
                </div>
            </div>
        </div>
        """
        display(HTML(loading_html))
        
        # Helper function to update loading bar
        def update_loading_display(percent, status):
            update_html = f"""
            <script>
            (function() {{
                var loadingBar = document.getElementById('loading-bar-{container_id}');
                var loadingStatus = document.getElementById('loading-status-{container_id}');
                
                if (loadingBar) {{
                    loadingBar.style.width = '{percent:.1f}%';
                }}
                if (loadingStatus) {{
                    loadingStatus.innerHTML = '{status}';
                }}
            }})();
            </script>
            """
            display(HTML(update_html))
            time.sleep(0.01)
        
        # Count datasites with progress (0-10% of loading bar)
        update_loading_display(2, "Finding SyftBox directory...")
        
        syftbox_dirs = [
            Path.home() / "SyftBox",
            Path.home() / ".syftbox",
            Path("/tmp/SyftBox"),
        ]

        datasites_path = None
        syftbox_path = None
        for path in syftbox_dirs:
            if path.exists():
                syftbox_path = path
                datasites_path = path / "datasites"
                if datasites_path.exists():
                    break
        
        # Check syft-perm installation status in background
        def check_syft_perm_status():
            import subprocess
            
            if syftbox_path:
                syft_perm_path = syftbox_path / "apps" / "syft-perm"
                if syft_perm_path.exists():
                    # Get last modified time of the directory
                    import os
                    from datetime import datetime
                    mod_time = os.path.getmtime(syft_perm_path)
                    last_modified = datetime.fromtimestamp(mod_time).strftime('%Y-%m-%d %H:%M:%S')
                    # Found syft-perm (no print)
                    
                    # Check if run.sh is running
                    try:
                        # Check for running processes containing the syft-perm path
                        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                        if result.returncode == 0:
                            processes = result.stdout
                            if str(syft_perm_path) in processes and 'run.sh' in processes:
                                pass  # run.sh is running
                            else:
                                # run.sh is not running
                                
                                # Check if it was cloned/modified recently (within 2 minutes)
                                import time
                                current_time = time.time()
                                time_since_modified = current_time - mod_time
                                
                                if time_since_modified < 120:  # 120 seconds = 2 minutes
                                    # Recently modified - likely still starting up
                                    return
                                
                                # Delete and re-clone only if it's been more than 2 minutes
                                # Remove non-running installation
                                try:
                                    import shutil
                                    shutil.rmtree(syft_perm_path)
                                    # Removed old directory
                                    
                                    # Re-clone
                                    # Re-clone syft-perm
                                    clone_result = subprocess.run(
                                        ['git', 'clone', 'https://github.com/OpenMined/syft-perm.git', str(syft_perm_path)],
                                        capture_output=True,
                                        text=True
                                    )
                                    
                                    if clone_result.returncode == 0:
                                        # Successfully re-cloned
                                        
                                        # Make run.sh executable
                                        run_sh_path = syft_perm_path / "run.sh"
                                        if run_sh_path.exists():
                                            subprocess.run(['chmod', '+x', str(run_sh_path)], capture_output=True)
                                            pass  # Made executable
                                    else:
                                        pass  # Failed to re-clone
                                except Exception as e:
                                    pass  # Error during re-clone
                    except Exception as e:
                        pass  # Could not check process status
                else:
                    # syft-perm not found
                    
                    # Clone syft-perm in the background
                    # Clone syft-perm
                    try:
                        # Ensure apps directory exists
                        apps_dir = syftbox_path / "apps"
                        apps_dir.mkdir(exist_ok=True)
                        
                        # Clone the repository
                        clone_result = subprocess.run(
                            ['git', 'clone', 'https://github.com/OpenMined/syft-perm.git', str(syft_perm_path)],
                            capture_output=True,
                            text=True
                        )
                        
                        if clone_result.returncode == 0:
                            # Successfully cloned
                            
                            # Make run.sh executable
                            run_sh_path = syft_perm_path / "run.sh"
                            if run_sh_path.exists():
                                subprocess.run(['chmod', '+x', str(run_sh_path)], capture_output=True)
                        else:
                            pass  # Failed to clone
                    except Exception as e:
                        pass  # Error cloning
        
        # Run the check in a background thread
        import threading
        background_thread = threading.Thread(target=check_syft_perm_status, daemon=True)
        background_thread.start()
        
        update_loading_display(5, "Counting datasites...")
        
        total_datasites = 0
        if datasites_path and datasites_path.exists():
            datasite_dirs = [d for d in datasites_path.iterdir() if d.is_dir() and not d.name.startswith(".")]
            total_datasites = len(datasite_dirs)
            update_loading_display(10, f"Found {total_datasites} datasites. Starting scan...")
        else:
            update_loading_display(10, "No datasites found...")

        # Variables for throttling updates
        datasite_count = [0]  # Use list to make it mutable in nested function
        last_datasite = [None]  # Track last datasite to detect changes
        update_interval = max(1, total_datasites // 20) if total_datasites > 0 else 1  # Update at most 20 times
        
        # Progress callback function for file scanning (10-100%)
        def update_progress(current, total, status):
            progress_data["current"] = current
            progress_data["total"] = total
            progress_data["status"] = status
            
            # Extract datasite from status (status format: "Scanning email@domain.com")
            current_datasite = status.split(" ")[-1] if " " in status else status
            
            # Check if datasite changed
            if current_datasite != last_datasite[0]:
                last_datasite[0] = current_datasite
                datasite_count[0] += 1
            
            # Only update every update_interval datasites or on the last one
            if datasite_count[0] % update_interval != 0 and current < total:
                return  # Skip this update unless it's time for an update or the last one

            # Update the display - map scanning progress from 10% to 100%
            scan_percent = (current / max(total, 1)) * 100
            # Map to 10-100% range (first 10% was for initialization)
            progress_percent = 10 + (scan_percent * 0.9)
            
            update_html = f"""
            <script>
            (function() {{
                var loadingBar = document.getElementById('loading-bar-{container_id}');
                var currentCount = document.getElementById('current-count-{container_id}');
                var loadingStatus = document.getElementById('loading-status-{container_id}');
                
                if (loadingBar) {{
                    loadingBar.style.width = '{progress_percent:.1f}%';
                    loadingBar.className = 'progress-bar-gradient';
                }}
                if (currentCount) currentCount.textContent = '{current}';
                if (loadingStatus) loadingStatus.innerHTML = '{status} - <span id="current-count-{container_id}">{current}</span> of {total} datasites...';
            }})();
            </script>
            """
            display(HTML(update_html))
            time.sleep(0.01)  # Small delay to make progress visible

        # Scan files with progress tracking
        all_files = self._scan_files(progress_callback=update_progress)

        # Create chronological index based on modified date (newest first)
        sorted_by_date = sorted(all_files, key=lambda x: x.get("modified", 0), reverse=True)
        chronological_ids = {}
        for i, file in enumerate(sorted_by_date):
            file_key = f"{file['name']}|{file['path']}"
            chronological_ids[file_key] = i + 1

        # Get initial display files
        data = {"files": all_files[:100], "total_count": len(all_files)}
        files = data["files"]
        total = data["total_count"]

        if not files:
            clear_output()
            return (
                "<div style='padding: 40px; text-align: center; color: #666; "
                "font-family: -apple-system, BlinkMacSystemFont, sans-serif;'>"
                "No files found in SyftBox/datasites directory</div>"
            )

        # Use the already scanned files for search

        # Clear loading animation
        clear_output()

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
            background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
            overflow: hidden;
            display: flex;
            flex-direction: column;
            width: 100%;
            margin: 0;
            border: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            border-radius: 8px;
            color: {'#cccccc' if is_dark_mode else '#000000'};
        }}

        #{container_id} .search-controls {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            padding: 0.75rem;
            background: {'#252526' if is_dark_mode else '#f8f9fa'};
            border-bottom: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            flex-shrink: 0;
        }}

        #{container_id} .search-controls input {{
            flex: 1;
            min-width: 200px;
            padding: 0.5rem;
            border: 1px solid {'#3e3e42' if is_dark_mode else '#d1d5db'};
            border-radius: 0.25rem;
            font-size: 0.875rem;
            background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
        }}

        #{container_id} .table-container {{
            flex: 1;
            overflow-y: auto;
            overflow-x: auto;
            background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
            min-height: 0;
            max-height: 600px;
        }}

        #{container_id} table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75rem;
        }}

        #{container_id} thead {{
            background: {'#252526' if is_dark_mode else '#f8f9fa'};
            border-bottom: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
        }}

        #{container_id} th {{
            text-align: left;
            padding: 0.375rem 0.25rem;
            font-weight: 500;
            font-size: 0.75rem;
            border-bottom: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            position: sticky;
            top: 0;
            background: {'#252526' if is_dark_mode else '#f8f9fa'};
            z-index: 10;
            color: {'#cccccc' if is_dark_mode else '#000000'};
        }}

        #{container_id} td {{
            padding: 0.375rem 0.25rem;
            border-bottom: 1px solid {'#2d2d30' if is_dark_mode else '#f3f4f6'};
            vertical-align: top;
            font-size: 0.75rem;
            text-align: left;
        }}

        #{container_id} tbody tr {{
            transition: background-color 0.15s;
            cursor: pointer;
        }}

        #{container_id} tbody tr:hover {{
            background: {'rgba(255, 255, 255, 0.04)' if is_dark_mode else 'rgba(0, 0, 0, 0.03)'};
        }}

        @keyframes rainbow-light {{
            0% {{ background-color: #ffe9ec; }}
            14.28% {{ background-color: #fff4ea; }}
            28.57% {{ background-color: #ffffea; }}
            42.86% {{ background-color: #eaffef; }}
            57.14% {{ background-color: #eaf6ff; }}
            71.43% {{ background-color: #f5eaff; }}
            85.71% {{ background-color: #ffeaff; }}
            100% {{ background-color: #ffe9ec; }}
        }}
        
        @keyframes rainbow-dark {{
            0% {{ background-color: #3d2c2e; }}
            14.28% {{ background-color: #3d352c; }}
            28.57% {{ background-color: #3d3d2c; }}
            42.86% {{ background-color: #2c3d31; }}
            57.14% {{ background-color: #2c363d; }}
            71.43% {{ background-color: #352c3d; }}
            85.71% {{ background-color: #3d2c3d; }}
            100% {{ background-color: #3d2c2e; }}
        }}

        #{container_id} .rainbow-flash {{
            animation: {'rainbow-dark' if is_dark_mode else 'rainbow-light'} 0.8s ease-in-out;
        }}

        #{container_id} .pagination {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem;
            border-top: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            background: {'rgba(255, 255, 255, 0.02)' if is_dark_mode else 'rgba(0, 0, 0, 0.02)'};
            flex-shrink: 0;
        }}

        #{container_id} .pagination button {{
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            border: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            background: {'#1e1e1e' if is_dark_mode else 'white'};
            cursor: pointer;
            transition: all 0.15s;
        }}

        #{container_id} .pagination button:hover:not(:disabled) {{
            background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
        }}

        #{container_id} .pagination button:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        #{container_id} .pagination .page-info {{
            font-size: 0.75rem;
        }}

        #{container_id} .pagination .status {{
            font-size: 0.75rem;
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
            cursor: not-allowed;
            display: inline-flex;
            align-items: center;
            gap: 0.125rem;
            transition: all 0.15s;
            opacity: 0.5;
        }}

        #{container_id} .btn:hover {{
            opacity: 0.5;
        }}

        #{container_id} .btn-blue {{
            background: {'#1e3a5f' if is_dark_mode else '#dbeafe'};
            color: {'#60a5fa' if is_dark_mode else '#3b82f6'};
        }}

        #{container_id} .btn-purple {{
            background: {'#3b2e4d' if is_dark_mode else '#e9d5ff'};
            color: {'#c084fc' if is_dark_mode else '#a855f7'};
        }}

        #{container_id} .btn-red {{
            background: {'#4d2828' if is_dark_mode else '#fee2e2'};
            color: {'#f87171' if is_dark_mode else '#ef4444'};
        }}

        #{container_id} .btn-green {{
            background: {'#1e4032' if is_dark_mode else '#d1fae5'};
            color: {'#34d399' if is_dark_mode else '#10b981'};
        }}

        #{container_id} .btn-gray {{
            background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
            color: {'#9ca3af' if is_dark_mode else '#6b7280'};
        }}

        #{container_id} .icon {{
            width: 0.5rem;
            height: 0.5rem;
        }}
        
        #{container_id} .autocomplete-dropdown {{
            position: absolute;
            background: {'#1e1e1e' if is_dark_mode else 'white'};
            border: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
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
            background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
        }}

        #{container_id} .type-badge {{
            display: inline-block;
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 500;
            background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
            color: {'#d1d5db' if is_dark_mode else '#374151'};
            text-align: center;
            white-space: nowrap;
        }}

        #{container_id} .admin-email {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-family: monospace;
            font-size: 0.75rem;
            color: {'#d1d5db' if is_dark_mode else '#374151'};
        }}

        #{container_id} .date-text {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-size: 0.75rem;
        }}
        </style>

        <div id="{container_id}">
            <div class="search-controls">
                <input id="{container_id}-search" placeholder="🔍 Search files..." style="flex: 1;">
                <input id="{container_id}-admin-filter" placeholder="Filter by Admin..." style="flex: 1;">
                <button class="btn btn-green">New</button>
                <button class="btn btn-blue">Select All</button>
                <button class="btn btn-gray">Refresh</button>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 1.5rem;"><input type="checkbox" id="{container_id}-select-all" onclick="toggleSelectAll_{container_id}()"></th>
                            <th style="width: 2rem; cursor: pointer;" onclick="sortTable_{container_id}('index')"># ↕</th>
                            <th style="width: 25rem; cursor: pointer;" onclick="sortTable_{container_id}('name')">URL ↕</th>
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
            file_path = file["name"]
            full_syft_path = f"syft://{file_path}"  # Full syft:// path
            datasite_owner = file.get("datasite_owner", "unknown")
            modified = datetime.fromtimestamp(file.get("modified", 0)).strftime("%m/%d/%Y %H:%M")
            file_ext = file.get("extension", ".txt")
            size = file.get("size", 0)
            is_dir = file.get("is_dir", False)

            # Get chronological ID based on modified date
            file_key = f"{file['name']}|{file['path']}"
            chrono_id = chronological_ids.get(file_key, i + 1)

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
                        <td>{chrono_id}</td>
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
                        <td><span style="color: {'#9ca3af' if is_dark_mode else '#6b7280'};">{size_str}</span></td>
                        <td>
                            <div style="display: flex; flex-direction: column; gap: 0.125rem; font-size: 0.625rem; color: {'#9ca3af' if is_dark_mode else '#6b7280'};">
            """

            # Add each permission line
            perms = file.get("permissions_summary", [])
            if perms:
                for perm_line in perms[:3]:  # Limit to 3 lines
                    html += f"                                <span>{html_module.escape(perm_line)}</span>\n"
                if len(perms) > 3:
                    html += (
                        f"                                <span>+{len(perms) - 3} more...</span>\n"
                    )
            else:
                html += '                                <span style="color: {'#6b7280' if is_dark_mode else '#9ca3af'};">No permissions</span>\n'

            html += f"""
                            </div>
                        </td>
                        <td>
                            <div style="display: flex; gap: 0.125rem;">
                                <button class="btn btn-gray" title="Open in editor">File</button>
                                <button class="btn btn-blue" title="View file info">Info</button>
                                <button class="btn btn-purple" title="Copy path">Copy</button>
                                <button class="btn btn-red" title="Delete file">
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
            
            // Create chronological index based on modified date (newest first)
            var sortedByDate = allFiles.slice().sort(function(a, b) {{
                return (b.modified || 0) - (a.modified || 0);
            }});
            
            // Assign chronological IDs
            var chronologicalIds = {{}};
            for (var i = 0; i < sortedByDate.length; i++) {{
                var file = sortedByDate[i];
                var fileKey = file.name + '|' + file.path; // Unique key for each file
                chronologicalIds[fileKey] = i + 1;
            }}
            
            var filteredFiles = allFiles.slice();
            var currentPage = {self._initial_page};
            var itemsPerPage = {self._items_per_page};
            var sortColumn = 'modified';
            var sortDirection = 'desc';
            var searchHistory = [];
            var adminHistory = [];
            var showFooterTip = {'true' if show_footer_tip else 'false'};
            var footerTip = {json.dumps(footer_tip)};

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
                       date.getFullYear() + ' ' +
                       date.getHours().toString().padStart(2, '0') + ':' +
                       date.getMinutes().toString().padStart(2, '0');
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
                
                // Check if we're searching
                var searchValue = document.getElementById('{container_id}-search').value;
                var adminFilter = document.getElementById('{container_id}-admin-filter').value;
                var isSearching = searchValue !== '' || adminFilter !== '';
                
                var statusText = fileCount + ' files';
                if (folderCount > 0) {{
                    statusText += ', ' + folderCount + ' folders';
                }}
                statusText += ' • Total size: ' + sizeStr;
                
                // Show tip if not searching and showFooterTip is true
                if (!isSearching && showFooterTip) {{
                    statusText += ' • 💡 ' + footerTip;
                }}
                
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
                    
                    // Get chronological ID based on modified date
                    var fileKey = file.name + '|' + file.path;
                    var chronoId = chronologicalIds[fileKey] || (i + 1);
                    
                    html += '<tr onclick="copyPath_{container_id}(\\'syft://' + filePath + '\\', this)">' +
                        '<td><input type="checkbox" onclick="event.stopPropagation(); updateSelectAllState_{container_id}()"></td>' +
                        '<td>' + chronoId + '</td>' +
                        '<td><div class="truncate" style="font-weight: 500;" title="' + escapeHtml(fullSyftPath) + '">' + escapeHtml(fullSyftPath) + '</div></td>' +
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
                        '<td><span style="color: {'#9ca3af' if is_dark_mode else '#6b7280'};">' + sizeStr + '</span></td>' +
                        '<td>' +
                            '<div style="display: flex; flex-direction: column; gap: 0.125rem; font-size: 0.625rem; color: {'#9ca3af' if is_dark_mode else '#6b7280'};">';
                    
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
                        html += '<span style="color: {'#6b7280' if is_dark_mode else '#9ca3af'};">No permissions</span>';
                    }}
                    
                    html += '</div>' +
                        '</td>' +
                        '<td>' +
                            '<div style="display: flex; gap: 0.125rem;">' +
                                '<button class="btn btn-gray" title="Open in editor">File</button>' +
                                '<button class="btn btn-blue" title="View file info">Info</button>' +
                                '<button class="btn btn-purple" title="Copy path">Copy</button>' +
                                '<button class="btn btn-red" title="Delete file">' +
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
                
                // Parse search terms to handle quoted phrases
                var searchTerms = [];
                var currentTerm = '';
                var inQuotes = false;
                var quoteChar = '';
                
                for (var i = 0; i < searchTerm.length; i++) {{
                    var char = searchTerm[i];
                    
                    if ((char === '"' || char === "'") && !inQuotes) {{
                        // Start of quoted string
                        inQuotes = true;
                        quoteChar = char;
                    }} else if (char === quoteChar && inQuotes) {{
                        // End of quoted string
                        inQuotes = false;
                        if (currentTerm.length > 0) {{
                            searchTerms.push(currentTerm);
                            currentTerm = '';
                        }}
                        quoteChar = '';
                    }} else if (char === ' ' && !inQuotes) {{
                        // Space outside quotes - end current term
                        if (currentTerm.length > 0) {{
                            searchTerms.push(currentTerm);
                            currentTerm = '';
                        }}
                    }} else {{
                        // Regular character - add to current term
                        currentTerm += char;
                    }}
                }}
                
                // Add final term if exists
                if (currentTerm.length > 0) {{
                    searchTerms.push(currentTerm);
                }}
                
                filteredFiles = allFiles.filter(function(file) {{
                    // Admin filter
                    var adminMatch = adminFilter === '' || (file.datasite_owner || '').toLowerCase().includes(adminFilter);
                    if (!adminMatch) return false;
                    
                    // If no search terms, show all (that match admin filter)
                    if (searchTerms.length === 0) return true;
                    
                    // Check if all search terms match somewhere in the file data
                    return searchTerms.every(function(term) {{
                        // Create searchable string from all file properties
                        var searchableContent = [
                            file.name,
                            file.datasite_owner || '',
                            file.extension || '',
                            formatSize(file.size || 0),
                            formatDate(file.modified || 0),
                            file.is_dir ? 'folder' : 'file',
                            (file.permissions_summary || []).join(' ')
                        ].join(' ').toLowerCase();
                        
                        return searchableContent.includes(term);
                    }});
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
                            // Sort by modified timestamp for chronological order (newest first)
                            aVal = a.modified || 0;
                            bVal = b.modified || 0;
                            // Reverse the values so newest (higher timestamp) comes first
                            var temp = aVal;
                            aVal = -bVal;
                            bVal = -temp;
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
                            // Trigger search after selecting from dropdown
                            searchFiles_{container_id}();
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
                        // Trigger search after selecting from dropdown
                        searchFiles_{container_id}();
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
            
            // Validate initial page and update
            var totalPages = Math.ceil(filteredFiles.length / itemsPerPage);
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;
            
            // Apply initial sort by modified date (newest first)
            filteredFiles.sort(function(a, b) {{
                var aVal = a.modified || 0;
                var bVal = b.modified || 0;
                return bVal - aVal; // Descending order (newest first)
            }});
            
            // Initial render
            renderTable();
            updateStatus();
        }})();
        </script>
        """

        return html


class FilteredFiles(Files):
    """
    Filtered version of Files that works with a predefined set of files.
    Used for search(), filter(), and slice operations.
    """
    
    def __init__(self, filtered_files: list, limit: int = None, offset: int = 0):
        super().__init__()
        self._filtered_files = filtered_files
        self._limit = limit
        self._offset = offset
    
    def _scan_files(self, search: _Union[str, None] = None, progress_callback=None, show_ascii_progress=False) -> list:
        """Return the pre-filtered files instead of scanning."""
        return self._filtered_files
    
    def _repr_html_(self) -> str:
        """Generate HTML widget with filtered files."""
        import html as html_module
        import json
        import time
        import uuid
        from datetime import datetime
        from pathlib import Path

        from IPython.display import HTML, clear_output, display

        container_id = f"syft_files_{uuid.uuid4().hex[:8]}"

        # Use the filtered files directly
        all_files = self._filtered_files
        
        # Create chronological index based on modified date (newest first)
        sorted_by_date = sorted(all_files, key=lambda x: x.get("modified", 0), reverse=True)
        chronological_ids = {}
        for i, file in enumerate(sorted_by_date):
            file_key = f"{file['name']}|{file['path']}"
            chronological_ids[file_key] = i + 1

        # Apply pagination if specified
        if self._limit:
            files = all_files[self._offset:self._offset + self._limit]
        else:
            files = all_files[:100]  # Default limit for display
        
        total = len(all_files)

        if not files:
            return (
                "<div style='padding: 40px; text-align: center; color: #666; "
                "font-family: -apple-system, BlinkMacSystemFont, sans-serif;'>"
                f"No files found (filtered from {total} total files)</div>"
            )

        # Build HTML template (same as original but without loading animation)
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
            background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
            overflow: hidden;
            display: flex;
            flex-direction: column;
            width: 100%;
            margin: 0;
            border: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            border-radius: 8px;
            color: {'#cccccc' if is_dark_mode else '#000000'};
        }}

        #{container_id} .search-controls {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            padding: 0.75rem;
            background: {'#252526' if is_dark_mode else '#f8f9fa'};
            border-bottom: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            flex-shrink: 0;
        }}

        #{container_id} .search-controls input {{
            flex: 1;
            min-width: 200px;
            padding: 0.5rem;
            border: 1px solid {'#3e3e42' if is_dark_mode else '#d1d5db'};
            border-radius: 0.25rem;
            font-size: 0.875rem;
        }}

        #{container_id} .table-container {{
            flex: 1;
            overflow-y: auto;
            overflow-x: auto;
            background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
            min-height: 0;
            max-height: 600px;
        }}

        #{container_id} table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75rem;
        }}

        #{container_id} thead {{
            background: {'#252526' if is_dark_mode else '#f8f9fa'};
            border-bottom: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
        }}

        #{container_id} th {{
            text-align: left;
            padding: 0.375rem 0.25rem;
            font-weight: 500;
            font-size: 0.75rem;
            border-bottom: 1px solid {'#3e3e42' if is_dark_mode else '#e5e7eb'};
            position: sticky;
            top: 0;
            background: {'#252526' if is_dark_mode else '#f8f9fa'};
            z-index: 10;
            color: {'#cccccc' if is_dark_mode else '#000000'};
        }}

        #{container_id} td {{
            padding: 0.375rem 0.25rem;
            border-bottom: 1px solid {'#2d2d30' if is_dark_mode else '#f3f4f6'};
            vertical-align: top;
            font-size: 0.75rem;
            text-align: left;
        }}

        #{container_id} tbody tr {{
            transition: background-color 0.15s;
            cursor: pointer;
        }}

        #{container_id} tbody tr:hover {{
            background: {'rgba(255, 255, 255, 0.04)' if is_dark_mode else 'rgba(0, 0, 0, 0.03)'};
        }}

        @keyframes rainbow {{
            0% {{ background-color: #fee2e2; }}
            16% {{ background-color: #fef3c7; }}
            33% {{ background-color: #d1fae5; }}
            50% {{ background-color: #bfdbfe; }}
            66% {{ background-color: #e0e7ff; }}
            83% {{ background-color: #ede9fe; }}
            100% {{ background-color: #ffe9ec; }}
        }}

        #{container_id} .rainbow-flash {{
            animation: rainbow 0.8s ease-in-out;
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
            cursor: not-allowed;
            display: inline-flex;
            align-items: center;
            gap: 0.125rem;
            transition: all 0.15s;
            opacity: 0.5;
        }}

        #{container_id} .btn:hover {{
            opacity: 0.5;
        }}

        #{container_id} .btn-blue {{
            background: {'#1e3a5f' if is_dark_mode else '#dbeafe'};
            color: {'#60a5fa' if is_dark_mode else '#3b82f6'};
        }}

        #{container_id} .btn-purple {{
            background: {'#3b2e4d' if is_dark_mode else '#e9d5ff'};
            color: {'#c084fc' if is_dark_mode else '#a855f7'};
        }}

        #{container_id} .btn-red {{
            background: {'#4d2828' if is_dark_mode else '#fee2e2'};
            color: {'#f87171' if is_dark_mode else '#ef4444'};
        }}

        #{container_id} .btn-green {{
            background: {'#1e4032' if is_dark_mode else '#d1fae5'};
            color: {'#34d399' if is_dark_mode else '#10b981'};
        }}

        #{container_id} .btn-gray {{
            background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
            color: {'#9ca3af' if is_dark_mode else '#6b7280'};
        }}

        #{container_id} .icon {{
            width: 0.5rem;
            height: 0.5rem;
        }}

        #{container_id} .type-badge {{
            display: inline-block;
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: 500;
            background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
            color: {'#d1d5db' if is_dark_mode else '#374151'};
            text-align: center;
            white-space: nowrap;
        }}

        #{container_id} .admin-email {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-family: monospace;
            font-size: 0.75rem;
            color: {'#d1d5db' if is_dark_mode else '#374151'};
        }}

        #{container_id} .date-text {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-size: 0.75rem;
        }}
        </style>

        <div id="{container_id}">
            <div class="search-controls">
                <div style="font-size: 0.875rem; color: {'#9ca3af' if is_dark_mode else '#6b7280'}; align-self: center;">
                    Showing {len(files)} of {total} filtered files
                </div>
            </div>

            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th style="width: 1.5rem;"><input type="checkbox" id="{container_id}-select-all" onclick="toggleSelectAll_{container_id}()"></th>
                            <th style="width: 2rem; cursor: pointer;" onclick="sortTable_{container_id}('index')"># ↕</th>
                            <th style="width: 25rem; cursor: pointer;" onclick="sortTable_{container_id}('name')">URL ↕</th>
                            <th style="width: 7rem; cursor: pointer;" onclick="sortTable_{container_id}('modified')">Modified ↕</th>
                            <th style="width: 5rem; cursor: pointer;" onclick="sortTable_{container_id}('type')">Type ↕</th>
                            <th style="width: 4rem; cursor: pointer;" onclick="sortTable_{container_id}('size')">Size ↕</th>
                            <th style="width: 10rem; cursor: pointer;" onclick="sortTable_{container_id}('permissions')">Permissions ↕</th>
                            <th style="width: 15rem;">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="{container_id}-tbody">
        """

        # Initial table rows - show files
        for i, file in enumerate(files[:50]):
            # Format file info
            file_path = file["name"]
            full_syft_path = f"syft://{file_path}"  # Full syft:// path
            datasite_owner = file.get("datasite_owner", "unknown")
            modified = datetime.fromtimestamp(file.get("modified", 0)).strftime("%m/%d/%Y %H:%M")
            file_ext = file.get("extension", ".txt")
            size = file.get("size", 0)
            is_dir = file.get("is_dir", False)

            # Get chronological ID based on modified date
            file_key = f"{file['name']}|{file['path']}"
            chrono_id = chronological_ids.get(file_key, i + 1)

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
                        <td>{chrono_id}</td>
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
                                <span>{modified}</span>
                            </div>
                        </td>
                        <td>
                            <div class="type-badge">
                                {"DIR" if is_dir else file_ext.upper().replace(".", "")}
                            </div>
                        </td>
                        <td>{size_str}</td>
                        <td>
                            <div style="font-size: 0.75rem; color: {'#9ca3af' if is_dark_mode else '#6b7280'};">
                                {"; ".join(file.get("permissions_summary", [])[:2])}
                            </div>
                        </td>
                        <td>
                            <div style="display: flex; gap: 0.125rem;">
                                <button class="btn btn-gray" title="Open in editor">File</button>
                                <button class="btn btn-blue" title="View file info">Info</button>
                                <button class="btn btn-purple" title="Copy path">Copy</button>
                                <button class="btn btn-red" title="Delete file">
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
        </div>
        """

        return html

    def __repr__(self) -> str:
        """Generate ASCII table representation of filtered files."""
        from datetime import datetime
        
        if not self._filtered_files:
            return "FilteredFiles: No files match the filter criteria"
        
        # Sort by modified date (newest first) to match main Files display
        sorted_files = sorted(self._filtered_files, key=lambda x: x.get("modified", 0), reverse=True)
        
        # Calculate display range
        total_files = len(sorted_files)
        items_per_page = self._limit if self._limit else 50
        
        # Get files to display
        if self._limit:
            # If limit is set, show from offset to offset+limit
            start = self._offset
            end = min(start + self._limit, total_files)
            display_files = sorted_files[start:end]
            page_info = f"FilteredFiles (showing {start+1}-{end} of {total_files} filtered files)"
        else:
            # Otherwise show first page
            end = min(items_per_page, total_files)
            display_files = sorted_files[:end]
            page_info = f"FilteredFiles (showing 1-{end} of {total_files} filtered files)"
        
        # Create chronological index for all filtered files
        chronological_ids = {}
        for i, file in enumerate(sorted_files):
            file_key = f"{file['name']}|{file['path']}"
            chronological_ids[file_key] = i + 1
        
        # Define column widths (same as main Files class)
        col_widths = {
            'num': 5,
            'url': 60,
            'modified': 16,
            'type': 8,
            'size': 10,
            'perms': 12
        }
        
        # Build header
        header = (
            f"{'#':<{col_widths['num']}} "
            f"{'URL':<{col_widths['url']}} "
            f"{'Modified':<{col_widths['modified']}} "
            f"{'Type':<{col_widths['type']}} "
            f"{'Size':<{col_widths['size']}} "
            f"{'Permissions':<{col_widths['perms']}}"
        )
        
        separator = "-" * len(header)
        
        # Build rows
        rows = []
        for file in display_files:
            # Get chronological number
            file_key = f"{file['name']}|{file['path']}"
            num = chronological_ids.get(file_key, 0)
            
            # Format URL (truncate if needed)
            url = file['name']
            if len(url) > col_widths['url']:
                url = url[:col_widths['url']-3] + "..."
            
            # Format modified date
            modified_ts = file.get('modified', 0)
            if modified_ts:
                modified = datetime.fromtimestamp(modified_ts).strftime('%Y-%m-%d %H:%M')
            else:
                modified = 'Unknown'
            
            # Format file type
            file_type = file.get('extension', '').lstrip('.') or 'file'
            if len(file_type) > col_widths['type']:
                file_type = file_type[:col_widths['type']-3] + "..."
            
            # Format size
            size_bytes = file.get('size', 0)
            if size_bytes < 1024:
                size = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size = f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                size = f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                size = f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"
            
            # Format permissions count
            perms = file.get('permissions_summary', [])
            perm_str = f"{len(perms)} users"
            
            # Build row
            row = (
                f"{num:<{col_widths['num']}} "
                f"{url:<{col_widths['url']}} "
                f"{modified:<{col_widths['modified']}} "
                f"{file_type:<{col_widths['type']}} "
                f"{size:>{col_widths['size']}} "
                f"{perm_str:<{col_widths['perms']}}"
            )
            rows.append(row)
        
        # Calculate totals for footer
        file_count = 0
        folder_count = 0
        total_size = 0
        
        for file in sorted_files:
            if file.get('is_dir', False):
                folder_count += 1
            else:
                file_count += 1
                total_size += file.get('size', 0)
        
        # Format total size
        if total_size < 1024:
            size_str = f"{total_size} B"
        elif total_size < 1024 * 1024:
            size_str = f"{total_size / 1024:.1f} KB"
        elif total_size < 1024 * 1024 * 1024:
            size_str = f"{total_size / (1024 * 1024):.1f} MB"
        else:
            size_str = f"{total_size / (1024 * 1024 * 1024):.1f} GB"
        
        # Build output
        output = [
            page_info,
            separator,
            header,
            separator
        ]
        output.extend(rows)
        output.append(separator)
        output.append(f"{file_count} files, {folder_count} folders • Total size: {size_str}")
        if total_files > len(display_files):
            output.append(f"Use FilteredFiles in Jupyter for interactive view of all {total_files} results")
        
        return "\n".join(output)


# Create singleton instance
files = Files()


def is_dark():
    """
    Check if Jupyter Notebook/Lab is running in dark mode.
    
    Returns:
        bool: True if dark mode is detected, False otherwise
    """
    try:
        import os
        import json
        from pathlib import Path
        import re
        import builtins
        
        # First, try to read JupyterLab theme settings file
        jupyter_config_paths = [
            Path.home() / ".jupyter" / "lab" / "user-settings" / "@jupyterlab" / "apputils-extension" / "themes.jupyterlab-settings",
            Path.home() / ".jupyter" / "lab" / "user-settings" / "@jupyterlab" / "apputils-extension" / "themes.jupyterlab-settings.json",
        ]
        
        for config_path in jupyter_config_paths:
            if config_path.exists():
                try:
                    with builtins.open(config_path, 'r') as f:
                        content = f.read()
                        # Remove comments from the JSON (JupyterLab allows comments)
                        # Remove single-line comments
                        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
                        # Remove multi-line comments
                        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
                        
                        settings = json.loads(content)
                        theme = settings.get('theme', '').lower()
                        # Check if it's a dark theme
                        if 'dark' in theme:
                            return True
                        # If theme is explicitly set to light, return False
                        if 'light' in theme:
                            return False
                except Exception:
                    pass
        
        # Check VS Code settings
        if 'VSCODE_PID' in os.environ:
            # VS Code Jupyter might have its own theme
            # Check workspace settings
            vscode_settings_paths = [
                Path.cwd() / ".vscode" / "settings.json",
                Path.home() / ".config" / "Code" / "User" / "settings.json",
                Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json",  # macOS
            ]
            
            for settings_path in vscode_settings_paths:
                if settings_path.exists():
                    try:
                        with builtins.open(settings_path, 'r') as f:
                            settings = json.load(f)
                            # Check workbench color theme
                            theme = settings.get('workbench.colorTheme', '').lower()
                            if 'dark' in theme:
                                return True
                    except Exception:
                        pass
        
        # Try JavaScript detection as fallback
        try:
            from IPython import get_ipython
            ipython = get_ipython()
            
            if ipython is not None:
                # Execute JavaScript to check theme
                result = ipython.run_cell_magic('javascript', '', '''
                if (typeof IPython !== 'undefined' && IPython.notebook) {
                    IPython.notebook.kernel.execute("_is_dark_mode = " + 
                        (document.body.classList.contains('theme-dark') || 
                         (document.body.getAttribute('data-jp-theme-name') && 
                          document.body.getAttribute('data-jp-theme-name').includes('dark'))));
                }
                ''')
                
                # Check if we got a result
                import sys
                if hasattr(sys.modules['__main__'], '_is_dark_mode'):
                    is_dark = sys.modules['__main__']._is_dark_mode
                    delattr(sys.modules['__main__'], '_is_dark_mode')
                    return is_dark
        except Exception:
            pass
            
        # Default to False (light mode) if we can't detect
        return False
        
    except Exception:
        # If any error occurs, assume light mode
        return False


# Server will auto-start when _repr_html_ is called in Jupyter notebooks
