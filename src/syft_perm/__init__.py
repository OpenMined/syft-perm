"""SyftPerm - File permission management for SyftBox."""

from pathlib import Path as _Path
from typing import Optional as _Optional
from typing import Union as _Union

from ._impl import SyftFile as _SyftFile
from ._impl import SyftFolder as _SyftFolder
from ._public import Files as _Files
from ._public import FilteredFiles as _FilteredFiles
from ._public import files
from ._public import folders
from ._public import files_and_folders
from ._public import is_dark as _is_dark
from .fastapi_files import FastAPIFiles as _FastAPIFiles

__version__ = "0.4.0"

__all__ = ["open", "files", "folders", "files_and_folders"]


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


def _get_editor_url(path: _Union[str, _Path]) -> str:
    """
    Get the URL for the Google Drive-style permission editor for a file/folder.

    Args:
        path: Path to the file/folder

    Returns:
        URL to the permission editor
    """
    from .server import get_editor_url as _get_editor_url_from_server

    return _get_editor_url_from_server(str(path))


def _get_files_widget_url() -> str:
    """
    Get the URL for the files widget interface (identical to sp.files in Jupyter).

    Returns:
        URL to the files widget
    """
    from .server import get_files_widget_url as _get_files_widget_url_from_server

    return _get_files_widget_url_from_server()


def _get_file_editor_url(path: _Union[str, _Path] = None) -> str:
    """
    Get the URL for the file editor interface.

    Args:
        path: Optional path to open in the editor

    Returns:
        URL to the file editor
    """
    from .server import get_file_editor_url as _get_file_editor_url_from_server

    if path:
        return _get_file_editor_url_from_server(str(path))
    return _get_file_editor_url_from_server()


class _Files:
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

    def _check_server(self) -> _Union[str, None]:
        """Check if syft-perm server is available. Returns server URL or None."""
        # Use a try-except block to gracefully handle non-IPython environments
        try:
            import urllib.request

            # First, try to read port from config file to avoid unnecessary scanning
            try:
                from .server import _get_configured_port

                port = _get_configured_port()
                if port:
                    url = f"http://localhost:{port}/"
                    with urllib.request.urlopen(url, timeout=0.1) as response:
                        if response.status == 200:
                            # Only read first 100 bytes to check for "SyftPerm"
                            content = response.read(100).decode("utf-8")
                            if "SyftPerm" in content:
                                return url
            except Exception:
                pass

            # If not found, fall back to scanning common ports
            for port in range(8000, 8101):
                url = f"http://localhost:{port}/"
                try:
                    with urllib.request.urlopen(url, timeout=0.02) as response:
                        if response.status == 200:
                            content = response.read(100).decode("utf-8")
                            if "SyftPerm" in content:
                                return url
                except Exception:
                    continue

        except Exception:
            # If any check fails, assume server is not running
            pass

        # At this point no reachable server was found – attempt to start one
        try:
            from .server import _SERVER_AVAILABLE
            from .server import get_server_url as _get_url
            from .server import start_server as _start_server

            if not _SERVER_AVAILABLE:
                # server dependencies (fastapi, uvicorn) not installed – abort
                return None

            # If another thread already spawned one, just return its url
            running = _get_url()
            if running:
                return running

            # Otherwise spin up a new background server (same helper used by SyftFile/SyftFolder)
            server_url = _start_server()
            return server_url
        except ImportError:
            # FastAPI stack not installed – ignore
            return None
        except Exception:
            # Any other failure – silently fall back to None so that Files can render static widget
            return None

    def _scan_files(
        self, search: _Union[str, None] = None, progress_callback=None, show_ascii_progress=False
    ) -> list:
        """Scan SyftBox directory for files with permissions."""
        import os
        import sys
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
                bar = "█" * filled_length + "░" * (bar_length - filled_length)
                sys.stdout.write(f"\r[{bar}] {percent:.0f}% - {status}")
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
                    permissions = syft_obj._permissions_dict.copy()

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
                        "_has_yaml": path.joinpath("syft.pub.yaml").exists(),
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
                _has_yaml = False
                permissions_summary = []
                try:
                    syft_obj = open(path)
                    permissions = syft_obj._permissions_dict.copy()

                    if hasattr(syft_obj, "_has_yaml"):
                        _has_yaml = syft_obj._has_yaml
                    elif any(users for users in permissions.values()):
                        _has_yaml = True

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
                    _has_yaml = False
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
                        "_has_yaml": _has_yaml,
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
            sys.stdout.write("\r" + " " * 80 + "\r")  # Clear the line
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

    def search(
        self,
        files: _Union[str, None] = None,
        admin: _Union[str, None] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> "_Files":
        """
        Search and filter files by query and admin.

        Args:
            files: Search term for file names (same as textbar search)
            admin: Filter by admin email
            limit: Number of items per page (default: 50)
            offset: Starting index (default: 0)

        Returns:
            New Files instance with filtered results or FastAPIFiles with iframe
        """
        # Check if server is available
        server_url = self._check_server()
        if server_url:
            # Server is available, return FastAPIFiles instance that will show iframe
            try:
                # Server is available, return FastAPIFiles for iframe display
                # Don't test the API endpoint as it may be slow
                api_files = _FastAPIFiles(server_url)
                return api_files.search(files=files, admin=admin, limit=limit, offset=offset)
            except Exception:
                # If server fails, fall back to local
                pass

        # Fall back to local scanning
        all_files = self._scan_files()

        # Apply filters
        filtered_files = self._apply_filters(all_files, files_query=files, admin=admin)

        # Sort by modified date (newest first)
        filtered_files.sort(key=lambda x: x.get("modified", 0), reverse=True)

        # Create new Files instance with filtered data
        result = _FilteredFiles(filtered_files, limit=limit, offset=offset)
        return result

    def filter(self, folders: _Union[list, str, None] = None) -> "_Files":
        """
        Filter files by folder paths.

        Args:
            folders: List of file or folder paths to include, or a single string

        Returns:
            New Files instance with filtered results or FastAPIFiles with iframe
        """
        # Check if server is available
        server_url = self._check_server()
        if server_url:
            # Server is available, return FastAPIFiles instance that will show iframe
            try:
                # Server is available, return FastAPIFiles for iframe display
                api_files = _FastAPIFiles(server_url)
                return api_files.filter(folders=folders)
            except Exception:
                # If server fails, fall back to local
                pass

        # Fall back to local scanning
        all_files = self._scan_files()

        # Convert string to list if needed for local processing
        if isinstance(folders, str):
            folders = [folders]

        # Apply folder filter
        filtered_files = self._apply_folder_filter(all_files, folders=folders)

        # Create new Files instance with filtered data
        result = _FilteredFiles(filtered_files)
        return result

    def _apply_filters(
        self, files: list, files_query: _Union[str, None] = None, admin: _Union[str, None] = None
    ) -> list:
        """Apply search and admin filters to file list."""
        filtered = files.copy()

        # Apply files search filter (same as textbar search)
        if files_query:
            # Parse search terms to handle quoted phrases (same logic as in JS)
            search_terms = self._parse_search_terms(files_query)

            filtered = [file for file in filtered if self._matches_search_terms(file, search_terms)]

        # Apply admin filter
        if admin:
            filtered = [
                file for file in filtered if file.get("datasite_owner", "").lower() == admin.lower()
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
        current_term = ""
        in_quotes = False
        quote_char = ""

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
                    current_term = ""
                quote_char = ""
            elif char.isspace() and not in_quotes:
                # End of unquoted term
                if current_term.strip():
                    terms.append(current_term.strip())
                    current_term = ""
            else:
                current_term += char

        # Add final term
        if current_term.strip():
            terms.append(current_term.strip())

        return terms

    def _matches_search_terms(self, file: dict, search_terms: list) -> bool:
        """Check if file matches all search terms."""

        # Format date for search
        def format_date(timestamp):
            if not timestamp:
                return ""
            from datetime import datetime

            dt = datetime.fromtimestamp(timestamp)
            return dt.strftime("%m/%d/%Y %H:%M")

        # Format size for search
        def format_size(size):
            if not size:
                return "0 B"
            if size > 1024 * 1024:
                return f"{size / (1024 * 1024):.1f} MB"
            elif size > 1024:
                return f"{size / 1024:.1f} KB"
            else:
                return f"{size} B"

        # Create searchable content from all file properties (matching JavaScript implementation)
        searchable_parts = [
            file.get("name", ""),
            file.get("datasite_owner", ""),
            file.get("extension", ""),
            format_size(file.get("size", 0)),
            format_date(file.get("modified", 0)),
            "folder" if file.get("is_dir") else "file",
            " ".join(file.get("permissions_summary", [])),
        ]

        searchable_content = " ".join(searchable_parts).lower()

        # Check if all search terms match
        for term in search_terms:
            if term.lower() not in searchable_content:
                return False

        return True

    def __getitem__(self, key) -> "_Files":
        """Support slice notation sp.files[x:y] for range selection by chronological #."""
        if isinstance(key, slice):
            # Check if server is available
            server_url = self._check_server()
            if server_url:
                # Server is available, use it for slicing
                try:
                    # Convert slice to start/end parameters for server
                    start = key.start
                    end = key.stop

                    # Create FastAPIFiles and use server for slicing
                    _ = _FastAPIFiles(server_url)  # noqa: F841

                    # Build URL with start/end parameters
                    import urllib.parse

                    params = {}
                    if start is not None:
                        params["start"] = start
                    if end is not None:
                        params["end"] = end

                    url = f"{server_url}/files-widget"
                    if params:
                        url += "?" + urllib.parse.urlencode(params)

                    # Return FastAPIFiles instance for iframe display
                    result = _FastAPIFiles(server_url)
                    result._url = url
                    return result
                except Exception:
                    # If server fails, fall back to local
                    pass

            # Fall back to local processing
            all_files = self._scan_files()

            # Sort by modified date to get chronological order (newest first)
            sorted_files = sorted(all_files, key=lambda x: x.get("modified", 0), reverse=True)

            # Apply slice (convert to 0-based indexing since user expects 1-based)
            start = (key.start - 1) if key.start is not None and key.start > 0 else key.start
            stop = (key.stop - 1) if key.stop is not None and key.stop > 0 else key.stop

            sliced_files = sorted_files[slice(start, stop, key.step)]

            # Create new Files instance with sliced data
            result = _FilteredFiles(sliced_files)
            return result
        else:
            raise TypeError("Files indexing only supports slice notation, e.g., files[1:10]")

    def page(self, page_number: int = 2, items_per_page: int = 50) -> "_Files":
        """
        Return a Files instance that will display starting at a specific page.

        Args:
            page_number: The page number to jump to (1-based indexing, defaults to 2)
            items_per_page: Number of items per page (default: 50)

        Returns:
            Files instance with full table or FastAPIFiles with iframe
        """
        if page_number < 1:
            raise ValueError("Page number must be >= 1")

        # Check if server is available
        server_url = self._check_server()
        if server_url:
            # Server is available, return FastAPIFiles instance that will show iframe
            try:
                # Server is available, return FastAPIFiles for iframe display
                api_files = _FastAPIFiles(server_url)
                return api_files.page(page_number=page_number, items_per_page=items_per_page)
            except Exception:
                # If server fails, fall back to local
                pass

        # Fall back to local - create a new Files instance with the initial page set
        new_files = _Files()
        new_files._initial_page = page_number
        new_files._items_per_page = items_per_page
        return new_files

    def _repr_pretty_(self, p, cycle):
        """Called by IPython for pretty printing. We disable ASCII progress here."""
        if cycle:
            p.text("...")
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
        col_widths = {"num": 5, "url": 60, "modified": 16, "type": 8, "size": 10, "perms": 12}

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
            url = file["name"]
            if len(url) > col_widths["url"]:
                url = url[: col_widths["url"] - 3] + "..."

            # Format modified date
            modified_ts = file.get("modified", 0)
            if modified_ts:
                modified = datetime.fromtimestamp(modified_ts).strftime("%Y-%m-%d %H:%M")
            else:
                modified = "Unknown"

            # Format file type
            file_type = file.get("extension", "").lstrip(".") or "file"
            if len(file_type) > col_widths["type"]:
                file_type = file_type[: col_widths["type"] - 3] + "..."

            # Format size
            size_bytes = file.get("size", 0)
            if size_bytes < 1024:
                size = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size = f"{size_bytes / 1024:.1f} KB"
            elif size_bytes < 1024 * 1024 * 1024:
                size = f"{size_bytes / (1024 * 1024):.1f} MB"
            else:
                size = f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

            # Format permissions count
            perms = file.get("permissions_summary", [])
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
            if file.get("is_dir", False):
                folder_count += 1
            else:
                file_count += 1
                total_size += file.get("size", 0)

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
            (
                f"Files (Page {current_page} of {total_pages}, "
                f"showing {start+1}-{end} of {total_files} items)"
            ),
            separator,
            header,
            separator,
        ]
        output.extend(rows)
        output.append(separator)
        output.append(f"{file_count} files, {folder_count} folders • Total size: {size_str}")
        output.append(
            "Use sp.files.page(n) to view other pages or sp.files in Jupyter for interactive view"
        )

        return "\n".join(output)

    def _ensure_server_running(self) -> tuple[bool, _Optional[int]]:
        """Ensure the permission server is running and return (success, port)."""
        try:
            from ._auto_recovery import ensure_server_running
            from .server import get_server_url, start_server

            # Check if server is already running
            server_url = get_server_url()
            if server_url:
                # Verify it's actually responding
                success, error = ensure_server_running(server_url)
                if success:
                    # Extract port from URL
                    port = int(server_url.split(":")[-1].rstrip("/"))
                    return True, port

            # Server not running or not healthy, start it
            server_url = start_server()
            if server_url:
                # Extract port from URL
                port = int(server_url.split(":")[-1].rstrip("/"))
                return True, port

            return False, None
        except Exception:
            return False, None

    def _repr_html_(self) -> str:
        """Generate SyftObjects-style widget for Jupyter."""
        from .jupyter_widget import generate_jupyter_widget

        return generate_jupyter_widget(self)


# Create singleton instance
files = _Files()
