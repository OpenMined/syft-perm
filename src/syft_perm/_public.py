"""Public API for syft_perm, intended for user-facing interactions."""

import json
from pathlib import Path as _Path
from typing import Union as _Union

__all__ = ["files", "is_dark", "FastAPIFiles", "Files", "FilteredFiles"]


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

    def _check_server(self) -> _Union[str, None]:
        """Check if syft-perm server is available. Returns server URL or None."""
        try:
            import urllib.request
            from pathlib import Path

            # First check config file for port
            config_path = Path.home() / ".syftperm" / "config.json"
            ports_to_check = []

            if config_path.exists():
                try:
                    with open(config_path, "r") as f:
                        config = json.load(f)
                        port = config.get("port")
                        if port:
                            ports_to_check.append(port)
                except Exception:
                    pass

            # Try each port with 20 second timeout
            for port in ports_to_check:
                try:
                    url = f"http://localhost:{port}"
                    with urllib.request.urlopen(url, timeout=20) as response:
                        if response.status == 200:
                            content = response.read().decode("utf-8")
                            if "SyftPerm" in content:
                                return url
                except Exception:
                    continue

        except Exception:
            pass

        return None

    def _scan_files(
        self,
        search: _Union[str, None] = None,
        progress_callback=None,
        show_ascii_progress=False,
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
        user_email = os.environ.get("SYFTBOX_USER_EMAIL")

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
                    all_paths.add(root_path / file_name)

            processed_datasites += 1
            if show_ascii_progress:
                update_ascii_progress(processed_datasites, total_datasites, "Scan complete.")

        if show_ascii_progress:
            sys.stdout.write("\n")  # Newline after progress bar

        # Process all collected paths
        for path in all_paths:
            try:
                if search and search.lower() not in str(path).lower():
                    continue

                from ._impl import SyftFolder

                if path.is_dir():
                    folder = SyftFolder(path)
                    perms = folder.permissions
                else:
                    from ._impl import SyftFile

                    file = SyftFile(path)
                    perms = file.permissions

                if not perms:
                    continue

                # Get datasite owner
                datasite_owner = "unknown"
                try:
                    parts = path.parts
                    datasites_index = parts.index("datasites")
                    datasite_owner = parts[datasites_index + 1]
                except ValueError:
                    pass

                # Check if current user has any access
                has_access = False
                if user_email:
                    if perms.has_access(user_email):
                        has_access = True
                else:
                    # If user email is unknown, assume access if public
                    if perms.is_public:
                        has_access = True

                files.append(
                    {
                        "name": str(path.relative_to(datasites_path)),
                        "path": str(path),
                        "is_dir": path.is_dir(),
                        "size": path.stat().st_size if path.exists() and not path.is_dir() else 0,
                        "modified": path.stat().st_mtime if path.exists() else 0,
                        "extension": path.suffix.lower(),
                        "permissions": perms.to_dict(),
                        "permissions_summary": perms.summary(),
                        "datasite_owner": datasite_owner,
                        "has_access": has_access,
                    }
                )
            except Exception:
                continue

        return files

    def get(self, limit: int = 50, offset: int = 0, search: _Union[str, None] = None) -> dict:
        """
        Get a paginated list of files.

        Args:
            limit: Max number of files to return
            offset: Starting offset
            search: Optional search filter

        Returns:
            Dictionary with files and total count
        """
        if self._cache is None:
            self._cache = self._scan_files(search=search)

        files_to_return = self._cache[offset : offset + limit]

        return {"files": files_to_return, "total": len(self._cache)}

    def all(self, search: _Union[str, None] = None) -> list:
        """Get all files, bypassing pagination."""
        if self._cache is None or search:
            self._cache = self._scan_files(search=search, show_ascii_progress=True)
        return self._cache

    def search(
        self,
        files: _Union[str, None] = None,
        admin: _Union[str, None] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> "Files":
        if self._cache is None:
            self._cache = self._scan_files()

        filtered = self._apply_filters(self._cache, files_query=files, admin=admin)

        return FilteredFiles(filtered, limit=limit, offset=offset)

    def filter(self, folders: _Union[list, str, None] = None) -> "Files":
        if self._cache is None:
            self._cache = self._scan_files()

        if isinstance(folders, str):
            folders = [folders]

        filtered = self._apply_folder_filter(self._cache, folders=folders)

        return FilteredFiles(filtered)

    def _apply_filters(
        self, files: list, files_query: _Union[str, None] = None, admin: _Union[str, None] = None
    ) -> list:
        """Apply combined filters for file name and admin user."""
        if files_query is None and admin is None:
            return files

        search_terms = self._parse_search_terms(files_query) if files_query else []

        # Filter logic
        filtered_files = []
        for file in files:
            matches_files = not search_terms or self._matches_search_terms(file, search_terms)
            matches_admin = not admin or admin.lower() in [
                u.lower() for u in file.get("permissions", {}).get("admin", [])
            ]

            if matches_files and matches_admin:
                filtered_files.append(file)

        return filtered_files

    def _apply_folder_filter(self, files: list, folders: _Union[list, None] = None) -> list:
        """Apply filter for folders."""
        if not folders:
            return files

        # Normalize folder paths
        normalized_folders = [f.strip().lower().replace("/", "") for f in folders]

        filtered_list = []
        for file in files:
            # Check if file path starts with any of the specified folders
            file_path = file["name"].lower()
            if any(file_path.startswith(folder) for folder in normalized_folders):
                filtered_list.append(file)

        return filtered_list

    def _parse_search_terms(self, search: str) -> list:
        """Parse search string into terms, handling quotes and keywords."""
        import shlex

        try:
            # Use shlex to handle quoted terms correctly
            return shlex.split(search)
        except Exception:
            return search.split()

    def _matches_search_terms(self, file: dict, search_terms: list) -> bool:
        """Check if a file matches all search terms."""
        file_path = file.get("name", "").lower()
        file_path_parts = set(file_path.split("/"))

        for term in search_terms:
            term_lower = term.lower()
            is_negative = term_lower.startswith("-")
            search_term = term_lower[1:] if is_negative else term_lower

            # Check for keyword searches like 'admin:email'
            if ":" in search_term:
                key, value = search_term.split(":", 1)
                if key == "admin":
                    admins = {u.lower() for u in file.get("permissions", {}).get("admin", [])}
                    match = value in admins
                else:
                    match = search_term in file_path
            else:
                match = any(search_term in part for part in file_path_parts)

            if is_negative and match:
                return False
            if not is_negative and not match:
                return False

        return True

    def __getitem__(self, key) -> "Files":
        if isinstance(key, slice):
            start = key.start or 0
            stop = key.stop or 50  # Default to 50 items if not specified
            limit = stop - start
            return self.search(limit=limit, offset=start)
        else:
            raise TypeError("Files slicing only supports slicing, not direct indexing.")

    def page(self, page_number: int = 2, items_per_page: int = 50) -> "Files":
        if page_number < 1:
            raise ValueError("Page number must be 1 or greater.")

        offset = (page_number - 1) * items_per_page
        return self.search(limit=items_per_page, offset=offset)

    def _repr_pretty_(self, p, cycle):
        if cycle:
            p.text("<Files ...>")
        else:
            # Defer to the HTML representation for rich display in notebooks
            p.text(self._repr_html_())

    def __repr__(self) -> str:
        """Generate ASCII table representation of files."""
        from datetime import datetime

        if self._cache is None:
            self._cache = self._scan_files(show_ascii_progress=True)

        if not self._cache:
            return "No permissioned files found."

        # Sort by modified date (newest first)
        sorted_files = sorted(self._cache, key=lambda x: x.get("modified", 0), reverse=True)

        # Create chronological index (oldest first)
        chronological_ids = {}
        for i, file in enumerate(sorted(sorted_files, key=lambda x: x.get("modified", 0))):
            file_key = f"{file['name']}|{file['path']}"
            chronological_ids[file_key] = i + 1

        # Calculate display range
        total_files = len(sorted_files)
        items_per_page = 50
        start_index = (self._initial_page - 1) * items_per_page
        end_index = min(start_index + items_per_page, total_files)
        display_files = sorted_files[start_index:end_index]

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
        for file in display_files:
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

        # Calculate totals
        file_count = 0
        folder_count = 0
        total_size = 0

        for file in self._cache:
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
            f"SyftBox Files (showing 1-{len(display_files)} of {total_files} files)",
            separator,
            header,
            separator,
        ]
        output.extend(rows)
        output.append(separator)
        output.append(f"{file_count} files, {folder_count} folders • Total size: {size_str}")
        if total_files > len(display_files):
            output.append("Use sp.files.page(2) for more or sp.files.all() to see all files")

        return "\n".join(output)

    def _repr_html_(self) -> str:
        """Generate HTML widget for Jupyter notebooks."""
        import html as html_module
        import json
        import time
        import uuid
        from datetime import datetime
        from pathlib import Path

        from IPython.display import HTML, clear_output, display

        container_id = f"syft_files_{uuid.uuid4().hex[:8]}"

        # Check if Jupyter is in dark mode
        is_dark_mode = is_dark()

        # Check for syft-perm server for live updates
        syft_perm_url = self._check_server()

        # HTML template
        html = f"""
        <!-- HTML and CSS for the widget -->
        """

        # JavaScript for interactivity
        js = f"""
        <script>
            // JS code for the widget
        </script>
        """

        # Initial display with loading state
        initial_html = f"""
        <div id="{container_id}">
            <p>Loading files...</p>
        </div>
        <script>
            // JS to load data
        </script>
        """
        display(HTML(initial_html))

        # Asynchronously fetch and render files
        def fetch_and_render():
            try:
                files_data = self.get()
                files = files_data["files"]
                total = files_data["total"]

                # Create chronological index
                sorted_by_date = sorted(files, key=lambda x: x.get("modified", 0))
                chronological_ids = {
                    f"{f['name']}|{f['path']}": i for i, f in enumerate(sorted_by_date)
                }

                # Build full HTML with data
                full_html = "..."  # Full HTML content here

                # Update the display
                clear_output(wait=True)
                display(HTML(full_html))

            except Exception as e:
                # Fallback to ASCII representation on error
                clear_output(wait=True)
                display(self.__repr__())

        # Run rendering in a separate thread to avoid blocking
        import threading

        thread = threading.Thread(target=fetch_and_render)
        thread.start()

        return ""


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

    def _scan_files(
        self, search: _Union[str, None] = None, progress_callback=None, show_ascii_progress=False
    ) -> list:
        """Return the pre-filtered files instead of scanning."""
        return self._filtered_files

    def __repr__(self) -> str:
        """Simple string representation for FilteredFiles."""
        return f"<FilteredFiles: {len(self._filtered_files)} files>"


class FastAPIFiles(Files):
    """
    Files implementation that fetches data from a FastAPI server.
    """

    def __init__(self, server_url: str = "http://localhost:8005"):
        super().__init__()
        self.server_url = server_url
        self._search_params = {}

    def search(
        self,
        files: _Union[str, None] = None,
        admin: _Union[str, None] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> "Files":
        """Set search parameters for FastAPI query."""
        # Fetch files from server with search parameters
        self._search_params = {
            "files_query": files,
            "admin_query": admin,
            "limit": limit,
            "offset": offset,
        }
        # Get filtered files from the server
        filtered = self._scan_files()
        # Return a FilteredFiles instance to match the base class behavior
        return FilteredFiles(filtered, limit=limit, offset=offset)

    def _scan_files(
        self, search: _Union[str, None] = None, progress_callback=None, show_ascii_progress=False
    ) -> list:
        """Fetch files from the FastAPI server."""
        import requests

        try:
            params = self._search_params or {}
            if search:
                params["files_query"] = search

            response = requests.get(f"{self.server_url}/files/", params=params)
            response.raise_for_status()
            data = response.json()
            return data.get("files", [])
        except requests.RequestException:
            return []

    def _repr_html_(self) -> str:
        """Fetch and render HTML from the FastAPI server."""
        import requests

        try:
            params = self._search_params or {}
            response = requests.get(f"{self.server_url}/files/widget", params=params)
            response.raise_for_status()
            return response.text
        except requests.RequestException:
            return "<p>Error connecting to SyftPerm server.</p>"


def is_dark():
    """
    Check if Jupyter Notebook/Lab is running in dark mode.

    Returns:
        bool: True if dark mode is detected, False otherwise
    """
    try:
        import builtins
        import json
        import os
        import re
        from pathlib import Path

        # First, try to read JupyterLab theme settings file
        jupyter_config_paths = [
            Path.home()
            / ".jupyter"
            / "lab"
            / "user-settings"
            / "@jupyterlab"
            / "apputils-extension"
            / "themes.jupyterlab-settings",
            Path.home()
            / ".jupyter"
            / "lab"
            / "user-settings"
            / "@jupyterlab"
            / "apputils-extension"
            / "themes.jupyterlab-settings.json",
        ]

        for config_path in jupyter_config_paths:
            if config_path.exists():
                try:
                    with builtins.open(config_path, "r") as f:
                        content = f.read()
                        # Remove comments from the JSON (JupyterLab allows comments)
                        # Remove single-line comments
                        content = re.sub(r"//.*$", "", content, flags=re.MULTILINE)
                        # Remove multi-line comments
                        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)

                        settings = json.loads(content)
                        theme = settings.get("theme", "").lower()
                        # Check if it's a dark theme
                        if "dark" in theme:
                            return True
                        # If theme is explicitly set to light, return False
                        if "light" in theme:
                            return False
                except Exception:
                    pass

        # Check VS Code settings
        if "VSCODE_PID" in os.environ:
            # VS Code Jupyter might have its own theme
            # Check workspace settings
            vscode_settings_paths = [
                Path.cwd() / ".vscode" / "settings.json",
                Path.home() / ".config" / "Code" / "User" / "settings.json",
                Path.home()
                / "Library"
                / "Application Support"
                / "Code"
                / "User"
                / "settings.json",  # macOS
            ]

            for settings_path in vscode_settings_paths:
                if settings_path.exists():
                    try:
                        with builtins.open(settings_path, "r") as f:
                            settings = json.load(f)
                            # Check workbench color theme
                            theme = settings.get("workbench.colorTheme", "").lower()
                            if "dark" in theme:
                                return True
                    except Exception:
                        pass

        # Try JavaScript detection as fallback
        try:
            from IPython import get_ipython

            ipython = get_ipython()

            if ipython is not None:
                # Execute JavaScript to check theme
                result = ipython.run_cell_magic(
                    "javascript",
                    "",
                    """
                if (typeof IPython !== 'undefined' && IPython.notebook) {
                    IPython.notebook.kernel.execute("_is_dark_mode = " + 
                        (document.body.classList.contains('theme-dark') || 
                         (document.body.getAttribute('data-jp-theme-name') && 
                          document.body.getAttribute('data-jp-theme-name').includes('dark'))));
                }
                """,
                )

                # Check if we got a result
                import sys

                if hasattr(sys.modules["__main__"], "_is_dark_mode"):
                    is_dark = sys.modules["__main__"]._is_dark_mode
                    delattr(sys.modules["__main__"], "_is_dark_mode")
                    return is_dark
        except Exception:
            pass

        # Default to False (light mode) if we can't detect
        return False

    except Exception:
        # If any error occurs, assume light mode
        return False


# Create a single instance of Files for easy access
files = Files()
