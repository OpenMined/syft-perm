"""Files widget using unified infrastructure."""

from datetime import datetime
from typing import Dict, List, Optional

from ..base import UnifiedWidget
from ..html_generator import HTMLGenerator


class FilesWidgetUnified(UnifiedWidget):
    """Files widget with unified server handling."""

    def __init__(
        self,
        files_data: Optional[List[Dict]] = None,
        initial_page: int = 1,
        items_per_page: int = 50,
    ):
        """Initialize the files widget."""
        super().__init__("files")
        self.files_data = files_data or []
        self.initial_page = initial_page
        self.items_per_page = items_per_page

        # Check for dark mode
        try:
            from ... import is_dark

            dark_mode = is_dark()
        except Exception:
            dark_mode = False

        self.html_generator = HTMLGenerator(dark_mode=dark_mode)

    def get_static_html(self, **kwargs) -> str:
        """Generate static HTML for files display."""
        # Calculate pagination
        total_files = len(self.files_data)
        start_idx = (self.initial_page - 1) * self.items_per_page
        end_idx = min(start_idx + self.items_per_page, total_files)
        display_files = self.files_data[start_idx:end_idx]

        # Create table headers
        headers = ["#", "URL", "Modified", "Type", "Size", "Permissions"]

        # Build rows
        rows = []
        for i, file in enumerate(display_files):
            # Format data
            num = start_idx + i + 1
            url = file.get("name", "Unknown")
            modified = self._format_date(file.get("modified", 0))
            file_type = file.get("extension", "").lstrip(".") or (
                "folder" if file.get("is_dir") else "file"
            )
            size = self._format_size(file.get("size", 0))
            perms = f"{len(file.get('permissions', {}))} users"

            rows.append([num, url, modified, file_type, size, perms])

        # Generate table
        table_html = self.html_generator.render_table(headers=headers, rows=rows, sortable=True)

        # Add search box (disabled in static mode)
        search_section = f"""
        <div style="margin-bottom: 16px; display: flex; gap: 8px;">
            {self.html_generator.render_input(
                type="text",
                name="search",
                placeholder="Search files...",
                interactive_only=True
            )}
            {self.html_generator.render_button(
                "Search",
                variant="primary",
                interactive_only=True,
                icon="🔍"
            )}
        </div>
        """

        # Add pagination info
        pagination_info = f"""
        <div style="margin-top: 16px; display: flex; justify-content: space-between; align-items: center;">
            <div style="color: {self.html_generator.theme['muted']}; font-size: 14px;">
                Showing {start_idx + 1}-{end_idx} of {total_files} files
            </div>
            <div style="display: flex; gap: 8px;">
                {self.html_generator.render_button(
                    "Previous",
                    variant="secondary",
                    disabled=self.initial_page <= 1,
                    interactive_only=True
                )}
                {self.html_generator.render_button(
                    "Next",
                    variant="secondary",
                    disabled=end_idx >= total_files,
                    interactive_only=True
                )}
            </div>
        </div>
        """

        # Add notification if server not available
        notification = ""
        if total_files > self.items_per_page:
            notification = self.html_generator.render_notification(
                f"Showing page {self.initial_page}. Interactive features like search and navigation require server.",
                type="info",
            )

        # Add static mode indicator
        indicator_bg = "rgba(30,30,30,0.8)" if self.html_generator.dark_mode else "rgba(255,255,255,0.8)"
        indicator_color = "#ccc" if self.html_generator.dark_mode else "#666"
        
        # Combine all elements
        return f"""
        <div class="syft-widget syft-files-widget" style="
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: {self.html_generator.theme['fg']};
            position: relative;
        ">
            <h2 style="margin-top: 0; margin-bottom: 16px;">SyftBox Files</h2>
            {notification}
            {search_section}
            {table_html}
            {pagination_info}
            <div style="position: absolute; bottom: 8px; left: 12px; background: {indicator_bg}; color: {indicator_color}; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; z-index: 1000;">
                unified-static
            </div>
        </div>
        """

    def get_interactive_html(self, server_url: str, **kwargs) -> str:
        """Generate interactive HTML that connects to server."""
        # Build query parameters
        params = []
        if self.initial_page > 1:
            offset = (self.initial_page - 1) * self.items_per_page
            params.append(f"offset={offset}")
        params.append(f"limit={self.items_per_page}")

        query_string = "&".join(params) if params else ""
        endpoint_url = f"{server_url}/files/widget"
        if query_string:
            endpoint_url += f"?{query_string}"

        # Determine server type
        server_type = "unified"  # This is the unified widget system
        try:
            import urllib.request
            import json
            with urllib.request.urlopen(f"{server_url}/server-info", timeout=1) as response:
                if response.status == 200:
                    info = json.loads(response.read().decode('utf-8'))
                    base_type = info.get('type', 'unknown')
                    server_type = f"unified-{base_type}"
        except Exception:
            pass

        # Return iframe with server content
        border_color = self.html_generator.theme["border"]
        indicator_bg = "rgba(30,30,30,0.8)" if self.html_generator.dark_mode else "rgba(255,255,255,0.8)"
        indicator_color = "#ccc" if self.html_generator.dark_mode else "#666"
        
        return f"""
        <div style="width: 100%; height: 600px; border: 1px solid {border_color}; border-radius: 12px; overflow: hidden; position: relative;">
            <iframe src="{endpoint_url}" style="width: 100%; height: 100%; border: none;"></iframe>
            <div style="position: absolute; bottom: 8px; left: 12px; background: {indicator_bg}; color: {indicator_color}; padding: 4px 8px; border-radius: 4px; font-size: 11px; font-family: monospace; pointer-events: none; z-index: 1000;">
                {server_type}
            </div>
        </div>
        """

    def get_server_endpoint(self) -> str:
        """Get the server endpoint for this widget."""
        return "/files/widget"

    def _format_size(self, size_bytes: int) -> str:
        """Format file size for display."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

    def _format_date(self, timestamp: float) -> str:
        """Format timestamp for display."""
        if timestamp:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")
        return "Unknown"
