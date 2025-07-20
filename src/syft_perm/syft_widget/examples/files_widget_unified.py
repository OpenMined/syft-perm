"""Example of Files widget using unified infrastructure."""

from typing import Dict, List, Optional

from ..base import UnifiedWidget
from ..html_generator import HTMLGenerator


class FilesWidgetUnified(UnifiedWidget):
    """Files widget with unified server handling."""

    def __init__(self, files_data: Optional[List[Dict]] = None):
        """Initialize the files widget."""
        super().__init__("files")
        self.files_data = files_data or []
        self.html_generator = HTMLGenerator()

    def get_static_html(self, **kwargs) -> str:
        """Generate static HTML for files display."""
        # Create static table of files
        headers = ["Name", "Size", "Modified", "Permissions", "Actions"]

        rows = []
        for file in self.files_data[:10]:  # Show first 10 files
            rows.append(
                [
                    file.get("name", "Unknown"),
                    self._format_size(file.get("size", 0)),
                    self._format_date(file.get("modified", 0)),
                    f"{len(file.get('permissions', {}))} users",
                    {
                        "content": self.html_generator.render_button(
                            "Open",
                            onclick=None,
                            variant="secondary",
                            interactive_only=True,
                            icon="📂",
                        ),
                        "interactive": True,
                    },
                ]
            )

        table_html = self.html_generator.render_table(
            headers=headers, rows=rows, interactive_columns=[4], sortable=True  # Actions column
        )

        # Add search box (disabled in static mode)
        search_html = self.html_generator.render_input(
            type="text", name="search", placeholder="Search files...", interactive_only=True
        )

        # Add notification about limited functionality
        notification_html = self.html_generator.render_notification(
            "Showing first 10 files. Interactive features require server.", type="info"
        )

        # Combine all elements
        return f"""
        <div class="syft-widget syft-files-widget">
            <h2 style="margin-top: 0;">SyftBox Files</h2>
            {notification_html}
            <div style="margin-bottom: 16px;">
                {search_html}
            </div>
            {table_html}
        </div>
        """

    def get_interactive_html(self, server_url: str, **kwargs) -> str:
        """Generate interactive HTML that connects to server."""
        # In interactive mode, we'll load content from server
        return f"""
        <iframe src="{server_url}/files/widget" style="
            width: 100%;
            height: 600px;
            border: none;
            border-radius: 8px;
        "></iframe>
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
        from datetime import datetime

        if timestamp:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M")
        return "Unknown"


# Example usage in the existing Files class
def integrate_with_files_class():
    """
    Example of how to integrate with existing Files class.

    This would go in _public.py:
    """
    # In Files._repr_html_ method:
    """
    def _repr_html_(self) -> str:
        # Scan files if not cached
        if self._cache is None:
            self._cache = self._scan_files()
        
        # Use unified widget
        widget = FilesWidgetUnified(files_data=self._cache)
        return widget._repr_html_()
    """
