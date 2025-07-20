"""File editor widget using unified infrastructure."""

from pathlib import Path
from typing import Optional, Union

from ..base import UnifiedWidget
from ..html_generator import HTMLGenerator


class FileEditorWidgetUnified(UnifiedWidget):
    """File editor widget with unified server handling."""

    def __init__(self, file_path: Union[str, Path]):
        """Initialize the file editor widget."""
        super().__init__("editor")
        self.file_path = Path(file_path) if isinstance(file_path, str) else file_path

        # Check for dark mode
        try:
            from ... import is_dark

            dark_mode = is_dark()
        except Exception:
            dark_mode = False

        self.html_generator = HTMLGenerator(dark_mode=dark_mode)

        # Try to read file content for static display
        self.file_content = self._read_file_safely()
        self.file_metadata = self._get_file_metadata()

    def get_static_html(self, **kwargs) -> str:
        """Generate static HTML for file display."""
        # Create header with file info
        header = f"""
        <div style="
            background: {self.html_generator.theme['header_bg']};
            padding: 12px 16px;
            border-bottom: 1px solid {self.html_generator.theme['border']};
            margin-bottom: 16px;
            border-radius: 8px 8px 0 0;
        ">
            <h3 style="margin: 0; font-size: 16px; font-weight: 600;">
                📄 {self.file_path.name}
            </h3>
            <div style="margin-top: 4px; font-size: 12px; color: {self.html_generator.theme['muted']};">
                {self.file_path.parent} • {self._format_size(self.file_metadata.get('size', 0))} • 
                {self.file_metadata.get('extension', 'file')}
            </div>
        </div>
        """

        # Create content area
        if self.file_content is not None:
            # Show file content in a code block
            content = f"""
            <pre style="
                background: {self.html_generator.theme['card_bg']};
                padding: 16px;
                border-radius: 6px;
                overflow-x: auto;
                font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
                font-size: 13px;
                line-height: 1.5;
                margin: 0;
                max-height: 400px;
                overflow-y: auto;
            "><code>{self._escape_html(self.file_content[:5000])}</code></pre>
            """

            if len(self.file_content) > 5000:
                content += self.html_generator.render_notification(
                    "File truncated for display. Full content available in interactive mode.",
                    type="warning",
                )
        else:
            content = self.html_generator.render_notification(
                "File content not available. Interactive mode required for editing.", type="info"
            )

        # Add action buttons (disabled in static mode)
        actions = f"""
        <div style="margin-top: 16px; display: flex; gap: 8px;">
            {self.html_generator.render_button(
                "Edit",
                variant="primary",
                interactive_only=True,
                icon="✏️"
            )}
            {self.html_generator.render_button(
                "Save",
                variant="success",
                interactive_only=True,
                icon="💾"
            )}
            {self.html_generator.render_button(
                "Download",
                variant="secondary",
                interactive_only=True,
                icon="⬇️"
            )}
        </div>
        """

        # Add syntax highlighting hint
        syntax_hint = ""
        if self.file_metadata.get("extension") in [".py", ".js", ".json", ".yaml", ".yml", ".md"]:
            syntax_hint = self.html_generator.render_notification(
                "Syntax highlighting and advanced editing features available in interactive mode.",
                type="info",
                dismissible=True,
            )

        # Combine all elements
        return f"""
        <div class="syft-widget syft-file-editor-widget" style="
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: {self.html_generator.theme['bg']};
            color: {self.html_generator.theme['fg']};
            border: 1px solid {self.html_generator.theme['border']};
            border-radius: 8px;
            overflow: hidden;
        ">
            {header}
            <div style="padding: 16px;">
                {syntax_hint}
                {content}
                {actions}
            </div>
        </div>
        """

    def get_interactive_html(self, server_url: str, **kwargs) -> str:
        """Generate interactive HTML that connects to server."""
        import urllib.parse

        # Encode file path for URL
        encoded_path = urllib.parse.quote(str(self.file_path))
        endpoint_url = f"{server_url}/editor?path={encoded_path}"

        # Return iframe with editor
        border_color = self.html_generator.theme["border"]
        return f"""
        <div style="width: 100%; height: 600px; border: 1px solid {border_color}; border-radius: 12px; overflow: hidden;">
            <iframe src="{endpoint_url}" style="width: 100%; height: 100%; border: none;"></iframe>
        </div>
        """

    def get_server_endpoint(self) -> str:
        """Get the server endpoint for this widget."""
        return "/editor"

    def _read_file_safely(self) -> Optional[str]:
        """Safely read file content for static display."""
        try:
            if self.file_path.exists() and self.file_path.is_file():
                # Only read text files up to 1MB for static display
                if self.file_path.stat().st_size <= 1024 * 1024:
                    try:
                        return self.file_path.read_text(encoding="utf-8")
                    except UnicodeDecodeError:
                        # Try with different encoding
                        try:
                            return self.file_path.read_text(encoding="latin-1")
                        except Exception:
                            return None
            return None
        except Exception:
            return None

    def _get_file_metadata(self) -> dict:
        """Get file metadata."""
        try:
            if self.file_path.exists():
                stat = self.file_path.stat()
                return {
                    "size": stat.st_size,
                    "extension": self.file_path.suffix or "file",
                    "modified": stat.st_mtime,
                    "is_readable": self.file_path.is_file(),
                }
        except Exception:
            pass

        return {
            "size": 0,
            "extension": self.file_path.suffix or "file",
            "modified": 0,
            "is_readable": False,
        }

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

    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters."""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
