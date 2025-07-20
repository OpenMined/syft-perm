"""Files widget for browsing and managing files with permissions."""

from .routes import register_routes
from .widget import get_files_widget_html

__all__ = ["get_files_widget_html", "register_routes"]
