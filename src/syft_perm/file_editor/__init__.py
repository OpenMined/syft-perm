"""File editor widget for editing files with permission checks."""

from .editor import generate_editor_html
from .routes import register_routes

__all__ = ["generate_editor_html", "register_routes"]
