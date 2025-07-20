"""Share widget for managing file permissions through a modal interface."""

from .modal import generate_share_modal_html
from .permission_editor import get_editor_html
from .routes import register_routes

__all__ = ["generate_share_modal_html", "get_editor_html", "register_routes"]
