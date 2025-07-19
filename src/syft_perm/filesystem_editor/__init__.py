"""Filesystem editor module for syft-perm."""

# Import main components for backward compatibility
from .manager import FileSystemManager
from .templates.editor import generate_editor_html
from .templates.share_modal import generate_share_modal_html
from .utils import get_current_user_email

__all__ = [
    "FileSystemManager",
    "get_current_user_email",
    "generate_editor_html",
    "generate_share_modal_html",
]
