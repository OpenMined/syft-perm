"""Unified widget infrastructure for syft-perm."""

from .base import UnifiedWidget
from .html_generator import HTMLGenerator
from .port_registry import PortRegistry
from .server_manager import ServerManager, ServerState
from .transitions import TransitionRenderer

__all__ = [
    "UnifiedWidget",
    "ServerManager",
    "ServerState",
    "TransitionRenderer",
    "PortRegistry",
    "HTMLGenerator",
]

# Package version
__version__ = "0.1.0"
