"""Base widget class with unified server detection and HTML generation."""

import json
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

from .server_manager import ServerManager, ServerState
from .transitions import TransitionRenderer


class UnifiedWidget(ABC):
    """
    Base class for all syft-perm widgets with unified server handling.

    Provides:
    - Parallel server detection and startup
    - Smooth transitions from static to interactive
    - Consistent HTML generation across all widgets
    - Port discovery and coordination
    """

    def __init__(self, widget_name: str):
        """
        Initialize the widget.

        Args:
            widget_name: Name of the widget (e.g., 'files', 'editor', 'share')
        """
        self.widget_name = widget_name
        self.server_manager = ServerManager()
        self.transition_renderer = TransitionRenderer()
        self._widget_id = f"{widget_name}_{int(time.time() * 1000)}"

    @abstractmethod
    def get_static_html(self, **kwargs) -> str:
        """
        Generate static HTML for the widget.

        This should return a fully functional read-only version
        of the widget that works without any server.

        Returns:
            HTML string for static display
        """
        pass

    @abstractmethod
    def get_interactive_html(self, server_url: str, **kwargs) -> str:
        """
        Generate interactive HTML that connects to the server.

        Args:
            server_url: URL of the running server
            **kwargs: Widget-specific parameters

        Returns:
            HTML string for interactive display
        """
        pass

    @abstractmethod
    def get_server_endpoint(self) -> str:
        """
        Get the server endpoint path for this widget.

        Returns:
            Endpoint path (e.g., '/files/widget', '/editor', '/share-modal')
        """
        pass

    def _repr_html_(self) -> str:
        """
        Main entry point for Jupyter display.

        This method orchestrates the entire widget lifecycle:
        1. Quick server check
        2. Immediate static display
        3. Background server startup
        4. Progressive enhancement
        """
        # Check server state
        state, server_url = self.server_manager.get_server_state()

        # Generate appropriate HTML based on state
        if state == ServerState.RUNNING and server_url:
            # Server is running - show interactive immediately
            return self.get_interactive_html(server_url)

        elif state == ServerState.STARTING:
            # Server is starting - show static with transition
            static_html = self.get_static_html()
            transition_html = self.transition_renderer.render_transition(
                widget_id=self._widget_id,
                static_content=static_html,
                transition_style="fade",
                server_check_interval=500,
                max_wait_time=30000,
            )

            # Start monitoring for server availability
            self._start_server_monitor()

            return transition_html

        else:
            # Server not available - show static and start servers
            static_html = self.get_static_html()

            # Add installation prompt if SyftBox app not installed
            if not self.server_manager.is_syftbox_installed():
                static_html = self._add_installation_prompt(static_html)

            # Render with transition capability
            transition_html = self.transition_renderer.render_transition(
                widget_id=self._widget_id,
                static_content=static_html,
                transition_style="morph",
                server_check_interval=1000,
                max_wait_time=60000,
            )

            # Start servers in background
            self.server_manager.start_all_servers()

            return transition_html

    def _add_installation_prompt(self, html: str) -> str:
        """Add SyftBox installation prompt to HTML."""
        prompt = """
        <div style="
            background: #FEF3C7;
            border: 1px solid #F59E0B;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 16px;
            font-size: 14px;
            color: #92400E;
        ">
            <strong>🚀 Enhanced Features Available!</strong><br>
            Install the SyftBox app for persistent server and better performance:<br>
            <code style="background: #FDE68A; padding: 2px 4px; border-radius: 3px;">
                syftbox app install src/syft_perm
            </code>
        </div>
        """
        return prompt + html

    def _start_server_monitor(self):
        """Start monitoring for server availability in background."""
        # This would use WebSockets or polling to detect when server comes online
        # For now, the JavaScript in transition_renderer handles this
        pass

    def get_widget_config(self) -> Dict:
        """
        Get configuration for this widget.

        Returns:
            Dictionary with widget configuration
        """
        return {
            "name": self.widget_name,
            "endpoint": self.get_server_endpoint(),
            "supports_static": True,
            "supports_interactive": True,
            "transition_style": "fade",
            "server_timeout": 30000,
        }

    def render_with_options(
        self,
        mode: str = "auto",
        force_static: bool = False,
        transition_style: str = "fade",
        custom_css: Optional[str] = None,
    ) -> str:
        """
        Render widget with custom options.

        Args:
            mode: Rendering mode ('auto', 'static', 'interactive')
            force_static: Force static rendering even if server available
            transition_style: Style for transitions ('fade', 'slide', 'morph')
            custom_css: Additional CSS to inject

        Returns:
            HTML string
        """
        if mode == "static" or force_static:
            return self.get_static_html()

        elif mode == "interactive":
            state, server_url = self.server_manager.get_server_state()
            if state == ServerState.RUNNING and server_url:
                return self.get_interactive_html(server_url)
            else:
                raise RuntimeError("Server not available for interactive mode")

        else:
            # Auto mode - use default behavior
            return self._repr_html_()
