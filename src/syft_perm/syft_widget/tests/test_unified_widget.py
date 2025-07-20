"""Tests for unified widget infrastructure."""

import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ..base import UnifiedWidget
from ..html_generator import HTMLGenerator
from ..port_registry import PortRegistry
from ..server_manager import ServerManager, ServerState
from ..transitions import TransitionRenderer


class TestWidget(UnifiedWidget):
    """Test implementation of UnifiedWidget."""

    def __init__(self):
        super().__init__("test")

    def get_static_html(self, **kwargs):
        return "<div>Static content</div>"

    def get_interactive_html(self, server_url, **kwargs):
        return f"<iframe src='{server_url}/test'></iframe>"

    def get_server_endpoint(self):
        return "/test"


class TestUnifiedWidget(unittest.TestCase):
    """Test UnifiedWidget base class."""

    def setUp(self):
        """Set up test fixtures."""
        self.widget = TestWidget()

    def test_widget_initialization(self):
        """Test widget initializes correctly."""
        self.assertEqual(self.widget.widget_name, "test")
        self.assertIsInstance(self.widget.server_manager, ServerManager)
        self.assertIsInstance(self.widget.transition_renderer, TransitionRenderer)

    @patch.object(ServerManager, "get_server_state")
    def test_repr_html_with_running_server(self, mock_get_state):
        """Test HTML generation when server is running."""
        mock_get_state.return_value = (ServerState.RUNNING, "http://localhost:8005")

        html = self.widget._repr_html_()
        self.assertIn("iframe", html)
        self.assertIn("http://localhost:8005/test", html)

    @patch.object(ServerManager, "get_server_state")
    @patch.object(ServerManager, "start_all_servers")
    def test_repr_html_without_server(self, mock_start, mock_get_state):
        """Test HTML generation when server is not available."""
        mock_get_state.return_value = (ServerState.UNKNOWN, None)

        html = self.widget._repr_html_()
        self.assertIn("Static content", html)
        self.assertIn("syft-widget-container", html)
        mock_start.assert_called_once()

    def test_get_widget_config(self):
        """Test widget configuration."""
        config = self.widget.get_widget_config()
        self.assertEqual(config["name"], "test")
        self.assertEqual(config["endpoint"], "/test")
        self.assertTrue(config["supports_static"])
        self.assertTrue(config["supports_interactive"])


class TestServerManager(unittest.TestCase):
    """Test ServerManager functionality."""

    def setUp(self):
        """Set up test fixtures."""
        # Clear singleton instance
        ServerManager._instance = None
        self.manager = ServerManager()

    def test_singleton_pattern(self):
        """Test ServerManager is a singleton."""
        manager2 = ServerManager()
        self.assertIs(self.manager, manager2)

    @patch("urllib.request.urlopen")
    def test_check_server_success(self, mock_urlopen):
        """Test successful server check."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"SyftPerm Server"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        result = self.manager._check_server("http://localhost:8005")
        self.assertTrue(result)

    @patch("urllib.request.urlopen")
    def test_check_server_failure(self, mock_urlopen):
        """Test failed server check."""
        mock_urlopen.side_effect = Exception("Connection refused")

        result = self.manager._check_server("http://localhost:8005")
        self.assertFalse(result)

    def test_is_syftbox_installed(self):
        """Test SyftBox installation check."""
        with patch.object(Path, "exists") as mock_exists:
            mock_exists.return_value = True
            self.assertTrue(self.manager.is_syftbox_installed())

            mock_exists.return_value = False
            self.assertFalse(self.manager.is_syftbox_installed())


class TestPortRegistry(unittest.TestCase):
    """Test PortRegistry functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.registry = PortRegistry()
        # Use temporary directory for testing
        self.test_dir = Path("/tmp/test_syftperm_ports")
        self.test_dir.mkdir(parents=True, exist_ok=True)
        self.registry.registry_dir = self.test_dir
        self.registry.registry_file = self.test_dir / "registry.json"
        self.registry.lock_file = self.test_dir / ".lock"

    def tearDown(self):
        """Clean up test files."""
        import shutil

        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_register_and_get_port(self):
        """Test port registration and retrieval."""
        # Don't use PID in test as it will be validated
        self.registry.register_port("test_service", 8005)

        port = self.registry.get_port("test_service")
        self.assertEqual(port, 8005)

    def test_get_all_services(self):
        """Test getting all registered services."""
        self.registry.register_port("service1", 8005)
        self.registry.register_port("service2", 8006)

        services = self.registry.get_all_services()
        self.assertEqual(len(services), 2)
        self.assertIn("service1", services)
        self.assertIn("service2", services)

    def test_unregister_port(self):
        """Test port unregistration."""
        self.registry.register_port("test_service", 8005)
        self.assertTrue(self.registry.unregister_port("test_service"))
        self.assertIsNone(self.registry.get_port("test_service"))


class TestHTMLGenerator(unittest.TestCase):
    """Test HTMLGenerator functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.generator = HTMLGenerator(dark_mode=False)
        self.dark_generator = HTMLGenerator(dark_mode=True)

    def test_theme_colors(self):
        """Test theme color selection."""
        light_theme = self.generator._get_theme()
        dark_theme = self.dark_generator._get_theme()

        self.assertEqual(light_theme["bg"], "#ffffff")
        self.assertEqual(dark_theme["bg"], "#1e1e1e")

    def test_render_button(self):
        """Test button rendering."""
        button = self.generator.render_button(
            "Click me", onclick="alert('clicked')", variant="primary"
        )

        self.assertIn("Click me", button)
        self.assertIn("onclick=\"alert('clicked')\"", button)
        self.assertIn("#3b82f6", button)  # Primary color

    def test_render_input(self):
        """Test input rendering."""
        input_html = self.generator.render_input(
            type="text", name="test_input", placeholder="Enter text..."
        )

        self.assertIn('type="text"', input_html)
        self.assertIn('name="test_input"', input_html)
        self.assertIn('placeholder="Enter text..."', input_html)

    def test_render_table(self):
        """Test table rendering."""
        headers = ["Name", "Value"]
        rows = [["Row 1", "Value 1"], ["Row 2", "Value 2"]]

        table = self.generator.render_table(headers, rows)

        self.assertIn("<table", table)
        self.assertIn("Name", table)
        self.assertIn("Row 1", table)
        self.assertIn("Value 2", table)

    def test_render_notification(self):
        """Test notification rendering."""
        notification = self.generator.render_notification("Test message", type="success")

        self.assertIn("Test message", notification)
        self.assertIn("#10b981", notification)  # Success color


class TestTransitionRenderer(unittest.TestCase):
    """Test TransitionRenderer functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.renderer = TransitionRenderer()

    def test_render_transition(self):
        """Test transition HTML rendering."""
        html = self.renderer.render_transition(
            widget_id="test_widget", static_content="<div>Static</div>", transition_style="fade"
        )

        self.assertIn("test_widget_container", html)
        self.assertIn("test_widget_static", html)
        self.assertIn("test_widget_interactive", html)
        self.assertIn("SyftWidgetTransition", html)

    def test_transition_css(self):
        """Test transition CSS generation."""
        css = self.renderer._get_transition_css()

        self.assertIn(".syft-widget-container", css)
        self.assertIn("transition: opacity", css)
        self.assertIn("@keyframes syft-spin", css)

    def test_transition_js(self):
        """Test transition JavaScript generation."""
        js = self.renderer._get_transition_js()

        self.assertIn("class SyftWidgetTransition", js)
        self.assertIn("checkServers", js)
        self.assertIn("transitionToInteractive", js)


if __name__ == "__main__":
    unittest.main()
