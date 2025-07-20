"""Centralized server management for syft-perm widgets."""

import json
import subprocess
import threading
import time
import urllib.request
from enum import Enum
from pathlib import Path
from typing import Dict, Optional, Tuple


class ServerState(Enum):
    """Server state enumeration."""

    UNKNOWN = "unknown"
    STARTING = "starting"
    RUNNING = "running"
    FAILED = "failed"
    INSTALLING = "installing"


class ServerManager:
    """
    Manages server lifecycle for syft-perm widgets.

    Features:
    - Singleton pattern for cross-widget coordination
    - State tracking to prevent duplicate work
    - Parallel startup of thread and SyftBox servers
    - Port discovery and caching
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the server manager."""
        if self._initialized:
            return

        self._initialized = True
        self._state_cache = {}
        self._port_cache = {}
        self._startup_locks = {}
        self._state_file = Path.home() / ".syftperm" / "server_state.json"
        self._state_file.parent.mkdir(parents=True, exist_ok=True)

        # Load persisted state
        self._load_state()

    def _load_state(self):
        """Load server state from disk."""
        try:
            if self._state_file.exists():
                with open(self._state_file, "r") as f:
                    data = json.load(f)
                    self._state_cache = {
                        k: ServerState(v) for k, v in data.get("states", {}).items()
                    }
                    self._port_cache = data.get("ports", {})
        except Exception:
            pass

    def _save_state(self):
        """Persist server state to disk."""
        try:
            data = {
                "states": {k: v.value for k, v in self._state_cache.items()},
                "ports": self._port_cache,
                "timestamp": time.time(),
            }
            with open(self._state_file, "w") as f:
                json.dump(data, f)
        except Exception:
            pass

    def get_server_state(self) -> Tuple[ServerState, Optional[str]]:
        """
        Check current server state.

        Returns:
            Tuple of (ServerState, server_url)
        """
        # Quick check for running servers
        for port in [8005, 8006, 8007, 8008]:
            url = f"http://localhost:{port}"
            if self._check_server(url):
                self._update_state("thread_server", ServerState.RUNNING, port)
                return ServerState.RUNNING, url

        # Check discovery port for SyftBox servers
        discovery_url = self._check_discovery_port()
        if discovery_url:
            return ServerState.RUNNING, discovery_url

        # Check if servers are starting
        if self._state_cache.get("thread_server") == ServerState.STARTING:
            return ServerState.STARTING, None

        if self._state_cache.get("syftbox_app") == ServerState.STARTING:
            return ServerState.STARTING, None

        return ServerState.UNKNOWN, None

    def _check_server(self, url: str) -> bool:
        """Check if a server is responding."""
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    content = response.read().decode("utf-8")
                    return "SyftPerm" in content or "syft-perm" in content
        except Exception:
            pass
        return False

    def _check_discovery_port(self) -> Optional[str]:
        """Check discovery port for SyftBox app servers."""
        try:
            discovery_url = "http://localhost:62050"
            with urllib.request.urlopen(discovery_url, timeout=1) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode("utf-8"))
                    port = data.get("main_server_port")
                    if port:
                        server_url = f"http://localhost:{port}"
                        if self._check_server(server_url):
                            self._update_state("syftbox_app", ServerState.RUNNING, port)
                            return server_url
        except Exception:
            pass
        return None

    def start_all_servers(self):
        """Start all available server types in parallel."""
        threads = []

        # Start thread server
        t1 = threading.Thread(target=self._start_thread_server)
        t1.daemon = True
        t1.start()
        threads.append(t1)

        # Install/start SyftBox app
        if not self.is_syftbox_installed():
            t2 = threading.Thread(target=self._install_syftbox_app)
            t2.daemon = True
            t2.start()
            threads.append(t2)

        # Don't wait for threads - let them run in background
        return threads

    def _start_thread_server(self):
        """Start the thread-based FastAPI server."""
        # Prevent duplicate starts
        lock_key = "thread_server"
        if lock_key not in self._startup_locks:
            self._startup_locks[lock_key] = threading.Lock()

        if not self._startup_locks[lock_key].acquire(blocking=False):
            return  # Another thread is already starting this server

        try:
            # Check if already running
            state, url = self.get_server_state()
            if state == ServerState.RUNNING:
                return

            # Update state
            self._update_state("thread_server", ServerState.STARTING)

            # Import and start server
            try:
                from ..server import start_server

                # This should start server in background thread
                server_url = start_server()

                if server_url:
                    # Extract port from URL
                    port = int(server_url.split(":")[-1].rstrip("/"))
                    self._update_state("thread_server", ServerState.RUNNING, port)
                else:
                    self._update_state("thread_server", ServerState.FAILED)

            except Exception as e:
                print(f"Failed to start thread server: {e}")
                self._update_state("thread_server", ServerState.FAILED)

        finally:
            self._startup_locks[lock_key].release()

    def _install_syftbox_app(self):
        """Install the SyftBox app."""
        # Prevent duplicate installs
        lock_key = "syftbox_install"
        if lock_key not in self._startup_locks:
            self._startup_locks[lock_key] = threading.Lock()

        if not self._startup_locks[lock_key].acquire(blocking=False):
            return

        try:
            self._update_state("syftbox_app", ServerState.INSTALLING)

            # Run installation command
            result = subprocess.run(
                ["syftbox", "app", "install", "src/syft_perm"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode == 0:
                # Installation successful - app should auto-start
                self._update_state("syftbox_app", ServerState.STARTING)

                # Wait a bit for server to come up
                time.sleep(2)

                # Check if it started
                discovery_url = self._check_discovery_port()
                if discovery_url:
                    self._update_state("syftbox_app", ServerState.RUNNING)
                else:
                    self._update_state("syftbox_app", ServerState.FAILED)
            else:
                self._update_state("syftbox_app", ServerState.FAILED)

        except Exception as e:
            print(f"Failed to install SyftBox app: {e}")
            self._update_state("syftbox_app", ServerState.FAILED)
        finally:
            self._startup_locks[lock_key].release()

    def is_syftbox_installed(self) -> bool:
        """Check if SyftBox app is installed."""
        syftbox_path = Path.home() / "SyftBox" / "apps" / "syft-perm"
        return syftbox_path.exists()

    def _update_state(self, server_type: str, state: ServerState, port: Optional[int] = None):
        """Update server state and persist."""
        self._state_cache[server_type] = state
        if port:
            self._port_cache[server_type] = port
        self._save_state()

    def get_available_port(self) -> Optional[int]:
        """Get an available port for a new server."""
        import socket

        # Try preferred ports first
        for port in [8005, 8006, 8007, 8008]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(("", port))
                    return port
            except OSError:
                continue

        # Get random available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    def reset_state(self):
        """Reset all server states (useful for debugging)."""
        self._state_cache.clear()
        self._port_cache.clear()
        if self._state_file.exists():
            self._state_file.unlink()
