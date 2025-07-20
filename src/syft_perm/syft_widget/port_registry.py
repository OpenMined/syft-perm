"""Port discovery and registry for cross-process coordination."""

import json
import time
from pathlib import Path
from typing import Dict, List, Optional


class PortRegistry:
    """
    File-based port registry for server discovery.

    Features:
    - Cross-process port discovery
    - Automatic stale entry cleanup
    - Support for multiple server types
    """

    def __init__(self):
        """Initialize the port registry."""
        self.registry_dir = Path.home() / ".syftperm" / "ports"
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.registry_file = self.registry_dir / "registry.json"
        self.lock_file = self.registry_dir / ".lock"
        self.stale_threshold = 300  # 5 minutes

    def register_port(self, service_name: str, port: int, pid: Optional[int] = None) -> bool:
        """
        Register a port for a service.

        Args:
            service_name: Name of the service (e.g., 'thread_server', 'syftbox_app')
            port: Port number
            pid: Optional process ID

        Returns:
            True if registered successfully
        """
        entry = {
            "service": service_name,
            "port": port,
            "pid": pid,
            "timestamp": time.time(),
            "host": "localhost",
        }

        with self._file_lock():
            registry = self._load_registry()
            registry[service_name] = entry
            self._save_registry(registry)

        return True

    def get_port(self, service_name: str) -> Optional[int]:
        """
        Get port for a service.

        Args:
            service_name: Name of the service

        Returns:
            Port number if found and not stale, None otherwise
        """
        with self._file_lock():
            registry = self._load_registry()
            self._cleanup_stale_entries(registry)

            if service_name in registry:
                entry = registry[service_name]
                if self._is_entry_valid(entry):
                    return entry["port"]

        return None

    def get_all_services(self) -> Dict[str, Dict]:
        """
        Get all registered services.

        Returns:
            Dictionary of service_name -> service_info
        """
        with self._file_lock():
            registry = self._load_registry()
            self._cleanup_stale_entries(registry)
            return {k: v for k, v in registry.items() if self._is_entry_valid(v)}

    def unregister_port(self, service_name: str) -> bool:
        """
        Unregister a port for a service.

        Args:
            service_name: Name of the service

        Returns:
            True if unregistered successfully
        """
        with self._file_lock():
            registry = self._load_registry()
            if service_name in registry:
                del registry[service_name]
                self._save_registry(registry)
                return True

        return False

    def _load_registry(self) -> Dict:
        """Load registry from file."""
        try:
            if self.registry_file.exists():
                with open(self.registry_file, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_registry(self, registry: Dict):
        """Save registry to file."""
        try:
            with open(self.registry_file, "w") as f:
                json.dump(registry, f, indent=2)
        except Exception:
            pass

    def _is_entry_valid(self, entry: Dict) -> bool:
        """Check if a registry entry is valid."""
        # Check timestamp
        if time.time() - entry.get("timestamp", 0) > self.stale_threshold:
            return False

        # Check if process is still running (if PID provided)
        if entry.get("pid"):
            try:
                import os
                import signal

                os.kill(entry["pid"], signal.SIGCONT)  # Just check if process exists
                return True
            except (OSError, ProcessLookupError):
                return False

        return True

    def _cleanup_stale_entries(self, registry: Dict):
        """Remove stale entries from registry."""
        stale_keys = []
        for key, entry in registry.items():
            if not self._is_entry_valid(entry):
                stale_keys.append(key)

        for key in stale_keys:
            del registry[key]

        if stale_keys:
            self._save_registry(registry)

    def _file_lock(self):
        """Simple file-based lock for registry access."""
        from contextlib import contextmanager

        @contextmanager
        def lock():
            lock_fd = None
            try:
                # Create lock file if it doesn't exist
                self.lock_file.touch(exist_ok=True)

                # Try to use fcntl if available (Unix-like systems)
                try:
                    import fcntl

                    # Open and acquire lock
                    lock_fd = open(self.lock_file, "w")
                    fcntl.flock(lock_fd, fcntl.LOCK_EX)
                except ImportError:
                    # fcntl not available (Windows), use simple file-based lock
                    pass

                yield

            finally:
                if lock_fd:
                    try:
                        import fcntl

                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    except ImportError:
                        pass
                    lock_fd.close()

        return lock()

    def write_discovery_file(self, port: int, service_type: str = "main"):
        """
        Write a discovery file for a specific service.

        This creates individual port files that can be quickly checked
        without needing to parse the full registry.

        Args:
            port: Port number
            service_type: Type of service ('main', 'discovery', etc.)
        """
        discovery_file = self.registry_dir / f"{service_type}.port"
        try:
            with open(discovery_file, "w") as f:
                f.write(str(port))
        except Exception:
            pass

    def read_discovery_file(self, service_type: str = "main") -> Optional[int]:
        """
        Read a discovery file for a specific service.

        Args:
            service_type: Type of service

        Returns:
            Port number if found, None otherwise
        """
        discovery_file = self.registry_dir / f"{service_type}.port"
        try:
            if discovery_file.exists():
                with open(discovery_file, "r") as f:
                    return int(f.read().strip())
        except Exception:
            pass
        return None
