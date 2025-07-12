"""Auto-recovery mechanism for syft-perm when running in SyftBox."""

import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

import requests


def _is_running_in_syftbox() -> bool:
    """Check if we're running inside SyftBox/apps directory."""
    try:
        cwd = Path.cwd()
        return "SyftBox/apps" in str(cwd)
    except Exception:
        return False


def _find_syftbox_root() -> Optional[Path]:
    """Find the SyftBox root directory."""
    try:
        cwd = Path.cwd()
        parts = cwd.parts
        for i, part in enumerate(parts):
            if part == "SyftBox":
                return Path(*parts[: i + 1])
        return None
    except Exception:
        return None


def _check_server_health(server_url: str, timeout: float = 2.0) -> bool:
    """Check if the server is healthy and responding."""
    try:
        response = requests.get(f"{server_url}/", timeout=timeout)
        return response.status_code == 200
    except Exception:
        return False


def _kill_syft_perm_processes() -> None:
    """Kill any running syft-perm processes."""
    try:
        # Find processes
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            check=False,
        )

        for line in result.stdout.splitlines():
            if "syft-perm" in line and "uvicorn" in line:
                # Extract PID (second column)
                parts = line.split()
                if len(parts) > 1:
                    pid = parts[1]
                    try:
                        subprocess.run(["kill", "-9", pid], check=False)
                        print(f"Killed syft-perm process {pid}")
                    except Exception:
                        pass
    except Exception as e:
        print(f"Error killing processes: {e}")


def _remove_syft_perm_from_apps() -> None:
    """Remove syft-perm directory from SyftBox/apps."""
    syftbox_root = _find_syftbox_root()
    if not syftbox_root:
        return

    syft_perm_dir = syftbox_root / "apps" / "syft-perm"
    if syft_perm_dir.exists():
        try:
            import shutil

            shutil.rmtree(syft_perm_dir)
            print(f"Removed {syft_perm_dir}")
        except Exception as e:
            print(f"Error removing directory: {e}")


def _reinstall_syft_perm() -> bool:
    """Reinstall syft-perm in SyftBox/apps."""
    syftbox_root = _find_syftbox_root()
    if not syftbox_root:
        return False

    apps_dir = syftbox_root / "apps"
    if not apps_dir.exists():
        return False

    try:
        # Clone the repository
        subprocess.run(
            ["git", "clone", "https://github.com/openmined/syft-perm.git"],
            cwd=apps_dir,
            capture_output=True,
            text=True,
            check=True,
        )
        print("Reinstalled syft-perm in SyftBox/apps")
        return True
    except Exception as e:
        print(f"Error reinstalling syft-perm: {e}")
        return False


def ensure_server_running(server_url: str) -> Tuple[bool, Optional[str]]:
    """
    Ensure the server is running, performing auto-recovery if needed.

    Returns:
        Tuple of (success, error_message)
    """
    # First check if server is healthy
    if _check_server_health(server_url):
        return True, None

    # If not running in SyftBox, don't do auto-recovery
    if not _is_running_in_syftbox():
        return False, "Server not responding"

    print("Server not responding. Attempting auto-recovery...")

    # Kill existing processes
    _kill_syft_perm_processes()
    time.sleep(1)

    # Remove from apps directory
    _remove_syft_perm_from_apps()
    time.sleep(1)

    # Reinstall
    if not _reinstall_syft_perm():
        return False, "Failed to reinstall syft-perm"

    # Wait a bit for the new instance to start
    time.sleep(3)

    # Check again
    if _check_server_health(server_url):
        print("Auto-recovery successful!")
        return True, None

    return False, "Auto-recovery failed - server still not responding"
