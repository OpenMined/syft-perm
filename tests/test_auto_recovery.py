"""Test auto-recovery mechanism for syft-perm."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from syft_perm._auto_recovery import (
    _check_server_health,
    _find_syftbox_root,
    _is_running_in_syftbox,
    _kill_syft_perm_processes,
    _reinstall_syft_perm,
    _remove_syft_perm_from_apps,
    ensure_server_running,
)


class TestAutoRecovery:
    """Test the auto-recovery functionality."""

    def test_is_running_in_syftbox(self):
        """Test detection of running in SyftBox."""
        with patch("pathlib.Path.cwd") as mock_cwd:
            # Test when in SyftBox
            mock_cwd.return_value = Path("/home/user/SyftBox/apps/syft-perm")
            assert _is_running_in_syftbox() is True

            # Test when not in SyftBox
            mock_cwd.return_value = Path("/home/user/other/location")
            assert _is_running_in_syftbox() is False

    def test_find_syftbox_root(self):
        """Test finding SyftBox root directory."""
        with patch("pathlib.Path.cwd") as mock_cwd:
            # Test when in SyftBox
            mock_cwd.return_value = Path("/home/user/SyftBox/apps/syft-perm")
            root = _find_syftbox_root()
            assert root == Path("/home/user/SyftBox")

            # Test when not in SyftBox
            mock_cwd.return_value = Path("/home/user/other/location")
            assert _find_syftbox_root() is None

    @patch("requests.get")
    def test_check_server_health(self, mock_get):
        """Test server health check."""
        # Test healthy server
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        assert _check_server_health("http://localhost:8765") is True

        # Test unhealthy server
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        assert _check_server_health("http://localhost:8765") is False

        # Test connection error
        mock_get.side_effect = Exception("Connection error")
        assert _check_server_health("http://localhost:8765") is False

    @patch("subprocess.run")
    def test_kill_syft_perm_processes(self, mock_run):
        """Test killing syft-perm processes."""
        # Mock ps aux output
        ps_result = MagicMock()
        ps_result.stdout = """
user 1234 0.0 0.1 python syft-perm uvicorn
user 5678 0.0 0.1 python other-process
user 9012 0.0 0.1 python syft-perm uvicorn
"""
        mock_run.return_value = ps_result

        _kill_syft_perm_processes()

        # Should call ps aux first
        assert mock_run.call_args_list[0][0][0] == ["ps", "aux"]

        # Should kill processes 1234 and 9012
        kill_calls = [call for call in mock_run.call_args_list if call[0][0][0] == "kill"]
        assert len(kill_calls) == 2

    @patch("shutil.rmtree")
    @patch("pathlib.Path.exists")
    def test_remove_syft_perm_from_apps(self, mock_exists, mock_rmtree):
        """Test removing syft-perm directory."""
        with patch("syft_perm._auto_recovery._find_syftbox_root") as mock_find_root:
            # Test when directory exists
            mock_find_root.return_value = Path("/home/user/SyftBox")
            mock_exists.return_value = True

            _remove_syft_perm_from_apps()

            mock_rmtree.assert_called_once_with(Path("/home/user/SyftBox/apps/syft-perm"))

            # Test when directory doesn't exist
            mock_exists.return_value = False
            mock_rmtree.reset_mock()

            _remove_syft_perm_from_apps()

            mock_rmtree.assert_not_called()

    @patch("subprocess.run")
    @patch("pathlib.Path.exists")
    def test_reinstall_syft_perm(self, mock_exists, mock_run):
        """Test reinstalling syft-perm."""
        with patch("syft_perm._auto_recovery._find_syftbox_root") as mock_find_root:
            # Test successful reinstall
            mock_find_root.return_value = Path("/home/user/SyftBox")
            mock_exists.return_value = True

            assert _reinstall_syft_perm() is True

            mock_run.assert_called_once_with(
                ["git", "clone", "https://github.com/openmined/syft-perm.git"],
                cwd=Path("/home/user/SyftBox/apps"),
                capture_output=True,
                text=True,
                check=True,
            )

            # Test failed reinstall
            mock_run.side_effect = Exception("Git error")
            assert _reinstall_syft_perm() is False

    def test_ensure_server_running_healthy_server(self):
        """Test ensure_server_running with healthy server."""
        with patch("syft_perm._auto_recovery._check_server_health") as mock_check:
            mock_check.return_value = True

            success, error = ensure_server_running("http://localhost:8765")

            assert success is True
            assert error is None
            mock_check.assert_called_once_with("http://localhost:8765")

    def test_ensure_server_running_not_in_syftbox(self):
        """Test ensure_server_running when not in SyftBox."""
        with patch("syft_perm._auto_recovery._check_server_health") as mock_check:
            with patch("syft_perm._auto_recovery._is_running_in_syftbox") as mock_in_syftbox:
                with patch("syft_perm._auto_recovery._kill_syft_perm_processes"):
                    mock_check.return_value = False
                    mock_in_syftbox.return_value = False

                    success, error = ensure_server_running("http://localhost:8765")

                    assert success is False
                    assert error == "Auto-recovery failed - server still not responding"

    @patch("time.sleep")  # Mock sleep to speed up tests
    def test_ensure_server_running_auto_recovery_success(self, mock_sleep):
        """Test successful auto-recovery."""
        with patch("syft_perm._auto_recovery._check_server_health") as mock_check:
            with patch("syft_perm._auto_recovery._is_running_in_syftbox") as mock_in_syftbox:
                with patch("syft_perm._auto_recovery._kill_syft_perm_processes") as mock_kill:
                    with patch(
                        "syft_perm._auto_recovery._remove_syft_perm_from_apps"
                    ) as mock_remove:
                        with patch(
                            "syft_perm._auto_recovery._reinstall_syft_perm"
                        ) as mock_reinstall:
                            # First check fails, second succeeds after recovery
                            mock_check.side_effect = [False, True]
                            mock_in_syftbox.return_value = True
                            mock_reinstall.return_value = True

                            success, error = ensure_server_running("http://localhost:8765")

                            assert success is True
                            assert error is None
                            mock_kill.assert_called_once()
                            mock_remove.assert_called_once()
                            mock_reinstall.assert_called_once()

    @patch("time.sleep")  # Mock sleep to speed up tests
    def test_ensure_server_running_auto_recovery_failure(self, mock_sleep):
        """Test failed auto-recovery."""
        with patch("syft_perm._auto_recovery._check_server_health") as mock_check:
            with patch("syft_perm._auto_recovery._is_running_in_syftbox") as mock_in_syftbox:
                with patch("syft_perm._auto_recovery._kill_syft_perm_processes"):
                    with patch("syft_perm._auto_recovery._remove_syft_perm_from_apps"):
                        with patch(
                            "syft_perm._auto_recovery._reinstall_syft_perm"
                        ) as mock_reinstall:
                            # Both checks fail
                            mock_check.return_value = False
                            mock_in_syftbox.return_value = True
                            mock_reinstall.return_value = True

                            success, error = ensure_server_running("http://localhost:8765")

                            assert success is False
                            assert error == "Auto-recovery failed - server still not responding"
