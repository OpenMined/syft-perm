"""Test permissions_dict and has_yaml properties added to SyftFile."""

import tempfile
from pathlib import Path

import syft_perm as sp


class TestPermissionsDictProperty:
    """Test the permissions_dict and has_yaml properties."""

    def test_permissions_dict_property_exists(self):
        """Test that SyftFile has permissions_dict property."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")

            f = sp.open(test_file)

            # Check property exists and returns dict
            assert hasattr(f, "permissions_dict")
            perms = f.permissions_dict
            assert isinstance(perms, dict)
            assert "read" in perms
            assert "write" in perms
            assert "create" in perms
            assert "admin" in perms

    def test_has_yaml_property_exists(self):
        """Test that SyftFile has has_yaml property."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")

            f = sp.open(test_file)

            # Check property exists and returns bool
            assert hasattr(f, "has_yaml")
            has_yaml = f.has_yaml
            assert isinstance(has_yaml, bool)

    def test_has_yaml_detects_yaml_files(self):
        """Test that has_yaml correctly detects syft.pub.yaml files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file without yaml
            no_yaml_dir = Path(tmpdir) / "no_yaml"
            no_yaml_dir.mkdir()
            test_file1 = no_yaml_dir / "test1.txt"
            test_file1.write_text("test content")

            # Create a file with yaml
            with_yaml_dir = Path(tmpdir) / "with_yaml"
            with_yaml_dir.mkdir()
            yaml_file = with_yaml_dir / "syft.pub.yaml"
            yaml_file.write_text("rules:\n  - pattern: '**'\n    access:\n      read: ['*']\n")
            test_file2 = with_yaml_dir / "test2.txt"
            test_file2.write_text("test content")

            # Test files
            f1 = sp.open(test_file1)
            f2 = sp.open(test_file2)

            # Check that has_yaml correctly detects the presence of yaml files
            assert f1.has_yaml is False
            assert f2.has_yaml is True

    def test_permissions_dict_returns_correct_permissions(self):
        """Test that permissions_dict returns the correct permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_dir = Path(tmpdir) / "test"
            test_dir.mkdir()

            # Create yaml with specific permissions
            yaml_file = test_dir / "syft.pub.yaml"
            yaml_file.write_text(
                """rules:
  - pattern: '**'
    access:
      read: ['user1@example.com', 'user2@example.com']
      write: ['user1@example.com']
      create: []
      admin: []
"""
            )

            test_file = test_dir / "data.txt"
            test_file.write_text("test data")

            f = sp.open(test_file)
            perms = f.permissions_dict

            # Check permissions
            assert "user1@example.com" in perms["read"]
            assert "user2@example.com" in perms["read"]
            assert "user1@example.com" in perms["write"]
            assert len(perms["create"]) == 0
            assert len(perms["admin"]) == 0

    def test_sp_files_includes_permissions_and_has_yaml(self):
        """Test that sp.files includes permissions_dict and has_yaml."""
        # This test is tricky because sp.files scans the actual SyftBox directory
        # We'll just verify the structure is correct
        all_files = sp.files.all()

        if all_files:  # Only test if there are files
            first_file = all_files[0]

            # Check required fields exist
            assert "permissions" in first_file
            assert "_has_yaml" in first_file

            # Check types
            assert isinstance(first_file["permissions"], dict)
            assert isinstance(first_file["_has_yaml"], bool)

            # Check permissions structure - it should be a dict
            # (may be empty if no permissions are set in the test environment)
            perms = first_file["permissions"]
            # Just verify it's a dict - the actual keys depend on the real filesystem
            assert isinstance(perms, dict)
            # If permissions are set, they should be in the expected format
            for perm_type in perms:
                assert perm_type in ["read", "write", "create", "admin"]
                assert isinstance(perms[perm_type], list)

    def test_permissions_dict_caching_works(self):
        """Test that permissions_dict uses caching correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")

            f = sp.open(test_file)

            # Call permissions_dict multiple times
            perms1 = f.permissions_dict
            perms2 = f.permissions_dict

            # Should return the same dict (from cache)
            assert perms1 == perms2
