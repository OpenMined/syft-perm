"""Test terminal property functionality for SyftFolder."""

import tempfile
import unittest
from pathlib import Path

import syft_perm


class TestTerminalProperty(unittest.TestCase):
    """Test the terminal property getter and setter for SyftFolder."""

    def setUp(self):
        """Set up test environment with temporary directory."""
        self.test_dir = tempfile.mkdtemp()
        self.test_path = Path(self.test_dir)

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_terminal_property_default_false(self):
        """Test that terminal property defaults to False for new folders."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)
        self.assertFalse(folder.terminal)

    def test_terminal_property_set_true(self):
        """Test setting terminal property to True."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)
        folder.terminal = True

        # Verify it was set
        self.assertTrue(folder.terminal)

        # Verify YAML file was created
        yaml_file = test_folder / "syft.pub.yaml"
        self.assertTrue(yaml_file.exists())

    def test_terminal_property_set_false(self):
        """Test setting terminal property to False."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)
        folder.terminal = True
        folder.terminal = False

        # Verify it was set to False
        self.assertFalse(folder.terminal)

    def test_terminal_property_persistence(self):
        """Test that terminal property persists across different folder instances."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        # Set terminal on first instance
        folder1 = syft_perm.open(test_folder)
        folder1.terminal = True

        # Check on second instance
        folder2 = syft_perm.open(test_folder)
        self.assertTrue(folder2.terminal)

    def test_terminal_preserves_existing_yaml(self):
        """Test that setting terminal preserves existing YAML content."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)

        # Add some permissions first
        folder.grant_read_access("user@example.com", force=True)

        # Then set terminal
        folder.terminal = True

        # Verify both terminal and permissions exist
        self.assertTrue(folder.terminal)
        permissions = folder.permissions_dict
        self.assertIn("user@example.com", permissions["read"])

    def test_terminal_yaml_structure(self):
        """Test that the YAML structure is correct when terminal is set."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)
        folder.terminal = True

        # Read YAML directly to verify structure
        yaml_file = test_folder / "syft.pub.yaml"
        import yaml

        with open(yaml_file, "r") as f:
            content = yaml.safe_load(f)

        self.assertEqual(content["terminal"], True)
        self.assertIn("rules", content)

    def test_terminal_invalid_yaml_handling(self):
        """Test that terminal property handles invalid YAML gracefully."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        # Create invalid YAML file
        yaml_file = test_folder / "syft.pub.yaml"
        yaml_file.write_text("invalid: yaml: content: [unclosed")

        folder = syft_perm.open(test_folder)

        # Should return False for invalid YAML
        self.assertFalse(folder.terminal)

        # Should be able to set terminal despite invalid existing file
        folder.terminal = True
        self.assertTrue(folder.terminal)

    def test_terminal_with_folder_permissions_integration(self):
        """Test that terminal works correctly with folder permission operations."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)

        # Set terminal first
        folder.terminal = True

        # Add permissions
        folder.grant_read_access("alice@example.com", force=True)
        folder.grant_write_access("bob@example.com", force=True)

        # Verify terminal is still set
        self.assertTrue(folder.terminal)

        # Verify permissions work
        permissions = folder.permissions_dict
        self.assertIn("alice@example.com", permissions["read"])
        self.assertIn("bob@example.com", permissions["write"])

    def test_terminal_cache_invalidation(self):
        """Test that setting terminal invalidates permission cache."""
        test_folder = self.test_path / "test_folder"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)

        # Access permissions to populate cache
        _ = folder.permissions_dict

        # Set terminal (should clear cache)
        folder.terminal = True

        # Access permissions again (should work with new terminal setting)
        permissions = folder.permissions_dict
        self.assertIsInstance(permissions, dict)


if __name__ == "__main__":
    unittest.main()
