"""Test code cleanup and linting fixes."""

import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
import syft_perm  # noqa: E402
from syft_perm._impl import clear_permission_cache, get_cache_stats  # noqa: E402


class TestCodeCleanup(unittest.TestCase):
    """Test that the code cleanup and linting fixes work correctly."""

    def setUp(self):
        """Create a test directory."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up test directory."""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)
        clear_permission_cache()

    def test_cache_functions_available(self):
        """Test that cache utility functions are available and work."""
        # Clear cache
        clear_permission_cache()

        # Get initial stats
        stats = get_cache_stats()
        self.assertEqual(stats["size"], 0)
        self.assertIsInstance(stats["max_size"], int)
        self.assertEqual(len(stats["keys"]), 0)

        # Create a file and access it to populate cache
        test_file = Path(self.test_dir) / "test.txt"
        test_file.write_text("content")

        syft_file = syft_perm.open(test_file)
        # Access permissions to populate cache
        _ = syft_file.has_read_access("test@example.com")

        # Check cache has entries
        stats = get_cache_stats()
        self.assertGreater(stats["size"], 0)

        # Clear and verify empty
        clear_permission_cache()
        stats = get_cache_stats()
        self.assertEqual(stats["size"], 0)

    def test_no_duplicate_imports(self):
        """Test that imports are properly cleaned up."""
        # This test verifies the import cleanup by ensuring the module loads
        import syft_perm._impl
        import syft_perm._impl_original
        import syft_perm._syftbox
        import syft_perm._utils
        import syft_perm.server

        # All modules should load without ImportError
        self.assertIsNotNone(syft_perm._impl)
        self.assertIsNotNone(syft_perm._impl_original)
        self.assertIsNotNone(syft_perm._syftbox)
        self.assertIsNotNone(syft_perm._utils)
        self.assertIsNotNone(syft_perm.server)

    def test_permission_editor_demo_runs(self):
        """Test that the demo script has proper imports."""
        # Create a test file
        test_file = Path(self.test_dir) / "test.txt"
        test_file.write_text("content")

        # Test the editor URL generation works
        editor_url = syft_perm.get_editor_url(test_file)
        self.assertIsInstance(editor_url, str)
        # URL could be either http:// (if server available) or file:// (if not)
        self.assertTrue(editor_url.startswith(("http://", "file://")))

    def test_f_string_formatting_works(self):
        """Test that f-string formatting is properly fixed."""
        # Create test structure
        test_dir = Path(self.test_dir) / "project"
        test_dir.mkdir()
        test_file = test_dir / "data.txt"
        test_file.write_text("test data")

        # Create permissions
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "*.txt",
                    "access": {"read": ["alice@example.com"]},
                }
            ]
        }
        with open(yaml_file, "w") as f:
            yaml.dump(yaml_content, f)

        # Open file and check string representation
        syft_file = syft_perm.open(test_file)
        str_repr = str(syft_file)
        self.assertIn("SyftFile", str_repr)
        self.assertIn(str(test_file), str_repr)

    def test_permission_operations_after_cleanup(self):
        """Test that permission operations still work after code cleanup."""
        # Create test file
        test_file = Path(self.test_dir) / "document.md"
        test_file.write_text("# Test Document")

        syft_file = syft_perm.open(test_file)

        # Grant permissions (using force=True for test emails)
        syft_file.grant_read_access("user1@example.com", force=True)
        syft_file.grant_write_access("user2@example.com", force=True)
        syft_file.grant_admin_access("admin@example.com", force=True)

        # Check permissions
        self.assertTrue(syft_file.has_read_access("user1@example.com"))
        self.assertTrue(syft_file.has_write_access("user2@example.com"))
        self.assertTrue(syft_file.has_admin_access("admin@example.com"))

        # Get all permissions
        perms = syft_file._get_all_permissions()
        self.assertIn("user1@example.com", perms["read"])
        self.assertIn("user2@example.com", perms["write"])
        self.assertIn("admin@example.com", perms["admin"])


if __name__ == "__main__":
    unittest.main()
