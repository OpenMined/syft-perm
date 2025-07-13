"""Test suite for SyftFolder permissions behavior."""

import shutil
import tempfile
import unittest
from pathlib import Path

import syft_perm


class TestFolderPermissions(unittest.TestCase):
    """Test SyftFolder permissions creation and checking."""

    def setUp(self):
        """Set up test directory."""
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_folder_permissions_yaml_created_inside_folder(self):
        """Test that SyftFolder creates syft.pub.yaml inside the folder, not in parent."""
        # Create test folder structure
        test_folder = Path(self.test_dir) / "my_chat"
        test_folder.mkdir()

        # Open folder and grant permission
        folder = syft_perm.open(test_folder)
        folder.grant_read_access("andrew@openmined.org", force=True)

        # Verify yaml file locations
        parent_yaml = Path(self.test_dir) / "syft.pub.yaml"
        folder_yaml = test_folder / "syft.pub.yaml"

        self.assertFalse(parent_yaml.exists(), "YAML should not be created in parent directory")
        self.assertTrue(folder_yaml.exists(), "YAML should be created inside the folder")

        # Verify yaml content uses "**" pattern
        content = folder_yaml.read_text()
        self.assertIn("pattern: '**'", content)
        self.assertIn("andrew@openmined.org", content)

    def test_folder_permission_checking_works_correctly(self):
        """Test that SyftFolder can correctly check its own permissions."""
        # Create test folder
        test_folder = Path(self.test_dir) / "permissions_test"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)

        # Before granting permission
        self.assertFalse(folder.has_read_access("andrew@openmined.org"))
        self.assertFalse(folder.has_write_access("andrew@openmined.org"))
        self.assertFalse(folder.has_create_access("andrew@openmined.org"))
        self.assertFalse(folder.has_admin_access("andrew@openmined.org"))

        # Grant read access
        folder.grant_read_access("andrew@openmined.org", force=True)

        # After granting permission
        self.assertTrue(folder.has_read_access("andrew@openmined.org"))
        self.assertFalse(folder.has_write_access("andrew@openmined.org"))
        self.assertFalse(folder.has_create_access("andrew@openmined.org"))
        self.assertFalse(folder.has_admin_access("andrew@openmined.org"))

        # Grant write access
        folder.grant_write_access("andrew@openmined.org", force=True)

        # Write includes read, create
        self.assertTrue(folder.has_read_access("andrew@openmined.org"))
        self.assertTrue(folder.has_create_access("andrew@openmined.org"))
        self.assertTrue(folder.has_write_access("andrew@openmined.org"))
        self.assertFalse(folder.has_admin_access("andrew@openmined.org"))

    def test_folder_permission_explanations(self):
        """Test that SyftFolder.explain_permissions() shows correct information."""
        # Create test folder
        test_folder = Path(self.test_dir) / "explain_test"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)
        folder.grant_read_access("andrew@openmined.org", force=True)

        # Check explanation shows granted read permission
        explanation = folder.explain_permissions("andrew@openmined.org")

        self.assertIn("READ: ✓ GRANTED", explanation)
        self.assertIn("WRITE: ✗ DENIED", explanation)
        self.assertIn("CREATE: ✗ DENIED", explanation)
        self.assertIn("ADMIN: ✗ DENIED", explanation)
        self.assertIn("Pattern '**' matched", explanation)
        self.assertIn(f"Explicitly granted read in {test_folder}", explanation)

    def test_file_inheritance_from_folder_permissions(self):
        """Test that files inside folder inherit permissions correctly."""
        # Create test folder and file
        test_folder = Path(self.test_dir) / "inheritance_test"
        test_folder.mkdir()
        test_file = test_folder / "test_file.txt"
        test_file.write_text("test content")

        # Grant permission to folder
        folder = syft_perm.open(test_folder)
        folder.grant_read_access("andrew@openmined.org", force=True)

        # Open file and check inherited permissions
        file_obj = syft_perm.open(test_file)
        self.assertTrue(file_obj.has_read_access("andrew@openmined.org"))
        self.assertFalse(file_obj.has_write_access("andrew@openmined.org"))

        # Check file explanation shows inheritance
        file_explanation = file_obj.explain_permissions("andrew@openmined.org")
        self.assertIn("READ: ✓ GRANTED", file_explanation)
        self.assertIn(f"Explicitly granted read in {test_folder}", file_explanation)
        self.assertIn("Pattern '**' matched", file_explanation)

    def test_folder_permissions_with_multiple_users(self):
        """Test folder permissions with multiple users."""
        # Create test folder
        test_folder = Path(self.test_dir) / "multi_user_test"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)

        # Grant different permissions to different users
        folder.grant_read_access("user1@example.com", force=True)
        folder.grant_write_access("user2@example.com", force=True)
        folder.grant_admin_access("user3@example.com", force=True)

        # Check permissions for each user
        self.assertTrue(folder.has_read_access("user1@example.com"))
        self.assertFalse(folder.has_write_access("user1@example.com"))
        self.assertFalse(folder.has_admin_access("user1@example.com"))

        self.assertTrue(folder.has_read_access("user2@example.com"))
        self.assertTrue(folder.has_write_access("user2@example.com"))
        self.assertTrue(folder.has_create_access("user2@example.com"))
        self.assertFalse(folder.has_admin_access("user2@example.com"))

        self.assertTrue(folder.has_read_access("user3@example.com"))
        self.assertTrue(folder.has_write_access("user3@example.com"))
        self.assertTrue(folder.has_create_access("user3@example.com"))
        self.assertTrue(folder.has_admin_access("user3@example.com"))

    def test_folder_string_representation_shows_permissions(self):
        """Test that folder string representation shows permissions correctly."""
        # Create test folder
        test_folder = Path(self.test_dir) / "repr_test"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)

        # Before granting permissions
        folder_str = str(folder)
        self.assertIn("No permissions set", folder_str)

        # After granting permissions
        folder.grant_read_access("andrew@openmined.org", force=True)
        folder_str = str(folder)
        self.assertIn("andrew@openmined.org", folder_str)
        self.assertIn("Read", folder_str or folder._get_permission_table())

    def test_folder_revoke_access(self):
        """Test that revoking folder access works correctly."""
        # Create test folder
        test_folder = Path(self.test_dir) / "revoke_test"
        test_folder.mkdir()

        folder = syft_perm.open(test_folder)

        # Grant and verify permission
        folder.grant_read_access("andrew@openmined.org", force=True)
        self.assertTrue(folder.has_read_access("andrew@openmined.org"))

        # Revoke and verify permission removed
        folder.revoke_read_access("andrew@openmined.org")
        self.assertFalse(folder.has_read_access("andrew@openmined.org"))

        # Verify yaml file still exists but permission is removed
        folder_yaml = test_folder / "syft.pub.yaml"
        self.assertTrue(folder_yaml.exists())
        content = folder_yaml.read_text()
        # Should have empty read list but still have the structure
        self.assertIn("read: []", content)


if __name__ == "__main__":
    unittest.main()
