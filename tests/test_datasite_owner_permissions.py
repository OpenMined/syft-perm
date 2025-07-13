"""Test suite for automatic datasite owner permissions."""

import shutil
import tempfile
import unittest
from pathlib import Path

import syft_perm


class TestDatasiteOwnerPermissions(unittest.TestCase):
    """Test that datasite owners automatically get admin permissions."""

    def setUp(self):
        """Set up test directory structure that mimics SyftBox datasites."""
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

        # Create a mock datasites directory structure
        self.datasites_dir = Path(self.test_dir) / "SyftBox" / "datasites"
        self.datasites_dir.mkdir(parents=True)

        # Create datasite directories for different users
        self.user1_datasite = self.datasites_dir / "user1@example.com"
        self.user2_datasite = self.datasites_dir / "user2@example.com"

        self.user1_datasite.mkdir()
        self.user2_datasite.mkdir()

    def test_file_in_datasite_grants_owner_admin_permissions(self):
        """Test that files in a user's datasite automatically grant admin permissions."""
        # Create a file in user1's datasite
        test_file = self.user1_datasite / "test_file.txt"
        test_file.write_text("test content")

        # Open the file and check permissions
        file_obj = syft_perm.open(test_file)
        permissions = file_obj.permissions_dict

        # user1@example.com should have all permissions including admin
        self.assertIn("user1@example.com", permissions["read"])
        self.assertIn("user1@example.com", permissions["write"])
        self.assertIn("user1@example.com", permissions["create"])
        self.assertIn("user1@example.com", permissions["admin"])

        # user2@example.com should not have permissions
        self.assertNotIn("user2@example.com", permissions["read"])
        self.assertNotIn("user2@example.com", permissions["write"])
        self.assertNotIn("user2@example.com", permissions["create"])
        self.assertNotIn("user2@example.com", permissions["admin"])

    def test_folder_in_datasite_grants_owner_admin_permissions(self):
        """Test that folders in a user's datasite automatically grant admin permissions."""
        # Create a subfolder in user2's datasite
        test_folder = self.user2_datasite / "subfolder"
        test_folder.mkdir()

        # Open the folder and check permissions
        folder_obj = syft_perm.open(test_folder)
        permissions = folder_obj.permissions_dict

        # user2@example.com should have all permissions including admin
        self.assertIn("user2@example.com", permissions["read"])
        self.assertIn("user2@example.com", permissions["write"])
        self.assertIn("user2@example.com", permissions["create"])
        self.assertIn("user2@example.com", permissions["admin"])

        # user1@example.com should not have permissions
        self.assertNotIn("user1@example.com", permissions["read"])
        self.assertNotIn("user1@example.com", permissions["write"])
        self.assertNotIn("user1@example.com", permissions["create"])
        self.assertNotIn("user1@example.com", permissions["admin"])

    def test_nested_file_in_datasite_grants_owner_admin_permissions(self):
        """Test that deeply nested files in a datasite grant admin permissions to the owner."""
        # Create deeply nested structure in user1's datasite
        nested_dir = self.user1_datasite / "app_data" / "deep" / "nested"
        nested_dir.mkdir(parents=True)

        nested_file = nested_dir / "deep_file.txt"
        nested_file.write_text("deeply nested content")

        # Open the nested file and check permissions
        file_obj = syft_perm.open(nested_file)
        permissions = file_obj.permissions_dict

        # user1@example.com should have all permissions
        self.assertIn("user1@example.com", permissions["read"])
        self.assertIn("user1@example.com", permissions["write"])
        self.assertIn("user1@example.com", permissions["create"])
        self.assertIn("user1@example.com", permissions["admin"])

    def test_datasite_root_folder_grants_owner_admin_permissions(self):
        """Test that the datasite root folder itself grants admin permissions to the owner."""
        # Open the datasite root folder directly
        folder_obj = syft_perm.open(self.user1_datasite)
        permissions = folder_obj.permissions_dict

        # user1@example.com should have all permissions
        self.assertIn("user1@example.com", permissions["read"])
        self.assertIn("user1@example.com", permissions["write"])
        self.assertIn("user1@example.com", permissions["create"])
        self.assertIn("user1@example.com", permissions["admin"])

    def test_owner_permissions_work_with_has_access_methods(self):
        """Test that the has_*_access methods recognize owner permissions."""
        # Create a file in user1's datasite
        test_file = self.user1_datasite / "access_test.txt"
        test_file.write_text("test content")

        file_obj = syft_perm.open(test_file)

        # All access methods should return True for the datasite owner
        self.assertTrue(file_obj.has_read_access("user1@example.com"))
        self.assertTrue(file_obj.has_write_access("user1@example.com"))
        self.assertTrue(file_obj.has_create_access("user1@example.com"))
        self.assertTrue(file_obj.has_admin_access("user1@example.com"))

        # All access methods should return False for other users
        self.assertFalse(file_obj.has_read_access("user2@example.com"))
        self.assertFalse(file_obj.has_write_access("user2@example.com"))
        self.assertFalse(file_obj.has_create_access("user2@example.com"))
        self.assertFalse(file_obj.has_admin_access("user2@example.com"))

    def test_owner_permissions_dont_interfere_with_explicit_permissions(self):
        """Test that owner permissions work alongside explicit yaml permissions."""
        # Create a file and set explicit permissions
        test_file = self.user1_datasite / "explicit_perms.txt"
        test_file.write_text("test content")

        file_obj = syft_perm.open(test_file)

        # Grant read access to user2
        file_obj.grant_read_access("user2@example.com", force=True)

        # Refresh to get updated permissions
        permissions = file_obj.permissions_dict

        # Both owner and explicitly granted user should have appropriate permissions
        self.assertIn("user1@example.com", permissions["admin"])  # Owner has admin
        self.assertIn("user2@example.com", permissions["read"])  # Explicitly granted read

        # But user2 should not have admin permissions
        self.assertNotIn("user2@example.com", permissions["admin"])


if __name__ == "__main__":
    unittest.main()
