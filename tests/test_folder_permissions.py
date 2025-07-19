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
        self.assertIn("pattern: '**'", str(content))
        self.assertIn("andrew@openmined.org", str(content))

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

        self.assertIn("READ: ✓ GRANTED", str(explanation))
        self.assertIn("WRITE: ✗ DENIED", str(explanation))
        self.assertIn("CREATE: ✗ DENIED", str(explanation))
        self.assertIn("ADMIN: ✗ DENIED", str(explanation))
        self.assertIn("Pattern '**' matched", str(explanation))
        self.assertIn(f"Explicitly granted read in {test_folder}", str(explanation))

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
        self.assertIn("READ: ✓ GRANTED", str(file_explanation))
        self.assertIn(f"Explicitly granted read in {test_folder}", str(file_explanation))
        self.assertIn("Pattern '**' matched", str(file_explanation))

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
        self.assertIn("No permissions set", str(folder_str))

        # After granting permissions
        folder.grant_read_access("andrew@openmined.org", force=True)
        folder_str = str(folder)
        self.assertIn("andrew@openmined.org", str(folder_str))
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
        self.assertIn("read: []", str(content))

    def test_grandchild_file_inheritance_from_folder_permissions(self):
        """Test that files in nested subdirectories inherit folder permissions correctly."""
        # Create test folder structure: chat/inner_dialogue/convo2.txt
        test_folder = Path(self.test_dir) / "chat"
        test_folder.mkdir()

        # Create nested subdirectory
        inner_folder = test_folder / "inner_dialogue"
        inner_folder.mkdir()

        # Create files at different levels
        direct_file = test_folder / "convo1.txt"
        direct_file.write_text("direct conversation")

        grandchild_file = inner_folder / "convo2.txt"
        grandchild_file.write_text("nested conversation")

        # Grant permission to the root folder
        folder = syft_perm.open(test_folder)
        folder.grant_read_access("andrew@openmined.org", force=True)

        # Verify folder permissions
        self.assertTrue(folder.has_read_access("andrew@openmined.org"))
        folder_explanation = folder.explain_permissions("andrew@openmined.org")
        self.assertIn("READ: ✓ GRANTED", str(folder_explanation))
        self.assertIn(f"Explicitly granted read in {test_folder}", str(folder_explanation))
        self.assertIn("Pattern '**' matched", str(folder_explanation))

        # Open and test direct child file
        direct_file_obj = syft_perm.open(direct_file)
        self.assertTrue(direct_file_obj.has_read_access("andrew@openmined.org"))
        self.assertFalse(direct_file_obj.has_write_access("andrew@openmined.org"))

        # Check direct file explanation shows inheritance
        direct_explanation = direct_file_obj.explain_permissions("andrew@openmined.org")
        self.assertIn("READ: ✓ GRANTED", str(direct_explanation))
        self.assertIn(f"Explicitly granted read in {test_folder}", str(direct_explanation))
        self.assertIn("Pattern '**' matched", str(direct_explanation))

        # Open and test grandchild file (in nested subdirectory)
        grandchild_file_obj = syft_perm.open(grandchild_file)
        self.assertTrue(grandchild_file_obj.has_read_access("andrew@openmined.org"))
        self.assertFalse(grandchild_file_obj.has_write_access("andrew@openmined.org"))

        # Check grandchild file explanation shows inheritance
        grandchild_explanation = grandchild_file_obj.explain_permissions("andrew@openmined.org")
        self.assertIn("READ: ✓ GRANTED", str(grandchild_explanation))
        self.assertIn(f"Explicitly granted read in {test_folder}", str(grandchild_explanation))
        self.assertIn("Pattern '**' matched", str(grandchild_explanation))

        # Verify only one yaml file exists (in the root folder)
        folder_yaml = test_folder / "syft.pub.yaml"
        inner_yaml = inner_folder / "syft.pub.yaml"

        self.assertTrue(folder_yaml.exists(), "Root folder should have syft.pub.yaml")
        self.assertFalse(inner_yaml.exists(), "Nested folder should not have its own syft.pub.yaml")

        # Verify yaml content uses "**" pattern for inheritance
        content = folder_yaml.read_text()
        self.assertIn("pattern: '**'", str(content))
        self.assertIn("andrew@openmined.org", str(content))

        # Test that grandchild file can override inherited permissions
        # Revoke access specifically for the grandchild file
        grandchild_file_obj.revoke_read_access("andrew@openmined.org")

        # Verify grandchild file no longer has access
        self.assertFalse(grandchild_file_obj.has_read_access("andrew@openmined.org"))

        # But direct file should still have access from folder inheritance
        self.assertTrue(direct_file_obj.has_read_access("andrew@openmined.org"))

        # Check that grandchild explanation shows it was specifically denied
        override_explanation = grandchild_file_obj.explain_permissions("andrew@openmined.org")
        self.assertIn("READ: ✗ DENIED", str(override_explanation))
        # Should show the specific file pattern that matched for the override
        self.assertIn("Pattern 'convo2.txt' matched", str(override_explanation))

        # Verify that a new yaml file was created in the grandchild's directory
        grandchild_dir_yaml = inner_folder / "syft.pub.yaml"
        self.assertTrue(
            grandchild_dir_yaml.exists(), "Grandchild directory should have its own syft.pub.yaml"
        )

        # Verify the override yaml content
        override_content = grandchild_dir_yaml.read_text()
        self.assertIn("pattern: convo2.txt", str(override_content))
        self.assertIn("read: []", str(override_content))  # Empty read permissions (revoked)

    def test_multiple_nested_levels_inheritance(self):
        """Test inheritance through multiple nested levels."""
        # Create deep nested structure: root/level1/level2/level3/file.txt
        root_folder = Path(self.test_dir) / "root"
        root_folder.mkdir()

        level1 = root_folder / "level1"
        level1.mkdir()

        level2 = level1 / "level2"
        level2.mkdir()

        level3 = level2 / "level3"
        level3.mkdir()

        deep_file = level3 / "deep_file.txt"
        deep_file.write_text("deeply nested content")

        # Grant permission to root folder
        root = syft_perm.open(root_folder)
        root.grant_write_access("andrew@openmined.org", force=True)

        # Test deep file inheritance
        deep_file_obj = syft_perm.open(deep_file)

        # Write permission includes read, create
        self.assertTrue(deep_file_obj.has_read_access("andrew@openmined.org"))
        self.assertTrue(deep_file_obj.has_create_access("andrew@openmined.org"))
        self.assertTrue(deep_file_obj.has_write_access("andrew@openmined.org"))
        self.assertFalse(deep_file_obj.has_admin_access("andrew@openmined.org"))

        # Check explanation
        explanation = deep_file_obj.explain_permissions("andrew@openmined.org")
        self.assertIn("READ: ✓ GRANTED", str(explanation))
        self.assertIn("CREATE: ✓ GRANTED", str(explanation))
        self.assertIn("WRITE: ✓ GRANTED", str(explanation))
        self.assertIn("ADMIN: ✗ DENIED", str(explanation))
        self.assertIn(f"Explicitly granted write in {root_folder}", str(explanation))

        # Verify only root has yaml file
        root_yaml = root_folder / "syft.pub.yaml"
        self.assertTrue(root_yaml.exists())

        # Check that no intermediate folders have yaml files
        self.assertFalse((level1 / "syft.pub.yaml").exists())
        self.assertFalse((level2 / "syft.pub.yaml").exists())
        self.assertFalse((level3 / "syft.pub.yaml").exists())

    def test_file_override_folder_permissions(self):
        """Test that individual files can override inherited folder permissions."""
        # Create folder structure
        test_folder = Path(self.test_dir) / "override_test"
        test_folder.mkdir()

        subfolder = test_folder / "subfolder"
        subfolder.mkdir()

        # Create files
        file1 = test_folder / "file1.txt"
        file1.write_text("file 1 content")

        file2 = subfolder / "file2.txt"
        file2.write_text("file 2 content")

        # Grant folder-level permissions
        folder = syft_perm.open(test_folder)
        folder.grant_read_access("user@example.com", force=True)

        # Both files should inherit permissions
        file1_obj = syft_perm.open(file1)
        file2_obj = syft_perm.open(file2)

        self.assertTrue(file1_obj.has_read_access("user@example.com"))
        self.assertTrue(file2_obj.has_read_access("user@example.com"))

        # Override permissions for file2 specifically
        file2_obj.revoke_read_access("user@example.com")

        # file1 should still have access, file2 should not
        self.assertTrue(file1_obj.has_read_access("user@example.com"))
        self.assertFalse(file2_obj.has_read_access("user@example.com"))

        # Check explanations
        file1_explanation = file1_obj.explain_permissions("user@example.com")
        file2_explanation = file2_obj.explain_permissions("user@example.com")

        # file1 should show inheritance from folder
        self.assertIn("READ: ✓ GRANTED", file1_explanation)
        self.assertIn(f"Explicitly granted read in {test_folder}", file1_explanation)

        # file2 should show specific denial
        self.assertIn("READ: ✗ DENIED", file2_explanation)
        self.assertIn("Pattern 'file2.txt' matched", file2_explanation)

        # Verify yaml file structure
        folder_yaml = test_folder / "syft.pub.yaml"
        subfolder_yaml = subfolder / "syft.pub.yaml"

        self.assertTrue(folder_yaml.exists())
        self.assertTrue(subfolder_yaml.exists())  # Created by file2 override

        # Test granting different permission to override file
        file2_obj.grant_write_access("user@example.com", force=True)

        # file2 should now have write (and inherited read, create) but not admin
        self.assertTrue(file2_obj.has_read_access("user@example.com"))
        self.assertTrue(file2_obj.has_create_access("user@example.com"))
        self.assertTrue(file2_obj.has_write_access("user@example.com"))
        self.assertFalse(file2_obj.has_admin_access("user@example.com"))

        # file1 should still only have read from folder inheritance
        self.assertTrue(file1_obj.has_read_access("user@example.com"))
        self.assertFalse(file1_obj.has_write_access("user@example.com"))


if __name__ == "__main__":
    unittest.main()
