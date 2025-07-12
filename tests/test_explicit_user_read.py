"""Test files with explicit user read permissions."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestExplicitUserRead(unittest.TestCase):
    """Test cases for files with explicit user read permissions."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
        self.test_users = [
            "alice@example.com",
            "bob@example.com", 
            "charlie@example.com"
        ]
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_single_user_read_only(self):
        """Test a file with read permission for a single user."""
        # Create test file
        test_file = Path(self.test_dir) / "single_user_read.txt"
        test_file.write_text("test content")
        
        # Create syft.pub.yaml with read permission for alice
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: single_user_read.txt
  access:
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check alice has read but not write/admin
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Check reason for alice's read permission
        has_read, reasons = syft_file._check_permission_with_reasons("alice@example.com", "read")
        self.assertTrue(has_read)
        self.assertIn("Explicitly granted read in", reasons[0])
        
        # Check other users have no permissions
        for user in ["bob@example.com", "charlie@example.com"]:
            self.assertFalse(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_multiple_users_read_only(self):
        """Test a file with read permission for multiple users."""
        # Create test file
        test_file = Path(self.test_dir) / "multi_user_read.txt"
        test_file.write_text("test content")
        
        # Create syft.pub.yaml with read permission for alice and bob
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: multi_user_read.txt
  access:
    read:
    - alice@example.com
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check alice and bob have read but not write/admin
        for user in ["alice@example.com", "bob@example.com"]:
            self.assertTrue(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
        
        # Check charlie has no permissions
        self.assertFalse(syft_file.has_read_access("charlie@example.com"))
        self.assertFalse(syft_file.has_write_access("charlie@example.com"))
        self.assertFalse(syft_file.has_admin_access("charlie@example.com"))
    
    def test_read_permission_with_empty_write_admin(self):
        """Test explicit empty write/admin lists don't grant permissions."""
        # Create test file
        test_file = Path(self.test_dir) / "explicit_empty.txt"
        test_file.write_text("test content")
        
        # Create syft.pub.yaml with explicit empty write/admin
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: explicit_empty.txt
  access:
    admin: []
    write: []
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check alice has only read
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
    
    def test_read_permission_inheritance_from_parent(self):
        """Test read permission inherited from parent directory."""
        # Create nested directory
        nested_dir = Path(self.test_dir) / "parent" / "child"
        nested_dir.mkdir(parents=True)
        
        # Create test file in child
        test_file = nested_dir / "inherited_read.txt"
        test_file.write_text("test content")
        
        # Create syft.pub.yaml in parent with wildcard pattern
        parent_yaml = Path(self.test_dir) / "parent" / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
"""
        parent_yaml.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check alice has inherited read permission
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Check others have no permissions
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
    
    def test_read_permission_not_inherited_past_terminal(self):
        """Test read permission not inherited past terminal node."""
        # Create deeper nested directory structure
        grandparent_dir = Path(self.test_dir) / "grandparent"
        parent_dir = grandparent_dir / "parent" 
        child_dir = parent_dir / "child"
        child_dir.mkdir(parents=True)
        
        # Create test file in deepest child
        test_file = child_dir / "blocked_read.txt"
        test_file.write_text("test content")
        
        # Grandparent has read permission for alice
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
"""
        grandparent_yaml.write_text(grandparent_content)
        
        # Parent is a terminal node with no rules for this file
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """terminal: true
rules:
- pattern: "*.log"
  access:
    read:
    - bob@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check alice has NO permission (inheritance blocked by terminal parent)
        self.assertFalse(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
    
    def test_folder_with_explicit_user_read(self):
        """Test a folder with read permission for a user."""
        # Create test folder
        test_folder = Path(self.test_dir) / "read_folder"
        test_folder.mkdir()
        
        # Create syft.pub.yaml with read permission
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: read_folder
  access:
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open folder with syft_perm
        syft_folder = syft_perm.open(test_folder)
        
        # Check alice has read but not write/admin
        self.assertTrue(syft_folder.has_read_access("alice@example.com"))
        self.assertFalse(syft_folder.has_write_access("alice@example.com"))
        self.assertFalse(syft_folder.has_admin_access("alice@example.com"))
    
    def test_grant_read_then_check_permissions(self):
        """Test granting read permission and verifying only read is granted."""
        # Create test file
        test_file = Path(self.test_dir) / "grant_read.txt"
        test_file.write_text("test content")
        
        # Open file and grant read permission
        syft_file = syft_perm.open(test_file)
        syft_file.grant_read_access("alice@example.com", force=True)
        
        # Verify only read permission was granted
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Verify yaml was created correctly
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        self.assertTrue(yaml_file.exists())
        content = yaml_file.read_text()
        self.assertIn("alice@example.com", content)
        self.assertIn("read:", content)
    
    def test_read_permission_with_pattern_matching(self):
        """Test read permission with pattern matching."""
        # Create multiple test files
        txt_file = Path(self.test_dir) / "document.txt"
        csv_file = Path(self.test_dir) / "data.csv"
        txt_file.write_text("text content")
        csv_file.write_text("csv content")
        
        # Create syft.pub.yaml with pattern for .txt files
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open both files
        syft_txt = syft_perm.open(txt_file)
        syft_csv = syft_perm.open(csv_file)
        
        # Check .txt file has permission
        self.assertTrue(syft_txt.has_read_access("alice@example.com"))
        self.assertFalse(syft_txt.has_write_access("alice@example.com"))
        self.assertFalse(syft_txt.has_admin_access("alice@example.com"))
        
        # Check .csv file has no permission
        self.assertFalse(syft_csv.has_read_access("alice@example.com"))
        self.assertFalse(syft_csv.has_write_access("alice@example.com"))
        self.assertFalse(syft_csv.has_admin_access("alice@example.com"))
    
    def test_read_permission_override_in_child(self):
        """Test child directory can override parent's read permissions."""
        # Create nested directory
        nested_dir = Path(self.test_dir) / "parent" / "child"
        nested_dir.mkdir(parents=True)
        
        # Create test file
        test_file = nested_dir / "override.txt"
        test_file.write_text("test content")
        
        # Parent gives alice read permission
        parent_yaml = Path(self.test_dir) / "parent" / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Child gives bob read permission (overrides parent)
        child_yaml = nested_dir / "syft.pub.yaml"
        child_content = """rules:
- pattern: "override.txt"
  access:
    read:
    - bob@example.com
"""
        child_yaml.write_text(child_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check bob has read (from child rule)
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        
        # Check alice has NO read (overridden by child)
        self.assertFalse(syft_file.has_read_access("alice@example.com"))
    
    def test_owner_has_all_permissions_despite_read_only(self):
        """Test file owner has all permissions even if only read is granted."""
        # Create a path that simulates being under datasites/alice@example.com/
        owner_dir = Path(self.test_dir) / "datasites" / "alice@example.com" / "mydata"
        owner_dir.mkdir(parents=True)
        
        # Create test file
        test_file = owner_dir / "owner_file.txt"
        test_file.write_text("owner's content")
        
        # Create syft.pub.yaml granting only read to bob
        yaml_file = owner_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "owner_file.txt"
  access:
    read:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check owner (alice) has all permissions
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        
        # Check bob has only read
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))

    def test_owner_permissions_with_reasons(self):
        """Test owner has all permissions with appropriate reasons."""
        # Create file under datasites owner path
        owner_dir = Path(self.test_dir) / "datasites" / "alice@example.com"
        owner_dir.mkdir(parents=True)
        test_file = owner_dir / "owned_file.txt"
        test_file.write_text("owned content")
        
        # Open file
        syft_file = syft_perm.open(test_file)
        
        # Owner should have all permissions
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        
        # Check reasons for owner permissions
        has_admin, reasons = syft_file._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertEqual(len(reasons), 1)
        self.assertEqual(reasons[0], "Owner of path")
        
        # Non-owner should have no permissions
        has_read, reasons = syft_file._check_permission_with_reasons("bob@example.com", "read")
        self.assertFalse(has_read)
        self.assertEqual(reasons[0], "No permission found")


if __name__ == "__main__":
    unittest.main()