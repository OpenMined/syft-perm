"""Test files and folders with no permissions set."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestNoPermissions(unittest.TestCase):
    """Test cases for files and folders with no permissions."""
    
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
    
    def test_file_no_permissions_single_file(self):
        """Test a single file with no permissions returns False for all access checks."""
        # Create a test file
        test_file = Path(self.test_dir) / "test_file.txt"
        test_file.write_text("test content")
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check that all users have no permissions
        for user in self.test_users:
            self.assertFalse(syft_file.has_read_access(user), 
                           f"User {user} should not have read access")
            self.assertFalse(syft_file.has_write_access(user),
                           f"User {user} should not have write access") 
            self.assertFalse(syft_file.has_admin_access(user),
                           f"User {user} should not have admin access")
        
        # Also check public access
        self.assertFalse(syft_file.has_read_access("*"))
        self.assertFalse(syft_file.has_write_access("*"))
        self.assertFalse(syft_file.has_admin_access("*"))
    
    def test_file_no_permissions_empty_yaml(self):
        """Test a file where syft.pub.yaml exists but has no rules."""
        # Create test file
        test_file = Path(self.test_dir) / "empty_rules.txt"
        test_file.write_text("test content")
        
        # Create empty syft.pub.yaml
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_file.write_text("rules: []\n")
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check all permissions are false
        for user in self.test_users:
            self.assertFalse(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_file_no_permissions_other_file_has_permissions(self):
        """Test a file with no permissions when another file in same dir has permissions."""
        # Create two test files
        file1 = Path(self.test_dir) / "file1.txt"
        file2 = Path(self.test_dir) / "file2.txt" 
        file1.write_text("content 1")
        file2.write_text("content 2")
        
        # Create syft.pub.yaml with permissions only for file1
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: file1.txt
  access:
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open both files
        syft_file1 = syft_perm.open(file1)
        syft_file2 = syft_perm.open(file2)
        
        # Check file1 has permissions
        self.assertTrue(syft_file1.has_read_access("alice@example.com"))
        
        # Check file2 has no permissions
        for user in self.test_users:
            self.assertFalse(syft_file2.has_read_access(user))
            self.assertFalse(syft_file2.has_write_access(user))
            self.assertFalse(syft_file2.has_admin_access(user))
    
    def test_folder_no_permissions(self):
        """Test a folder with no permissions returns False for all access checks."""
        # Create a test folder
        test_folder = Path(self.test_dir) / "test_folder"
        test_folder.mkdir()
        
        # Open folder with syft_perm
        syft_folder = syft_perm.open(test_folder)
        
        # Check that all users have no permissions
        for user in self.test_users:
            self.assertFalse(syft_folder.has_read_access(user))
            self.assertFalse(syft_folder.has_write_access(user))
            self.assertFalse(syft_folder.has_admin_access(user))
    
    def test_file_no_permissions_nested_directory(self):
        """Test a file in nested directory with no permissions anywhere."""
        # Create nested directory structure
        nested_dir = Path(self.test_dir) / "level1" / "level2" / "level3"
        nested_dir.mkdir(parents=True)
        
        # Create file in deepest level
        test_file = nested_dir / "deep_file.txt"
        test_file.write_text("deep content")
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check no permissions
        for user in self.test_users:
            self.assertFalse(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_file_no_permissions_with_pattern_not_matching(self):
        """Test file has no permissions when patterns exist but don't match."""
        # Create test file
        test_file = Path(self.test_dir) / "data.csv"
        test_file.write_text("csv content")
        
        # Create syft.pub.yaml with pattern that doesn't match
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
- pattern: "*.log"
  access:
    write:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check no permissions (patterns don't match .csv)
        for user in self.test_users:
            self.assertFalse(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_file_no_permissions_after_revoke_all(self):
        """Test file has no permissions after granting then revoking all."""
        # Create test file
        test_file = Path(self.test_dir) / "revoke_test.txt"
        test_file.write_text("test content")
        
        # Open file and grant permissions
        syft_file = syft_perm.open(test_file)
        syft_file.grant_read_access("alice@example.com", force=True)
        syft_file.grant_write_access("bob@example.com", force=True)
        syft_file.grant_admin_access("charlie@example.com", force=True)
        
        # Verify permissions were granted
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        self.assertTrue(syft_file.has_admin_access("charlie@example.com"))
        
        # Revoke all permissions
        syft_file.revoke_read_access("alice@example.com")
        syft_file.revoke_write_access("bob@example.com")
        syft_file.revoke_admin_access("charlie@example.com")
        
        # Check all permissions are now false
        for user in self.test_users:
            self.assertFalse(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_multiple_files_no_permissions_same_directory(self):
        """Test multiple files in same directory all with no permissions."""
        # Create multiple files
        files = []
        for i in range(3):
            file_path = Path(self.test_dir) / f"file_{i}.dat"
            file_path.write_text(f"content {i}")
            files.append(file_path)
        
        # Check each file has no permissions
        for file_path in files:
            syft_file = syft_perm.open(file_path)
            for user in self.test_users:
                self.assertFalse(syft_file.has_read_access(user),
                               f"{file_path.name}: {user} should not have read")
                self.assertFalse(syft_file.has_write_access(user),
                               f"{file_path.name}: {user} should not have write")
                self.assertFalse(syft_file.has_admin_access(user),
                               f"{file_path.name}: {user} should not have admin")


if __name__ == "__main__":
    unittest.main()