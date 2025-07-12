"""Test files with public (*) read permissions."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestPublicRead(unittest.TestCase):
    """Test cases for files with public (*) read permissions."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
        self.test_users = [
            "alice@example.com",
            "bob@example.com", 
            "charlie@example.com",
            "unknown@random.org",
            "test.user@company.io"
        ]
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_star_read_allows_any_user(self):
        """Test a file with * read permission allows any user to read."""
        # Create test file
        test_file = Path(self.test_dir) / "public_read.txt"
        test_file.write_text("public content")
        
        # Create syft.pub.yaml with * read permission
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: public_read.txt
  access:
    read:
    - "*"
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check ALL users have read but not write/admin
        for user in self.test_users:
            self.assertTrue(syft_file.has_read_access(user), 
                          f"{user} should have read access with * permission")
            self.assertFalse(syft_file.has_write_access(user),
                           f"{user} should not have write access")
            self.assertFalse(syft_file.has_admin_access(user),
                           f"{user} should not have admin access")
        
        # Also check with * itself
        self.assertTrue(syft_file.has_read_access("*"))
        self.assertFalse(syft_file.has_write_access("*"))
        self.assertFalse(syft_file.has_admin_access("*"))
    
    def test_public_keyword_as_star_alias(self):
        """Test 'public' keyword is treated as * for permissions."""
        # Create test file
        test_file = Path(self.test_dir) / "public_keyword.txt"
        test_file.write_text("public content")
        
        # Create syft.pub.yaml with 'public' read permission
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: public_keyword.txt
  access:
    read:
    - public
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check ALL users have read access (public is converted to *)
        for user in self.test_users:
            self.assertTrue(syft_file.has_read_access(user),
                          f"{user} should have read access with 'public' permission")
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_star_read_with_specific_users(self):
        """Test * read combined with specific user permissions."""
        # Create test file
        test_file = Path(self.test_dir) / "mixed_permissions.txt"
        test_file.write_text("mixed content")
        
        # Create syft.pub.yaml with * read and specific write/admin
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: mixed_permissions.txt
  access:
    admin:
    - alice@example.com
    write:
    - bob@example.com
    read:
    - "*"
"""
        yaml_file.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check everyone has read
        for user in self.test_users:
            self.assertTrue(syft_file.has_read_access(user))
        
        # Check only alice has admin
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("charlie@example.com"))
        
        # Check write access (alice has it through admin hierarchy, bob has explicit write)
        self.assertTrue(syft_file.has_write_access("alice@example.com"))  # Admin includes write
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("charlie@example.com"))
    
    def test_star_read_inheritance(self):
        """Test * read permission inherited from parent directory."""
        # Create nested directory
        nested_dir = Path(self.test_dir) / "parent" / "child"
        nested_dir.mkdir(parents=True)
        
        # Create test file in child
        test_file = nested_dir / "inherited_public.txt"
        test_file.write_text("inherited content")
        
        # Create syft.pub.yaml in parent with * read
        parent_yaml = Path(self.test_dir) / "parent" / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - "*"
"""
        parent_yaml.write_text(yaml_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check all users have inherited read permission
        for user in self.test_users:
            self.assertTrue(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_star_read_override_by_specific_user(self):
        """Test specific user permission overrides inherited * read."""
        # Create nested directory
        nested_dir = Path(self.test_dir) / "parent" / "child"
        nested_dir.mkdir(parents=True)
        
        # Create test file
        test_file = nested_dir / "override.txt"
        test_file.write_text("override content")
        
        # Parent gives * read permission
        parent_yaml = Path(self.test_dir) / "parent" / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - "*"
"""
        parent_yaml.write_text(parent_content)
        
        # Child restricts to specific user (overrides parent)
        child_yaml = nested_dir / "syft.pub.yaml"
        child_content = """rules:
- pattern: "override.txt"
  access:
    read:
    - alice@example.com
"""
        child_yaml.write_text(child_content)
        
        # Open file with syft_perm
        syft_file = syft_perm.open(test_file)
        
        # Check only alice has read (public access overridden)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_read_access("charlie@example.com"))
    
    def test_grant_public_read_access(self):
        """Test granting * read permission via API."""
        # Create test file
        test_file = Path(self.test_dir) / "grant_public.txt"
        test_file.write_text("test content")
        
        # Open file and grant public read
        syft_file = syft_perm.open(test_file)
        syft_file.grant_read_access("*", force=True)
        
        # Verify all users have read access
        for user in self.test_users:
            self.assertTrue(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
        
        # Verify yaml contains *
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        content = yaml_file.read_text()
        self.assertIn("- '*'", content)
    
    def test_grant_public_keyword_read_access(self):
        """Test granting 'public' read permission via API."""
        # Create test file
        test_file = Path(self.test_dir) / "grant_public_keyword.txt"
        test_file.write_text("test content")
        
        # Open file and grant public read using 'public' keyword
        syft_file = syft_perm.open(test_file)
        syft_file.grant_read_access("public", force=True)
        
        # Verify all users have read access
        for user in self.test_users:
            self.assertTrue(syft_file.has_read_access(user))
            self.assertFalse(syft_file.has_write_access(user))
            self.assertFalse(syft_file.has_admin_access(user))
    
    def test_folder_with_star_read(self):
        """Test a folder with * read permission."""
        # Create test folder
        test_folder = Path(self.test_dir) / "public_folder"
        test_folder.mkdir()
        
        # Create syft.pub.yaml with * read
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: public_folder
  access:
    read:
    - "*"
"""
        yaml_file.write_text(yaml_content)
        
        # Open folder with syft_perm
        syft_folder = syft_perm.open(test_folder)
        
        # Check all users have read but not write/admin
        for user in self.test_users:
            self.assertTrue(syft_folder.has_read_access(user))
            self.assertFalse(syft_folder.has_write_access(user))
            self.assertFalse(syft_folder.has_admin_access(user))
    
    def test_pattern_with_star_read(self):
        """Test pattern matching with * read permission."""
        # Create multiple files
        files = {
            "report.pdf": "pdf content",
            "data.csv": "csv content",
            "image.jpg": "jpg content",
            "document.pdf": "another pdf"
        }
        
        for filename, content in files.items():
            (Path(self.test_dir) / filename).write_text(content)
        
        # Create syft.pub.yaml with * read for PDF files only
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.pdf"
  access:
    read:
    - "*"
"""
        yaml_file.write_text(yaml_content)
        
        # Check PDF files have public read
        for pdf_file in ["report.pdf", "document.pdf"]:
            syft_file = syft_perm.open(Path(self.test_dir) / pdf_file)
            for user in self.test_users:
                self.assertTrue(syft_file.has_read_access(user),
                              f"{user} should read {pdf_file}")
                self.assertFalse(syft_file.has_write_access(user))
        
        # Check non-PDF files have no public read
        for other_file in ["data.csv", "image.jpg"]:
            syft_file = syft_perm.open(Path(self.test_dir) / other_file)
            for user in self.test_users:
                self.assertFalse(syft_file.has_read_access(user),
                               f"{user} should not read {other_file}")
    
    def test_revoke_public_read_access(self):
        """Test revoking * read permission."""
        # Create test file
        test_file = Path(self.test_dir) / "revoke_public.txt"
        test_file.write_text("test content")
        
        # Grant public read first
        syft_file = syft_perm.open(test_file)
        syft_file.grant_read_access("*", force=True)
        
        # Verify public has read
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        
        # Revoke public read
        syft_file.revoke_read_access("*")
        
        # Verify no one has read anymore
        for user in self.test_users:
            self.assertFalse(syft_file.has_read_access(user))
    
    def test_star_read_with_terminal_parent(self):
        """Test * read in terminal node blocks inheritance from above."""
        # Create deeper nested structure
        grandparent_dir = Path(self.test_dir) / "grandparent"
        parent_dir = grandparent_dir / "parent"
        child_dir = parent_dir / "child"
        child_dir.mkdir(parents=True)
        
        # Create test file in child
        test_file = child_dir / "test.txt"
        test_file.write_text("test content")
        
        # Grandparent has * read for all
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - "*"
"""
        grandparent_yaml.write_text(grandparent_content)
        
        # Parent is terminal with specific user only
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """terminal: true
rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Open file
        syft_file = syft_perm.open(test_file)
        
        # Check only alice has read (terminal blocks grandparent's * permission)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_read_access("charlie@example.com"))


if __name__ == "__main__":
    unittest.main()