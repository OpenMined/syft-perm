"""Test files with create permission level."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestCreatePermissions(unittest.TestCase):
    """Test cases for create permission level functionality."""
    
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
    
    def test_explicit_user_create_permission(self):
        """Test file with explicit user create permission."""
        # Create test file
        test_file = Path(self.test_dir) / "test.txt"
        test_file.write_text("test content")
        
        # Create syft.pub.yaml with create permission
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "test.txt"
  access:
    create:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check permissions
        syft_file = syft_perm.open(test_file)
        
        # Alice should have create permission
        perms = syft_file._get_all_permissions()
        self.assertIn("alice@example.com", perms.get("create", []))
        
        # With hierarchy: create includes read, but not write/admin
        self.assertTrue(syft_file.has_read_access("alice@example.com"))  # Create includes read
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Check reason for hierarchical read permission
        has_read, reasons = syft_file._check_permission_with_reasons("alice@example.com", "read")
        self.assertTrue(has_read)
        self.assertIn("Included via create permission", reasons[0])
        
        # Others have no permissions
        self.assertNotIn("bob@example.com", perms.get("create", []))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
    
    def test_create_without_write(self):
        """Test create permission without write (can make new files, not edit)."""
        # Create directory for testing
        test_dir = Path(self.test_dir) / "project"
        test_dir.mkdir()
        
        # Create syft.pub.yaml with create but not write
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**"
  access:
    create:
    - alice@example.com
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Create existing file
        existing_file = test_dir / "existing.txt"
        existing_file.write_text("existing content")
        
        # Check existing file permissions
        syft_existing = syft_perm.open(existing_file)
        perms = syft_existing._get_all_permissions()
        
        # Alice has create and read, but not write
        self.assertIn("alice@example.com", perms.get("create", []))
        self.assertIn("alice@example.com", perms.get("read", []))
        self.assertNotIn("alice@example.com", perms.get("write", []))
        self.assertFalse(syft_existing.has_write_access("alice@example.com"))
        
        # Check new file would have same permissions
        new_file = test_dir / "new_file.txt"
        new_file.write_text("new content")
        syft_new = syft_perm.open(new_file)
        new_perms = syft_new._get_all_permissions()
        
        self.assertIn("alice@example.com", new_perms.get("create", []))
        self.assertIn("alice@example.com", new_perms.get("read", []))
        self.assertNotIn("alice@example.com", new_perms.get("write", []))
    
    def test_write_without_create(self):
        """Test write permission without create (can edit, not make new)."""
        # Create directory
        test_dir = Path(self.test_dir) / "docs"
        test_dir.mkdir()
        
        # Create syft.pub.yaml with write but not create
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**/*.md"
  access:
    read:
    - bob@example.com
    write:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Create existing file
        existing_doc = test_dir / "README.md"
        existing_doc.write_text("# Documentation")
        
        # Check permissions
        syft_doc = syft_perm.open(existing_doc)
        perms = syft_doc._get_all_permissions()
        
        # Bob has read and write, but not create
        self.assertIn("bob@example.com", perms.get("read", []))
        self.assertIn("bob@example.com", perms.get("write", []))
        self.assertNotIn("bob@example.com", perms.get("create", []))
        
        # Verify access methods
        self.assertTrue(syft_doc.has_read_access("bob@example.com"))
        self.assertTrue(syft_doc.has_write_access("bob@example.com"))
        self.assertFalse(syft_doc.has_admin_access("bob@example.com"))
    
    def test_create_permission_inheritance(self):
        """Test create permission inheritance through directory tree."""
        # Create nested structure
        parent_dir = Path(self.test_dir) / "parent"
        child_dir = parent_dir / "child"
        grandchild_dir = child_dir / "grandchild"
        
        for d in [parent_dir, child_dir, grandchild_dir]:
            d.mkdir(parents=True, exist_ok=True)
        
        # Parent grants create permission
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**"
  access:
    create:
    - alice@example.com
    read:
    - alice@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Create files at different levels
        files = [
            parent_dir / "parent_file.txt",
            child_dir / "child_file.txt",
            grandchild_dir / "grandchild_file.txt"
        ]
        
        for f in files:
            f.write_text("content")
        
        # Check all files inherit create permission
        for f in files:
            syft_file = syft_perm.open(f)
            perms = syft_file._get_all_permissions()
            self.assertIn("alice@example.com", perms.get("create", []),
                         f"Alice should have create permission for {f}")
            self.assertIn("alice@example.com", perms.get("read", []))
    
    def test_create_permission_override(self):
        """Test child directory can override parent's create permission."""
        # Create nested structure
        parent_dir = Path(self.test_dir) / "workspace"
        restricted_dir = parent_dir / "restricted"
        
        parent_dir.mkdir()
        restricted_dir.mkdir()
        
        # Parent grants create to everyone
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**"
  access:
    create:
    - "*"
    read:
    - "*"
"""
        parent_yaml.write_text(parent_content)
        
        # Restricted dir limits create permission
        restricted_yaml = restricted_dir / "syft.pub.yaml"
        restricted_content = """rules:
- pattern: "**"
  access:
    read:
    - "*"
    write:
    - alice@example.com
    create:
    - alice@example.com
    admin:
    - alice@example.com
"""
        restricted_yaml.write_text(restricted_content)
        
        # Create test files
        parent_file = parent_dir / "public.txt"
        restricted_file = restricted_dir / "private.txt"
        
        parent_file.write_text("public")
        restricted_file.write_text("private")
        
        # Check parent file has public create
        syft_public = syft_perm.open(parent_file)
        pub_perms = syft_public._get_all_permissions()
        self.assertIn("*", pub_perms.get("create", []))
        self.assertIn("*", pub_perms.get("read", []))
        
        # Check restricted file only allows alice to create
        syft_private = syft_perm.open(restricted_file)
        priv_perms = syft_private._get_all_permissions()
        self.assertIn("alice@example.com", priv_perms.get("create", []))
        self.assertNotIn("*", priv_perms.get("create", []))
        self.assertIn("*", priv_perms.get("read", []))
    
    def test_owner_implicit_create_permission(self):
        """Test that owner has implicit create permission in their datasite."""
        # Create alice's datasite directory
        alice_datasite = Path(self.test_dir) / "datasites" / "alice@example.com"
        alice_subdir = alice_datasite / "projects"
        alice_subdir.mkdir(parents=True, exist_ok=True)
        
        # Create a file without any explicit permissions
        alice_file = alice_subdir / "myfile.txt"
        alice_file.write_text("alice's file")
        
        # No syft.pub.yaml file exists
        self.assertFalse((alice_subdir / "syft.pub.yaml").exists())
        
        # Check permissions (owner detection might be mocked/simulated)
        syft_file = syft_perm.open(alice_file)
        
        # Note: The actual implementation may need to detect owner
        # based on the path pattern datasites/{email}/...
        # This test documents expected behavior
    
    def test_create_permission_with_patterns(self):
        """Test create permission with various glob patterns."""
        # Create directory structure
        src_dir = Path(self.test_dir) / "src"
        test_dir = Path(self.test_dir) / "tests"
        docs_dir = Path(self.test_dir) / "docs"
        
        for d in [src_dir, test_dir, docs_dir]:
            d.mkdir()
        
        # Create syft.pub.yaml with different create patterns
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "src/**/*.py"
  access:
    create:
    - alice@example.com
    read:
    - alice@example.com
    write:
    - alice@example.com
- pattern: "tests/**/*.py"
  access:
    create:
    - bob@example.com
    read:
    - "*"
- pattern: "docs/**/*.md"
  access:
    read:
    - "*"
    write:
    - charlie@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Create test files
        files = {
            src_dir / "main.py": "alice@example.com",
            src_dir / "utils" / "helper.py": "alice@example.com",
            test_dir / "test_main.py": "bob@example.com",
            docs_dir / "README.md": None  # No create permission
        }
        
        for file_path, expected_user in files.items():
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text("content")
            
            syft_file = syft_perm.open(file_path)
            perms = syft_file._get_all_permissions()
            
            if expected_user:
                self.assertIn(expected_user, perms.get("create", []),
                            f"{expected_user} should have create for {file_path}")
            else:
                self.assertEqual(perms.get("create", []), [],
                               f"No one should have create for {file_path}")
    
    def test_create_with_terminal_node(self):
        """Test create permission with terminal nodes."""
        # Create structure
        base_dir = Path(self.test_dir) / "base"
        sandbox_dir = base_dir / "sandbox"
        
        base_dir.mkdir()
        sandbox_dir.mkdir()
        
        # Base allows create for all
        base_yaml = base_dir / "syft.pub.yaml"
        base_content = """rules:
- pattern: "**"
  access:
    create:
    - "*"
    read:
    - "*"
"""
        base_yaml.write_text(base_content)
        
        # Sandbox is terminal with specific create permission
        sandbox_yaml = sandbox_dir / "syft.pub.yaml"
        sandbox_content = """terminal: true
rules:
- pattern: "**/*.tmp"
  access:
    create:
    - alice@example.com
    read:
    - alice@example.com
    write:
    - alice@example.com
"""
        sandbox_yaml.write_text(sandbox_content)
        
        # Create test files
        base_file = base_dir / "shared.txt"
        sandbox_file = sandbox_dir / "test.tmp"
        
        base_file.write_text("shared")
        sandbox_file.write_text("temp")
        
        # Check base file has public create
        syft_base = syft_perm.open(base_file)
        base_perms = syft_base._get_all_permissions()
        self.assertIn("*", base_perms.get("create", []))
        
        # Check sandbox file only allows alice
        syft_sandbox = syft_perm.open(sandbox_file)
        sandbox_perms = syft_sandbox._get_all_permissions()
        self.assertIn("alice@example.com", sandbox_perms.get("create", []))
        self.assertNotIn("*", sandbox_perms.get("create", []))
    
    def test_permission_accumulation_with_create(self):
        """Test how create permission accumulates with other permissions."""
        # Create test directory
        test_dir = Path(self.test_dir) / "mixed"
        test_dir.mkdir()
        
        # Create syft.pub.yaml with multiple rules
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
- pattern: "*.txt"
  access:
    create:
    - alice@example.com
- pattern: "*.txt"
  access:
    write:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Create test file
        test_file = test_dir / "test.txt"
        test_file.write_text("test")
        
        # Check permissions - only first matching rule applies (old syftbox behavior)
        syft_file = syft_perm.open(test_file)
        perms = syft_file._get_all_permissions()
        
        # Only first rule (*.txt with read: alice@example.com) should apply
        self.assertIn("alice@example.com", perms.get("read", []))
        self.assertNotIn("alice@example.com", perms.get("create", []))  # Not from first rule
        self.assertNotIn("bob@example.com", perms.get("write", []))     # Not from first rule
    
    def test_folder_create_permissions(self):
        """Test create permissions on folders."""
        # Create folder structure
        parent_folder = Path(self.test_dir) / "workspace"
        child_folder = parent_folder / "projects"
        child_folder.mkdir(parents=True, exist_ok=True)
        
        # Set create permission on parent
        yaml_file = parent_folder / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "projects"
  access:
    create:
    - alice@example.com
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check folder permissions
        syft_folder = syft_perm.open(child_folder)
        perms = syft_folder._get_all_permissions()
        
        # Alice should have create permission on the folder
        self.assertIn("alice@example.com", perms.get("create", []))
        self.assertIn("alice@example.com", perms.get("read", []))
        
        # Others should not
        self.assertNotIn("bob@example.com", perms.get("create", []))
    
    def test_create_permission_with_size_limits(self):
        """Test create permission with size limits (new files must be under limit)."""
        # Create test directory
        test_dir = Path(self.test_dir) / "uploads"
        test_dir.mkdir()
        
        # Create syft.pub.yaml with create permission and size limits
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    create:
    - alice@example.com
    read:
    - alice@example.com
  limits:
    max_file_size: 1024  # 1KB limit
- pattern: "*.log" 
  access:
    create:
    - bob@example.com
    read:
    - bob@example.com
  limits:
    max_file_size: 1048576  # 1MB limit
- pattern: "*.tmp"
  access:
    create:
    - charlie@example.com
    read:
    - charlie@example.com
  # No size limit
"""
        yaml_file.write_text(yaml_content)
        
        # Test 1: Small file under the limit - should have permissions
        small_txt = test_dir / "small.txt"
        small_txt.write_text("x" * 500)  # 500 bytes < 1KB limit
        
        syft_small = syft_perm.open(small_txt)
        self.assertTrue(syft_small.has_create_access("alice@example.com"))
        self.assertTrue(syft_small.has_read_access("alice@example.com"))
        
        # Test 2: Large file over the limit - should NOT have permissions
        # In current syft-perm implementation, size limits are checked during
        # permission resolution, so exceeding the limit blocks access
        large_txt = test_dir / "large.txt"
        large_txt.write_text("x" * 2000)  # 2KB > 1KB limit
        
        syft_large = syft_perm.open(large_txt)
        self.assertFalse(syft_large.has_create_access("alice@example.com"))
        self.assertFalse(syft_large.has_read_access("alice@example.com"))
        
        # Test 3: File with larger limit
        medium_log = test_dir / "app.log"
        medium_log.write_text("x" * 500000)  # 500KB < 1MB limit
        
        syft_log = syft_perm.open(medium_log)
        self.assertTrue(syft_log.has_create_access("bob@example.com"))
        self.assertTrue(syft_log.has_read_access("bob@example.com"))
        
        # Test 4: File with no size limit
        any_size_tmp = test_dir / "cache.tmp"
        any_size_tmp.write_text("x" * 2000000)  # 2MB - no limit
        
        syft_tmp = syft_perm.open(any_size_tmp)
        self.assertTrue(syft_tmp.has_create_access("charlie@example.com"))
        self.assertTrue(syft_tmp.has_read_access("charlie@example.com"))
        
        # Test 5: Create permission hierarchy with size limits
        # Admin/write users should also be subject to size limits
        yaml_content_admin = """rules:
- pattern: "*.data"
  access:
    admin:
    - admin@example.com
  limits:
    max_file_size: 1024  # 1KB limit for admin too
"""
        yaml_file.write_text(yaml_content_admin)
        
        # Even admin is subject to size limits
        large_data = test_dir / "large.data"
        large_data.write_text("x" * 2000)  # 2KB > 1KB limit
        
        syft_data = syft_perm.open(large_data)
        # In syft-perm, size limits block permission resolution
        self.assertFalse(syft_data.has_admin_access("admin@example.com"))
        self.assertFalse(syft_data.has_write_access("admin@example.com"))
        self.assertFalse(syft_data.has_create_access("admin@example.com"))
        self.assertFalse(syft_data.has_read_access("admin@example.com"))
        
        # Small file should work for admin
        small_data = test_dir / "small.data" 
        small_data.write_text("x" * 500)  # 500 bytes < 1KB limit
        
        syft_small_data = syft_perm.open(small_data)
        self.assertTrue(syft_small_data.has_admin_access("admin@example.com"))
        self.assertTrue(syft_small_data.has_write_access("admin@example.com"))  # Via hierarchy
        self.assertTrue(syft_small_data.has_create_access("admin@example.com"))  # Via hierarchy
        self.assertTrue(syft_small_data.has_read_access("admin@example.com"))  # Via hierarchy


if __name__ == "__main__":
    unittest.main()