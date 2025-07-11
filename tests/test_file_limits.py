"""Test file limits functionality (size, symlinks, directories)."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestFileLimits(unittest.TestCase):
    """Test cases for file size, symlink, and directory limits."""
    
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
    
    def test_file_size_limit_blocks_access(self):
        """Test file size limit blocks access to large files."""
        # Create a large file (over limit) and small file (under limit)
        large_file = Path(self.test_dir) / "large.txt"
        small_file = Path(self.test_dir) / "small.txt"
        
        # Write content to make files of different sizes
        large_content = "x" * 2000  # 2KB
        small_content = "x" * 500   # 500 bytes
        
        large_file.write_text(large_content)
        small_file.write_text(small_content)
        
        # Create syft.pub.yaml with size limit
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 1024  # 1KB limit
"""
        yaml_file.write_text(yaml_content)
        
        # Check small file has permission
        syft_small = syft_perm.open(small_file)
        self.assertTrue(syft_small.has_read_access("alice@example.com"),
                       "Alice should read small file under size limit")
        
        # Check large file has no permission due to size limit
        syft_large = syft_perm.open(large_file)
        self.assertFalse(syft_large.has_read_access("alice@example.com"),
                        "Alice should not read large file over size limit")
    
    def test_symlink_restriction(self):
        """Test symlink restrictions in permissions."""
        # Create a regular file and a symlink to it
        regular_file = Path(self.test_dir) / "regular.txt"
        symlink_file = Path(self.test_dir) / "symlink.txt"
        
        regular_file.write_text("regular content")
        symlink_file.symlink_to(regular_file)
        
        # Create syft.pub.yaml that doesn't allow symlinks
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
  limits:
    allow_symlinks: false
"""
        yaml_file.write_text(yaml_content)
        
        # Check regular file has permission
        syft_regular = syft_perm.open(regular_file)
        self.assertTrue(syft_regular.has_read_access("alice@example.com"),
                       "Alice should read regular file")
        
        # Check symlink has no permission
        syft_symlink = syft_perm.open(symlink_file)
        self.assertFalse(syft_symlink.has_read_access("alice@example.com"),
                        "Alice should not read symlink when not allowed")
    
    def test_symlink_allowed_by_default(self):
        """Test symlinks are allowed when no restriction specified."""
        # Create a regular file and a symlink
        regular_file = Path(self.test_dir) / "regular.txt"
        symlink_file = Path(self.test_dir) / "symlink.txt"
        
        regular_file.write_text("content")
        symlink_file.symlink_to(regular_file)
        
        # Create syft.pub.yaml without symlink restriction
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Both files should have permission
        syft_regular = syft_perm.open(regular_file)
        syft_symlink = syft_perm.open(symlink_file)
        
        self.assertTrue(syft_regular.has_read_access("bob@example.com"))
        self.assertTrue(syft_symlink.has_read_access("bob@example.com"),
                       "Symlinks should be allowed by default")
    
    def test_directory_restriction(self):
        """Test directory access restrictions."""
        # Create a directory and a file
        test_dir = Path(self.test_dir) / "subdir"
        test_file = Path(self.test_dir) / "file.txt"
        
        test_dir.mkdir()
        test_file.write_text("file content")
        
        # Create syft.pub.yaml that doesn't allow directories
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*"
  access:
    read:
    - alice@example.com
  limits:
    allow_dirs: false
"""
        yaml_file.write_text(yaml_content)
        
        # Check file has permission
        syft_file = syft_perm.open(test_file)
        self.assertTrue(syft_file.has_read_access("alice@example.com"),
                       "Alice should read file")
        
        # Check directory has no permission
        syft_dir = syft_perm.open(test_dir)
        self.assertFalse(syft_dir.has_read_access("alice@example.com"),
                        "Alice should not read directory when not allowed")
    
    def test_directories_allowed_by_default(self):
        """Test directories are allowed when no restriction specified."""
        # Create a directory
        test_dir = Path(self.test_dir) / "allowed_dir"
        test_dir.mkdir()
        
        # Create syft.pub.yaml without directory restriction
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*"
  access:
    read:
    - bob@example.com
    write:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Directory should have permission
        syft_dir = syft_perm.open(test_dir)
        self.assertTrue(syft_dir.has_read_access("bob@example.com"),
                       "Directories should be allowed by default")
        self.assertTrue(syft_dir.has_write_access("bob@example.com"))
    
    def test_multiple_limits_combined(self):
        """Test multiple limits can be combined."""
        # Create various test items
        large_file = Path(self.test_dir) / "large.txt"
        small_file = Path(self.test_dir) / "small.txt"
        symlink = Path(self.test_dir) / "link.txt"
        directory = Path(self.test_dir) / "subdir"
        
        large_file.write_text("x" * 2000)  # 2KB
        small_file.write_text("x" * 100)   # 100 bytes
        symlink.symlink_to(small_file)
        directory.mkdir()
        
        # Create syft.pub.yaml with multiple limits
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 500      # 500 bytes
    allow_symlinks: false
    allow_dirs: false
"""
        yaml_file.write_text(yaml_content)
        
        # Only small regular file should have permission
        syft_small = syft_perm.open(small_file)
        self.assertTrue(syft_small.has_read_access("alice@example.com"),
                       "Small file should be accessible")
        
        # Others should be blocked
        syft_large = syft_perm.open(large_file)
        self.assertFalse(syft_large.has_read_access("alice@example.com"),
                        "Large file blocked by size limit")
        
        syft_symlink = syft_perm.open(symlink)
        self.assertFalse(syft_symlink.has_read_access("alice@example.com"),
                        "Symlink blocked by symlink restriction")
        
        syft_dir = syft_perm.open(directory)
        self.assertFalse(syft_dir.has_read_access("alice@example.com"),
                        "Directory blocked by directory restriction")
    
    def test_limits_inheritance(self):
        """Test limits are inherited from parent directories."""
        # Create nested structure
        parent_dir = Path(self.test_dir) / "parent"
        child_dir = parent_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create files at different levels
        parent_file = parent_dir / "parent.txt"
        child_file = child_dir / "child.txt"
        
        parent_file.write_text("x" * 2000)  # 2KB
        child_file.write_text("x" * 2000)   # 2KB
        
        # Parent has size limit
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 1024  # 1KB
"""
        parent_yaml.write_text(parent_content)
        
        # Both files should be blocked by size limit
        syft_parent = syft_perm.open(parent_file)
        syft_child = syft_perm.open(child_file)
        
        self.assertFalse(syft_parent.has_read_access("alice@example.com"),
                        "Parent file blocked by size limit")
        self.assertFalse(syft_child.has_read_access("alice@example.com"),
                        "Child file inherits size limit")
    
    def test_limits_override_in_child(self):
        """Test child directory can override parent's limits."""
        # Create nested structure
        parent_dir = Path(self.test_dir) / "parent"
        child_dir = parent_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create large files
        parent_file = parent_dir / "large.txt"
        child_file = child_dir / "large.txt"
        
        parent_file.write_text("x" * 2000)  # 2KB
        child_file.write_text("x" * 2000)   # 2KB
        
        # Parent has restrictive size limit
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 1024  # 1KB
"""
        parent_yaml.write_text(parent_content)
        
        # Child overrides with larger limit
        child_yaml = child_dir / "syft.pub.yaml"
        child_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 5000  # 5KB
"""
        child_yaml.write_text(child_content)
        
        # Parent file blocked, child file allowed
        syft_parent = syft_perm.open(parent_file)
        syft_child = syft_perm.open(child_file)
        
        self.assertFalse(syft_parent.has_read_access("alice@example.com"),
                        "Parent file blocked by parent's limit")
        self.assertTrue(syft_child.has_read_access("alice@example.com"),
                       "Child file allowed by child's override")
    
    def test_zero_size_limit(self):
        """Test zero size limit blocks all files."""
        # Create any file
        test_file = Path(self.test_dir) / "test.txt"
        test_file.write_text("any content")
        
        # Create syft.pub.yaml with zero size limit
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 0  # No files allowed
"""
        yaml_file.write_text(yaml_content)
        
        # File should be blocked
        syft_file = syft_perm.open(test_file)
        self.assertFalse(syft_file.has_read_access("alice@example.com"),
                        "Zero size limit should block all files")
    
    def test_limits_per_pattern(self):
        """Test different patterns can have different limits."""
        # Create files of different types
        small_txt = Path(self.test_dir) / "small.txt"
        large_txt = Path(self.test_dir) / "large.txt"
        large_py = Path(self.test_dir) / "large.py"
        
        small_txt.write_text("x" * 100)    # 100 bytes
        large_txt.write_text("x" * 2000)   # 2KB
        large_py.write_text("x" * 2000)    # 2KB
        
        # Create syft.pub.yaml with different limits per pattern
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 500  # Small limit for txt files
- pattern: "*.py"
  access:
    read:
    - alice@example.com
  limits:
    max_file_size: 5000  # Larger limit for py files
"""
        yaml_file.write_text(yaml_content)
        
        # Check access based on limits
        syft_small_txt = syft_perm.open(small_txt)
        syft_large_txt = syft_perm.open(large_txt)
        syft_large_py = syft_perm.open(large_py)
        
        self.assertTrue(syft_small_txt.has_read_access("alice@example.com"),
                       "Small txt file under limit")
        self.assertFalse(syft_large_txt.has_read_access("alice@example.com"),
                        "Large txt file over txt limit")
        self.assertTrue(syft_large_py.has_read_access("alice@example.com"),
                       "Large py file under py limit")


if __name__ == "__main__":
    unittest.main()