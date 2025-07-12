"""Test multiple files with different permissions in same syft.pub.yaml."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestMultipleFilesSameYaml(unittest.TestCase):
    """Test cases for multiple files with different permissions in same directory."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
        self.test_users = [
            "user1@example.com",
            "user2@example.com", 
            "user3@example.com"
        ]
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_comprehensive_multi_file_permissions(self):
        """Test all scenarios: file1-5 with different permission combinations."""
        # Create all test files
        files = {
            "file1.txt": "content 1",
            "file2.txt": "content 2", 
            "file3.txt": "content 3",
            "file4.txt": "content 4",
            "file5.bin": b"binary content 5"  # Binary file
        }
        
        for filename, content in files.items():
            file_path = Path(self.test_dir) / filename
            if filename.endswith('.bin'):
                file_path.write_bytes(content)
            else:
                file_path.write_text(content)
        
        # Create comprehensive syft.pub.yaml with all scenarios
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
# Scenario 1: file1.txt - user1 has read, user2 has write
- pattern: "file1.txt"
  access:
    read:
    - user1@example.com
    write:
    - user2@example.com

# Scenario 2: file2.txt - user1 has write, user2 has admin
- pattern: "file2.txt"
  access:
    write:
    - user1@example.com
    admin:
    - user2@example.com

# Scenario 3: file3.txt - * has read, user1 has admin
- pattern: "file3.txt"
  access:
    read:
    - "*"
    admin:
    - user1@example.com

# Scenario 4: file4.txt - user1 has create only
- pattern: "file4.txt"
  access:
    create:
    - user1@example.com

# Scenario 5: file5.bin - max_size=1MB, user1 has write
- pattern: "file5.bin"
  access:
    write:
    - user1@example.com
  limits:
    max_file_size: 1048576  # 1MB
    allow_dirs: true
    allow_symlinks: true

# Pattern overlap test: *.txt gives user3 read (should not override specific files)
- pattern: "*.txt"
  access:
    read:
    - user3@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test Scenario 1: file1.txt - user1 read, user2 write
        syft_file1 = syft_perm.open(Path(self.test_dir) / "file1.txt")
        
        # user1 should have read only
        self.assertTrue(syft_file1.has_read_access("user1@example.com"))
        self.assertFalse(syft_file1.has_write_access("user1@example.com"))
        self.assertFalse(syft_file1.has_create_access("user1@example.com"))
        self.assertFalse(syft_file1.has_admin_access("user1@example.com"))
        
        # user2 should have write (and create/read via hierarchy)
        self.assertTrue(syft_file1.has_write_access("user2@example.com"))
        self.assertTrue(syft_file1.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_file1.has_read_access("user2@example.com"))    # Via hierarchy
        self.assertFalse(syft_file1.has_admin_access("user2@example.com"))
        
        # user3 should have no access (specific pattern overrides *.txt)
        self.assertFalse(syft_file1.has_read_access("user3@example.com"))
        
        # Test Scenario 2: file2.txt - user1 write, user2 admin
        syft_file2 = syft_perm.open(Path(self.test_dir) / "file2.txt")
        
        # user1 should have write (and create/read via hierarchy)
        self.assertTrue(syft_file2.has_write_access("user1@example.com"))
        self.assertTrue(syft_file2.has_create_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_file2.has_read_access("user1@example.com"))    # Via hierarchy
        self.assertFalse(syft_file2.has_admin_access("user1@example.com"))
        
        # user2 should have admin (and all via hierarchy)
        self.assertTrue(syft_file2.has_admin_access("user2@example.com"))
        self.assertTrue(syft_file2.has_write_access("user2@example.com"))   # Via hierarchy
        self.assertTrue(syft_file2.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_file2.has_read_access("user2@example.com"))    # Via hierarchy
        
        # user3 should have no access
        self.assertFalse(syft_file2.has_read_access("user3@example.com"))
        
        # Test Scenario 3: file3.txt - * read, user1 admin
        syft_file3 = syft_perm.open(Path(self.test_dir) / "file3.txt")
        
        # user1 should have admin (and all via hierarchy)
        self.assertTrue(syft_file3.has_admin_access("user1@example.com"))
        self.assertTrue(syft_file3.has_write_access("user1@example.com"))   # Via hierarchy
        self.assertTrue(syft_file3.has_create_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_file3.has_read_access("user1@example.com"))    # Via hierarchy
        
        # Everyone should have read (* access)
        self.assertTrue(syft_file3.has_read_access("user2@example.com"))
        self.assertTrue(syft_file3.has_read_access("user3@example.com"))
        self.assertTrue(syft_file3.has_read_access("random@example.com"))
        
        # But others should not have higher permissions
        self.assertFalse(syft_file3.has_write_access("user2@example.com"))
        self.assertFalse(syft_file3.has_admin_access("user3@example.com"))
        
        # Test Scenario 4: file4.txt - user1 create only
        syft_file4 = syft_perm.open(Path(self.test_dir) / "file4.txt")
        
        # user1 should have create (and read via hierarchy)
        self.assertTrue(syft_file4.has_create_access("user1@example.com"))
        self.assertTrue(syft_file4.has_read_access("user1@example.com"))    # Via hierarchy
        self.assertFalse(syft_file4.has_write_access("user1@example.com"))
        self.assertFalse(syft_file4.has_admin_access("user1@example.com"))
        
        # Others should have no access
        self.assertFalse(syft_file4.has_read_access("user2@example.com"))
        self.assertFalse(syft_file4.has_create_access("user2@example.com"))
        
        # Test Scenario 5: file5.bin - max_size=1MB, user1 write
        syft_file5 = syft_perm.open(Path(self.test_dir) / "file5.bin")
        
        # user1 should have write (and create/read via hierarchy)
        self.assertTrue(syft_file5.has_write_access("user1@example.com"))
        self.assertTrue(syft_file5.has_create_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_file5.has_read_access("user1@example.com"))    # Via hierarchy
        self.assertFalse(syft_file5.has_admin_access("user1@example.com"))
        
        # Others should have no access
        self.assertFalse(syft_file5.has_read_access("user2@example.com"))
        self.assertFalse(syft_file5.has_write_access("user3@example.com"))
        
        # Verify limits are set (note: limits are in the config, enforcement is at service level)
        perms_data = syft_file5._get_all_permissions_with_sources()
        self.assertIsNotNone(perms_data)
    
    def test_cross_contamination_isolation(self):
        """Test that permissions for one file don't affect another file."""
        # Create test files
        test_files = ["isolated1.txt", "isolated2.txt", "isolated3.txt"]
        for filename in test_files:
            (Path(self.test_dir) / filename).write_text("content")
        
        # Create syft.pub.yaml with isolated permissions
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "isolated1.txt"
  access:
    admin:
    - user1@example.com

- pattern: "isolated2.txt"
  access:
    write:
    - user2@example.com

- pattern: "isolated3.txt"
  access:
    read:
    - user3@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test isolated1.txt - only user1 has admin
        syft_iso1 = syft_perm.open(Path(self.test_dir) / "isolated1.txt")
        self.assertTrue(syft_iso1.has_admin_access("user1@example.com"))
        self.assertFalse(syft_iso1.has_read_access("user2@example.com"))
        self.assertFalse(syft_iso1.has_read_access("user3@example.com"))
        
        # Test isolated2.txt - only user2 has write
        syft_iso2 = syft_perm.open(Path(self.test_dir) / "isolated2.txt")
        self.assertTrue(syft_iso2.has_write_access("user2@example.com"))
        self.assertFalse(syft_iso2.has_read_access("user1@example.com"))  # user1's admin doesn't leak
        self.assertFalse(syft_iso2.has_read_access("user3@example.com"))
        
        # Test isolated3.txt - only user3 has read
        syft_iso3 = syft_perm.open(Path(self.test_dir) / "isolated3.txt")
        self.assertTrue(syft_iso3.has_read_access("user3@example.com"))
        self.assertFalse(syft_iso3.has_read_access("user1@example.com"))  # user1's admin doesn't leak
        self.assertFalse(syft_iso3.has_read_access("user2@example.com"))  # user2's write doesn't leak
    
    def test_pattern_overlap_specificity(self):
        """Test that specific patterns override general patterns."""
        # Create files
        files = ["specific.txt", "general1.txt", "general2.txt"]
        for filename in files:
            (Path(self.test_dir) / filename).write_text("content")
        
        # Create syft.pub.yaml with overlapping patterns
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
# Specific pattern first (first-match-wins)
- pattern: "specific.txt"
  access:
    admin:
    - user1@example.com

# General pattern second
- pattern: "*.txt"
  access:
    read:
    - user2@example.com
    write:
    - user3@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test specific.txt - should match first pattern only
        syft_specific = syft_perm.open(Path(self.test_dir) / "specific.txt")
        self.assertTrue(syft_specific.has_admin_access("user1@example.com"))
        self.assertFalse(syft_specific.has_read_access("user2@example.com"))  # General pattern blocked
        self.assertFalse(syft_specific.has_write_access("user3@example.com"))  # General pattern blocked
        
        # Test general files - should match *.txt pattern
        for filename in ["general1.txt", "general2.txt"]:
            syft_general = syft_perm.open(Path(self.test_dir) / filename)
            self.assertTrue(syft_general.has_read_access("user2@example.com"))
            self.assertTrue(syft_general.has_write_access("user3@example.com"))
            self.assertFalse(syft_general.has_admin_access("user1@example.com"))  # Specific pattern doesn't leak
    
    def test_user_accumulation_no_bleeding(self):
        """Test that user permissions don't accumulate across different file patterns."""
        # Create test files
        files = ["accum1.txt", "accum2.txt", "accum3.py"]
        for filename in files:
            (Path(self.test_dir) / filename).write_text("content")
        
        # Create syft.pub.yaml where same users have different permissions on different files
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "accum1.txt"
  access:
    read:
    - user1@example.com
    write:
    - user2@example.com

- pattern: "accum2.txt"
  access:
    write:
    - user1@example.com  # user1 promoted from read to write
    admin:
    - user2@example.com  # user2 promoted from write to admin

- pattern: "accum3.py"
  access:
    admin:
    - user1@example.com  # user1 promoted to admin
    read:
    - user2@example.com  # user2 demoted to read
"""
        yaml_file.write_text(yaml_content)
        
        # Test accum1.txt - baseline permissions
        syft_accum1 = syft_perm.open(Path(self.test_dir) / "accum1.txt")
        self.assertTrue(syft_accum1.has_read_access("user1@example.com"))
        self.assertFalse(syft_accum1.has_write_access("user1@example.com"))
        self.assertTrue(syft_accum1.has_write_access("user2@example.com"))
        self.assertFalse(syft_accum1.has_admin_access("user2@example.com"))
        
        # Test accum2.txt - different permissions (no bleeding from accum1)
        syft_accum2 = syft_perm.open(Path(self.test_dir) / "accum2.txt")
        self.assertTrue(syft_accum2.has_write_access("user1@example.com"))
        self.assertTrue(syft_accum2.has_read_access("user1@example.com"))   # Has read via write hierarchy
        self.assertTrue(syft_accum2.has_admin_access("user2@example.com"))
        
        # Test accum3.py - completely different permissions
        syft_accum3 = syft_perm.open(Path(self.test_dir) / "accum3.py")
        self.assertTrue(syft_accum3.has_admin_access("user1@example.com"))
        self.assertTrue(syft_accum3.has_read_access("user2@example.com"))     # Explicitly granted read
        self.assertFalse(syft_accum3.has_write_access("user2@example.com"))  # Only has read, not write
        self.assertFalse(syft_accum3.has_admin_access("user2@example.com"))
    
    def test_reason_tracking_multi_file(self):
        """Test that reason tracking works correctly for multiple files."""
        # Create test files
        files = ["reason1.txt", "reason2.txt"]
        for filename in files:
            (Path(self.test_dir) / filename).write_text("content")
        
        # Create syft.pub.yaml
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "reason1.txt"
  access:
    read:
    - user1@example.com

- pattern: "reason2.txt"
  access:
    write:
    - user1@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test reason1.txt - user1 has read
        syft_reason1 = syft_perm.open(Path(self.test_dir) / "reason1.txt")
        has_read, read_reasons = syft_reason1._check_permission_with_reasons("user1@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Explicitly granted read" in r for r in read_reasons))
        self.assertTrue(any("reason1.txt" in r for r in read_reasons))
        
        # Check that user1 doesn't have write on reason1.txt
        has_write, write_reasons = syft_reason1._check_permission_with_reasons("user1@example.com", "write")
        self.assertFalse(has_write)
        
        # Test reason2.txt - user1 has write
        syft_reason2 = syft_perm.open(Path(self.test_dir) / "reason2.txt")
        has_write2, write_reasons2 = syft_reason2._check_permission_with_reasons("user1@example.com", "write")
        self.assertTrue(has_write2)
        self.assertTrue(any("Explicitly granted write" in r for r in write_reasons2))
        self.assertTrue(any("reason2.txt" in r for r in write_reasons2))
        
        # Check that user1 has read via hierarchy on reason2.txt
        has_read2, read_reasons2 = syft_reason2._check_permission_with_reasons("user1@example.com", "read")
        self.assertTrue(has_read2)
        self.assertTrue(any("Included via write permission" in r for r in read_reasons2))


if __name__ == "__main__":
    unittest.main()