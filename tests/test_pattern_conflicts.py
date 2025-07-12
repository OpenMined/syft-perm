"""Test pattern conflicts in the same directory with proper specificity resolution."""

import unittest
import tempfile
import shutil
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestPatternConflicts(unittest.TestCase):
    """Test pattern conflicts and specificity resolution based on old ACL system."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["user1@example.com", "user2@example.com", "user3@example.com"]
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_prefix_wildcard_vs_exact_match(self):
        """Test prefix wildcard pattern vs exact file match: test*.txt vs test.txt."""
        # Create test directory
        test_dir = Path(self.test_dir) / "conflict1"
        test_dir.mkdir(parents=True)
        
        # Create test files
        test_file = test_dir / "test.txt"
        test_other = test_dir / "test123.txt"
        test_file.write_text("exact match file")
        test_other.write_text("prefix match file")
        
        # Create syft.pub.yaml with conflicting patterns
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "test*.txt"  # Prefix wildcard: 2*9 + 0*10 - 10 = 8 (has one *)
  access:
    admin:
    - user3@example.com
- pattern: "test.txt"   # Exact match: 2*8 + 0*10 = 16 (no wildcards)
  access:
    write:
    - user2@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test exact match file (test.txt) - should use exact pattern (higher specificity)
        syft_exact = syft_perm.open(test_file)
        
        # user2 should have write from exact match pattern (test.txt has higher specificity)
        self.assertTrue(syft_exact.has_write_access("user2@example.com"))
        self.assertTrue(syft_exact.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_exact.has_read_access("user2@example.com"))    # Via hierarchy
        
        # user3 should NOT have admin (test*.txt pattern is less specific than test.txt)
        self.assertFalse(syft_exact.has_admin_access("user3@example.com"))
        
        # Test prefix match file (test123.txt) - should use prefix wildcard pattern
        syft_prefix = syft_perm.open(test_other)
        
        # user3 should have admin from test*.txt pattern (only pattern that matches)
        self.assertTrue(syft_prefix.has_admin_access("user3@example.com"))
        self.assertTrue(syft_prefix.has_write_access("user3@example.com"))   # Via hierarchy
        self.assertTrue(syft_prefix.has_create_access("user3@example.com"))  # Via hierarchy
        self.assertTrue(syft_prefix.has_read_access("user3@example.com"))    # Via hierarchy
        
        # user2 should NOT have access (test.txt pattern doesn't match test123.txt)
        self.assertFalse(syft_prefix.has_write_access("user2@example.com"))
        
        # Verify reasons for exact match
        has_write, write_reasons = syft_exact._check_permission_with_reasons("user2@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("test.txt" in r for r in write_reasons))
        
        # Verify reasons for prefix match
        has_admin, admin_reasons = syft_prefix._check_permission_with_reasons("user3@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("test*.txt" in r for r in admin_reasons))
    
    def test_directory_wildcard_vs_exact_directory(self):
        """Test directory wildcard vs exact directory match: folder*/* vs folder1/*."""
        # Create test directory structure
        base_dir = Path(self.test_dir) / "conflict2"
        folder1_dir = base_dir / "folder1"
        folder2_dir = base_dir / "folder_other"
        
        base_dir.mkdir(parents=True)
        folder1_dir.mkdir()
        folder2_dir.mkdir()
        
        # Create test files in directories
        file1 = folder1_dir / "file1.txt"
        file2 = folder2_dir / "file2.txt"
        file1.write_text("in folder1")
        file2.write_text("in folder_other")
        
        # Create syft.pub.yaml with conflicting directory patterns
        yaml_file = base_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "folder*/*"   # Directory wildcard with files: 2*10 + 0*10 - 20 = 0 (leading * + other *)
  access:
    read:
    - "*"
- pattern: "folder1/*"   # Exact directory with files: 2*10 + 0*10 - 10 = 10 (one *)
  access:
    write:
    - user1@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test file in exact directory match (folder1/*) - should use exact pattern
        syft_exact_dir = syft_perm.open(file1)
        
        # user1 should have write from exact folder1/* pattern (higher specificity)
        self.assertTrue(syft_exact_dir.has_write_access("user1@example.com"))
        self.assertTrue(syft_exact_dir.has_create_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_exact_dir.has_read_access("user1@example.com"))    # Via hierarchy
        
        # Public should NOT have read (folder*/* pattern is less specific than folder1/*)
        self.assertFalse(syft_exact_dir.has_read_access("user2@example.com"))
        
        # Test file in wildcard directory match (folder_other/*) - should use wildcard pattern
        syft_wildcard_dir = syft_perm.open(file2)
        
        # Public should have read from folder*/* pattern (only pattern that matches)
        self.assertTrue(syft_wildcard_dir.has_read_access("user2@example.com"))
        self.assertTrue(syft_wildcard_dir.has_read_access("*"))
        
        # user1 should NOT have write (folder1/* pattern doesn't match folder_other/*)
        self.assertFalse(syft_wildcard_dir.has_write_access("user1@example.com"))
        
        # Verify reasons for exact directory match
        has_write, write_reasons = syft_exact_dir._check_permission_with_reasons("user1@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("folder1/*" in r for r in write_reasons))
        
        # Verify reasons for wildcard directory match
        has_read, read_reasons = syft_wildcard_dir._check_permission_with_reasons("user2@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("folder*/*" in r for r in read_reasons))
    
    def test_nested_recursive_patterns(self):
        """Test nested recursive patterns: **/*.log vs logs/**/*.log."""
        # Create test directory structure
        base_dir = Path(self.test_dir) / "conflict3"
        logs_dir = base_dir / "logs"
        other_dir = base_dir / "other"
        nested_logs = logs_dir / "2023" / "app"
        
        base_dir.mkdir(parents=True)
        logs_dir.mkdir()
        other_dir.mkdir()
        nested_logs.mkdir(parents=True)
        
        # Create test log files
        root_log = base_dir / "app.log"
        other_log = other_dir / "debug.log"
        logs_log = logs_dir / "system.log"
        nested_log = nested_logs / "error.log"
        
        for log_file in [root_log, other_log, logs_log, nested_log]:
            log_file.write_text("log content")
        
        # Create syft.pub.yaml with conflicting recursive patterns
        yaml_file = base_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**/*.log"      # General recursive: 2*9 + 0*10 - 100 - 10 = -92 (** + *)
  access:
    create:
    - user1@example.com
- pattern: "logs/**/*.log" # Specific recursive: 2*13 + 10*2 - 100 - 10 = -64 (higher specificity)
  access:
    write:
    - user2@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test log file in logs directory - should use more specific pattern (logs/**/*.log)
        syft_logs_log = syft_perm.open(logs_log)
        
        # user2 should have write from logs/**/*.log pattern (higher specificity)
        self.assertTrue(syft_logs_log.has_write_access("user2@example.com"))
        self.assertTrue(syft_logs_log.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_logs_log.has_read_access("user2@example.com"))    # Via hierarchy
        
        # user1 should NOT have create (**/*.log pattern is less specific)
        self.assertFalse(syft_logs_log.has_create_access("user1@example.com"))
        
        # Test nested log file in logs subdirectory - should also use logs/**/*.log
        syft_nested_log = syft_perm.open(nested_log)
        
        # user2 should have write from logs/**/*.log pattern
        self.assertTrue(syft_nested_log.has_write_access("user2@example.com"))
        self.assertTrue(syft_nested_log.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_nested_log.has_read_access("user2@example.com"))    # Via hierarchy
        
        # user1 should NOT have create
        self.assertFalse(syft_nested_log.has_create_access("user1@example.com"))
        
        # Test log file outside logs directory - should use general pattern (**/*.log)
        syft_other_log = syft_perm.open(other_log)
        
        # user1 should have create from **/*.log pattern (only pattern that matches)
        self.assertTrue(syft_other_log.has_create_access("user1@example.com"))
        self.assertTrue(syft_other_log.has_read_access("user1@example.com"))    # Via hierarchy
        
        # user2 should NOT have write (logs/**/*.log doesn't match other/debug.log)
        self.assertFalse(syft_other_log.has_write_access("user2@example.com"))
        
        # Test root log file - should use general pattern (**/*.log)
        syft_root_log = syft_perm.open(root_log)
        
        # user1 should have create from **/*.log pattern
        self.assertTrue(syft_root_log.has_create_access("user1@example.com"))
        self.assertTrue(syft_root_log.has_read_access("user1@example.com"))    # Via hierarchy
        
        # user2 should NOT have write
        self.assertFalse(syft_root_log.has_write_access("user2@example.com"))
        
        # Verify reasons for logs directory file
        has_write, write_reasons = syft_logs_log._check_permission_with_reasons("user2@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("logs/**/*.log" in r for r in write_reasons))
        
        # Verify reasons for other directory file
        has_create, create_reasons = syft_other_log._check_permission_with_reasons("user1@example.com", "create")
        self.assertTrue(has_create)
        self.assertTrue(any("**/*.log" in r for r in create_reasons))
    
    def test_pattern_specificity_edge_cases(self):
        """Test additional pattern specificity edge cases."""
        # Create test directory
        test_dir = Path(self.test_dir) / "edge_cases"
        test_dir.mkdir(parents=True)
        
        # Create test files
        test_file = test_dir / "test1.txt"
        test_file.write_text("edge case file")
        
        # Create syft.pub.yaml with edge case patterns
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "test?.txt"     # Single char wildcard: 2*10 + 0*10 - 2 = 18 (? penalty)
  access:
    read:
    - user1@example.com
- pattern: "test1.txt"     # Exact match: 2*9 + 0*10 = 18 (no wildcards)
  access:
    write:
    - user2@example.com
- pattern: "test[0-9].txt" # Character class: 2*13 + 0*10 - 2 = 24 ([ penalty)
  access:
    admin:
    - user3@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Test the file - character class should win (highest specificity: 24)
        syft_file = syft_perm.open(test_file)
        
        # user3 should have admin from test[0-9].txt pattern (highest specificity)
        self.assertTrue(syft_file.has_admin_access("user3@example.com"))
        self.assertTrue(syft_file.has_write_access("user3@example.com"))   # Via hierarchy
        self.assertTrue(syft_file.has_create_access("user3@example.com"))  # Via hierarchy
        self.assertTrue(syft_file.has_read_access("user3@example.com"))    # Via hierarchy
        
        # Others should NOT have access (less specific patterns)
        self.assertFalse(syft_file.has_write_access("user2@example.com"))
        self.assertFalse(syft_file.has_read_access("user1@example.com"))
        
        # Verify reasons
        has_admin, admin_reasons = syft_file._check_permission_with_reasons("user3@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("test[0-9].txt" in r for r in admin_reasons))


if __name__ == "__main__":
    unittest.main()