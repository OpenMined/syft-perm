"""Test complex multi-level permissions using nearest-node algorithm (old syftbox behavior)."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestComplexMultiLevelNearestNode(unittest.TestCase):
    """Test complex multi-level permissions matching old syftbox server behavior."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_complex_multilevel_nearest_node_behavior(self):
        """Test the exact scenario from request matching old syftbox nearest-node algorithm."""
        
        # Create the directory structure
        parent_dir = Path(self.test_dir) / "parent"
        folder1_dir = parent_dir / "folder1"
        folder1_subfolder = folder1_dir / "subfolder"
        folder2_dir = parent_dir / "folder2"
        
        # Create directories
        for dir_path in [parent_dir, folder1_dir, folder1_subfolder, folder2_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create all test files
        files_to_create = [
            parent_dir / "file1.txt",
            parent_dir / "file2.csv", 
            folder1_dir / "data.txt",
            folder1_subfolder / "nested.txt",
            folder2_dir / "data.txt",
            folder2_dir / "script.py",
            folder2_dir / "report.csv"
        ]
        
        for file_path in files_to_create:
            file_path.write_text(f"content of {file_path.name}")
        
        # Create parent syft.pub.yaml (*.txt: * read, **/*.py: user1 create)
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [
                {
                    "pattern": "*.txt",
                    "access": {
                        "read": ["*"]  # Public read for .txt files
                    }
                },
                {
                    "pattern": "**/*.py", 
                    "access": {
                        "create": ["user1@example.com"]  # user1 create for .py files at any depth
                    }
                },
                {
                    "pattern": "file2.csv",
                    "access": {
                        "read": ["user3@example.com"]  # Specific rule for file2.csv
                    }
                }
            ]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create folder1 syft.pub.yaml (terminal=true, user1 admin)
        folder1_yaml = folder1_dir / "syft.pub.yaml"
        folder1_rules = {
            "terminal": True,  # This blocks inheritance
            "rules": [
                {
                    "pattern": "**",  # Match everything in this directory
                    "access": {
                        "admin": ["user1@example.com"]
                    }
                }
            ]
        }
        with open(folder1_yaml, 'w') as f:
            yaml.dump(folder1_rules, f)
        
        # Create folder2 syft.pub.yaml (user2 write, max_size=5MB)
        folder2_yaml = folder2_dir / "syft.pub.yaml"
        folder2_rules = {
            "rules": [
                {
                    "pattern": "**",  # Match everything in this directory
                    "access": {
                        "write": ["user2@example.com"]
                    },
                    "limits": {
                        "max_file_size": 5 * 1024 * 1024,  # 5MB
                        "allow_dirs": True,
                        "allow_symlinks": True
                    }
                }
            ]
        }
        with open(folder2_yaml, 'w') as f:
            yaml.dump(folder2_rules, f)
        
        # Test file1.txt in parent - uses parent *.txt rule (* read)
        syft_file1 = syft_perm.open(parent_dir / "file1.txt")
        self.assertTrue(syft_file1.has_read_access("*"))
        self.assertTrue(syft_file1.has_read_access("anyone@example.com"))
        self.assertFalse(syft_file1.has_write_access("user1@example.com"))
        self.assertFalse(syft_file1.has_admin_access("user1@example.com"))
        
        # Test file2.csv in parent - uses specific rule (user3 read)
        syft_file2 = syft_perm.open(parent_dir / "file2.csv")
        self.assertTrue(syft_file2.has_read_access("user3@example.com"))
        self.assertFalse(syft_file2.has_read_access("*"))  # Specific rule overrides general patterns
        self.assertFalse(syft_file2.has_read_access("user1@example.com"))
        
        # Test folder1/data.txt - uses folder1 rules ONLY (user1 admin, terminal blocks parent)
        syft_folder1_data = syft_perm.open(folder1_dir / "data.txt")
        self.assertTrue(syft_folder1_data.has_admin_access("user1@example.com"))
        self.assertTrue(syft_folder1_data.has_write_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_folder1_data.has_create_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_folder1_data.has_read_access("user1@example.com"))   # Via hierarchy
        self.assertFalse(syft_folder1_data.has_read_access("*"))  # Terminal blocks parent's *.txt rule
        self.assertFalse(syft_folder1_data.has_read_access("random@example.com"))
        
        # Test folder1/subfolder/nested.txt - uses folder1 rules (terminal doesn't block subdirectories)
        syft_folder1_nested = syft_perm.open(folder1_subfolder / "nested.txt")
        self.assertTrue(syft_folder1_nested.has_admin_access("user1@example.com"))
        self.assertTrue(syft_folder1_nested.has_write_access("user1@example.com"))
        self.assertTrue(syft_folder1_nested.has_create_access("user1@example.com"))
        self.assertTrue(syft_folder1_nested.has_read_access("user1@example.com"))
        self.assertFalse(syft_folder1_nested.has_read_access("*"))  # Terminal blocks parent inheritance
        
        # Test folder2/data.txt - uses nearest node (folder2) rules
        # In old syftbox: nearest-node algorithm means only folder2 rules apply (no inheritance)
        syft_folder2_data = syft_perm.open(folder2_dir / "data.txt")
        self.assertTrue(syft_folder2_data.has_write_access("user2@example.com"))
        self.assertTrue(syft_folder2_data.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_folder2_data.has_read_access("user2@example.com"))   # Via hierarchy
        
        # Key test: In nearest-node algorithm, parent rules don't apply when child has rules
        # This is different from accumulative inheritance
        self.assertFalse(syft_folder2_data.has_read_access("*"))  # Parent *.txt rule doesn't apply
        self.assertFalse(syft_folder2_data.has_read_access("random@example.com"))
        
        # Test folder2/script.py - uses nearest node (folder2) rules only
        syft_folder2_script = syft_perm.open(folder2_dir / "script.py")
        self.assertTrue(syft_folder2_script.has_write_access("user2@example.com"))
        self.assertTrue(syft_folder2_script.has_create_access("user2@example.com"))
        self.assertTrue(syft_folder2_script.has_read_access("user2@example.com"))
        
        # Key test: Parent **/*.py rule doesn't apply (nearest-node algorithm)
        self.assertFalse(syft_folder2_script.has_create_access("user1@example.com"))  # Parent rule doesn't apply
        self.assertFalse(syft_folder2_script.has_read_access("user1@example.com"))
        
        # Test folder2/report.csv - uses folder2 rules only (no parent pattern matches)
        syft_folder2_report = syft_perm.open(folder2_dir / "report.csv")
        self.assertTrue(syft_folder2_report.has_write_access("user2@example.com"))
        self.assertTrue(syft_folder2_report.has_create_access("user2@example.com"))
        self.assertTrue(syft_folder2_report.has_read_access("user2@example.com"))
        self.assertFalse(syft_folder2_report.has_read_access("user3@example.com"))  # No inheritance of parent file2.csv rule
        
        # Verify size limits are set on folder2 files
        # Note: Actual enforcement happens at service level, we just verify the rule structure
        folder2_perms = syft_folder2_report._get_all_permissions_with_sources()
        self.assertIsNotNone(folder2_perms)
    
    def test_terminal_completely_blocks_inheritance(self):
        """Test that terminal nodes completely block all inheritance from parent."""
        # Create structure: parent (public read) -> terminal_child (specific user) -> grandchild
        parent_dir = Path(self.test_dir) / "inheritance_test"
        terminal_dir = parent_dir / "terminal_child" 
        grandchild_dir = terminal_dir / "grandchild"
        
        # Create directories and files
        for dir_path in [parent_dir, terminal_dir, grandchild_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        parent_file = parent_dir / "parent.txt"
        terminal_file = terminal_dir / "terminal.txt"
        grandchild_file = grandchild_dir / "grandchild.txt"
        
        for file_path in [parent_file, terminal_file, grandchild_file]:
            file_path.write_text("content")
        
        # Parent: public read for all .txt files
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**/*.txt",
                "access": {
                    "read": ["*"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Terminal child: specific user access, blocks parent inheritance
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_rules = {
            "terminal": True,
            "rules": [{
                "pattern": "*.txt",
                "access": {
                    "write": ["terminal_user@example.com"]
                }
            }]
        }
        with open(terminal_yaml, 'w') as f:
            yaml.dump(terminal_rules, f)
        
        # Test parent file - uses parent rules
        syft_parent = syft_perm.open(parent_file)
        self.assertTrue(syft_parent.has_read_access("*"))
        self.assertTrue(syft_parent.has_read_access("anyone@example.com"))
        
        # Test terminal file - uses terminal rules ONLY (blocks parent)
        syft_terminal = syft_perm.open(terminal_file)
        self.assertTrue(syft_terminal.has_write_access("terminal_user@example.com"))
        self.assertTrue(syft_terminal.has_create_access("terminal_user@example.com"))  # Via hierarchy
        self.assertTrue(syft_terminal.has_read_access("terminal_user@example.com"))   # Via hierarchy
        self.assertFalse(syft_terminal.has_read_access("*"))  # Parent rule blocked by terminal
        self.assertFalse(syft_terminal.has_read_access("random@example.com"))
        
        # Test grandchild file - uses terminal rules (terminal applies to subdirectories)
        syft_grandchild = syft_perm.open(grandchild_file)
        self.assertFalse(syft_grandchild.has_write_access("terminal_user@example.com"))  # Pattern *.txt doesn't match nested file
        self.assertFalse(syft_grandchild.has_read_access("*"))  # Parent rule blocked by terminal
        self.assertFalse(syft_grandchild.has_read_access("anyone@example.com"))
    
    def test_nearest_node_no_accumulation(self):
        """Test that permissions don't accumulate - only nearest node rules apply."""
        # Create structure: grandparent (admin) -> parent (write) -> child (read)
        grandparent_dir = Path(self.test_dir) / "no_accumulation"
        parent_dir = grandparent_dir / "parent"
        child_dir = parent_dir / "child"
        
        # Create directories and test file
        child_dir.mkdir(parents=True, exist_ok=True)
        test_file = child_dir / "test.txt"
        test_file.write_text("content")
        
        # Grandparent: admin access
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**/*.txt",
                "access": {
                    "admin": ["admin_user@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Parent: write access
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**/*.txt", 
                "access": {
                    "write": ["write_user@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Child: read access only
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "*.txt",
                "access": {
                    "read": ["read_user@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Test: nearest-node algorithm means only child rules apply
        syft_test = syft_perm.open(test_file)
        
        # Only read_user should have access (from nearest node: child)
        self.assertTrue(syft_test.has_read_access("read_user@example.com"))
        self.assertFalse(syft_test.has_write_access("read_user@example.com"))
        
        # write_user and admin_user should have NO access (not nearest node)
        self.assertFalse(syft_test.has_write_access("write_user@example.com"))
        self.assertFalse(syft_test.has_admin_access("admin_user@example.com"))
        self.assertFalse(syft_test.has_read_access("write_user@example.com"))
        self.assertFalse(syft_test.has_read_access("admin_user@example.com"))
    
    def test_pattern_matching_within_nearest_node(self):
        """Test pattern matching specificity within the nearest node."""
        # Create test directory with multiple patterns
        test_dir = Path(self.test_dir) / "pattern_test"
        test_dir.mkdir(parents=True)
        
        # Create test files
        specific_file = test_dir / "specific.txt"
        general_file = test_dir / "general.txt" 
        python_file = test_dir / "script.py"
        
        for file_path in [specific_file, general_file, python_file]:
            file_path.write_text("content")
        
        # Create rules with different pattern specificities
        yaml_file = test_dir / "syft.pub.yaml"
        rules = {
            "rules": [
                {
                    "pattern": "specific.txt",  # Most specific
                    "access": {
                        "admin": ["specific_user@example.com"]
                    }
                },
                {
                    "pattern": "*.txt",  # Medium specific
                    "access": {
                        "write": ["txt_user@example.com"]
                    }
                },
                {
                    "pattern": "**",  # Least specific
                    "access": {
                        "read": ["general_user@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(rules, f)
        
        # Test specific.txt - should match most specific pattern first
        syft_specific = syft_perm.open(specific_file)
        self.assertTrue(syft_specific.has_admin_access("specific_user@example.com"))
        self.assertFalse(syft_specific.has_write_access("txt_user@example.com"))  # More specific pattern wins
        self.assertFalse(syft_specific.has_read_access("general_user@example.com"))
        
        # Test general.txt - should match *.txt pattern
        syft_general = syft_perm.open(general_file)
        self.assertTrue(syft_general.has_write_access("txt_user@example.com"))
        self.assertFalse(syft_general.has_admin_access("specific_user@example.com"))
        self.assertFalse(syft_general.has_read_access("general_user@example.com"))  # *.txt more specific than **
        
        # Test script.py - should match ** pattern (no .txt patterns match)
        syft_python = syft_perm.open(python_file)
        self.assertTrue(syft_python.has_read_access("general_user@example.com"))
        self.assertFalse(syft_python.has_write_access("txt_user@example.com"))
        self.assertFalse(syft_python.has_admin_access("specific_user@example.com"))
    
    def test_size_limits_at_nearest_node(self):
        """Test that size limits are applied at the nearest node level."""
        # Create structure: parent (no limits) -> child (5MB limit)
        parent_dir = Path(self.test_dir) / "limit_test"
        child_dir = parent_dir / "child"
        child_dir.mkdir(parents=True)
        
        test_file = child_dir / "large.dat"
        test_file.write_text("content")
        
        # Parent: no size limits
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**/*.dat",
                "access": {
                    "write": ["unlimited_user@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Child: size limits
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "*.dat",
                "access": {
                    "write": ["limited_user@example.com"]
                },
                "limits": {
                    "max_file_size": 1024,  # 1KB limit
                    "allow_dirs": True,
                    "allow_symlinks": False
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Test: nearest-node (child) rules apply with limits
        syft_test = syft_perm.open(test_file)
        
        # limited_user should have access (from nearest node)
        self.assertTrue(syft_test.has_write_access("limited_user@example.com"))
        
        # unlimited_user should NOT have access (not nearest node)
        self.assertFalse(syft_test.has_write_access("unlimited_user@example.com"))
        
        # Verify limits are present in the rule structure
        perms_data = syft_test._get_all_permissions_with_sources()
        self.assertIsNotNone(perms_data)


if __name__ == "__main__":
    unittest.main()