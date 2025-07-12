"""Test cross-sibling pattern interactions based on old syftbox behavior."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm
from syft_perm._impl import _permission_cache


class TestCrossSiblingPatternInteractions(unittest.TestCase):
    """Test cross-sibling folder pattern interactions and file moves.
    
    Based on old syftbox behavior:
    - File moves are treated as delete + create operations
    - Permissions are completely re-evaluated based on destination rules
    - No permissions are carried over from source location
    - Size limits are checked at write time, not during permission resolution
    - Each folder's ACL rules are independent (no sibling interaction)
    """
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["user1@example.com", "user2@example.com", 
                          "user3@example.com", "user4@example.com"]
        # Clear cache before each test
        _permission_cache.clear()
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
        # Clear cache after each test
        _permission_cache.clear()
    
    def test_cross_sibling_pattern_interactions_with_moves(self):
        """Test moving files between sibling folders with different pattern rules."""
        # Create base directory structure
        base_dir = Path(self.test_dir) / "project"
        folder1 = base_dir / "folder1"
        folder2 = base_dir / "folder2"
        
        # Create nested structure in folder1
        folder1_deep = folder1 / "deep" / "nested"
        folder1_deep.mkdir(parents=True)
        folder2.mkdir(parents=True)
        
        # Create YAML files for each folder with different rules
        # folder1 rules: *.py for user1, **/*.py for user3
        folder1_yaml = folder1 / "syft.pub.yaml"
        folder1_rules = {
            "rules": [
                {
                    "pattern": "*.py",
                    "access": {
                        "write": ["user1@example.com"]
                    }
                },
                {
                    "pattern": "**/*.py",
                    "access": {
                        "create": ["user3@example.com"]
                    }
                }
            ]
        }
        with open(folder1_yaml, 'w') as f:
            yaml.dump(folder1_rules, f)
        
        # folder2 rules: *.py for user2, **/*.py for user4 with size limit
        folder2_yaml = folder2 / "syft.pub.yaml"
        folder2_rules = {
            "rules": [
                {
                    "pattern": "*.py",
                    "access": {
                        "write": ["user2@example.com"]
                    }
                },
                {
                    "pattern": "**/*.py",
                    "access": {
                        "create": ["user4@example.com"]
                    },
                    "limits": {
                        "max_file_size": 1024 * 1024  # 1MB limit
                    }
                }
            ]
        }
        with open(folder2_yaml, 'w') as f:
            yaml.dump(folder2_rules, f)
        
        # Test 1: Create file.py in folder1 and check permissions
        file_py = folder1 / "file.py"
        file_py.write_text("print('hello')")
        
        syft_file = syft_perm.open(file_py)
        
        # In folder1, file.py matches *.py pattern (more specific than **/*.py)
        # So user1 should have write access, user3 should NOT have create access
        self.assertTrue(syft_file.has_write_access("user1@example.com"))
        self.assertTrue(syft_file.has_create_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_file.has_read_access("user1@example.com"))    # Via hierarchy
        
        self.assertFalse(syft_file.has_write_access("user2@example.com"))
        self.assertFalse(syft_file.has_create_access("user3@example.com"))
        self.assertFalse(syft_file.has_create_access("user4@example.com"))
        
        # Test 2: Create deep/nested/file.py in folder1
        deep_file_py = folder1_deep / "file.py"
        deep_file_py.write_text("print('deep hello')")
        
        syft_deep_file = syft_perm.open(deep_file_py)
        
        # In folder1, deep/nested/file.py only matches **/*.py pattern
        # So only user3 should have create access
        self.assertFalse(syft_deep_file.has_write_access("user1@example.com"))
        self.assertFalse(syft_deep_file.has_write_access("user2@example.com"))
        self.assertTrue(syft_deep_file.has_create_access("user3@example.com"))
        self.assertTrue(syft_deep_file.has_read_access("user3@example.com"))  # Via hierarchy
        self.assertFalse(syft_deep_file.has_create_access("user4@example.com"))
        
        # Test 3: Move file.py from folder1 to folder2
        new_file_py = folder2 / "file.py"
        shutil.move(str(file_py), str(new_file_py))
        
        # Clear cache to simulate fresh permission evaluation (old syftbox doesn't auto-invalidate)
        _permission_cache.clear()
        
        syft_moved_file = syft_perm.open(new_file_py)
        
        # After move to folder2, permissions should be completely different
        # file.py in folder2 matches *.py pattern, so user2 has write
        self.assertFalse(syft_moved_file.has_write_access("user1@example.com"))  # No residual permissions
        self.assertTrue(syft_moved_file.has_write_access("user2@example.com"))   # New permissions
        self.assertTrue(syft_moved_file.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_moved_file.has_read_access("user2@example.com"))    # Via hierarchy
        self.assertFalse(syft_moved_file.has_create_access("user3@example.com")) # No residual permissions
        self.assertFalse(syft_moved_file.has_create_access("user4@example.com")) # *.py more specific
        
        # Verify old file doesn't exist
        self.assertFalse(file_py.exists())
        
        # Test 4: Move deep/nested/file.py from folder1 to folder2
        folder2_deep = folder2 / "deep" / "nested"
        folder2_deep.mkdir(parents=True)
        new_deep_file_py = folder2_deep / "file.py"
        shutil.move(str(deep_file_py), str(new_deep_file_py))
        
        # Clear cache again
        _permission_cache.clear()
        
        syft_moved_deep_file = syft_perm.open(new_deep_file_py)
        
        # After move to folder2/deep/nested/, only matches **/*.py pattern
        # So only user4 should have create access
        self.assertFalse(syft_moved_deep_file.has_write_access("user1@example.com"))  # No residual
        self.assertFalse(syft_moved_deep_file.has_write_access("user2@example.com"))  # *.py doesn't match
        self.assertFalse(syft_moved_deep_file.has_create_access("user3@example.com")) # No residual
        self.assertTrue(syft_moved_deep_file.has_create_access("user4@example.com"))  # New permissions
        self.assertTrue(syft_moved_deep_file.has_read_access("user4@example.com"))    # Via hierarchy
        
        # Test 5: Create a large file to test size limits
        large_file = folder2 / "subdir" / "large.py"
        large_file.parent.mkdir(parents=True)
        large_file.write_text("x" * (2 * 1024 * 1024))  # 2MB file
        
        syft_large_file = syft_perm.open(large_file)
        
        # In the current syft-perm implementation, size limits ARE checked during
        # permission resolution (different from old syftbox where they're only 
        # checked at write time). Since the file exceeds the 1MB limit,
        # the **/*.py rule with size limit is skipped, and no permissions are granted
        self.assertFalse(syft_large_file.has_create_access("user4@example.com"))
        self.assertFalse(syft_large_file.has_read_access("user4@example.com"))
        
        # Test 6: Create a small file that respects size limits
        small_file = folder2 / "subdir" / "small.py"
        small_file.write_text("x" * 1000)  # 1KB file
        
        syft_small_file = syft_perm.open(small_file)
        
        # Small file is under the 1MB limit, so user4 gets permissions
        self.assertTrue(syft_small_file.has_create_access("user4@example.com"))
        self.assertTrue(syft_small_file.has_read_access("user4@example.com"))
        
        # This demonstrates that size limits apply after move - files moved to
        # folder2 are subject to folder2's size restrictions
    
    def test_pattern_specificity_across_siblings(self):
        """Test that pattern specificity is evaluated independently in each sibling folder."""
        # Create sibling folders
        base_dir = Path(self.test_dir) / "workspace"
        module_a = base_dir / "module_a"
        module_b = base_dir / "module_b"
        module_a.mkdir(parents=True)
        module_b.mkdir(parents=True)
        
        # module_a: general pattern less specific than exact match
        module_a_yaml = module_a / "syft.pub.yaml"
        module_a_rules = {
            "rules": [
                {
                    "pattern": "*.py",  # General pattern
                    "access": {
                        "read": ["*"]  # Public read
                    }
                },
                {
                    "pattern": "secret.py",  # Exact match (more specific)
                    "access": {
                        "admin": ["admin@example.com"]
                    }
                }
            ]
        }
        with open(module_a_yaml, 'w') as f:
            yaml.dump(module_a_rules, f)
        
        # module_b: different specificity ordering
        module_b_yaml = module_b / "syft.pub.yaml"
        module_b_rules = {
            "rules": [
                {
                    "pattern": "**/*.py",  # Recursive pattern
                    "access": {
                        "write": ["developer@example.com"]
                    }
                },
                {
                    "pattern": "config/*.py",  # More specific path pattern
                    "access": {
                        "read": ["config_reader@example.com"]
                    }
                }
            ]
        }
        with open(module_b_yaml, 'w') as f:
            yaml.dump(module_b_rules, f)
        
        # Test secret.py in module_a - exact match wins
        secret_a = module_a / "secret.py"
        secret_a.write_text("SECRET_KEY = 'xyz'")
        
        syft_secret_a = syft_perm.open(secret_a)
        self.assertTrue(syft_secret_a.has_admin_access("admin@example.com"))
        self.assertFalse(syft_secret_a.has_read_access("*"))  # More specific rule wins
        
        # Move secret.py to module_b
        secret_b = module_b / "secret.py"
        shutil.move(str(secret_a), str(secret_b))
        _permission_cache.clear()
        
        # In module_b, secret.py only matches **/*.py (no exact rule)
        syft_secret_b = syft_perm.open(secret_b)
        self.assertFalse(syft_secret_b.has_admin_access("admin@example.com"))  # No admin rule in module_b
        self.assertTrue(syft_secret_b.has_write_access("developer@example.com"))  # New permissions
        
        # Test config file in module_b
        config_dir = module_b / "config"
        config_dir.mkdir()
        config_py = config_dir / "settings.py"
        config_py.write_text("DEBUG = True")
        
        syft_config = syft_perm.open(config_py)
        # config/*.py is more specific than **/*.py
        self.assertTrue(syft_config.has_read_access("config_reader@example.com"))
        self.assertFalse(syft_config.has_write_access("developer@example.com"))  # Less specific rule
    
    def test_no_permission_carryover_on_move(self):
        """Test that custom permissions don't carry over when files are moved."""
        # Create two folders with different default rules
        src_dir = Path(self.test_dir) / "source"
        dst_dir = Path(self.test_dir) / "destination"
        src_dir.mkdir(parents=True)
        dst_dir.mkdir(parents=True)
        
        # Source has permissive defaults
        src_yaml = src_dir / "syft.pub.yaml"
        src_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["*"]
                }
            }]
        }
        with open(src_yaml, 'w') as f:
            yaml.dump(src_rules, f)
        
        # Destination has restrictive defaults
        dst_yaml = dst_dir / "syft.pub.yaml"
        dst_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["trusted@example.com"]
                }
            }]
        }
        with open(dst_yaml, 'w') as f:
            yaml.dump(dst_rules, f)
        
        # Create a file in source
        test_file = src_dir / "data.txt"
        test_file.write_text("public data")
        
        # Check initial permissions from pattern
        syft_src = syft_perm.open(test_file)
        self.assertTrue(syft_src.has_read_access("*"))  # From pattern
        self.assertTrue(syft_src.has_read_access("anyone@example.com"))  # Public means anyone
        
        # Also create a file with specific pattern-based permission
        py_file = src_dir / "script.py"
        py_file.write_text("print('hello')")
        
        # Add a specific pattern rule for .py files
        src_rules["rules"].append({
            "pattern": "*.py",
            "access": {
                "write": ["writer@example.com"]
            }
        })
        with open(src_yaml, 'w') as f:
            yaml.dump(src_rules, f)
        _permission_cache.clear()
        
        # Verify .py file has write permission from pattern
        syft_py = syft_perm.open(py_file)
        self.assertTrue(syft_py.has_write_access("writer@example.com"))  # From *.py pattern
        
        # Move file to destination
        dst_file = dst_dir / "data.txt"
        shutil.move(str(test_file), str(dst_file))
        _permission_cache.clear()
        
        # Check permissions in destination
        syft_dst = syft_perm.open(dst_file)
        
        # Should have destination's permissions only
        self.assertFalse(syft_dst.has_read_access("*"))  # No public read in destination
        self.assertTrue(syft_dst.has_read_access("trusted@example.com"))  # Destination's rule
        
        # Move the .py file too
        dst_py = dst_dir / "script.py"
        shutil.move(str(py_file), str(dst_py))
        _permission_cache.clear()
        
        syft_dst_py = syft_perm.open(dst_py)
        # The .py file now only has destination's general ** rule permissions
        self.assertFalse(syft_dst_py.has_write_access("writer@example.com"))  # Source permission not carried
        self.assertTrue(syft_dst_py.has_read_access("trusted@example.com"))  # Destination's ** rule
        
        # This demonstrates that in old syftbox, moves are delete+create operations,
        # and permissions are completely re-evaluated based on destination rules


if __name__ == "__main__":
    unittest.main()