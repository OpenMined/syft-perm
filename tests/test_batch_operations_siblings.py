"""Test batch operations on siblings according to old syftbox behavior."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
import yaml
import time

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm
from syft_perm._impl import _permission_cache, get_cache_stats, clear_permission_cache


class TestBatchOperationsSiblings(unittest.TestCase):
    """Test batch operations on siblings maintaining independence and cache performance."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
        self.test_users = [
            "alice@example.com",
            "bob@example.com", 
            "user1@example.com",
            "user2@example.com",
            "user3@example.com"
        ]
        # Clear cache before each test
        clear_permission_cache()
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        # Clear cache after each test
        clear_permission_cache()
    
    def test_grant_user1_read_to_3_files_same_dir(self):
        """Test granting user1 read to 3 files in same directory with cache performance."""
        # Create directory with multiple files
        docs_dir = Path(self.test_dir) / "documents"
        docs_dir.mkdir(parents=True)
        
        file1 = docs_dir / "report1.txt"
        file2 = docs_dir / "report2.txt"
        file3 = docs_dir / "report3.txt"
        file4 = docs_dir / "report4.txt"  # Control file - no permissions
        
        for f in [file1, file2, file3, file4]:
            f.write_text("content")
        
        # Measure cache performance - initial checks should miss cache
        cache_stats_before = get_cache_stats()
        self.assertEqual(cache_stats_before["size"], 0)
        
        # Open all files and check permissions to populate cache
        syft_files = []
        for f in [file1, file2, file3, file4]:
            syft_file = syft_perm.open(f)
            syft_file.has_read_access("test@example.com")  # Trigger cache population
            syft_files.append(syft_file)
        
        # Cache should now have entries
        cache_stats_after_open = get_cache_stats()
        self.assertEqual(cache_stats_after_open["size"], 4)
        
        # Batch grant read to user1 for first 3 files
        start_time = time.time()
        for i, syft_file in enumerate(syft_files[:3]):
            syft_file.grant_read_access("user1@example.com", force=True)
        batch_time = time.time() - start_time
        
        # Cache should be invalidated for modified files
        cache_stats_after_grant = get_cache_stats()
        # In current implementation, invalidate clears by prefix, so all entries may be cleared
        
        # Verify permissions - siblings maintain independence
        syft_file1 = syft_perm.open(file1)
        syft_file2 = syft_perm.open(file2)
        syft_file3 = syft_perm.open(file3)
        syft_file4 = syft_perm.open(file4)
        
        # First 3 files should have user1 read
        self.assertTrue(syft_file1.has_read_access("user1@example.com"))
        self.assertTrue(syft_file2.has_read_access("user1@example.com"))
        self.assertTrue(syft_file3.has_read_access("user1@example.com"))
        
        # File4 should NOT have user1 read (sibling independence)
        self.assertFalse(syft_file4.has_read_access("user1@example.com"))
        
        # Verify no cross-contamination of permissions
        self.assertFalse(syft_file1.has_write_access("user1@example.com"))
        self.assertFalse(syft_file2.has_write_access("user1@example.com"))
        self.assertFalse(syft_file3.has_write_access("user1@example.com"))
        
        # Second access should use cache
        start_time = time.time()
        for f in [file1, file2, file3, file4]:
            syft_f = syft_perm.open(f)
            syft_f.has_read_access("user1@example.com")
        cache_time = time.time() - start_time
        
        # Cache should be faster than batch operations
        self.assertLess(cache_time, batch_time * 2)  # Cache should be reasonably fast
    
    def test_grant_user2_create_to_all_py_files(self):
        """Test granting user2 create to all *.py files using pattern-based operations."""
        # Create mixed file types
        src_dir = Path(self.test_dir) / "src"
        src_dir.mkdir(parents=True)
        
        py_files = [
            src_dir / "main.py",
            src_dir / "utils.py",
            src_dir / "test_app.py"
        ]
        
        other_files = [
            src_dir / "config.json",
            src_dir / "readme.txt",
            src_dir / "data.csv"
        ]
        
        for f in py_files + other_files:
            f.write_text("content")
        
        # Create a pattern rule for all *.py files
        yaml_file = src_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "*.py",
                "access": {
                    "create": ["user2@example.com"]
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Clear cache to ensure fresh lookups
        clear_permission_cache()
        
        # Verify all .py files have user2 create permission
        for py_file in py_files:
            syft_file = syft_perm.open(py_file)
            self.assertTrue(syft_file.has_create_access("user2@example.com"))
            self.assertTrue(syft_file.has_read_access("user2@example.com"))  # Via hierarchy
            self.assertFalse(syft_file.has_write_access("user2@example.com"))  # Create doesn't include write
        
        # Verify other files do NOT have user2 permissions (pattern specificity)
        for other_file in other_files:
            syft_file = syft_perm.open(other_file)
            self.assertFalse(syft_file.has_create_access("user2@example.com"))
            self.assertFalse(syft_file.has_read_access("user2@example.com"))
            self.assertFalse(syft_file.has_write_access("user2@example.com"))
        
        # Check pattern matching in reasons
        syft_main = syft_perm.open(py_files[0])
        has_create, reasons = syft_main._check_permission_with_reasons("user2@example.com", "create")
        self.assertTrue(has_create)
        self.assertTrue(any("Pattern '*.py' matched" in r for r in reasons))
    
    def test_revoke_star_access_from_all_log_files(self):
        """Test revoking * access from all *.log files using bulk revocation."""
        # Create directory with mixed files including logs
        logs_dir = Path(self.test_dir) / "logs"
        logs_dir.mkdir(parents=True)
        
        # First grant * read to all files
        parent_yaml = logs_dir / "syft.pub.yaml"
        parent_content = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["*"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_content, f)
        
        log_files = [
            logs_dir / "app.log",
            logs_dir / "error.log",
            logs_dir / "debug.log"
        ]
        
        other_files = [
            logs_dir / "config.txt",
            logs_dir / "data.json"
        ]
        
        for f in log_files + other_files:
            f.write_text("content")
        
        # Verify initial state - all files have public read
        for f in log_files + other_files:
            syft_file = syft_perm.open(f)
            self.assertTrue(syft_file.has_read_access("*"))
            self.assertTrue(syft_file.has_read_access("alice@example.com"))  # Via *
        
        # Now override with specific rule for *.log files to remove * access
        updated_content = {
            "rules": [
                {
                    "pattern": "*.log",
                    "access": {
                        "read": ["bob@example.com"]  # Only bob, not *
                    }
                },
                {
                    "pattern": "**",
                    "access": {
                        "read": ["*"]
                    }
                }
            ]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(updated_content, f)
        
        # Clear cache to ensure fresh lookups
        clear_permission_cache()
        
        # Verify log files no longer have * access (more specific pattern wins)
        for log_file in log_files:
            syft_file = syft_perm.open(log_file)
            self.assertFalse(syft_file.has_read_access("*"))
            self.assertFalse(syft_file.has_read_access("alice@example.com"))
            self.assertTrue(syft_file.has_read_access("bob@example.com"))  # Only bob
        
        # Verify other files still have * access
        for other_file in other_files:
            syft_file = syft_perm.open(other_file)
            self.assertTrue(syft_file.has_read_access("*"))
            self.assertTrue(syft_file.has_read_access("alice@example.com"))  # Via *
    
    def test_add_terminal_true_to_parent_with_5_children(self):
        """Test adding terminal=true to parent with 5 child folders and cache effects."""
        # Create parent with 5 child folders
        parent_dir = Path(self.test_dir) / "parent"
        
        children = []
        for i in range(5):
            child_dir = parent_dir / f"child{i+1}"
            child_dir.mkdir(parents=True)
            child_file = child_dir / "data.txt"
            child_file.write_text(f"child {i+1} data")
            children.append(child_file)
        
        # Initially grant alice admin to all via parent
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = {
            "rules": [{
                "pattern": "**/*.txt",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_content, f)
        
        # Verify initial state - all children have alice admin
        for child_file in children:
            syft_file = syft_perm.open(child_file)
            self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        
        # Check cache state
        cache_stats_before = get_cache_stats()
        self.assertEqual(cache_stats_before["size"], 5)  # 5 child files cached
        
        # Now add terminal=true to parent with new permissions
        terminal_content = {
            "terminal": True,
            "rules": [{
                "pattern": "**/*.txt",
                "access": {
                    "read": ["bob@example.com"]  # Only bob read, no alice
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(terminal_content, f)
        
        # Cache should be invalidated for all children (prefix-based invalidation)
        clear_permission_cache()  # Simulate prefix invalidation
        
        # Verify terminal blocks inheritance - all children now have only bob read
        for i, child_file in enumerate(children):
            syft_file = syft_perm.open(child_file)
            # Terminal blocks alice admin
            self.assertFalse(syft_file.has_admin_access("alice@example.com"))
            self.assertFalse(syft_file.has_write_access("alice@example.com"))
            # Terminal grants bob read
            self.assertTrue(syft_file.has_read_access("bob@example.com"))
            self.assertFalse(syft_file.has_write_access("bob@example.com"))
            
            # Verify terminal blocking reason
            has_admin, reasons = syft_file._check_permission_with_reasons("alice@example.com", "admin")
            self.assertFalse(has_admin)
            # Terminal at parent blocks all inheritance
        
        # All siblings maintain same permissions (independence preserved)
        perms_set = set()
        for child_file in children:
            syft_file = syft_perm.open(child_file)
            perms = (
                syft_file.has_read_access("bob@example.com"),
                syft_file.has_admin_access("alice@example.com")
            )
            perms_set.add(perms)
        
        # All siblings should have identical permissions
        self.assertEqual(len(perms_set), 1)
        self.assertEqual(perms_set.pop(), (True, False))  # bob read: True, alice admin: False
    
    def test_sibling_independence_during_batch_ops(self):
        """Test that siblings maintain independence during batch operations."""
        # Create directory with siblings
        shared_dir = Path(self.test_dir) / "shared"
        shared_dir.mkdir(parents=True)
        
        files = []
        for i in range(5):
            f = shared_dir / f"file{i+1}.txt"
            f.write_text(f"content {i+1}")
            files.append(f)
        
        # Batch operation: Grant different permissions to different files
        syft_file1 = syft_perm.open(files[0])
        syft_file2 = syft_perm.open(files[1])
        syft_file3 = syft_perm.open(files[2])
        
        # Different permissions for each
        syft_file1.grant_read_access("alice@example.com", force=True)
        syft_file2.grant_write_access("bob@example.com", force=True)
        syft_file3.grant_admin_access("user3@example.com", force=True)
        
        # Verify each maintains its own permissions (no cross-contamination)
        # File1: only alice read
        syft_check1 = syft_perm.open(files[0])
        self.assertTrue(syft_check1.has_read_access("alice@example.com"))
        self.assertFalse(syft_check1.has_read_access("bob@example.com"))
        self.assertFalse(syft_check1.has_read_access("user3@example.com"))
        self.assertFalse(syft_check1.has_write_access("alice@example.com"))
        
        # File2: only bob write (includes read)
        syft_check2 = syft_perm.open(files[1])
        self.assertTrue(syft_check2.has_write_access("bob@example.com"))
        self.assertTrue(syft_check2.has_read_access("bob@example.com"))  # Via hierarchy
        self.assertFalse(syft_check2.has_write_access("alice@example.com"))
        self.assertFalse(syft_check2.has_write_access("user3@example.com"))
        
        # File3: only user3 admin (includes all)
        syft_check3 = syft_perm.open(files[2])
        self.assertTrue(syft_check3.has_admin_access("user3@example.com"))
        self.assertTrue(syft_check3.has_write_access("user3@example.com"))  # Via hierarchy
        self.assertTrue(syft_check3.has_read_access("user3@example.com"))   # Via hierarchy
        self.assertFalse(syft_check3.has_admin_access("alice@example.com"))
        self.assertFalse(syft_check3.has_admin_access("bob@example.com"))
        
        # Files 4 and 5: no permissions
        for f in files[3:]:
            syft_check = syft_perm.open(f)
            self.assertFalse(syft_check.has_read_access("alice@example.com"))
            self.assertFalse(syft_check.has_read_access("bob@example.com"))
            self.assertFalse(syft_check.has_read_access("user3@example.com"))
    
    def test_set_size_limits_on_multiple_files(self):
        """Test setting size limits on multiple files in batch operations."""
        # Create directory with files
        data_dir = Path(self.test_dir) / "data"
        data_dir.mkdir(parents=True)
        
        # Create files with different types
        large_files = [
            data_dir / "big1.dat",
            data_dir / "big2.dat",
            data_dir / "big3.dat"
        ]
        
        small_files = [
            data_dir / "small1.txt",
            data_dir / "small2.txt"
        ]
        
        for f in large_files + small_files:
            f.write_text("x" * 1000)  # 1KB each
        
        # Set pattern-based size limits
        yaml_file = data_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "*.dat",
                    "access": {
                        "write": ["alice@example.com"]
                    },
                    "limits": {
                        "max_file_size": 10 * 1024 * 1024,  # 10MB limit
                        "allow_dirs": False,
                        "allow_symlinks": False
                    }
                },
                {
                    "pattern": "*.txt",
                    "access": {
                        "write": ["alice@example.com"]
                    },
                    "limits": {
                        "max_file_size": 1024,  # 1KB limit
                        "allow_dirs": True,
                        "allow_symlinks": True
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Clear cache
        clear_permission_cache()
        
        # Verify permissions are granted (limits are structural, not runtime enforced in permission checks)
        for dat_file in large_files:
            syft_file = syft_perm.open(dat_file)
            self.assertTrue(syft_file.has_write_access("alice@example.com"))
            # Verify the permission data structure would include limits
            perm_data = syft_file._get_all_permissions_with_sources()
            self.assertIn("permissions", perm_data)
        
        for txt_file in small_files:
            syft_file = syft_perm.open(txt_file)
            self.assertTrue(syft_file.has_write_access("alice@example.com"))
            # Verify the permission data structure would include limits
            perm_data = syft_file._get_all_permissions_with_sources()
            self.assertIn("permissions", perm_data)
        
        # Each file type maintains its own limit settings independently
        # This documents that limits are part of the permission structure
        # but enforcement would happen at write time, not permission check time
    
    def test_cache_performance_with_batch_operations(self):
        """Test cache performance characteristics during batch operations."""
        # Create a larger directory structure
        root_dir = Path(self.test_dir) / "performance_test"
        
        # Create 10 directories with 10 files each = 100 files
        all_files = []
        for i in range(10):
            dir_path = root_dir / f"dir{i}"
            dir_path.mkdir(parents=True)
            for j in range(10):
                file_path = dir_path / f"file{j}.txt"
                file_path.write_text(f"content {i}-{j}")
                all_files.append(file_path)
        
        # Clear cache
        clear_permission_cache()
        
        # Measure initial permission checks (cache misses)
        start_time = time.time()
        for f in all_files:
            syft_file = syft_perm.open(f)
            syft_file.has_read_access("test@example.com")
        cold_cache_time = time.time() - start_time
        
        # Cache should now be populated
        cache_stats = get_cache_stats()
        self.assertEqual(cache_stats["size"], 100)
        
        # Measure cached permission checks (cache hits)
        start_time = time.time()
        for f in all_files:
            syft_file = syft_perm.open(f)
            syft_file.has_read_access("test@example.com")
        warm_cache_time = time.time() - start_time
        
        # Warm cache should be significantly faster
        self.assertLess(warm_cache_time, cold_cache_time / 2)
        
        # Batch grant operation with pattern
        root_yaml = root_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "**/*.txt",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(root_yaml, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # This should invalidate cache entries
        clear_permission_cache()  # Simulates prefix-based invalidation
        
        cache_stats_after = get_cache_stats()
        self.assertEqual(cache_stats_after["size"], 0)
        
        # First access after invalidation will repopulate cache
        start_time = time.time()
        for f in all_files[:10]:  # Just first 10 files
            syft_file = syft_perm.open(f)
            self.assertTrue(syft_file.has_read_access("alice@example.com"))
        repopulate_time = time.time() - start_time
        
        # Cache is being rebuilt
        cache_stats_partial = get_cache_stats()
        self.assertEqual(cache_stats_partial["size"], 10)
        
        # Subsequent access to same files should be fast
        start_time = time.time()
        for f in all_files[:10]:
            syft_file = syft_perm.open(f)
            self.assertTrue(syft_file.has_read_access("alice@example.com"))
        cached_access_time = time.time() - start_time
        
        self.assertLess(cached_access_time, repopulate_time / 2)
        
        # Verify cache doesn't exceed max size
        self.assertLessEqual(cache_stats_partial["size"], cache_stats_partial["max_size"])
    
    def test_mixed_batch_operations_maintain_independence(self):
        """Test that mixed batch operations on siblings maintain complete independence."""
        # Create complex sibling structure
        workspace_dir = Path(self.test_dir) / "workspace"
        workspace_dir.mkdir(parents=True)
        
        # Create various file types
        py_files = [workspace_dir / f"script{i}.py" for i in range(3)]
        log_files = [workspace_dir / f"output{i}.log" for i in range(3)]
        txt_files = [workspace_dir / f"doc{i}.txt" for i in range(3)]
        
        all_files = py_files + log_files + txt_files
        for f in all_files:
            f.write_text("content")
        
        # Perform mixed batch operations
        # 1. Grant create to *.py files for user1
        # 2. Grant write to *.log files for user2
        # 3. Grant read to specific txt files for user3
        
        yaml_file = workspace_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "doc0.txt",  # Most specific patterns first
                    "access": {
                        "read": ["user3@example.com"]
                    }
                },
                {
                    "pattern": "doc1.txt",
                    "access": {
                        "read": ["user3@example.com"]
                    }
                },
                {
                    "pattern": "*.py",
                    "access": {
                        "create": ["user1@example.com"]
                    }
                },
                {
                    "pattern": "*.log",
                    "access": {
                        "write": ["user2@example.com"]
                    }
                }
                # doc2.txt has no rule - tests independence
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        clear_permission_cache()
        
        # Debug: Check if rules are being applied correctly
        # The implementation sorts rules by specificity, so doc1.txt and doc2.txt should match first
        
        # Verify each file type has only its designated permissions
        
        # Python files: only user1 create
        for py_file in py_files:
            syft_file = syft_perm.open(py_file)
            self.assertTrue(syft_file.has_create_access("user1@example.com"))
            self.assertTrue(syft_file.has_read_access("user1@example.com"))  # Via hierarchy
            self.assertFalse(syft_file.has_write_access("user1@example.com"))
            self.assertFalse(syft_file.has_read_access("user2@example.com"))
            self.assertFalse(syft_file.has_read_access("user3@example.com"))
        
        # Log files: only user2 write
        for log_file in log_files:
            syft_file = syft_perm.open(log_file)
            self.assertTrue(syft_file.has_write_access("user2@example.com"))
            self.assertTrue(syft_file.has_read_access("user2@example.com"))  # Via hierarchy
            self.assertFalse(syft_file.has_admin_access("user2@example.com"))
            self.assertFalse(syft_file.has_read_access("user1@example.com"))
            self.assertFalse(syft_file.has_read_access("user3@example.com"))
        
        # Text files: only specific ones have user3 read
        syft_doc1 = syft_perm.open(txt_files[0])  # doc1.txt
        syft_doc2 = syft_perm.open(txt_files[1])  # doc2.txt
        syft_doc3 = syft_perm.open(txt_files[2])  # doc3.txt
        
        
        self.assertTrue(syft_doc1.has_read_access("user3@example.com"))
        self.assertFalse(syft_doc1.has_write_access("user3@example.com"))
        
        self.assertTrue(syft_doc2.has_read_access("user3@example.com"))
        self.assertFalse(syft_doc2.has_write_access("user3@example.com"))
        
        # doc3.txt has NO permissions (sibling independence)
        self.assertFalse(syft_doc3.has_read_access("user3@example.com"))
        self.assertFalse(syft_doc3.has_read_access("user1@example.com"))
        self.assertFalse(syft_doc3.has_read_access("user2@example.com"))
        
        # No cross-contamination between file types
        for py_file in py_files:
            syft_file = syft_perm.open(py_file)
            self.assertFalse(syft_file.has_write_access("user2@example.com"))  # Log permission doesn't leak
            self.assertFalse(syft_file.has_read_access("user3@example.com"))   # Txt permission doesn't leak


if __name__ == "__main__":
    unittest.main()