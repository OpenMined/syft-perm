"""Test movement between multi-file directories based on old syftbox behavior."""

import unittest
import tempfile
import shutil
import os
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm
from syft_perm._impl import _permission_cache


class TestMovementBetweenDirectories(unittest.TestCase):
    """Test file/folder movement between directories with different permission structures.
    
    Based on old syftbox behavior analysis:
    - Moves are simple filesystem operations (os.rename)
    - No cache invalidation occurs during moves
    - Permissions are determined by current location (destination) 
    - No preservation of source permissions
    - Files immediately get permissions based on destination directory rules
    """
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        # Clear cache before each test
        _permission_cache.clear()
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
        # Clear cache after each test  
        _permission_cache.clear()
    
    def test_move_file_from_dir_with_3_files_to_dir_with_2_files(self):
        """Test moving file between directories with different file counts (basic move)."""
        # Create source directory with 3 files and permissive rules
        source_dir = Path(self.test_dir) / "source_3files"
        source_dir.mkdir(parents=True)
        
        # Create 3 files in source
        file1 = source_dir / "file1.txt"
        file2 = source_dir / "file2.txt" 
        file3 = source_dir / "file3.txt"
        file1.write_text("content1")
        file2.write_text("content2")
        file3.write_text("content3")
        
        # Source directory has write permissions for alice
        source_yaml = source_dir / "syft.pub.yaml"
        source_rules = {
            "rules": [{
                "pattern": "*.txt",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(source_yaml, 'w') as f:
            yaml.dump(source_rules, f)
        
        # Create destination directory with 2 files and restrictive rules
        dest_dir = Path(self.test_dir) / "dest_2files"
        dest_dir.mkdir(parents=True)
        
        # Create 2 files in destination
        dest_file1 = dest_dir / "existing1.txt"
        dest_file2 = dest_dir / "existing2.txt"
        dest_file1.write_text("existing1")
        dest_file2.write_text("existing2")
        
        # Destination directory has only read permissions for bob
        dest_yaml = dest_dir / "syft.pub.yaml"
        dest_rules = {
            "rules": [{
                "pattern": "*.txt",
                "access": {
                    "read": ["bob@example.com"]
                }
            }]
        }
        with open(dest_yaml, 'w') as f:
            yaml.dump(dest_rules, f)
        
        # Verify source permissions before move
        syft_file1_before = syft_perm.open(file1)
        self.assertTrue(syft_file1_before.has_write_access("alice@example.com"))
        self.assertFalse(syft_file1_before.has_read_access("bob@example.com"))
        
        # Move file1 from source to destination (simulating old syftbox os.rename behavior)
        moved_file = dest_dir / "file1.txt"
        os.rename(str(file1), str(moved_file))
        
        # Verify moved file now has destination permissions (no cache invalidation in old syftbox)
        syft_moved_file = syft_perm.open(moved_file)
        self.assertFalse(syft_moved_file.has_write_access("alice@example.com"))  # Lost source permissions
        self.assertTrue(syft_moved_file.has_read_access("bob@example.com"))      # Gained dest permissions
        
        # Verify other files in source still have source permissions
        syft_file2 = syft_perm.open(file2)
        self.assertTrue(syft_file2.has_write_access("alice@example.com"))
        self.assertFalse(syft_file2.has_read_access("bob@example.com"))
        
        # Verify existing files in destination still have destination permissions
        syft_dest_file1 = syft_perm.open(dest_file1)
        self.assertTrue(syft_dest_file1.has_read_access("bob@example.com"))
        self.assertFalse(syft_dest_file1.has_write_access("alice@example.com"))
    
    def test_move_file_with_specific_permissions_among_siblings_with_patterns(self):
        """Test moving file with specific permissions among sibling files with pattern rules."""
        # Create parent directory
        parent_dir = Path(self.test_dir) / "parent"
        parent_dir.mkdir(parents=True)
        
        # Create multiple subdirectories with different patterns
        dir_txt = parent_dir / "txt_files"
        dir_py = parent_dir / "py_files" 
        dir_txt.mkdir()
        dir_py.mkdir()
        
        # txt_files directory - specific permissions for .txt files
        txt_yaml = dir_txt / "syft.pub.yaml"
        txt_rules = {
            "rules": [{
                "pattern": "*.txt",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }, {
                "pattern": "*.py", 
                "access": {
                    "read": ["charlie@example.com"]
                }
            }]
        }
        with open(txt_yaml, 'w') as f:
            yaml.dump(txt_rules, f)
        
        # py_files directory - different permissions for same patterns
        py_yaml = dir_py / "syft.pub.yaml"
        py_rules = {
            "rules": [{
                "pattern": "*.txt",
                "access": {
                    "read": ["bob@example.com"]
                }
            }, {
                "pattern": "*.py",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(py_yaml, 'w') as f:
            yaml.dump(py_rules, f)
        
        # Create files in both directories
        txt_file = dir_txt / "document.txt"
        py_file = dir_txt / "script.py"
        txt_file.write_text("document content")
        py_file.write_text("python script")
        
        # Verify initial permissions
        syft_txt_before = syft_perm.open(txt_file)
        syft_py_before = syft_perm.open(py_file)
        
        self.assertTrue(syft_txt_before.has_admin_access("alice@example.com"))
        self.assertFalse(syft_txt_before.has_read_access("bob@example.com"))
        
        self.assertTrue(syft_py_before.has_read_access("charlie@example.com"))
        self.assertFalse(syft_py_before.has_write_access("alice@example.com"))
        
        # Move both files to py_files directory
        moved_txt = dir_py / "document.txt"
        moved_py = dir_py / "script.py"
        
        os.rename(str(txt_file), str(moved_txt))
        os.rename(str(py_file), str(moved_py))
        
        # Verify permissions changed based on destination patterns
        syft_moved_txt = syft_perm.open(moved_txt)
        syft_moved_py = syft_perm.open(moved_py)
        
        # document.txt now follows py_files/*.txt rule (read for bob)
        self.assertFalse(syft_moved_txt.has_admin_access("alice@example.com"))  # Lost admin
        self.assertTrue(syft_moved_txt.has_read_access("bob@example.com"))      # Gained read
        
        # script.py now follows py_files/*.py rule (write for alice)
        self.assertFalse(syft_moved_py.has_read_access("charlie@example.com"))  # Lost read for charlie
        self.assertTrue(syft_moved_py.has_write_access("alice@example.com"))    # Gained write for alice
    
    def test_move_folder_from_mixed_to_empty_directory(self):
        """Test moving folder from directory with mixed files/folders to empty directory."""
        # Create source directory with mixed content
        source_parent = Path(self.test_dir) / "mixed_source"
        source_parent.mkdir(parents=True)
        
        # Create mixed content in source parent
        source_file1 = source_parent / "file1.txt"
        source_file1.write_text("source file")
        
        target_folder = source_parent / "target_folder"
        target_folder.mkdir()
        
        folder_file = target_folder / "folder_content.txt"
        folder_file.write_text("folder content")
        
        source_subfolder = source_parent / "other_folder"
        source_subfolder.mkdir()
        
        # Source parent has admin permissions
        source_yaml = source_parent / "syft.pub.yaml"
        source_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(source_yaml, 'w') as f:
            yaml.dump(source_rules, f)
        
        # Create empty destination directory with different permissions
        dest_parent = Path(self.test_dir) / "empty_dest"
        dest_parent.mkdir(parents=True)
        
        # Destination has only read permissions
        dest_yaml = dest_parent / "syft.pub.yaml"
        dest_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["bob@example.com"]
                }
            }]
        }
        with open(dest_yaml, 'w') as f:
            yaml.dump(dest_rules, f)
        
        # Verify permissions before move
        syft_folder_file_before = syft_perm.open(folder_file)
        self.assertTrue(syft_folder_file_before.has_admin_access("alice@example.com"))
        self.assertFalse(syft_folder_file_before.has_read_access("bob@example.com"))
        
        # Move entire folder to destination (simulating old syftbox behavior)
        moved_folder = dest_parent / "target_folder"
        os.rename(str(target_folder), str(moved_folder))
        
        # Verify folder content now has destination permissions
        moved_folder_file = moved_folder / "folder_content.txt"
        syft_moved_folder_file = syft_perm.open(moved_folder_file)
        
        self.assertFalse(syft_moved_folder_file.has_admin_access("alice@example.com"))  # Lost admin
        self.assertTrue(syft_moved_folder_file.has_read_access("bob@example.com"))      # Gained read
        
        # Verify original source files still have source permissions
        syft_source_file1 = syft_perm.open(source_file1)
        self.assertTrue(syft_source_file1.has_admin_access("alice@example.com"))
    
    def test_move_between_dirs_with_same_ext_patterns(self):
        """Test moving between directories where both have *.ext patterns."""
        # Create two directories with same pattern but different permissions
        dir_a = Path(self.test_dir) / "dir_a"
        dir_b = Path(self.test_dir) / "dir_b"
        dir_a.mkdir(parents=True)
        dir_b.mkdir(parents=True)
        
        # Both directories have *.log pattern but different permissions
        yaml_a = dir_a / "syft.pub.yaml"
        rules_a = {
            "rules": [{
                "pattern": "*.log",
                "access": {
                    "write": ["alice@example.com"],
                    "read": ["*"]  # Public read
                }
            }]
        }
        with open(yaml_a, 'w') as f:
            yaml.dump(rules_a, f)
        
        yaml_b = dir_b / "syft.pub.yaml"
        rules_b = {
            "rules": [{
                "pattern": "*.log",
                "access": {
                    "admin": ["bob@example.com"]
                    # No public read
                }
            }]
        }
        with open(yaml_b, 'w') as f:
            yaml.dump(rules_b, f)
        
        # Create log file in dir_a
        log_file = dir_a / "application.log"
        log_file.write_text("log content")
        
        # Verify initial permissions in dir_a
        syft_log_before = syft_perm.open(log_file)
        self.assertTrue(syft_log_before.has_write_access("alice@example.com"))
        self.assertTrue(syft_log_before.has_read_access("charlie@example.com"))  # Public read
        self.assertFalse(syft_log_before.has_admin_access("bob@example.com"))
        
        # Move log file to dir_b
        moved_log = dir_b / "application.log"
        os.rename(str(log_file), str(moved_log))
        
        # Verify permissions changed to dir_b's pattern rules
        syft_moved_log = syft_perm.open(moved_log)
        self.assertFalse(syft_moved_log.has_write_access("alice@example.com"))   # Lost write
        self.assertFalse(syft_moved_log.has_read_access("charlie@example.com"))  # Lost public read
        self.assertTrue(syft_moved_log.has_admin_access("bob@example.com"))      # Gained admin
    
    def test_move_file_with_create_permission_between_dirs(self):
        """Test moving file with create permission between directories."""
        # Create source directory with create permissions
        source_dir = Path(self.test_dir) / "create_source"
        source_dir.mkdir(parents=True)
        
        source_yaml = source_dir / "syft.pub.yaml"
        source_rules = {
            "rules": [{
                "pattern": "*.doc",
                "access": {
                    "create": ["alice@example.com"]
                    # Create includes read via hierarchy
                }
            }]
        }
        with open(source_yaml, 'w') as f:
            yaml.dump(source_rules, f)
        
        # Create destination directory with different create permissions
        dest_dir = Path(self.test_dir) / "create_dest"
        dest_dir.mkdir(parents=True)
        
        dest_yaml = dest_dir / "syft.pub.yaml"
        dest_rules = {
            "rules": [{
                "pattern": "*.doc",
                "access": {
                    "create": ["bob@example.com"],
                    "write": ["charlie@example.com"]
                }
            }]
        }
        with open(dest_yaml, 'w') as f:
            yaml.dump(dest_rules, f)
        
        # Create document file in source
        doc_file = source_dir / "document.doc"
        doc_file.write_text("document content")
        
        # Verify source permissions
        syft_doc_before = syft_perm.open(doc_file)
        self.assertTrue(syft_doc_before.has_create_access("alice@example.com"))
        self.assertTrue(syft_doc_before.has_read_access("alice@example.com"))  # Via hierarchy
        self.assertFalse(syft_doc_before.has_create_access("bob@example.com"))
        self.assertFalse(syft_doc_before.has_write_access("charlie@example.com"))
        
        # Move document to destination
        moved_doc = dest_dir / "document.doc"
        os.rename(str(doc_file), str(moved_doc))
        
        # Verify permissions changed to destination rules
        syft_moved_doc = syft_perm.open(moved_doc)
        self.assertFalse(syft_moved_doc.has_create_access("alice@example.com"))  # Lost create
        self.assertFalse(syft_moved_doc.has_read_access("alice@example.com"))    # Lost read
        self.assertTrue(syft_moved_doc.has_create_access("bob@example.com"))     # Gained create
        self.assertTrue(syft_moved_doc.has_write_access("charlie@example.com"))  # Gained write
        self.assertTrue(syft_moved_doc.has_read_access("bob@example.com"))       # Create->read hierarchy
        self.assertTrue(syft_moved_doc.has_read_access("charlie@example.com"))   # Write->read hierarchy
    
    def test_move_file_between_dirs_with_different_size_limits(self):
        """Test moving file between directories with different size limits."""
        # Create source directory with generous size limits
        source_dir = Path(self.test_dir) / "large_files"
        source_dir.mkdir(parents=True)
        
        source_yaml = source_dir / "syft.pub.yaml"
        source_rules = {
            "rules": [{
                "pattern": "*.bin",
                "access": {
                    "write": ["alice@example.com"]
                },
                "limits": {
                    "max_file_size": 10 * 1024 * 1024,  # 10MB
                    "allow_dirs": True,
                    "allow_symlinks": True
                }
            }]
        }
        with open(source_yaml, 'w') as f:
            yaml.dump(source_rules, f)
        
        # Create destination directory with strict size limits
        dest_dir = Path(self.test_dir) / "small_files"
        dest_dir.mkdir(parents=True)
        
        dest_yaml = dest_dir / "syft.pub.yaml"
        dest_rules = {
            "rules": [{
                "pattern": "*.bin",
                "access": {
                    "read": ["bob@example.com"]
                },
                "limits": {
                    "max_file_size": 1024,  # 1KB only
                    "allow_dirs": False,
                    "allow_symlinks": False
                }
            }]
        }
        with open(dest_yaml, 'w') as f:
            yaml.dump(dest_rules, f)
        
        # Create small binary file that fits both limits
        bin_file = source_dir / "data.bin" 
        bin_file.write_bytes(b"x" * 512)  # 512 bytes
        
        # Verify source permissions and limits
        syft_bin_before = syft_perm.open(bin_file)
        self.assertTrue(syft_bin_before.has_write_access("alice@example.com"))
        self.assertFalse(syft_bin_before.has_read_access("bob@example.com"))
        
        # Get permissions data to check limits (implementation detail)
        source_perms = syft_bin_before._get_all_permissions_with_sources()
        # Note: Actual limit enforcement happens in the ACL service, not in permission checking
        
        # Move file to destination with stricter limits
        moved_bin = dest_dir / "data.bin"
        os.rename(str(bin_file), str(moved_bin))
        
        # Verify permissions changed and new limits apply
        syft_moved_bin = syft_perm.open(moved_bin)
        self.assertFalse(syft_moved_bin.has_write_access("alice@example.com"))  # Lost write
        self.assertTrue(syft_moved_bin.has_read_access("bob@example.com"))      # Gained read
        
        # Verify the permission structure reflects new limits
        dest_perms = syft_moved_bin._get_all_permissions_with_sources()
        self.assertIsNotNone(dest_perms)
        # The new stricter limits are now in effect (would be enforced by ACL service)
    
    def test_move_triggers_no_cache_invalidation(self):
        """Test that move operations do NOT trigger cache invalidation (old syftbox behavior)."""
        # This test verifies the old syftbox behavior where moves don't invalidate cache
        
        # Create source directory
        source_dir = Path(self.test_dir) / "cache_source"
        source_dir.mkdir(parents=True)
        
        source_yaml = source_dir / "syft.pub.yaml"
        source_rules = {
            "rules": [{
                "pattern": "*.cache",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(source_yaml, 'w') as f:
            yaml.dump(source_rules, f)
        
        # Create destination directory
        dest_dir = Path(self.test_dir) / "cache_dest"
        dest_dir.mkdir(parents=True)
        
        dest_yaml = dest_dir / "syft.pub.yaml"
        dest_rules = {
            "rules": [{
                "pattern": "*.cache",
                "access": {
                    "read": ["bob@example.com"]
                }
            }]
        }
        with open(dest_yaml, 'w') as f:
            yaml.dump(dest_rules, f)
        
        # Create cache file
        cache_file = source_dir / "test.cache"
        cache_file.write_text("cache content")
        
        # Access file to populate cache
        syft_cache_before = syft_perm.open(cache_file)
        self.assertTrue(syft_cache_before.has_admin_access("alice@example.com"))
        
        # Verify cache has entries (implementation detail)
        cache_size_before = len(_permission_cache.cache)
        self.assertGreater(cache_size_before, 0)
        
        # Move file (this should NOT invalidate cache in old syftbox behavior)
        moved_cache = dest_dir / "test.cache"
        os.rename(str(cache_file), str(moved_cache))
        
        # Verify cache was NOT invalidated by the move operation
        cache_size_after = len(_permission_cache.cache)
        self.assertEqual(cache_size_before, cache_size_after)  # Cache unchanged
        
        # However, accessing the file at new location should get new permissions
        syft_moved_cache = syft_perm.open(moved_cache)
        self.assertFalse(syft_moved_cache.has_admin_access("alice@example.com"))  # Lost admin
        self.assertTrue(syft_moved_cache.has_read_access("bob@example.com"))      # Gained read
        
        # The cache now has additional entries for the new path
        cache_size_final = len(_permission_cache.cache)
        self.assertGreaterEqual(cache_size_final, cache_size_before)
        
        # Manual cache invalidation would be needed to clear stale entries
        # (this simulates the old syftbox behavior where cache could have stale data)
        _permission_cache.clear()
        
        # After manual cache clear, verify permissions still work correctly
        syft_cache_after_clear = syft_perm.open(moved_cache)
        self.assertFalse(syft_cache_after_clear.has_admin_access("alice@example.com"))
        self.assertTrue(syft_cache_after_clear.has_read_access("bob@example.com"))


if __name__ == "__main__":
    unittest.main()