"""Comprehensive test verifying all four permission levels with all features."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml
import time

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm
from syft_perm._impl import get_cache_stats, clear_permission_cache

class TestComprehensivePermissionVerification(unittest.TestCase):
    """Test all four permission levels comprehensively."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = [
            "admin@example.com",
            "writer@example.com", 
            "creator@example.com",
            "reader@example.com",
            "nobody@example.com",
            "pattern_user@example.com"
        ]
        # Clear cache before each test
        clear_permission_cache()
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
        clear_permission_cache()
    
    def test_all_four_permission_levels_with_inheritance(self):
        """Test all four permission levels ensuring correct inheritance."""
        # Create directory structure
        test_dir = Path(self.test_dir) / "four_levels"
        parent_dir = test_dir / "parent"
        child_dir = parent_dir / "child"
        grandchild_dir = child_dir / "grandchild"
        grandchild_dir.mkdir(parents=True)
        
        # Create test files at each level
        files = {
            "parent_file": parent_dir / "file.txt",
            "child_file": child_dir / "data.json",
            "grandchild_file": grandchild_dir / "doc.md",
            "python_file": child_dir / "script.py"
        }
        
        for file_path in files.values():
            file_path.write_text("content")
        
        # Create syft.pub.yaml with all four permission levels
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "parent/**",
                    "access": {
                        "admin": ["admin@example.com"]
                    }
                },
                {
                    "pattern": "parent/child/**",
                    "access": {
                        "write": ["writer@example.com"]
                    }
                },
                {
                    "pattern": "parent/child/grandchild/**",
                    "access": {
                        "create": ["creator@example.com"]
                    }
                },
                {
                    "pattern": "parent/child/grandchild/doc.md",
                    "access": {
                        "read": ["reader@example.com"]
                    }
                },
                {
                    "pattern": "**/*.py",
                    "access": {
                        "write": ["pattern_user@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test parent file - admin user has all permissions via hierarchy
        parent_syft = syft_perm.open(files["parent_file"])
        
        # Admin user - has all permissions
        self.assertTrue(parent_syft.has_admin_access("admin@example.com"))
        self.assertTrue(parent_syft.has_write_access("admin@example.com"))
        self.assertTrue(parent_syft.has_create_access("admin@example.com"))
        self.assertTrue(parent_syft.has_read_access("admin@example.com"))
        
        # Writer user - no permissions at parent level
        self.assertFalse(parent_syft.has_admin_access("writer@example.com"))
        self.assertFalse(parent_syft.has_write_access("writer@example.com"))
        self.assertFalse(parent_syft.has_create_access("writer@example.com"))
        self.assertFalse(parent_syft.has_read_access("writer@example.com"))
        
        # Test child file - parent/child/** is more specific than parent/** and should win
        child_syft = syft_perm.open(files["child_file"])
        
        # Admin user - doesn't get access because parent/child/** is more specific
        self.assertFalse(child_syft.has_admin_access("admin@example.com"))
        self.assertFalse(child_syft.has_write_access("admin@example.com"))
        self.assertFalse(child_syft.has_create_access("admin@example.com"))
        self.assertFalse(child_syft.has_read_access("admin@example.com"))
        
        # Writer user - has write and below via nearest-node rule
        self.assertFalse(child_syft.has_admin_access("writer@example.com"))
        self.assertTrue(child_syft.has_write_access("writer@example.com"))
        self.assertTrue(child_syft.has_create_access("writer@example.com"))
        self.assertTrue(child_syft.has_read_access("writer@example.com"))
        
        # Creator user - no permissions at child level
        self.assertFalse(child_syft.has_admin_access("creator@example.com"))
        self.assertFalse(child_syft.has_write_access("creator@example.com"))
        self.assertFalse(child_syft.has_create_access("creator@example.com"))
        self.assertFalse(child_syft.has_read_access("creator@example.com"))
        
        # Test grandchild file - exact match "parent/child/grandchild/doc.md" should win
        grandchild_syft = syft_perm.open(files["grandchild_file"])
        
        # Admin user - no access because exact match is most specific
        self.assertFalse(grandchild_syft.has_admin_access("admin@example.com"))
        self.assertFalse(grandchild_syft.has_write_access("admin@example.com"))
        self.assertFalse(grandchild_syft.has_create_access("admin@example.com"))
        self.assertFalse(grandchild_syft.has_read_access("admin@example.com"))
        
        # Writer user - no access because exact match is most specific
        self.assertFalse(grandchild_syft.has_admin_access("writer@example.com"))
        self.assertFalse(grandchild_syft.has_write_access("writer@example.com"))
        self.assertFalse(grandchild_syft.has_create_access("writer@example.com"))
        self.assertFalse(grandchild_syft.has_read_access("writer@example.com"))
        
        # Creator user - no access because exact match is most specific
        self.assertFalse(grandchild_syft.has_admin_access("creator@example.com"))
        self.assertFalse(grandchild_syft.has_write_access("creator@example.com"))
        self.assertFalse(grandchild_syft.has_create_access("creator@example.com"))
        self.assertFalse(grandchild_syft.has_read_access("creator@example.com"))
        
        # Reader user - only has read via exact match pattern
        self.assertFalse(grandchild_syft.has_admin_access("reader@example.com"))
        self.assertFalse(grandchild_syft.has_write_access("reader@example.com"))
        self.assertFalse(grandchild_syft.has_create_access("reader@example.com"))
        self.assertTrue(grandchild_syft.has_read_access("reader@example.com"))
        
        # Nobody user - no permissions anywhere
        self.assertFalse(grandchild_syft.has_admin_access("nobody@example.com"))
        self.assertFalse(grandchild_syft.has_write_access("nobody@example.com"))
        self.assertFalse(grandchild_syft.has_create_access("nobody@example.com"))
        self.assertFalse(grandchild_syft.has_read_access("nobody@example.com"))
        
        # Test Python file - parent/child/** is more specific than **/*.py
        python_syft = syft_perm.open(files["python_file"])
        
        # Pattern user - doesn't get access because parent/child/** is more specific
        self.assertFalse(python_syft.has_admin_access("pattern_user@example.com"))
        self.assertFalse(python_syft.has_write_access("pattern_user@example.com"))
        self.assertFalse(python_syft.has_create_access("pattern_user@example.com"))
        self.assertFalse(python_syft.has_read_access("pattern_user@example.com"))
        
        # Writer user - gets access because parent/child/** wins
        self.assertTrue(python_syft.has_write_access("writer@example.com"))
        self.assertTrue(python_syft.has_create_access("writer@example.com"))
        self.assertTrue(python_syft.has_read_access("writer@example.com"))
        
    def test_cache_working_correctly_across_permission_levels(self):
        """Test that cache works correctly for all permission levels."""
        # Create test structure
        test_dir = Path(self.test_dir) / "cache_test"
        test_dir.mkdir(parents=True)
        
        # Create multiple files
        files = []
        for i in range(5):
            file_path = test_dir / f"file{i}.txt"
            file_path.write_text(f"content{i}")
            files.append(file_path)
        
        # Create yaml with different permissions
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "file0.txt",
                    "access": {"admin": ["admin@example.com"]}
                },
                {
                    "pattern": "file1.txt", 
                    "access": {"write": ["writer@example.com"]}
                },
                {
                    "pattern": "file2.txt",
                    "access": {"create": ["creator@example.com"]}
                },
                {
                    "pattern": "file3.txt",
                    "access": {"read": ["reader@example.com"]}
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Clear cache
        clear_permission_cache()
        cache_stats = get_cache_stats()
        self.assertEqual(cache_stats["size"], 0)
        
        # First access - should populate cache
        for i, file_path in enumerate(files[:4]):
            syft_file = syft_perm.open(file_path)
            # Check all four levels to ensure cache stores complete info
            syft_file.has_admin_access("admin@example.com")
            syft_file.has_write_access("writer@example.com")
            syft_file.has_create_access("creator@example.com")
            syft_file.has_read_access("reader@example.com")
        
        # Check cache is populated
        cache_stats = get_cache_stats()
        self.assertGreater(cache_stats["size"], 0)
        initial_size = cache_stats["size"]
        
        # Second access - should use cache (no size increase)
        for file_path in files[:4]:
            syft_file = syft_perm.open(file_path)
            syft_file.has_admin_access("admin@example.com")
            syft_file.has_write_access("writer@example.com")
            syft_file.has_create_access("creator@example.com")
            syft_file.has_read_access("reader@example.com")
        
        cache_stats = get_cache_stats()
        self.assertEqual(cache_stats["size"], initial_size)
        
        # Modify permissions - should invalidate cache
        yaml_content["rules"][0]["access"]["admin"].append("new_admin@example.com")
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Clear cache to simulate cache invalidation
        clear_permission_cache()
        
        # Access after modification - cache should be invalidated and rebuilt
        syft_file = syft_perm.open(files[0])
        self.assertTrue(syft_file.has_admin_access("new_admin@example.com"))
        
    def test_doublestar_patterns_match_properly_all_levels(self):
        """Test doublestar patterns work correctly with all permission levels."""
        # Create nested structure
        test_dir = Path(self.test_dir) / "doublestar_test"
        deep_dir = test_dir / "level1" / "level2" / "level3"
        deep_dir.mkdir(parents=True)
        
        # Create files at different levels
        files = {
            "root_py": test_dir / "root.py",
            "level1_py": test_dir / "level1" / "script.py",
            "level2_json": test_dir / "level1" / "level2" / "data.json",
            "level3_py": deep_dir / "module.py",
            "level3_txt": deep_dir / "notes.txt"
        }
        
        for file_path in files.values():
            file_path.write_text("content")
        
        # Create yaml with doublestar patterns for each permission level
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "**/*.py",
                    "access": {"admin": ["py_admin@example.com"]}
                },
                {
                    "pattern": "**/level2/**",
                    "access": {"write": ["level2_writer@example.com"]}
                },
                {
                    "pattern": "**/*.json",
                    "access": {"create": ["json_creator@example.com"]}
                },
                {
                    "pattern": "**/notes.txt",
                    "access": {"read": ["notes_reader@example.com"]}
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test root Python file - matches **/*.py
        root_py_syft = syft_perm.open(files["root_py"])
        self.assertTrue(root_py_syft.has_admin_access("py_admin@example.com"))
        self.assertTrue(root_py_syft.has_write_access("py_admin@example.com"))
        self.assertTrue(root_py_syft.has_create_access("py_admin@example.com"))
        self.assertTrue(root_py_syft.has_read_access("py_admin@example.com"))
        self.assertFalse(root_py_syft.has_read_access("level2_writer@example.com"))
        
        # Test level2 JSON file - matches both **/level2/** and **/*.json
        # More specific pattern (**/level2/**) should win
        level2_json_syft = syft_perm.open(files["level2_json"])
        self.assertFalse(level2_json_syft.has_admin_access("json_creator@example.com"))
        self.assertTrue(level2_json_syft.has_write_access("level2_writer@example.com"))
        self.assertTrue(level2_json_syft.has_create_access("level2_writer@example.com"))
        self.assertTrue(level2_json_syft.has_read_access("level2_writer@example.com"))
        
        # Test level3 Python file - matches **/*.py and **/level2/**
        # **/level2/** is more specific and should win, granting write to level2_writer
        level3_py_syft = syft_perm.open(files["level3_py"])
        self.assertFalse(level3_py_syft.has_admin_access("py_admin@example.com"))  # **/level2/** wins
        self.assertTrue(level3_py_syft.has_write_access("level2_writer@example.com"))  # Most specific rule
        self.assertTrue(level3_py_syft.has_create_access("level2_writer@example.com"))  # Via hierarchy  
        self.assertTrue(level3_py_syft.has_read_access("level2_writer@example.com"))    # Via hierarchy
        
        # Test notes file - **/notes.txt is most specific pattern and should win
        notes_syft = syft_perm.open(files["level3_txt"])
        self.assertFalse(notes_syft.has_admin_access("notes_reader@example.com"))
        self.assertFalse(notes_syft.has_write_access("notes_reader@example.com"))
        self.assertFalse(notes_syft.has_create_access("notes_reader@example.com"))
        self.assertTrue(notes_syft.has_read_access("notes_reader@example.com"))
        # **/notes.txt wins over **/level2/** due to higher specificity
        self.assertFalse(notes_syft.has_write_access("level2_writer@example.com"))
        
    def test_file_limits_enforced_all_permission_levels(self):
        """Test file limits are enforced correctly for all permission levels."""
        # Create test directory
        test_dir = Path(self.test_dir) / "limits_test"
        test_dir.mkdir(parents=True)
        
        # Create files of different sizes
        small_file = test_dir / "small.txt"
        large_file = test_dir / "large.txt"
        small_file.write_text("x" * 100)  # 100 bytes
        large_file.write_text("x" * 2000)  # 2KB
        
        # Create a directory and symlink
        sub_dir = test_dir / "subdir"
        sub_dir.mkdir()
        symlink = test_dir / "link.txt"
        symlink.symlink_to(small_file)
        
        # Create yaml with different limits for each permission level
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "*.txt",
                    "access": {
                        "admin": ["admin@example.com"],
                        "write": ["writer@example.com"],
                        "create": ["creator@example.com"],
                        "read": ["reader@example.com"]
                    },
                    "limits": {
                        "max_file_size": 1024,  # 1KB limit
                        "allow_dirs": False,
                        "allow_symlinks": False
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test small file - all users should have their permissions
        small_syft = syft_perm.open(small_file)
        self.assertTrue(small_syft.has_admin_access("admin@example.com"))
        self.assertTrue(small_syft.has_write_access("writer@example.com"))
        self.assertTrue(small_syft.has_create_access("creator@example.com"))
        self.assertTrue(small_syft.has_read_access("reader@example.com"))
        
        # Test large file - limits should block ALL permissions
        large_syft = syft_perm.open(large_file)
        self.assertFalse(large_syft.has_admin_access("admin@example.com"))
        self.assertFalse(large_syft.has_write_access("writer@example.com"))
        self.assertFalse(large_syft.has_create_access("creator@example.com"))
        self.assertFalse(large_syft.has_read_access("reader@example.com"))
        
        # Test directory - should be blocked
        dir_syft = syft_perm.open(sub_dir)
        self.assertFalse(dir_syft.has_admin_access("admin@example.com"))
        self.assertFalse(dir_syft.has_write_access("writer@example.com"))
        self.assertFalse(dir_syft.has_create_access("creator@example.com"))
        self.assertFalse(dir_syft.has_read_access("reader@example.com"))
        
        # Test symlink - should be blocked
        symlink_syft = syft_perm.open(symlink)
        self.assertFalse(symlink_syft.has_admin_access("admin@example.com"))
        self.assertFalse(symlink_syft.has_write_access("writer@example.com"))
        self.assertFalse(symlink_syft.has_create_access("creator@example.com"))
        self.assertFalse(symlink_syft.has_read_access("reader@example.com"))
        
    def test_owner_detection_both_methods_all_levels(self):
        """Test owner detection works with both email and path prefix methods."""
        # Test with email-based owner
        email_dir = Path(self.test_dir) / "admin@example.com"
        email_subdir = email_dir / "projects" / "secret"
        email_subdir.mkdir(parents=True)
        
        email_file = email_subdir / "data.txt"
        email_file.write_text("secret data")
        
        # No yaml file - owner should still have all permissions
        email_syft = syft_perm.open(email_file)
        self.assertTrue(email_syft.has_admin_access("admin@example.com"))
        self.assertTrue(email_syft.has_write_access("admin@example.com"))
        self.assertTrue(email_syft.has_create_access("admin@example.com"))
        self.assertTrue(email_syft.has_read_access("admin@example.com"))
        
        # Non-owner should have no permissions
        self.assertFalse(email_syft.has_admin_access("other@example.com"))
        self.assertFalse(email_syft.has_write_access("other@example.com"))
        self.assertFalse(email_syft.has_create_access("other@example.com"))
        self.assertFalse(email_syft.has_read_access("other@example.com"))
        
        # Test with path prefix owner (no @ symbol)
        prefix_dir = Path(self.test_dir) / "myusername"
        prefix_subdir = prefix_dir / "workspace"
        prefix_subdir.mkdir(parents=True)
        
        prefix_file = prefix_subdir / "code.py"
        prefix_file.write_text("my code")
        
        # Owner with path prefix should have all permissions
        prefix_syft = syft_perm.open(prefix_file)
        self.assertTrue(prefix_syft.has_admin_access("myusername"))
        self.assertTrue(prefix_syft.has_write_access("myusername"))
        self.assertTrue(prefix_syft.has_create_access("myusername"))
        self.assertTrue(prefix_syft.has_read_access("myusername"))
        
        # Non-owner should have no permissions
        self.assertFalse(prefix_syft.has_admin_access("otheruser"))
        self.assertFalse(prefix_syft.has_write_access("otheruser"))
        self.assertFalse(prefix_syft.has_create_access("otheruser"))
        self.assertFalse(prefix_syft.has_read_access("otheruser"))
        
        # Add yaml that grants limited permissions
        yaml_file = prefix_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "workspace/code.py",
                    "access": {
                        "read": ["viewer@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Clear cache to ensure yaml changes are picked up
        clear_permission_cache()
        
        # Owner should still have all permissions
        prefix_syft2 = syft_perm.open(prefix_file)
        self.assertTrue(prefix_syft2.has_admin_access("myusername"))
        self.assertTrue(prefix_syft2.has_write_access("myusername"))
        self.assertTrue(prefix_syft2.has_create_access("myusername"))
        self.assertTrue(prefix_syft2.has_read_access("myusername"))
        
        # Viewer should only have read
        self.assertFalse(prefix_syft2.has_admin_access("viewer@example.com"))
        self.assertFalse(prefix_syft2.has_write_access("viewer@example.com"))
        self.assertFalse(prefix_syft2.has_create_access("viewer@example.com"))
        self.assertTrue(prefix_syft2.has_read_access("viewer@example.com"))
        
    def test_no_permission_leakage_between_levels(self):
        """Test that permissions don't leak between levels incorrectly."""
        # Create test structure
        test_dir = Path(self.test_dir) / "leakage_test"
        test_dir.mkdir(parents=True)
        
        # Create files
        admin_file = test_dir / "admin_only.txt"
        write_file = test_dir / "write_only.txt"
        create_file = test_dir / "create_only.txt"
        read_file = test_dir / "read_only.txt"
        
        for f in [admin_file, write_file, create_file, read_file]:
            f.write_text("content")
        
        # Create yaml with strict single-level permissions
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "admin_only.txt",
                    "access": {
                        "admin": ["admin@example.com"]
                    }
                },
                {
                    "pattern": "write_only.txt",
                    "access": {
                        "write": ["writer@example.com"]
                    }
                },
                {
                    "pattern": "create_only.txt",
                    "access": {
                        "create": ["creator@example.com"]
                    }
                },
                {
                    "pattern": "read_only.txt",
                    "access": {
                        "read": ["reader@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test admin file - only admin user should have permissions
        admin_syft = syft_perm.open(admin_file)
        # Admin user gets all via hierarchy
        self.assertTrue(admin_syft.has_admin_access("admin@example.com"))
        self.assertTrue(admin_syft.has_write_access("admin@example.com"))
        self.assertTrue(admin_syft.has_create_access("admin@example.com"))
        self.assertTrue(admin_syft.has_read_access("admin@example.com"))
        # Other users get nothing
        self.assertFalse(admin_syft.has_read_access("writer@example.com"))
        self.assertFalse(admin_syft.has_read_access("creator@example.com"))
        self.assertFalse(admin_syft.has_read_access("reader@example.com"))
        
        # Test write file - writer gets write and below
        write_syft = syft_perm.open(write_file)
        self.assertFalse(write_syft.has_admin_access("writer@example.com"))
        self.assertTrue(write_syft.has_write_access("writer@example.com"))
        self.assertTrue(write_syft.has_create_access("writer@example.com"))
        self.assertTrue(write_syft.has_read_access("writer@example.com"))
        # No leakage to other users
        self.assertFalse(write_syft.has_read_access("admin@example.com"))
        self.assertFalse(write_syft.has_read_access("creator@example.com"))
        self.assertFalse(write_syft.has_read_access("reader@example.com"))
        
        # Test create file - creator gets create and below
        create_syft = syft_perm.open(create_file)
        self.assertFalse(create_syft.has_admin_access("creator@example.com"))
        self.assertFalse(create_syft.has_write_access("creator@example.com"))
        self.assertTrue(create_syft.has_create_access("creator@example.com"))
        self.assertTrue(create_syft.has_read_access("creator@example.com"))
        # No leakage
        self.assertFalse(create_syft.has_read_access("admin@example.com"))
        self.assertFalse(create_syft.has_read_access("writer@example.com"))
        self.assertFalse(create_syft.has_read_access("reader@example.com"))
        
        # Test read file - reader only gets read
        read_syft = syft_perm.open(read_file)
        self.assertFalse(read_syft.has_admin_access("reader@example.com"))
        self.assertFalse(read_syft.has_write_access("reader@example.com"))
        self.assertFalse(read_syft.has_create_access("reader@example.com"))
        self.assertTrue(read_syft.has_read_access("reader@example.com"))
        # No leakage
        self.assertFalse(read_syft.has_read_access("admin@example.com"))
        self.assertFalse(read_syft.has_read_access("writer@example.com"))
        self.assertFalse(read_syft.has_read_access("creator@example.com"))
        
    def test_terminal_blocks_all_inheritance_all_levels(self):
        """Test terminal nodes block inheritance for all permission levels."""
        # Create nested structure
        test_dir = Path(self.test_dir) / "terminal_test"
        parent_dir = test_dir / "parent"
        terminal_dir = parent_dir / "terminal"
        child_dir = terminal_dir / "child"
        child_dir.mkdir(parents=True)
        
        # Create files
        parent_file = parent_dir / "parent.txt"
        terminal_file = terminal_dir / "terminal.txt"
        child_file = child_dir / "child.txt"
        
        for f in [parent_file, terminal_file, child_file]:
            f.write_text("content")
        
        # Create yamls with terminal node
        # Parent yaml grants all levels
        parent_yaml = test_dir / "syft.pub.yaml"
        parent_yaml_content = {
            "rules": [
                {
                    "pattern": "parent/**",
                    "access": {
                        "admin": ["admin@example.com"],
                        "write": ["writer@example.com"],
                        "create": ["creator@example.com"],
                        "read": ["reader@example.com"]
                    }
                }
            ]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_yaml_content, f)
        
        # Terminal yaml blocks inheritance
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_yaml_content = {
            "terminal": True,
            "rules": [
                {
                    "pattern": "terminal.txt",
                    "access": {
                        "read": ["terminal_reader@example.com"]
                    }
                }
            ]
        }
        with open(terminal_yaml, 'w') as f:
            yaml.dump(terminal_yaml_content, f)
        
        # Test parent file - all users have their permissions
        parent_syft = syft_perm.open(parent_file)
        self.assertTrue(parent_syft.has_admin_access("admin@example.com"))
        self.assertTrue(parent_syft.has_write_access("writer@example.com"))
        self.assertTrue(parent_syft.has_create_access("creator@example.com"))
        self.assertTrue(parent_syft.has_read_access("reader@example.com"))
        
        # Test terminal file - only terminal_reader has access
        terminal_syft = syft_perm.open(terminal_file)
        self.assertFalse(terminal_syft.has_admin_access("admin@example.com"))
        self.assertFalse(terminal_syft.has_write_access("writer@example.com"))
        self.assertFalse(terminal_syft.has_create_access("creator@example.com"))
        self.assertFalse(terminal_syft.has_read_access("reader@example.com"))
        self.assertTrue(terminal_syft.has_read_access("terminal_reader@example.com"))
        
        # Test child file - terminal blocks all inheritance
        child_syft = syft_perm.open(child_file)
        self.assertFalse(child_syft.has_admin_access("admin@example.com"))
        self.assertFalse(child_syft.has_write_access("writer@example.com"))
        self.assertFalse(child_syft.has_create_access("creator@example.com"))
        self.assertFalse(child_syft.has_read_access("reader@example.com"))
        self.assertFalse(child_syft.has_read_access("terminal_reader@example.com"))
        
    def test_pattern_specificity_with_all_levels(self):
        """Test pattern specificity works correctly with all permission levels."""
        # Create test structure
        test_dir = Path(self.test_dir) / "specificity_test"
        docs_dir = test_dir / "docs"
        api_dir = docs_dir / "api"
        api_dir.mkdir(parents=True)
        
        # Create test files
        generic_file = test_dir / "readme.txt"
        docs_file = docs_dir / "guide.txt"
        api_file = api_dir / "reference.txt"
        specific_file = api_dir / "auth.txt"
        
        for f in [generic_file, docs_file, api_file, specific_file]:
            f.write_text("content")
        
        # Create yaml with overlapping patterns of different specificity
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "**/*.txt",  # Least specific
                    "access": {
                        "read": ["txt_reader@example.com"]
                    }
                },
                {
                    "pattern": "docs/**",  # More specific
                    "access": {
                        "create": ["docs_creator@example.com"]
                    }
                },
                {
                    "pattern": "docs/api/*",  # Even more specific
                    "access": {
                        "write": ["api_writer@example.com"]
                    }
                },
                {
                    "pattern": "docs/api/auth.txt",  # Most specific
                    "access": {
                        "admin": ["auth_admin@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test generic file - only matches **/*.txt
        generic_syft = syft_perm.open(generic_file)
        self.assertTrue(generic_syft.has_read_access("txt_reader@example.com"))
        self.assertFalse(generic_syft.has_create_access("txt_reader@example.com"))
        self.assertFalse(generic_syft.has_read_access("docs_creator@example.com"))
        
        # Test docs file - matches **/*.txt and docs/**, more specific wins (docs/**)
        docs_syft = syft_perm.open(docs_file)
        self.assertFalse(docs_syft.has_read_access("txt_reader@example.com"))  # docs/** is more specific
        self.assertTrue(docs_syft.has_create_access("docs_creator@example.com"))
        self.assertTrue(docs_syft.has_read_access("docs_creator@example.com"))  # Via hierarchy
        self.assertFalse(docs_syft.has_write_access("docs_creator@example.com"))
        
        # Test api file - matches three patterns, most specific wins
        api_syft = syft_perm.open(api_file)
        self.assertFalse(api_syft.has_read_access("txt_reader@example.com"))
        self.assertFalse(api_syft.has_create_access("docs_creator@example.com"))
        self.assertTrue(api_syft.has_write_access("api_writer@example.com"))
        self.assertTrue(api_syft.has_create_access("api_writer@example.com"))
        self.assertTrue(api_syft.has_read_access("api_writer@example.com"))
        self.assertFalse(api_syft.has_admin_access("api_writer@example.com"))
        
        # Test specific file - exact match wins over all
        specific_syft = syft_perm.open(specific_file)
        self.assertFalse(specific_syft.has_read_access("txt_reader@example.com"))
        self.assertFalse(specific_syft.has_create_access("docs_creator@example.com"))
        self.assertFalse(specific_syft.has_write_access("api_writer@example.com"))
        self.assertTrue(specific_syft.has_admin_access("auth_admin@example.com"))
        self.assertTrue(specific_syft.has_write_access("auth_admin@example.com"))
        self.assertTrue(specific_syft.has_create_access("auth_admin@example.com"))
        self.assertTrue(specific_syft.has_read_access("auth_admin@example.com"))
        
    def test_public_star_access_all_levels(self):
        """Test public (*) access works correctly for all permission levels."""
        # Create test directory
        test_dir = Path(self.test_dir) / "public_test"
        test_dir.mkdir(parents=True)
        
        # Create test files
        public_admin = test_dir / "admin_public.txt"
        public_write = test_dir / "write_public.txt"
        public_create = test_dir / "create_public.txt"
        public_read = test_dir / "read_public.txt"
        
        for f in [public_admin, public_write, public_create, public_read]:
            f.write_text("content")
        
        # Create yaml with public access at each level
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "admin_public.txt",
                    "access": {
                        "admin": ["*"]
                    }
                },
                {
                    "pattern": "write_public.txt",
                    "access": {
                        "write": ["*"]
                    }
                },
                {
                    "pattern": "create_public.txt",
                    "access": {
                        "create": ["*"]
                    }
                },
                {
                    "pattern": "read_public.txt",
                    "access": {
                        "read": ["*"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test with random users
        random_users = ["anyone@test.com", "random@user.org", "somebody", "*"]
        
        # Test public admin - everyone has all permissions
        admin_syft = syft_perm.open(public_admin)
        for user in random_users:
            self.assertTrue(admin_syft.has_admin_access(user))
            self.assertTrue(admin_syft.has_write_access(user))
            self.assertTrue(admin_syft.has_create_access(user))
            self.assertTrue(admin_syft.has_read_access(user))
        
        # Test public write - everyone has write and below
        write_syft = syft_perm.open(public_write)
        for user in random_users:
            self.assertFalse(write_syft.has_admin_access(user))
            self.assertTrue(write_syft.has_write_access(user))
            self.assertTrue(write_syft.has_create_access(user))
            self.assertTrue(write_syft.has_read_access(user))
        
        # Test public create - everyone has create and below
        create_syft = syft_perm.open(public_create)
        for user in random_users:
            self.assertFalse(create_syft.has_admin_access(user))
            self.assertFalse(create_syft.has_write_access(user))
            self.assertTrue(create_syft.has_create_access(user))
            self.assertTrue(create_syft.has_read_access(user))
        
        # Test public read - everyone has only read
        read_syft = syft_perm.open(public_read)
        for user in random_users:
            self.assertFalse(read_syft.has_admin_access(user))
            self.assertFalse(read_syft.has_write_access(user))
            self.assertFalse(read_syft.has_create_access(user))
            self.assertTrue(read_syft.has_read_access(user))


if __name__ == "__main__":
    unittest.main()