"""Test permission priority and precedence rules."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm

class TestPermissionPriority(unittest.TestCase):
    """Test various permission priority scenarios and precedence rules."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["alice@example.com", "bob@example.com", "charlie@example.com"]
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_explicit_user_vs_public_at_same_level(self):
        """Test explicit user vs * permissions in same rule set."""
        # Create file with both explicit user and public permissions in same rule
        test_dir = Path(self.test_dir) / "priority_test"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "data.txt"
        test_file.write_text("test data")
        
        # Create permissions with both explicit user and public access
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "data.txt",
                "access": {
                    "read": ["alice@example.com", "*"],  # Both explicit and public
                    "write": ["*"],  # Only public write
                    "admin": ["alice@example.com"]  # Only explicit admin
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the file
        syft_file = syft_perm.open(test_file)
        
        # Alice should have read (both explicit and public), write (public), admin (explicit)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        
        # Bob should have read (public) and write (public), but not admin
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        
        # Check reasons for alice - should show explicit admin, not just public
        has_admin, admin_reasons = syft_file._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("Explicitly granted admin" in r for r in admin_reasons))
        
        # Check reasons for bob - should show public access where applicable
        has_write, write_reasons = syft_file._check_permission_with_reasons("bob@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Public access (*)" in r or "Explicitly granted write" in r for r in write_reasons))
    
    def test_explicit_user_vs_doublestar_pattern(self):
        """Test explicit user vs ** pattern at same level."""
        # Create nested directory structure
        parent_dir = Path(self.test_dir) / "patterns"
        sub_dir = parent_dir / "subdir"
        sub_dir.mkdir(parents=True)
        
        file1 = parent_dir / "file1.txt"
        file2 = sub_dir / "file2.txt"
        file1.write_text("file1 content")
        file2.write_text("file2 content")
        
        # Create permissions with both specific file and ** pattern
        yaml_file = parent_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "file1.txt",  # Specific file
                    "access": {
                        "write": ["alice@example.com"]
                    }
                },
                {
                    "pattern": "**/*.txt",  # Pattern matching all .txt files
                    "access": {
                        "read": ["bob@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test file1 - matches both specific pattern and ** pattern
        syft_file1 = syft_perm.open(file1)
        
        # Alice should have write from specific pattern
        self.assertTrue(syft_file1.has_write_access("alice@example.com"))
        self.assertTrue(syft_file1.has_create_access("alice@example.com"))  # Via hierarchy
        self.assertTrue(syft_file1.has_read_access("alice@example.com"))    # Via hierarchy
        
        # Bob should have NO access (file1.txt pattern has higher specificity than **/*.txt)
        self.assertFalse(syft_file1.has_read_access("bob@example.com"))
        self.assertFalse(syft_file1.has_write_access("bob@example.com"))
        
        # Test file2 - only matches ** pattern
        syft_file2 = syft_perm.open(file2)
        
        # Alice should have no permissions (specific pattern doesn't match)
        self.assertFalse(syft_file2.has_read_access("alice@example.com"))
        self.assertFalse(syft_file2.has_write_access("alice@example.com"))
        
        # Bob should have read from ** pattern
        self.assertTrue(syft_file2.has_read_access("bob@example.com"))
        self.assertFalse(syft_file2.has_write_access("bob@example.com"))
        
        # Check pattern matching in reasons for file1 - bob has no access
        has_read, read_reasons = syft_file1._check_permission_with_reasons("bob@example.com", "read")
        self.assertFalse(has_read)
        
        # Check pattern matching in reasons for file2 - bob should have access from **/*.txt
        has_read, read_reasons = syft_file2._check_permission_with_reasons("bob@example.com", "read") 
        self.assertTrue(has_read)
        self.assertTrue(any("**/*.txt" in r for r in read_reasons))
    
    def test_pattern_specificity_comprehensive(self):
        """Test various pattern specificity scenarios."""
        # Create complex directory structure
        root_dir = Path(self.test_dir) / "specificity"
        docs_dir = root_dir / "docs"
        api_dir = docs_dir / "api" 
        v1_dir = api_dir / "v1"
        v1_dir.mkdir(parents=True)
        
        # Create files at different levels
        files = {
            "root.txt": root_dir / "root.txt",
            "docs.txt": docs_dir / "guide.txt", 
            "api.txt": api_dir / "overview.txt",
            "v1.txt": v1_dir / "spec.txt"
        }
        
        for file_path in files.values():
            file_path.write_text("content")
        
        # Create permissions with patterns of different specificity
        yaml_file = root_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "**/*.txt",  # Least specific - all .txt files
                    "access": {
                        "read": ["charlie@example.com"]
                    }
                },
                {
                    "pattern": "docs/**/*.txt",  # More specific - .txt files under docs/
                    "access": {
                        "write": ["bob@example.com"]
                    }
                },
                {
                    "pattern": "docs/api/v1/*.txt",  # Most specific - .txt files in docs/api/v1/
                    "access": {
                        "admin": ["alice@example.com"]
                    }
                },
                {
                    "pattern": "docs/api/overview.txt",  # Exact file match
                    "access": {
                        "admin": ["bob@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test root.txt - only matches **/*.txt (least specific)
        syft_root = syft_perm.open(files["root.txt"])
        self.assertTrue(syft_root.has_read_access("charlie@example.com"))
        self.assertFalse(syft_root.has_write_access("bob@example.com"))
        self.assertFalse(syft_root.has_admin_access("alice@example.com"))
        
        # Test docs/guide.txt - most specific match is docs/**/*.txt  
        syft_docs = syft_perm.open(files["docs.txt"])
        self.assertFalse(syft_docs.has_read_access("charlie@example.com"))  # Not most specific
        self.assertTrue(syft_docs.has_write_access("bob@example.com"))      # Most specific match: docs/**/*.txt
        self.assertTrue(syft_docs.has_create_access("bob@example.com"))     # Via hierarchy
        self.assertTrue(syft_docs.has_read_access("bob@example.com"))       # Via hierarchy
        self.assertFalse(syft_docs.has_admin_access("alice@example.com"))   # No match for specific pattern
        
        # Test docs/api/overview.txt - most specific match is exact file pattern
        syft_api = syft_perm.open(files["api.txt"])
        self.assertTrue(syft_api.has_admin_access("bob@example.com"))       # Most specific: docs/api/overview.txt
        self.assertTrue(syft_api.has_write_access("bob@example.com"))       # Via hierarchy
        self.assertTrue(syft_api.has_create_access("bob@example.com"))      # Via hierarchy
        self.assertTrue(syft_api.has_read_access("bob@example.com"))        # Via hierarchy
        self.assertFalse(syft_api.has_read_access("charlie@example.com"))   # Not most specific
        
        # Test docs/api/v1/spec.txt - most specific match is docs/api/v1/*.txt
        syft_v1 = syft_perm.open(files["v1.txt"])
        self.assertTrue(syft_v1.has_admin_access("alice@example.com"))      # Most specific: docs/api/v1/*.txt
        self.assertTrue(syft_v1.has_write_access("alice@example.com"))      # Via hierarchy
        self.assertTrue(syft_v1.has_create_access("alice@example.com"))     # Via hierarchy
        self.assertTrue(syft_v1.has_read_access("alice@example.com"))       # Via hierarchy
        self.assertFalse(syft_v1.has_write_access("bob@example.com"))       # Not most specific
        self.assertFalse(syft_v1.has_read_access("charlie@example.com"))   # Not most specific
    
    def test_terminal_vs_non_terminal_same_patterns(self):
        """Test terminal vs non-terminal with identical patterns."""
        # Create parent with non-terminal permissions
        parent_dir = Path(self.test_dir) / "terminal_test"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**/*.data",
                "access": {
                    "admin": ["alice@example.com"],
                    "write": ["bob@example.com"],
                    "read": ["*"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create terminal child with same pattern but different permissions
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "terminal": True,  # This stops inheritance
            "rules": [{
                "pattern": "**/*.data", # Same pattern as parent
                "access": {
                    "read": ["charlie@example.com"]  # Only charlie can read
                    # No write or admin permissions
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create test files
        parent_file = parent_dir / "parent.data"
        child_file = child_dir / "child.data"
        parent_file.write_text("parent data")
        child_file.write_text("child data")
        
        # Test parent file - gets non-terminal permissions
        syft_parent = syft_perm.open(parent_file)
        self.assertTrue(syft_parent.has_admin_access("alice@example.com"))
        self.assertTrue(syft_parent.has_write_access("bob@example.com"))
        self.assertTrue(syft_parent.has_read_access("*"))
        
        # Test child file - terminal overrides, gets ONLY terminal permissions
        syft_child = syft_perm.open(child_file)
        self.assertFalse(syft_child.has_admin_access("alice@example.com"))  # Blocked by terminal
        self.assertFalse(syft_child.has_write_access("bob@example.com"))    # Blocked by terminal
        self.assertFalse(syft_child.has_read_access("*"))                   # Blocked by terminal
        
        # Only charlie has read access from terminal rule
        self.assertTrue(syft_child.has_read_access("charlie@example.com"))
        self.assertFalse(syft_child.has_write_access("charlie@example.com"))
        
        # Check reasons for terminal behavior
        has_admin, admin_reasons = syft_child._check_permission_with_reasons("alice@example.com", "admin")
        self.assertFalse(has_admin)
        self.assertTrue(any("Pattern '**/*.data' matched" in r for r in admin_reasons))
    
    def test_create_permission_inheritance_priority(self):
        """Test create permission priority in inheritance chains."""
        # Create grandparent with admin for alice
        grandparent_dir = Path(self.test_dir) / "create_priority"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "admin": ["alice@example.com"]  # Alice has admin (includes all lower permissions)
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with create for bob
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "create": ["bob@example.com"]  # Bob has create (includes read)
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with read for charlie
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "test.txt",
                "access": {
                    "read": ["charlie@example.com"]  # Charlie has only read
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create test file
        test_file = child_dir / "test.txt"
        test_file.write_text("test content")
        
        # Open the file
        syft_file = syft_perm.open(test_file)
        
        # Alice should have NO access (nearest-node: child rule doesn't grant to alice)
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_create_access("alice@example.com"))
        self.assertFalse(syft_file.has_read_access("alice@example.com"))
        
        # Bob should have NO access (nearest-node: child rule doesn't grant to bob)
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        
        # Charlie should have only read from child rule (nearest-node)
        self.assertFalse(syft_file.has_admin_access("charlie@example.com"))
        self.assertFalse(syft_file.has_write_access("charlie@example.com"))
        self.assertFalse(syft_file.has_create_access("charlie@example.com"))
        self.assertTrue(syft_file.has_read_access("charlie@example.com"))
        
        # Check reasons - alice should have no access
        has_read, read_reasons = syft_file._check_permission_with_reasons("alice@example.com", "read")
        self.assertFalse(has_read)
        
        # Bob should have no access
        has_read, read_reasons = syft_file._check_permission_with_reasons("bob@example.com", "read")
        self.assertFalse(has_read)
        
        # Charlie should show explicit read permission
        has_read, read_reasons = syft_file._check_permission_with_reasons("charlie@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Explicitly granted read" in r for r in read_reasons))
        
        # Charlie should show explicit read grant
        has_read, read_reasons = syft_file._check_permission_with_reasons("charlie@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Explicitly granted read" in r for r in read_reasons))
    
    def test_file_limits_priority_comprehensive(self):
        """Test various file limit priority scenarios."""
        # Create nested directory structure with different limits at each level
        root_dir = Path(self.test_dir) / "limits_priority"
        root_dir.mkdir(parents=True)
        
        # Root level - most permissive limits
        root_yaml = root_dir / "syft.pub.yaml"
        root_rules = {
            "rules": [{
                "pattern": "**",
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
        with open(root_yaml, 'w') as f:
            yaml.dump(root_rules, f)
        
        # Mid level - more restrictive
        mid_dir = root_dir / "restricted"
        mid_dir.mkdir()
        
        mid_yaml = mid_dir / "syft.pub.yaml"
        mid_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "write": ["alice@example.com"]
                },
                "limits": {
                    "max_file_size": 5 * 1024 * 1024,  # 5MB (more restrictive)
                    "allow_dirs": False,  # No directories
                    "allow_symlinks": True
                }
            }]
        }
        with open(mid_yaml, 'w') as f:
            yaml.dump(mid_rules, f)
        
        # Inner level - most restrictive
        inner_dir = mid_dir / "secure"
        inner_dir.mkdir()
        
        inner_yaml = inner_dir / "syft.pub.yaml"
        inner_rules = {
            "rules": [{
                "pattern": "*.secure",
                "access": {
                    "write": ["alice@example.com"]
                },
                "limits": {
                    "max_file_size": 1024 * 1024,  # 1MB (most restrictive)
                    "allow_dirs": False,
                    "allow_symlinks": False  # No symlinks either
                }
            }]
        }
        with open(inner_yaml, 'w') as f:
            yaml.dump(inner_rules, f)
        
        # Create test files at different levels
        root_file = root_dir / "large.txt"
        mid_file = mid_dir / "medium.txt"
        inner_file = inner_dir / "small.secure"
        
        # Write small content to all files (limits are structural, not enforced at runtime)
        for file_path in [root_file, mid_file, inner_file]:
            file_path.write_text("x" * 1000)  # 1KB content
        
        # Test that permissions are granted (file size enforcement would be at write time)
        syft_root = syft_perm.open(root_file)
        syft_mid = syft_perm.open(mid_file)
        syft_inner = syft_perm.open(inner_file)
        
        # All files should grant write access to alice (limit checking is structural)
        self.assertTrue(syft_root.has_write_access("alice@example.com"))
        self.assertTrue(syft_mid.has_write_access("alice@example.com"))
        self.assertTrue(syft_inner.has_write_access("alice@example.com"))
        
        # Test that the limit structure is preserved in permission data
        # This documents how limits would be used by the ACL service
        inner_perms = syft_inner._get_all_permissions_with_sources()
        self.assertIn("permissions", inner_perms)
        self.assertIn("sources", inner_perms)
        
        # Verify that alice has write permissions from the inner rule
        self.assertIn("write", inner_perms["permissions"])
        self.assertIn("alice@example.com", inner_perms["permissions"]["write"])
    
    def test_multiple_rule_priority_same_file(self):
        """Test priority when multiple rules in same file match."""
        # Create file with multiple overlapping rules
        test_dir = Path(self.test_dir) / "multi_rule"
        test_dir.mkdir(parents=True)
        
        test_file = test_dir / "document.txt"
        test_file.write_text("test document")
        
        # Create YAML with multiple rules that could match the same file
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "*.txt",  # Matches our file
                    "access": {
                        "read": ["alice@example.com"]
                    }
                },
                {
                    "pattern": "document.*",  # Also matches our file
                    "access": {
                        "write": ["bob@example.com"]
                    }
                },
                {
                    "pattern": "document.txt",  # Exact match (most specific)
                    "access": {
                        "admin": ["charlie@example.com"]
                    }
                },
                {
                    "pattern": "**/*.txt",  # Also matches but less specific than *.txt
                    "access": {
                        "create": ["david@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the file
        syft_file = syft_perm.open(test_file)
        
        # Following old syftbox behavior: most specific matching rule takes precedence
        # document.txt is most specific, so only charlie gets admin (and hierarchy permissions)
        self.assertFalse(syft_file.has_read_access("alice@example.com"))       # Not from most specific rule
        self.assertFalse(syft_file.has_write_access("bob@example.com"))        # Not from most specific rule
        self.assertTrue(syft_file.has_admin_access("charlie@example.com"))     # From most specific rule (document.txt)
        self.assertFalse(syft_file.has_create_access("david@example.com"))     # Not from most specific rule
        
        # Charlie also gets lower permissions via hierarchy
        self.assertTrue(syft_file.has_write_access("charlie@example.com"))     # Via admin hierarchy
        self.assertTrue(syft_file.has_create_access("charlie@example.com"))    # Via admin hierarchy  
        self.assertTrue(syft_file.has_read_access("charlie@example.com"))      # Via admin hierarchy


if __name__ == "__main__":
    unittest.main()