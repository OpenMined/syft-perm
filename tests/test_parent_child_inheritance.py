"""Test parent-child inheritance scenarios for permissions."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestParentChildInheritance(unittest.TestCase):
    """Test specific parent-child permission inheritance scenarios."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["alice@example.com", "bob@example.com", "charlie@example.com"]
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_parent_has_star_child_has_nothing(self):
        """Test that child with no permissions inherits parent's * permissions."""
        # Create parent directory with * (public) permissions
        parent_dir = Path(self.test_dir) / "parent"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["*"],
                    "write": ["*"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child directory with NO syft.pub.yaml
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        child_file = child_dir / "data.txt"
        child_file.write_text("test data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Everyone should have read and write access inherited from parent
        for user in self.test_users + ["random@user.com", "*"]:
            self.assertTrue(syft_file.has_read_access(user))
            self.assertTrue(syft_file.has_write_access(user))
            # Also create access through hierarchy
            self.assertTrue(syft_file.has_create_access(user))
            # But not admin
            self.assertFalse(syft_file.has_admin_access(user))
        
        # Check reasons show inheritance
        has_read, read_reasons = syft_file._check_permission_with_reasons("alice@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Public access (*)" in r for r in read_reasons))
    
    def test_parent_has_create_child_inherits(self):
        """Test that child inherits parent's create permission."""
        # Create parent with create permission for alice
        parent_dir = Path(self.test_dir) / "workspace"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "create": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create nested child structure
        child_path = parent_dir / "projects" / "new" / "code.py"
        child_path.parent.mkdir(parents=True)
        child_path.write_text("print('hello')")
        
        # Open the deeply nested child file
        syft_file = syft_perm.open(child_path)
        
        # Alice should have create and read (via hierarchy)
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Bob should have nothing
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        
        # Check reasons
        has_create, create_reasons = syft_file._check_permission_with_reasons("alice@example.com", "create")
        self.assertTrue(has_create)
        self.assertTrue(any("Explicitly granted create" in r for r in create_reasons))
        self.assertTrue(any("workspace" in r for r in create_reasons))
    
    def test_parent_has_user_child_has_different_user(self):
        """Test that child with different user permissions has both parent and child users."""
        # Parent gives permission to alice
        parent_dir = Path(self.test_dir) / "shared"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Child gives permission to bob
        child_dir = parent_dir / "documents"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "report.pdf",
                "access": {
                    "write": ["bob@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the file
        child_file = child_dir / "report.pdf"
        child_file.write_text("report content")
        
        # Open the file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have NO access (nearest-node: child rule doesn't grant to alice)
        self.assertFalse(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        
        # Bob should have write (and thus create+read) from child
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        self.assertTrue(syft_file.has_create_access("bob@example.com"))
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        
        # Charlie should have nothing
        self.assertFalse(syft_file.has_read_access("charlie@example.com"))
        
        # Check the permission table shows only bob (nearest-node: child rule only)
        table_rows = syft_file._get_permission_table()
        users_in_table = [row[0] for row in table_rows]
        self.assertNotIn("alice@example.com", users_in_table)
        self.assertIn("bob@example.com", users_in_table)
    
    def test_parent_read_child_write_combined(self):
        """Test parent has read, child has write → child has both read and write."""
        # Parent grants read to alice
        parent_dir = Path(self.test_dir) / "docs"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Child grants write to alice
        child_dir = parent_dir / "editable"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "draft.txt",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the file
        child_file = child_dir / "draft.txt"
        child_file.write_text("draft content")
        
        # Open the file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have both read (from parent) and write (from child)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        # And create through write hierarchy
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        
        # Check reasons show both sources
        has_write, write_reasons = syft_file._check_permission_with_reasons("alice@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Explicitly granted write" in r for r in write_reasons))
        self.assertTrue(any("editable" in r for r in write_reasons))
    
    def test_parent_read_create_child_write_all_three(self):
        """Test parent has read+create, child has write → child has all three."""
        # Parent grants read and create to alice
        parent_dir = Path(self.test_dir) / "workspace"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"],
                    "create": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Child grants write to alice
        child_dir = parent_dir / "project"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "main.py",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the file
        child_file = child_dir / "main.py"
        child_file.write_text("# main code")
        
        # Open the file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have all three permissions
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        # But not admin
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Table should show all three permissions
        table_rows = syft_file._get_permission_table()
        alice_row = next(row for row in table_rows if row[0] == "alice@example.com")
        self.assertEqual(alice_row[1], "✓")  # Read
        self.assertEqual(alice_row[2], "✓")  # Create
        self.assertEqual(alice_row[3], "✓")  # Write
        self.assertEqual(alice_row[4], "")   # Admin (not granted)
    
    def test_parent_double_star_pattern_child_matches(self):
        """Test parent has ** pattern, child file matches and inherits."""
        # Parent has ** pattern
        parent_dir = Path(self.test_dir) / "root"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create deeply nested file
        nested_file = parent_dir / "a" / "b" / "c" / "deep.txt"
        nested_file.parent.mkdir(parents=True)
        nested_file.write_text("deep content")
        
        # Open the file
        syft_file = syft_perm.open(nested_file)
        
        # Alice should have admin (and all other permissions)
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        
        # Check pattern is mentioned in reasons
        has_admin, admin_reasons = syft_file._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("Pattern '**' matched" in r for r in admin_reasons))
    
    def test_parent_py_pattern_child_matches(self):
        """Test parent has **/*.py pattern, child src/main.py matches."""
        # Parent has pattern for Python files
        parent_dir = Path(self.test_dir) / "project"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [
                {
                    "pattern": "**/*.py",
                    "access": {
                        "write": ["dev@example.com"]
                    }
                },
                {
                    "pattern": "**/*.txt",
                    "access": {
                        "read": ["*"]
                    }
                }
            ]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create Python file in subdirectory
        src_dir = parent_dir / "src"
        src_dir.mkdir()
        py_file = src_dir / "main.py"
        py_file.write_text("print('hello')")
        
        # Create text file in same directory
        txt_file = src_dir / "readme.txt"
        txt_file.write_text("readme")
        
        # Test Python file - dev should have write access
        syft_py = syft_perm.open(py_file)
        self.assertTrue(syft_py.has_write_access("dev@example.com"))
        self.assertTrue(syft_py.has_create_access("dev@example.com"))
        self.assertTrue(syft_py.has_read_access("dev@example.com"))
        self.assertFalse(syft_py.has_write_access("alice@example.com"))
        
        # Test text file - everyone should have read access
        syft_txt = syft_perm.open(txt_file)
        self.assertTrue(syft_txt.has_read_access("*"))
        self.assertTrue(syft_txt.has_read_access("anyone@example.com"))
        self.assertFalse(syft_txt.has_write_access("anyone@example.com"))
        
        # Check pattern matching in reasons
        has_write, write_reasons = syft_py._check_permission_with_reasons("dev@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Pattern '**/*.py' matched" in r for r in write_reasons))
    
    def test_parent_file_limits_child_inherits(self):
        """Test that child inherits parent's file limits."""
        # Parent sets file size limits
        parent_dir = Path(self.test_dir) / "limited"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]
                },
                "limits": {
                    "max_file_size": 1024,  # 1KB limit
                    "allow_dirs": False,
                    "allow_symlinks": False
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child directory
        child_dir = parent_dir / "data"
        child_dir.mkdir()
        
        # Create small file (should be allowed)
        small_file = child_dir / "small.txt"
        small_file.write_text("x" * 500)  # 500 bytes
        
        # Create large file (should be blocked)
        large_file = child_dir / "large.txt"
        large_file.write_text("x" * 2000)  # 2KB
        
        # Test small file - should have access
        syft_small = syft_perm.open(small_file)
        self.assertTrue(syft_small.has_read_access("alice@example.com"))
        
        # Test large file - should NOT have access due to inherited limit
        syft_large = syft_perm.open(large_file)
        self.assertFalse(syft_large.has_read_access("alice@example.com"))
        
        # Test directory access - should be blocked by allow_dirs=False
        syft_dir = syft_perm.open(child_dir)
        self.assertFalse(syft_dir.has_read_access("alice@example.com"))
        
        # Create symlink and test - should be blocked
        if hasattr(Path, 'symlink_to'):
            symlink = child_dir / "link.txt"
            symlink.symlink_to(small_file)
            syft_symlink = syft_perm.open(symlink)
            self.assertFalse(syft_symlink.has_read_access("alice@example.com"))


if __name__ == "__main__":
    unittest.main()