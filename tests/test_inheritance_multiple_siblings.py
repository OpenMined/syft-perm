"""Test inheritance behavior with multiple siblings according to old syftbox nearest-node algorithm."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestInheritanceMultipleSiblings(unittest.TestCase):
    """Test inheritance behavior with multiple siblings using old syftbox nearest-node algorithm."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
        self.test_users = [
            "alice@example.com",
            "bob@example.com", 
            "charlie@example.com",
            "user1@example.com",
            "user2@example.com",
            "user3@example.com"
        ]
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_inheritance_with_multiple_siblings(self):
        """
        Test the scenario from old syftbox:
        Parent has: * read
        - child1/file.txt: inherits * read
        - child2/file.txt: user1 write (overrides inherited)
        - child3/: terminal=true, user2 admin
        - child4/: no rules (pure inheritance)
        - file.txt: user3 read (sibling to folders)
        - child5/file.txt: user1 create (tests create inheritance)
        """
        # Create directory structure
        parent_dir = Path(self.test_dir) / "parent"
        child1_dir = parent_dir / "child1"
        child2_dir = parent_dir / "child2"
        child3_dir = parent_dir / "child3"
        child4_dir = parent_dir / "child4"
        child5_dir = parent_dir / "child5"
        
        # Create all directories
        for dir_path in [child1_dir, child2_dir, child3_dir, child4_dir, child5_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Create files
        child1_file = child1_dir / "file.txt"
        child2_file = child2_dir / "file.txt"
        child3_file = child3_dir / "file.txt"
        child4_file = child4_dir / "file.txt"
        child5_file = child5_dir / "file.txt"
        parent_file = parent_dir / "file.txt"  # Sibling to folders
        
        for file_path in [child1_file, child2_file, child3_file, child4_file, child5_file, parent_file]:
            file_path.write_text("test content")
        
        # Parent has * read (public read access)
        parent_yaml = parent_dir / "syft.pub.yaml"
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
        
        # child1/ has no rules - should inherit parent's * read
        # (no syft.pub.yaml file created)
        
        # child2/ has user1 write - should override inherited permissions (nearest-node)
        child2_yaml = child2_dir / "syft.pub.yaml"
        child2_content = {
            "rules": [{
                "pattern": "file.txt",
                "access": {
                    "write": ["user1@example.com"]
                }
            }]
        }
        with open(child2_yaml, 'w') as f:
            yaml.dump(child2_content, f)
        
        # child3/ has terminal=true with user2 admin - blocks inheritance
        child3_yaml = child3_dir / "syft.pub.yaml"
        child3_content = {
            "terminal": True,
            "rules": [{
                "pattern": "**",
                "access": {
                    "admin": ["user2@example.com"]
                }
            }]
        }
        with open(child3_yaml, 'w') as f:
            yaml.dump(child3_content, f)
        
        # child4/ has no rules - should inherit parent's * read
        # (no syft.pub.yaml file created)
        
        # child5/ has user1 create - should override inherited permissions (nearest-node)
        child5_yaml = child5_dir / "syft.pub.yaml"
        child5_content = {
            "rules": [{
                "pattern": "file.txt",
                "access": {
                    "create": ["user1@example.com"]
                }
            }]
        }
        with open(child5_yaml, 'w') as f:
            yaml.dump(child5_content, f)
        
        # Test child1/file.txt - should inherit parent's * read
        syft_child1 = syft_perm.open(child1_file)
        self.assertTrue(syft_child1.has_read_access("*"))
        self.assertTrue(syft_child1.has_read_access("alice@example.com"))  # Via *
        self.assertFalse(syft_child1.has_write_access("*"))
        self.assertFalse(syft_child1.has_write_access("user1@example.com"))
        self.assertFalse(syft_child1.has_admin_access("user2@example.com"))
        
        # Verify inheritance reason
        has_read, reasons = syft_child1._check_permission_with_reasons("alice@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Public access (*)" in r for r in reasons))
        
        # Test child2/file.txt - should use child2's nearest-node rules (user1 write)
        syft_child2 = syft_perm.open(child2_file)
        self.assertTrue(syft_child2.has_write_access("user1@example.com"))
        self.assertTrue(syft_child2.has_create_access("user1@example.com"))  # Via hierarchy
        self.assertTrue(syft_child2.has_read_access("user1@example.com"))    # Via hierarchy
        # Should NOT inherit parent's * read (nearest-node overrides)
        self.assertFalse(syft_child2.has_read_access("*"))
        self.assertFalse(syft_child2.has_read_access("alice@example.com"))
        self.assertFalse(syft_child2.has_admin_access("user2@example.com"))
        
        # Verify nearest-node override reason
        has_read, reasons = syft_child2._check_permission_with_reasons("user1@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Included via write permission" in r for r in reasons))
        
        # Test child3/file.txt - should use ONLY terminal rules (user2 admin)
        syft_child3 = syft_perm.open(child3_file)
        self.assertTrue(syft_child3.has_admin_access("user2@example.com"))
        self.assertTrue(syft_child3.has_write_access("user2@example.com"))   # Via hierarchy
        self.assertTrue(syft_child3.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(syft_child3.has_read_access("user2@example.com"))    # Via hierarchy
        # Should NOT inherit parent's * read (terminal blocks inheritance)
        self.assertFalse(syft_child3.has_read_access("*"))
        self.assertFalse(syft_child3.has_read_access("alice@example.com"))
        self.assertFalse(syft_child3.has_write_access("user1@example.com"))
        
        # Verify terminal reason
        has_admin, reasons = syft_child3._check_permission_with_reasons("user2@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("Explicitly granted admin" in r for r in reasons))
        
        # Test child4/file.txt - should inherit parent's * read (no rules)
        syft_child4 = syft_perm.open(child4_file)
        self.assertTrue(syft_child4.has_read_access("*"))
        self.assertTrue(syft_child4.has_read_access("alice@example.com"))  # Via *
        self.assertFalse(syft_child4.has_write_access("*"))
        self.assertFalse(syft_child4.has_write_access("user1@example.com"))
        self.assertFalse(syft_child4.has_admin_access("user2@example.com"))
        
        # Test parent/file.txt - sibling to folders, should inherit parent's * read
        syft_parent = syft_perm.open(parent_file)
        self.assertTrue(syft_parent.has_read_access("*"))
        self.assertTrue(syft_parent.has_read_access("alice@example.com"))  # Via *
        self.assertFalse(syft_parent.has_write_access("*"))
        self.assertFalse(syft_parent.has_write_access("user1@example.com"))
        self.assertFalse(syft_parent.has_admin_access("user2@example.com"))
        
        # Test child5/file.txt - should use child5's nearest-node rules (user1 create)
        syft_child5 = syft_perm.open(child5_file)
        self.assertTrue(syft_child5.has_create_access("user1@example.com"))
        self.assertTrue(syft_child5.has_read_access("user1@example.com"))    # Via hierarchy
        self.assertFalse(syft_child5.has_write_access("user1@example.com"))  # Create doesn't include write
        # Should NOT inherit parent's * read (nearest-node overrides)
        self.assertFalse(syft_child5.has_read_access("*"))
        self.assertFalse(syft_child5.has_read_access("alice@example.com"))
        self.assertFalse(syft_child5.has_admin_access("user2@example.com"))
        
        # Verify create permission hierarchy
        has_read, reasons = syft_child5._check_permission_with_reasons("user1@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Included via create permission" in r for r in reasons))
    
    def test_siblings_do_not_inherit_from_each_other(self):
        """Test that siblings don't inherit permissions from each other."""
        # Create parent with two children
        parent_dir = Path(self.test_dir) / "parent"
        child_a_dir = parent_dir / "child_a"
        child_b_dir = parent_dir / "child_b"
        
        child_a_dir.mkdir(parents=True)
        child_b_dir.mkdir(parents=True)
        
        file_a = child_a_dir / "data.txt"
        file_b = child_b_dir / "data.txt"
        file_a.write_text("content a")
        file_b.write_text("content b")
        
        # No parent rules
        
        # child_a has alice admin
        child_a_yaml = child_a_dir / "syft.pub.yaml"
        child_a_content = {
            "rules": [{
                "pattern": "data.txt",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(child_a_yaml, 'w') as f:
            yaml.dump(child_a_content, f)
        
        # child_b has no rules
        
        # Test file_a - should have alice admin
        syft_file_a = syft_perm.open(file_a)
        self.assertTrue(syft_file_a.has_admin_access("alice@example.com"))
        self.assertTrue(syft_file_a.has_write_access("alice@example.com"))   # Via hierarchy
        self.assertTrue(syft_file_a.has_create_access("alice@example.com"))  # Via hierarchy
        self.assertTrue(syft_file_a.has_read_access("alice@example.com"))    # Via hierarchy
        
        # Test file_b - should have NO permissions (siblings don't inherit from each other)
        syft_file_b = syft_perm.open(file_b)
        self.assertFalse(syft_file_b.has_admin_access("alice@example.com"))
        self.assertFalse(syft_file_b.has_write_access("alice@example.com"))
        self.assertFalse(syft_file_b.has_create_access("alice@example.com"))
        self.assertFalse(syft_file_b.has_read_access("alice@example.com"))
        
        # Verify no permission reason
        has_read, reasons = syft_file_b._check_permission_with_reasons("alice@example.com", "read")
        self.assertFalse(has_read)
        self.assertTrue(any("No permission found" in r for r in reasons))
    
    def test_terminal_only_affects_own_subtree(self):
        """Test that terminal nodes only affect their own subtree, not siblings."""
        # Create structure with terminal sibling
        parent_dir = Path(self.test_dir) / "parent"
        terminal_dir = parent_dir / "terminal_child"
        normal_dir = parent_dir / "normal_child"
        
        terminal_dir.mkdir(parents=True)
        normal_dir.mkdir(parents=True)
        
        terminal_file = terminal_dir / "secret.txt"
        normal_file = normal_dir / "public.txt"
        terminal_file.write_text("secret")
        normal_file.write_text("public")
        
        # Parent grants alice admin to everything
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
        
        # Terminal child blocks inheritance and grants only bob read
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_content = {
            "terminal": True,
            "rules": [{
                "pattern": "secret.txt",
                "access": {
                    "read": ["bob@example.com"]
                }
            }]
        }
        with open(terminal_yaml, 'w') as f:
            yaml.dump(terminal_content, f)
        
        # normal_child has no rules
        
        # Test terminal file - should have ONLY bob read (terminal blocks alice admin)
        syft_terminal = syft_perm.open(terminal_file)
        self.assertTrue(syft_terminal.has_read_access("bob@example.com"))
        self.assertFalse(syft_terminal.has_write_access("bob@example.com"))
        self.assertFalse(syft_terminal.has_admin_access("alice@example.com"))  # Blocked by terminal
        self.assertFalse(syft_terminal.has_read_access("alice@example.com"))   # Blocked by terminal
        
        # Test normal file - should inherit parent's alice admin (not affected by sibling terminal)
        syft_normal = syft_perm.open(normal_file)
        self.assertTrue(syft_normal.has_admin_access("alice@example.com"))
        self.assertTrue(syft_normal.has_write_access("alice@example.com"))    # Via hierarchy
        self.assertTrue(syft_normal.has_create_access("alice@example.com"))   # Via hierarchy
        self.assertTrue(syft_normal.has_read_access("alice@example.com"))     # Via hierarchy
        self.assertFalse(syft_normal.has_read_access("bob@example.com"))      # Terminal doesn't affect siblings
        
        # Verify reasons
        has_admin, reasons = syft_normal._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("Explicitly granted admin" in r for r in reasons))
    
    def test_pattern_specificity_with_siblings(self):
        """Test that pattern specificity works correctly when siblings have different rules."""
        # Create structure where siblings have overlapping patterns
        parent_dir = Path(self.test_dir) / "parent"
        docs_dir = parent_dir / "docs"
        api_dir = parent_dir / "api"
        
        docs_dir.mkdir(parents=True)
        api_dir.mkdir(parents=True)
        
        docs_file = docs_dir / "guide.md"
        api_file = api_dir / "guide.md"
        docs_file.write_text("documentation")
        api_file.write_text("api docs")
        
        # Parent has broad ** pattern for alice
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = {
            "rules": [{
                "pattern": "**/*.md",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_content, f)
        
        # docs/ has more specific pattern for bob
        docs_yaml = docs_dir / "syft.pub.yaml"
        docs_content = {
            "rules": [{
                "pattern": "guide.md",  # More specific than **/*.md
                "access": {
                    "write": ["bob@example.com"]
                }
            }]
        }
        with open(docs_yaml, 'w') as f:
            yaml.dump(docs_content, f)
        
        # api/ has no rules - inherits parent
        
        # Test docs/guide.md - should use docs' nearest-node rule (bob write)
        syft_docs = syft_perm.open(docs_file)
        self.assertTrue(syft_docs.has_write_access("bob@example.com"))
        self.assertTrue(syft_docs.has_create_access("bob@example.com"))  # Via hierarchy
        self.assertTrue(syft_docs.has_read_access("bob@example.com"))    # Via hierarchy
        # Should NOT inherit parent's alice read (nearest-node overrides)
        self.assertFalse(syft_docs.has_read_access("alice@example.com"))
        
        # Test api/guide.md - should inherit parent's alice read
        syft_api = syft_perm.open(api_file)
        self.assertTrue(syft_api.has_read_access("alice@example.com"))
        self.assertFalse(syft_api.has_write_access("alice@example.com"))
        self.assertFalse(syft_api.has_write_access("bob@example.com"))    # Siblings don't affect each other
        
        # Verify pattern specificity reasoning
        has_write, reasons = syft_docs._check_permission_with_reasons("bob@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Explicitly granted write" in r for r in reasons))
        self.assertTrue(any("Pattern 'guide.md' matched" in r for r in reasons))
    
    def test_create_permission_in_sibling_inheritance(self):
        """Test that create permission level works correctly in inheritance chains with siblings."""
        # Create hierarchy with different permission levels
        grandparent_dir = Path(self.test_dir) / "grandparent"
        parent_dir = grandparent_dir / "parent"
        create_child_dir = parent_dir / "create_child"
        inherit_child_dir = parent_dir / "inherit_child"
        
        create_child_dir.mkdir(parents=True)
        inherit_child_dir.mkdir(parents=True)
        
        create_file = create_child_dir / "data.json"
        inherit_file = inherit_child_dir / "data.json"
        create_file.write_text("{}")
        inherit_file.write_text("{}")
        
        # Grandparent grants admin to alice
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_content = {
            "rules": [{
                "pattern": "**/*.json",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_content, f)
        
        # Parent grants write to bob
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = {
            "rules": [{
                "pattern": "**/*.json",
                "access": {
                    "write": ["bob@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_content, f)
        
        # create_child grants create to charlie (nearest-node)
        create_child_yaml = create_child_dir / "syft.pub.yaml"
        create_child_content = {
            "rules": [{
                "pattern": "data.json",
                "access": {
                    "create": ["charlie@example.com"]
                }
            }]
        }
        with open(create_child_yaml, 'w') as f:
            yaml.dump(create_child_content, f)
        
        # inherit_child has no rules - inherits parent
        
        # Test create_child/data.json - should use nearest-node (charlie create)
        syft_create = syft_perm.open(create_file)
        self.assertTrue(syft_create.has_create_access("charlie@example.com"))
        self.assertTrue(syft_create.has_read_access("charlie@example.com"))   # Via hierarchy
        self.assertFalse(syft_create.has_write_access("charlie@example.com")) # Create doesn't include write
        # Should NOT inherit parent's bob write or grandparent's alice admin
        self.assertFalse(syft_create.has_write_access("bob@example.com"))
        self.assertFalse(syft_create.has_admin_access("alice@example.com"))
        
        # Test inherit_child/data.json - should inherit parent's bob write (nearest-node)
        syft_inherit = syft_perm.open(inherit_file)
        self.assertTrue(syft_inherit.has_write_access("bob@example.com"))
        self.assertTrue(syft_inherit.has_create_access("bob@example.com"))   # Via hierarchy
        self.assertTrue(syft_inherit.has_read_access("bob@example.com"))     # Via hierarchy
        # Should NOT inherit grandparent's alice admin (parent is nearest-node)
        self.assertFalse(syft_inherit.has_admin_access("alice@example.com"))
        # Should NOT get sibling's charlie create
        self.assertFalse(syft_inherit.has_create_access("charlie@example.com"))
        
        # Verify hierarchy reasoning
        has_read, reasons = syft_create._check_permission_with_reasons("charlie@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Included via create permission" in r for r in reasons))


if __name__ == "__main__":
    unittest.main()