"""Test permission accumulation across multiple hierarchy levels."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm

class TestPermissionAccumulation(unittest.TestCase):
    """Test how permissions accumulate across grandparent-parent-child hierarchy."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["alice@example.com", "bob@example.com", "charlie@example.com"]
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_read_write_admin_accumulation(self):
        """Test read at grandparent + write at parent + admin at current."""
        # Create grandparent with read permission for alice
        grandparent_dir = Path(self.test_dir) / "grandparent"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with write permission for alice
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with admin permission for alice
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "data.txt",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the test file
        child_file = child_dir / "data.txt"
        child_file.write_text("test data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have admin permission (highest level wins)
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))   # Via hierarchy
        self.assertTrue(syft_file.has_create_access("alice@example.com"))  # Via hierarchy
        self.assertTrue(syft_file.has_read_access("alice@example.com"))    # Via hierarchy
        
        # Check reasons - should show admin as the source
        has_admin, admin_reasons = syft_file._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("Explicitly granted admin" in r for r in admin_reasons))
        
        # Lower permissions should show hierarchy inclusion
        has_write, write_reasons = syft_file._check_permission_with_reasons("alice@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Included via admin permission" in r for r in write_reasons))
    
    def test_four_level_accumulation(self):
        """Test read at grandparent + create at parent + write at current + admin at current."""
        # Create grandparent with read for alice
        grandparent_dir = Path(self.test_dir) / "four_levels"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with create for alice
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
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
        
        # Create child with admin for alice (includes write/create/read via hierarchy)
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "important.txt",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the test file
        child_file = child_dir / "important.txt"
        child_file.write_text("important data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have admin/write/create/read from child rule (nearest-node)
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        
        # Test at each level to verify accumulation
        # Grandparent level - only read
        gp_file = grandparent_dir / "gp_test.txt"
        gp_file.write_text("gp data")
        gp_syft = syft_perm.open(gp_file)
        self.assertTrue(gp_syft.has_read_access("alice@example.com"))
        self.assertFalse(gp_syft.has_create_access("alice@example.com"))
        self.assertFalse(gp_syft.has_write_access("alice@example.com"))
        self.assertFalse(gp_syft.has_admin_access("alice@example.com"))
        
        # Parent level - read + create
        p_file = parent_dir / "p_test.txt"
        p_file.write_text("parent data")
        p_syft = syft_perm.open(p_file)
        self.assertTrue(p_syft.has_read_access("alice@example.com"))    # Via hierarchy
        self.assertTrue(p_syft.has_create_access("alice@example.com"))  # Explicit
        self.assertFalse(p_syft.has_write_access("alice@example.com"))
        self.assertFalse(p_syft.has_admin_access("alice@example.com"))
    
    def test_same_user_different_permissions_each_level(self):
        """Test same user with different permissions at each level - highest wins."""
        # Create hierarchy where alice gets escalating permissions
        base_dir = Path(self.test_dir) / "escalation"
        base_dir.mkdir(parents=True)
        
        # Level 1: Alice gets read
        level1_yaml = base_dir / "syft.pub.yaml"
        level1_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"],
                    "create": ["bob@example.com"]  # Bob for comparison
                }
            }]
        }
        with open(level1_yaml, 'w') as f:
            yaml.dump(level1_rules, f)
        
        # Level 2: Alice gets write
        level2_dir = base_dir / "level2"
        level2_dir.mkdir()
        
        level2_yaml = level2_dir / "syft.pub.yaml"
        level2_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(level2_yaml, 'w') as f:
            yaml.dump(level2_rules, f)
        
        # Level 3: Alice gets admin
        level3_dir = level2_dir / "level3"
        level3_dir.mkdir()
        
        level3_yaml = level3_dir / "syft.pub.yaml"
        level3_rules = {
            "rules": [{
                "pattern": "final.txt",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(level3_yaml, 'w') as f:
            yaml.dump(level3_rules, f)
        
        # Create files at each level
        level1_file = base_dir / "level1.txt"
        level1_file.write_text("level 1")
        
        level2_file = level2_dir / "level2.txt"
        level2_file.write_text("level 2")
        
        level3_file = level3_dir / "final.txt"
        level3_file.write_text("final level")
        
        # Test level 1 - alice has read, bob has create
        l1_syft = syft_perm.open(level1_file)
        self.assertTrue(l1_syft.has_read_access("alice@example.com"))
        self.assertFalse(l1_syft.has_create_access("alice@example.com"))
        self.assertTrue(l1_syft.has_create_access("bob@example.com"))
        self.assertTrue(l1_syft.has_read_access("bob@example.com"))  # Via hierarchy
        
        # Test level 2 - nearest-node: only alice has write (from level 2 rule)
        l2_syft = syft_perm.open(level2_file)
        self.assertTrue(l2_syft.has_write_access("alice@example.com"))   # From level 2 rule
        self.assertTrue(l2_syft.has_create_access("alice@example.com"))  # Via hierarchy
        self.assertTrue(l2_syft.has_read_access("alice@example.com"))    # Via hierarchy
        self.assertFalse(l2_syft.has_create_access("bob@example.com"))   # Not in nearest rule
        self.assertFalse(l2_syft.has_read_access("bob@example.com"))     # Not in nearest rule
        
        # Test level 3 - nearest-node: only alice has admin (from level 3 rule)
        l3_syft = syft_perm.open(level3_file)
        self.assertTrue(l3_syft.has_admin_access("alice@example.com"))   # From level 3 rule
        self.assertTrue(l3_syft.has_write_access("alice@example.com"))   # Via hierarchy
        self.assertTrue(l3_syft.has_create_access("alice@example.com"))  # Via hierarchy
        self.assertTrue(l3_syft.has_read_access("alice@example.com"))    # Via hierarchy
        self.assertFalse(l3_syft.has_create_access("bob@example.com"))   # Not in nearest rule
        self.assertFalse(l3_syft.has_read_access("bob@example.com"))     # Not in nearest rule
    
    def test_public_and_specific_user_accumulation(self):
        """Test public (*) at one level, specific users at another."""
        # Create grandparent with public read
        grandparent_dir = Path(self.test_dir) / "public_specific"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["*"]  # Public read
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with specific user permissions
        parent_dir = grandparent_dir / "restricted"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "write": ["alice@example.com"],
                    "create": ["bob@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with admin for specific user
        child_dir = parent_dir / "secure"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "secret.txt",
                "access": {
                    "admin": ["charlie@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the test file
        child_file = child_dir / "secret.txt"
        child_file.write_text("secret data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Charlie should have admin/write/create/read from child rule (nearest-node)
        self.assertTrue(syft_file.has_admin_access("charlie@example.com"))
        self.assertTrue(syft_file.has_write_access("charlie@example.com"))  # Via hierarchy
        self.assertTrue(syft_file.has_create_access("charlie@example.com")) # Via hierarchy
        self.assertTrue(syft_file.has_read_access("charlie@example.com"))   # Via hierarchy
        
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
        
        # Random user should have NO access (nearest-node: child rule only grants to charlie)
        self.assertFalse(syft_file.has_admin_access("random@example.com"))
        self.assertFalse(syft_file.has_write_access("random@example.com"))
        self.assertFalse(syft_file.has_create_access("random@example.com"))
        self.assertFalse(syft_file.has_read_access("random@example.com"))
    
    def test_patterns_becoming_more_specific(self):
        """Test ** patterns becoming more specific down the tree."""
        # Create grandparent with broad pattern
        grandparent_dir = Path(self.test_dir) / "pattern_specificity"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",  # Everything
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with more specific pattern
        parent_dir = grandparent_dir / "docs"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**/*.md",  # Only markdown files
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with even more specific pattern
        child_dir = parent_dir / "api"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "v*/*.md",  # Only versioned markdown files
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create test files with different patterns
        # Non-markdown file at child level
        v1_dir = child_dir / "v1"
        v1_dir.mkdir()
        
        txt_file = v1_dir / "readme.txt"
        txt_file.write_text("text file")
        
        md_file_general = child_dir / "general.md"
        md_file_general.write_text("general markdown")
        
        md_file_versioned = v1_dir / "api.md"
        md_file_versioned.write_text("versioned api docs")
        
        # Test .txt file - only gets grandparent read
        txt_syft = syft_perm.open(txt_file)
        self.assertTrue(txt_syft.has_read_access("alice@example.com"))      # From grandparent
        self.assertFalse(txt_syft.has_write_access("alice@example.com"))    # Pattern doesn't match parent
        self.assertFalse(txt_syft.has_admin_access("alice@example.com"))    # Pattern doesn't match child
        
        # Test general .md file - gets grandparent read + parent write
        md_general_syft = syft_perm.open(md_file_general)
        self.assertTrue(md_general_syft.has_read_access("alice@example.com"))    # From grandparent
        self.assertTrue(md_general_syft.has_write_access("alice@example.com"))   # From parent
        self.assertTrue(md_general_syft.has_create_access("alice@example.com"))  # Via hierarchy
        self.assertFalse(md_general_syft.has_admin_access("alice@example.com")) # Child pattern doesn't match
        
        # Test versioned .md file - gets all permissions (admin is highest)
        md_versioned_syft = syft_perm.open(md_file_versioned)
        self.assertTrue(md_versioned_syft.has_admin_access("alice@example.com"))  # From child
        self.assertTrue(md_versioned_syft.has_write_access("alice@example.com"))  # Via hierarchy
        self.assertTrue(md_versioned_syft.has_create_access("alice@example.com")) # Via hierarchy
        self.assertTrue(md_versioned_syft.has_read_access("alice@example.com"))   # Via hierarchy
        
        # Verify reasoning shows pattern progression
        has_admin, admin_reasons = md_versioned_syft._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertTrue(any("Explicitly granted admin" in r for r in admin_reasons))
        
        has_write, write_reasons = md_versioned_syft._check_permission_with_reasons("alice@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Included via admin permission" in r for r in write_reasons))
    
    def test_create_permission_accumulation_across_levels(self):
        """Test create permission accumulation across levels."""
        # Create grandparent with create for alice
        grandparent_dir = Path(self.test_dir) / "create_accumulation"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "create": ["alice@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with create for bob + write for alice
        parent_dir = grandparent_dir / "uploads"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "create": ["bob@example.com"],
                    "write": ["alice@example.com"]  # Alice gets upgraded from create to write
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with create for charlie
        child_dir = parent_dir / "submissions"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "*.doc",
                "access": {
                    "create": ["charlie@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create test file
        doc_file = child_dir / "report.doc"
        doc_file.write_text("report content")
        
        # Open the file
        syft_file = syft_perm.open(doc_file)
        
        # Alice should have NO access (nearest-node: child rule doesn't grant to alice)
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_create_access("alice@example.com"))
        self.assertFalse(syft_file.has_read_access("alice@example.com"))
        
        # Bob should NOT have create - child rule overrides parent rule
        # According to old syftbox behavior: nearest node with matching rule wins
        # Child has *.doc pattern that matches, so parent's ** rule is ignored
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        
        # Charlie should have create from child
        self.assertTrue(syft_file.has_create_access("charlie@example.com"))
        self.assertTrue(syft_file.has_read_access("charlie@example.com"))  # Via hierarchy
        self.assertFalse(syft_file.has_write_access("charlie@example.com"))
        
        # Test permission reasoning
        has_write, write_reasons = syft_file._check_permission_with_reasons("alice@example.com", "write")
        self.assertFalse(has_write)
        self.assertTrue(any("Pattern '*.doc' matched" in r for r in write_reasons))
        
        has_create_bob, create_reasons_bob = syft_file._check_permission_with_reasons("bob@example.com", "create")
        self.assertFalse(has_create_bob)
        # Bob has no permission because child rule matches but doesn't grant create to bob
        self.assertTrue(any("Pattern '*.doc' matched" in r for r in create_reasons_bob))
        
        has_create_charlie, create_reasons_charlie = syft_file._check_permission_with_reasons("charlie@example.com", "create")
        self.assertTrue(has_create_charlie)
        self.assertTrue(any("Explicitly granted create" in r for r in create_reasons_charlie))


if __name__ == "__main__":
    unittest.main()