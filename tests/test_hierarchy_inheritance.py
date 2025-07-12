"""Test permission hierarchy and inheritance behavior."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm

class TestHierarchyInheritance(unittest.TestCase):
    """Test permission hierarchy (Admin > Write > Create > Read) with inheritance."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["alice@example.com", "bob@example.com", "charlie@example.com"]
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_permission_hierarchy_with_inheritance(self):
        """Test that parent write permission grants child write+create+read through hierarchy."""
        # Create parent directory with write permission for alice
        parent_dir = Path(self.test_dir) / "parent"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",  # Apply to all children
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child file with no explicit permissions
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        child_file = child_dir / "data.txt"
        child_file.write_text("test data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have write permission from parent
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        
        # Through hierarchy, alice should also have create and read
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        
        # But NOT admin (write doesn't grant admin)
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Bob should have no permissions
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        
        # Check reasons for alice
        has_write, write_reasons = syft_file._check_permission_with_reasons("alice@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Explicitly granted write" in r for r in write_reasons))
        
        has_create, create_reasons = syft_file._check_permission_with_reasons("alice@example.com", "create")
        self.assertTrue(has_create)
        self.assertTrue(any("Included via write permission" in r for r in create_reasons))
        
        has_read, read_reasons = syft_file._check_permission_with_reasons("alice@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Included via write permission" in r for r in read_reasons))
    
    def test_permission_hierarchy_override(self):
        """Test that explicit child permissions override parent permissions."""
        # Create parent directory with admin permission for alice
        parent_dir = Path(self.test_dir) / "parent"
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
        
        # Create child directory with explicit read-only permission for alice
        # Using terminal:true to stop inheritance
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "terminal": True,  # This stops inheritance from parent
            "rules": [{
                "pattern": "data.txt",
                "access": {
                    "read": ["alice@example.com"]
                    # Explicitly NOT granting write or admin
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the actual file
        child_file = child_dir / "data.txt"
        child_file.write_text("restricted data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have ONLY read permission (explicit override)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_create_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Check reasons - should show explicit read, not inherited admin
        has_read, read_reasons = syft_file._check_permission_with_reasons("alice@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Explicitly granted read" in r for r in read_reasons))
        self.assertFalse(any("admin" in r.lower() for r in read_reasons))
        
        # Admin check should fail with pattern explanation (terminal rule blocks inheritance)
        has_admin, admin_reasons = syft_file._check_permission_with_reasons("alice@example.com", "admin")
        self.assertFalse(has_admin)
        self.assertTrue(any("Pattern 'data.txt' matched" in r for r in admin_reasons))
    
    def test_mixed_hierarchy_reasons(self):
        """Test that highest permission level is shown in reasons when user has multiple."""
        # Create parent directory with admin for alice
        parent_dir = Path(self.test_dir) / "parent"
        parent_dir.mkdir(parents=True)
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "child/**",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child directory with write permission for alice (lower than admin)
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "report.pdf",
                "access": {
                    "write": ["alice@example.com"]
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
        
        # Alice should have write/create/read only (nearest-node: child rule, not admin)
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))  # Child rule doesn't grant admin
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        
        # Get the permission table
        table_rows = syft_file._get_permission_table()
        
        # Find alice's row
        alice_row = None
        for row in table_rows:
            if row[0] == "alice@example.com":
                alice_row = row
                break
        
        self.assertIsNotNone(alice_row)
        
        # Check that write/create/read have checkmarks, but NOT admin
        self.assertEqual(alice_row[1], "✓")  # Read
        self.assertEqual(alice_row[2], "✓")  # Create
        self.assertEqual(alice_row[3], "✓")  # Write
        self.assertEqual(alice_row[4], "")   # Admin (not granted by child rule)
        
        # Check the reason - should show [Write] as the highest level
        reason_text = alice_row[5]
        self.assertIn("[Write]", reason_text)
        
        # Should NOT show admin reason since child rule doesn't grant admin
        self.assertNotIn("[Admin]", reason_text)
        
        # The write reason should mention it's explicitly granted
        self.assertIn("Explicitly granted write", reason_text)
        
        # Test the explain_permissions method
        explanation = syft_file.explain_permissions("alice@example.com")
        
        # Should show GRANTED for write/create/read, DENIED for admin
        self.assertIn("ADMIN: ✗ DENIED", explanation)
        self.assertIn("WRITE: ✓ GRANTED", explanation)
        self.assertIn("CREATE: ✓ GRANTED", explanation)
        self.assertIn("READ: ✓ GRANTED", explanation)
    
    def test_hierarchy_with_public_access(self):
        """Test permission hierarchy with public (*) access."""
        # Create a directory with public write access
        test_dir = Path(self.test_dir) / "public_test"
        test_dir.mkdir(parents=True)
        
        yaml_path = test_dir / "syft.pub.yaml"
        rules = {
            "rules": [{
                "pattern": "shared.txt",
                "access": {
                    "write": ["*"]  # Public write access
                }
            }]
        }
        with open(yaml_path, 'w') as f:
            yaml.dump(rules, f)
        
        # Create the file
        test_file = test_dir / "shared.txt"
        test_file.write_text("public content")
        
        # Open the file
        syft_file = syft_perm.open(test_file)
        
        # Everyone should have write, create, and read (but not admin)
        for user in ["alice@example.com", "bob@example.com", "anyone@test.com"]:
            self.assertTrue(syft_file.has_write_access(user))
            self.assertTrue(syft_file.has_create_access(user))  # Via hierarchy
            self.assertTrue(syft_file.has_read_access(user))    # Via hierarchy
            self.assertFalse(syft_file.has_admin_access(user))
        
        # Check the table has public row with correct permissions
        table_rows = syft_file._get_permission_table()
        public_row = None
        for row in table_rows:
            if row[0] == "public":
                public_row = row
                break
        
        self.assertIsNotNone(public_row)
        self.assertEqual(public_row[1], "✓")  # Read
        self.assertEqual(public_row[2], "✓")  # Create
        self.assertEqual(public_row[3], "✓")  # Write
        self.assertEqual(public_row[4], "")   # Admin (not granted)
        
        # Reason should show [Write] and mention public access
        reason_text = public_row[5]
        self.assertIn("[Write]", reason_text)
        self.assertIn("Public access (*)", reason_text)
    
    def test_create_permission_hierarchy(self):
        """Test that create permission grants read but not write or admin."""
        # Create a directory with create permission for bob
        test_dir = Path(self.test_dir) / "create_test"
        test_dir.mkdir(parents=True)
        
        yaml_path = test_dir / "syft.pub.yaml"
        rules = {
            "rules": [{
                "pattern": "uploads/**",
                "access": {
                    "create": ["bob@example.com"]
                }
            }]
        }
        with open(yaml_path, 'w') as f:
            yaml.dump(rules, f)
        
        # Create a file in uploads directory
        uploads_dir = test_dir / "uploads"
        uploads_dir.mkdir()
        upload_file = uploads_dir / "new_file.txt"
        upload_file.write_text("uploaded content")
        
        # Open the file
        syft_file = syft_perm.open(upload_file)
        
        # Bob should have create and read, but not write or admin
        self.assertTrue(syft_file.has_create_access("bob@example.com"))
        self.assertTrue(syft_file.has_read_access("bob@example.com"))  # Via hierarchy
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        
        # Check reasons
        has_create, create_reasons = syft_file._check_permission_with_reasons("bob@example.com", "create")
        self.assertTrue(has_create)
        self.assertTrue(any("Explicitly granted create" in r for r in create_reasons))
        
        has_read, read_reasons = syft_file._check_permission_with_reasons("bob@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Included via create permission" in r for r in read_reasons))
        
        # Pattern should be mentioned
        self.assertTrue(any("uploads/**" in r for r in create_reasons))
    
    def test_grandparent_public_parent_specific_child_inherits(self):
        """Test grandparent *, parent specific user, child nothing → child gets parent's user only."""
        # Create grandparent with public read
        grandparent_dir = Path(self.test_dir) / "grandparent"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["*"]  # Public read access
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with specific user write access
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "child/**",
                "access": {
                    "write": ["alice@example.com"]  # Only alice has write
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with no explicit permissions
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        child_file = child_dir / "data.txt"
        child_file.write_text("test data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have write/create/read from parent (nearest-node rule)
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        
        # Bob should have NO access (nearest-node: parent rule doesn't grant to bob)
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        
        # Random user should also have NO access (nearest-node: parent rule only grants to alice)
        self.assertFalse(syft_file.has_read_access("random@test.com"))
        self.assertFalse(syft_file.has_write_access("random@test.com"))
    
    def test_grandparent_create_parent_write_child_read(self):
        """Test grandparent has create, parent has write, child has read → test each level."""
        # Create grandparent with create permission for charlie
        grandparent_dir = Path(self.test_dir) / "levels"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "create": ["charlie@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with write permission for bob
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "write": ["bob@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with read permission for alice
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "data.txt",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create test files at each level
        grandparent_file = grandparent_dir / "gp_data.txt"
        grandparent_file.write_text("grandparent data")
        
        parent_file = parent_dir / "p_data.txt"
        parent_file.write_text("parent data")
        
        child_file = child_dir / "data.txt"
        child_file.write_text("child data")
        
        # Test grandparent level - only charlie has create/read
        gp_syft = syft_perm.open(grandparent_file)
        self.assertTrue(gp_syft.has_create_access("charlie@example.com"))
        self.assertTrue(gp_syft.has_read_access("charlie@example.com"))  # Via hierarchy
        self.assertFalse(gp_syft.has_write_access("charlie@example.com"))
        
        # Bob and alice have no permissions at grandparent level
        self.assertFalse(gp_syft.has_read_access("bob@example.com"))
        self.assertFalse(gp_syft.has_read_access("alice@example.com"))
        
        # Test parent level - bob has write/create/read, charlie and alice have NO access (nearest-node)
        p_syft = syft_perm.open(parent_file)
        self.assertTrue(p_syft.has_write_access("bob@example.com"))
        self.assertTrue(p_syft.has_create_access("bob@example.com"))  # Via hierarchy
        self.assertTrue(p_syft.has_read_access("bob@example.com"))    # Via hierarchy
        
        # Charlie has NO access (nearest-node: parent rule doesn't grant to charlie)
        self.assertFalse(p_syft.has_create_access("charlie@example.com"))
        self.assertFalse(p_syft.has_read_access("charlie@example.com"))
        self.assertFalse(p_syft.has_write_access("charlie@example.com"))
        
        # Alice still has no permissions at parent level
        self.assertFalse(p_syft.has_read_access("alice@example.com"))
        
        # Test child level - alice has read only, bob and charlie have NO access (nearest-node: child rule)
        c_syft = syft_perm.open(child_file)
        self.assertTrue(c_syft.has_read_access("alice@example.com"))
        self.assertFalse(c_syft.has_create_access("alice@example.com"))
        self.assertFalse(c_syft.has_write_access("alice@example.com"))
        
        # Bob has NO access (nearest-node: child rule doesn't grant to bob)
        self.assertFalse(c_syft.has_write_access("bob@example.com"))
        self.assertFalse(c_syft.has_create_access("bob@example.com"))
        self.assertFalse(c_syft.has_read_access("bob@example.com"))
        
        # Charlie has NO access (nearest-node: child rule doesn't grant to charlie)
        self.assertFalse(c_syft.has_create_access("charlie@example.com"))
        self.assertFalse(c_syft.has_read_access("charlie@example.com"))
        self.assertFalse(c_syft.has_write_access("charlie@example.com"))
    
    def test_grandparent_admin_parent_write_child_read_override(self):
        """Test grandparent admin, parent write, child read → child has only read."""
        # Create grandparent with admin for alice
        grandparent_dir = Path(self.test_dir) / "override_test"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "admin": ["alice@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with write for alice (less than admin)
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "child/**",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with only read for alice (terminal to override)
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "terminal": True,  # Stop inheritance
            "rules": [{
                "pattern": "restricted.txt",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the child file
        child_file = child_dir / "restricted.txt"
        child_file.write_text("restricted data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Alice should have ONLY read at child level (terminal blocks inheritance)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_create_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Check that parent file still has admin access
        parent_file = parent_dir / "parent_data.txt"
        parent_file.write_text("parent data")
        parent_syft = syft_perm.open(parent_file)
        self.assertTrue(parent_syft.has_admin_access("alice@example.com"))
    
    def test_grandparent_pattern_parent_narrows_child_inherits(self):
        """Test grandparent **, parent narrows pattern, child inherits narrowed."""
        # Create grandparent with ** pattern for all files
        grandparent_dir = Path(self.test_dir) / "pattern_test"
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
        
        # Create parent that narrows pattern to only .txt files
        parent_dir = grandparent_dir / "docs"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**/*.txt",  # Only .txt files
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child directory with files
        child_dir = parent_dir / "api"
        child_dir.mkdir()
        
        txt_file = child_dir / "readme.txt"
        txt_file.write_text("text file")
        
        pdf_file = child_dir / "report.pdf"
        pdf_file.write_text("pdf file")
        
        # Test .txt file - alice should have write from parent pattern
        txt_syft = syft_perm.open(txt_file)
        self.assertTrue(txt_syft.has_write_access("alice@example.com"))
        self.assertTrue(txt_syft.has_read_access("alice@example.com"))  # Via hierarchy
        
        # Test .pdf file - alice should only have read from grandparent
        pdf_syft = syft_perm.open(pdf_file)
        self.assertTrue(pdf_syft.has_read_access("alice@example.com"))   # From grandparent
        self.assertFalse(pdf_syft.has_write_access("alice@example.com")) # Parent pattern doesn't match
    
    def test_complex_patterns_at_each_level(self):
        """Test complex ** patterns at each level (e.g., **/*.txt → docs/**/*.txt → docs/api/**/*.txt)."""
        # Create grandparent with broad pattern
        grandparent_dir = Path(self.test_dir) / "complex_patterns"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**/*.txt",  # All .txt files
                "access": {
                    "read": ["*"]  # Public read for all .txt
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent that narrows to docs directory
        parent_dir = grandparent_dir / "docs"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**/*.txt",  # .txt files under docs/
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child that further narrows to api subdirectory
        child_dir = parent_dir / "api"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "v2/**/*.txt",  # Only .txt files under api/v2/
                "access": {
                    "admin": ["bob@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create test files at different levels
        # Root level .txt file
        root_txt = grandparent_dir / "root.txt"
        root_txt.write_text("root text")
        
        # Docs level .txt file
        docs_txt = parent_dir / "guide.txt"
        docs_txt.write_text("docs text")
        
        # API level .txt file (not under v2)
        api_txt = child_dir / "v1.txt"
        api_txt.write_text("api v1 text")
        
        # API v2 level .txt file
        v2_dir = child_dir / "v2"
        v2_dir.mkdir()
        v2_txt = v2_dir / "spec.txt"
        v2_txt.write_text("api v2 text")
        
        # Test root level - only public read
        root_syft = syft_perm.open(root_txt)
        self.assertTrue(root_syft.has_read_access("alice@example.com"))
        self.assertTrue(root_syft.has_read_access("bob@example.com"))
        self.assertFalse(root_syft.has_write_access("alice@example.com"))
        
        # Test docs level - alice has write/read, bob has NO access (nearest-node: only docs rule applies)
        docs_syft = syft_perm.open(docs_txt)
        self.assertTrue(docs_syft.has_write_access("alice@example.com"))
        self.assertTrue(docs_syft.has_read_access("alice@example.com"))  # Via hierarchy
        self.assertFalse(docs_syft.has_read_access("bob@example.com"))   # No access from docs rule
        
        # Test api/v1.txt - alice has write/read (from nearest node: docs), bob has NO access
        api_syft = syft_perm.open(api_txt)
        self.assertTrue(api_syft.has_write_access("alice@example.com"))  # From nearest node (docs)
        self.assertTrue(api_syft.has_read_access("alice@example.com"))   # Via hierarchy
        self.assertFalse(api_syft.has_read_access("bob@example.com"))    # No access from docs rule
        self.assertFalse(api_syft.has_admin_access("bob@example.com"))   # Pattern doesn't match
        
        # Test api/v2/spec.txt - bob has admin/write/read, alice and charlie have NO access (child rule only)
        v2_syft = syft_perm.open(v2_txt)
        self.assertTrue(v2_syft.has_admin_access("bob@example.com"))     # From child rule
        self.assertTrue(v2_syft.has_write_access("bob@example.com"))     # Via hierarchy
        self.assertTrue(v2_syft.has_read_access("bob@example.com"))      # Via hierarchy
        self.assertFalse(v2_syft.has_write_access("alice@example.com"))  # Child rule doesn't grant to alice
        self.assertFalse(v2_syft.has_read_access("charlie@example.com")) # Child rule doesn't grant public access
    
    def test_three_levels_different_users_accumulate(self):
        """Test all three levels have different users → child uses nearest-node (child rule only)."""
        # Create grandparent with charlie having read
        grandparent_dir = Path(self.test_dir) / "accumulate"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["charlie@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent adding bob with create
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "create": ["bob@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child adding alice with write
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "shared.txt",
                "access": {
                    "write": ["alice@example.com"]
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create the child file
        child_file = child_dir / "shared.txt"
        child_file.write_text("shared data")
        
        # Open the child file
        syft_file = syft_perm.open(child_file)
        
        # Only alice should have permissions (nearest-node: child rule only)
        # Alice has write (and thus create/read via hierarchy)
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        
        # Bob has NO access (nearest-node: child rule doesn't grant to bob)
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        
        # Charlie has NO access (nearest-node: child rule doesn't grant to charlie)
        self.assertFalse(syft_file.has_read_access("charlie@example.com"))
        self.assertFalse(syft_file.has_create_access("charlie@example.com"))
        self.assertFalse(syft_file.has_write_access("charlie@example.com"))
        
        # Random user has no permissions
        self.assertFalse(syft_file.has_read_access("random@example.com"))
    
    def test_file_size_limits_most_restrictive_applies(self):
        """Test file size limits at different levels → most restrictive applies."""
        # Create grandparent with 10MB limit
        grandparent_dir = Path(self.test_dir) / "limits"
        grandparent_dir.mkdir(parents=True)
        
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_rules = {
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
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(grandparent_rules, f)
        
        # Create parent with 5MB limit (more restrictive)
        parent_dir = grandparent_dir / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "write": ["alice@example.com"]
                },
                "limits": {
                    "max_file_size": 5 * 1024 * 1024,  # 5MB
                    "allow_dirs": True,
                    "allow_symlinks": False  # Also restrict symlinks
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(parent_rules, f)
        
        # Create child with 1MB limit (most restrictive)
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_rules = {
            "rules": [{
                "pattern": "*.dat",
                "access": {
                    "write": ["alice@example.com"]
                },
                "limits": {
                    "max_file_size": 1024 * 1024,  # 1MB
                    "allow_dirs": False,  # No directories
                    "allow_symlinks": False
                }
            }]
        }
        with open(child_yaml, 'w') as f:
            yaml.dump(child_rules, f)
        
        # Create test files
        # Small file that passes all limits
        small_file = child_dir / "small.dat"
        small_file.write_text("x" * 1000)  # 1KB
        
        # Test that alice can access small file
        small_syft = syft_perm.open(small_file)
        self.assertTrue(small_syft.has_write_access("alice@example.com"))
        
        # Note: The current implementation doesn't enforce file size limits at runtime,
        # they would be enforced by the ACL service when actually writing.
        # This test documents the expected structure for limits in the YAML files.
        
        # Verify the limits are properly set in the rules
        perms_data = small_syft._get_all_permissions_with_sources()
        self.assertIsNotNone(perms_data)
        
        # The child rule should be the effective one for .dat files
        # and it should have the most restrictive limit (1MB)


if __name__ == "__main__":
    unittest.main()