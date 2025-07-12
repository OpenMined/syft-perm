"""Comprehensive tests for terminal node behavior."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestTerminalNodes(unittest.TestCase):
    """Test cases for terminal node behavior at different hierarchy levels."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
        self.test_users = [
            "alice@example.com",
            "bob@example.com", 
            "charlie@example.com"
        ]
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_terminal_at_grandparent_blocks_inheritance(self):
        """Terminal at grandparent → parent and child get no inheritance past grandparent."""
        # Create three-level hierarchy
        grandparent_dir = Path(self.test_dir) / "grandparent"
        parent_dir = grandparent_dir / "parent"
        child_dir = parent_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create files at each level
        grandparent_file = grandparent_dir / "gp.txt"
        parent_file = parent_dir / "parent.txt"
        child_file = child_dir / "child.txt"
        
        grandparent_file.write_text("grandparent content")
        parent_file.write_text("parent content")
        child_file.write_text("child content")
        
        # Root has public access
        root_yaml = Path(self.test_dir) / "syft.pub.yaml"
        root_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - "*"
    write:
    - "*"
"""
        root_yaml.write_text(root_content)
        
        # Grandparent is terminal with specific permissions
        grandparent_yaml = grandparent_dir / "syft.pub.yaml"
        grandparent_content = """terminal: true
rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
"""
        grandparent_yaml.write_text(grandparent_content)
        
        # Check grandparent file - only alice has access (terminal permissions)
        syft_gp = syft_perm.open(grandparent_file)
        self.assertTrue(syft_gp.has_read_access("alice@example.com"))
        self.assertFalse(syft_gp.has_read_access("bob@example.com"))
        self.assertFalse(syft_gp.has_write_access("alice@example.com"))
        
        # Check parent file - no permissions (terminal blocks inheritance)
        syft_parent = syft_perm.open(parent_file)
        self.assertFalse(syft_parent.has_read_access("alice@example.com"))
        self.assertFalse(syft_parent.has_read_access("bob@example.com"))
        self.assertFalse(syft_parent.has_read_access("*"))
        
        # Check child file - no permissions (terminal blocks inheritance)
        syft_child = syft_perm.open(child_file)
        self.assertFalse(syft_child.has_read_access("alice@example.com"))
        self.assertFalse(syft_child.has_read_access("bob@example.com"))
        
        # Verify terminal block reason
        has_perm, reasons = syft_child._check_permission_with_reasons("alice@example.com", "read")
        self.assertFalse(has_perm)
        # The implementation should show "Blocked by terminal" when terminal blocks inheritance
        self.assertTrue(any("Blocked by terminal" in r for r in reasons))
    
    def test_terminal_affects_its_own_directory(self):
        """Terminal at current level → provides permissions for files in that directory."""
        # Create directory structure
        parent_dir = Path(self.test_dir) / "parent"
        terminal_dir = parent_dir / "terminal"
        child_dir = terminal_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create files
        terminal_file = terminal_dir / "terminal.txt"
        child_file = child_dir / "child.txt"
        
        terminal_file.write_text("terminal content")
        child_file.write_text("child content")
        
        # Parent grants public access
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - "*"
    write:
    - bob@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Terminal directory with specific permissions
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_content = """terminal: true
rules:
- pattern: "*.txt"
  access:
    read:
    - alice@example.com
"""
        terminal_yaml.write_text(terminal_content)
        
        # Check terminal file - gets ONLY terminal permissions (no inheritance from parent)
        syft_terminal = syft_perm.open(terminal_file)
        self.assertTrue(syft_terminal.has_read_access("alice@example.com"))  # From terminal rule
        self.assertFalse(syft_terminal.has_read_access("*"))  # Blocked by terminal
        self.assertFalse(syft_terminal.has_write_access("bob@example.com"))  # Blocked by terminal
        
        # Check child file - no permissions (terminal blocks inheritance and no child pattern match)
        syft_child = syft_perm.open(child_file)
        self.assertFalse(syft_child.has_read_access("alice@example.com"))
        self.assertFalse(syft_child.has_read_access("*"))
        self.assertFalse(syft_child.has_write_access("bob@example.com"))
    
    def test_terminal_at_child_level_no_effect_on_current(self):
        """Terminal at child level → no effect on current."""
        # Create directory structure
        current_dir = Path(self.test_dir) / "current"
        child_dir = current_dir / "child"
        grandchild_dir = child_dir / "grandchild"
        grandchild_dir.mkdir(parents=True, exist_ok=True)
        
        # Create files
        current_file = current_dir / "current.txt"
        child_file = child_dir / "child.txt"
        grandchild_file = grandchild_dir / "grandchild.txt"
        
        current_file.write_text("current content")
        child_file.write_text("child content")
        grandchild_file.write_text("grandchild content")
        
        # Current directory grants permissions
        current_yaml = current_dir / "syft.pub.yaml"
        current_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
    write:
    - alice@example.com
"""
        current_yaml.write_text(current_content)
        
        # Child is terminal with different permissions
        child_yaml = child_dir / "syft.pub.yaml"
        child_content = """terminal: true
rules:
- pattern: "**/*.txt"
  access:
    read:
    - bob@example.com
"""
        child_yaml.write_text(child_content)
        
        # Check current file - unaffected by child terminal
        syft_current = syft_perm.open(current_file)
        self.assertTrue(syft_current.has_read_access("alice@example.com"))
        self.assertTrue(syft_current.has_write_access("alice@example.com"))
        self.assertFalse(syft_current.has_read_access("bob@example.com"))
        
        # Check child file - gets permissions from terminal only (no inheritance from parent)
        syft_child = syft_perm.open(child_file)
        self.assertTrue(syft_child.has_read_access("bob@example.com"))  # From terminal
        self.assertFalse(syft_child.has_read_access("alice@example.com"))  # Blocked by terminal
        self.assertFalse(syft_child.has_write_access("alice@example.com"))  # Blocked by terminal
        
        # Check grandchild file - only terminal permissions
        syft_grandchild = syft_perm.open(grandchild_file)
        self.assertTrue(syft_grandchild.has_read_access("bob@example.com"))
        self.assertFalse(syft_grandchild.has_read_access("alice@example.com"))
        self.assertFalse(syft_grandchild.has_write_access("alice@example.com"))
    
    def test_terminal_with_create_permissions_blocks_inheritance(self):
        """Terminal with create permissions → verify create doesn't inherit past terminal."""
        # Create hierarchy
        parent_dir = Path(self.test_dir) / "parent"
        terminal_dir = parent_dir / "terminal"
        child_dir = terminal_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test files
        parent_file = parent_dir / "parent.txt"
        terminal_file = terminal_dir / "terminal.txt"
        child_file = child_dir / "child.txt"
        
        parent_file.write_text("parent")
        terminal_file.write_text("terminal")
        child_file.write_text("child")
        
        # Parent grants full hierarchy of permissions
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    admin:
    - alice@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Terminal grants only create (which includes read)
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_content = """terminal: true
rules:
- pattern: "**/*.txt"
  access:
    create:
    - bob@example.com
"""
        terminal_yaml.write_text(terminal_content)
        
        # Check parent file - alice has admin (all permissions)
        syft_parent = syft_perm.open(parent_file)
        self.assertTrue(syft_parent.has_admin_access("alice@example.com"))
        self.assertTrue(syft_parent.has_write_access("alice@example.com"))
        self.assertTrue(syft_parent.has_create_access("alice@example.com"))
        self.assertTrue(syft_parent.has_read_access("alice@example.com"))
        
        # Check terminal file - only terminal's permissions (alice admin blocked)
        syft_terminal = syft_perm.open(terminal_file)
        self.assertFalse(syft_terminal.has_admin_access("alice@example.com"))  # Blocked by terminal
        self.assertTrue(syft_terminal.has_create_access("bob@example.com"))
        self.assertTrue(syft_terminal.has_read_access("bob@example.com"))  # Via hierarchy
        self.assertFalse(syft_terminal.has_write_access("bob@example.com"))
        self.assertFalse(syft_terminal.has_admin_access("bob@example.com"))
        
        # Check child file - only bob's create permissions (no alice)
        syft_child = syft_perm.open(child_file)
        self.assertFalse(syft_child.has_admin_access("alice@example.com"))  # Blocked
        self.assertFalse(syft_child.has_write_access("alice@example.com"))  # Blocked
        self.assertFalse(syft_child.has_create_access("alice@example.com"))  # Blocked
        self.assertFalse(syft_child.has_read_access("alice@example.com"))  # Blocked
        
        self.assertTrue(syft_child.has_create_access("bob@example.com"))
        self.assertTrue(syft_child.has_read_access("bob@example.com"))  # Via hierarchy
        self.assertFalse(syft_child.has_write_access("bob@example.com"))
        
        # Verify create hierarchy reason
        has_read, reasons = syft_child._check_permission_with_reasons("bob@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Included via create permission" in r for r in reasons))
    
    def test_terminal_with_star_blocks_all_inheritance(self):
        """Terminal at parent with * → child gets no inheritance."""
        # Create hierarchy
        root_dir = Path(self.test_dir) / "root"
        terminal_dir = root_dir / "terminal"
        child_dir = terminal_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create files
        terminal_file = terminal_dir / "terminal.txt"
        child_file = child_dir / "child.txt"
        
        terminal_file.write_text("terminal")
        child_file.write_text("child")
        
        # Root grants alice admin
        root_yaml = root_dir / "syft.pub.yaml"
        root_content = """rules:
- pattern: "**/*.txt"
  access:
    admin:
    - alice@example.com
"""
        root_yaml.write_text(root_content)
        
        # Terminal grants * read only
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_content = """terminal: true
rules:
- pattern: "**/*.txt"
  access:
    read:
    - "*"
"""
        terminal_yaml.write_text(terminal_content)
        
        # Check terminal file - only terminal's permissions (* read, alice admin blocked)
        syft_terminal = syft_perm.open(terminal_file)
        self.assertFalse(syft_terminal.has_admin_access("alice@example.com"))  # Blocked by terminal
        self.assertTrue(syft_terminal.has_read_access("*"))
        self.assertFalse(syft_terminal.has_write_access("*"))
        
        # Check child file - only * read (alice's admin is blocked)
        syft_child = syft_perm.open(child_file)
        self.assertTrue(syft_child.has_read_access("*"))
        self.assertTrue(syft_child.has_read_access("anyone@example.com"))  # * means anyone
        self.assertFalse(syft_child.has_write_access("*"))
        self.assertFalse(syft_child.has_admin_access("alice@example.com"))  # Blocked by terminal
        self.assertFalse(syft_child.has_write_access("alice@example.com"))  # Blocked by terminal
    
    def test_terminal_with_matching_pattern_provides_permissions(self):
        """Terminal at parent with matching pattern → child gets terminal's permissions only."""
        # Create hierarchy
        parent_dir = Path(self.test_dir) / "parent"
        terminal_dir = parent_dir / "terminal"
        child_dir = terminal_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create files with different extensions
        child_py = child_dir / "script.py"
        child_txt = child_dir / "data.txt"
        child_log = child_dir / "output.log"
        
        child_py.write_text("python code")
        child_txt.write_text("text data")
        child_log.write_text("log output")
        
        # Parent grants different permissions for different patterns
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.py"
  access:
    admin:
    - alice@example.com
- pattern: "**/*.txt"
  access:
    write:
    - bob@example.com
- pattern: "**/*.log"
  access:
    read:
    - charlie@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Terminal has specific patterns
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_content = """terminal: true
rules:
- pattern: "**/*.py"
  access:
    read:
    - bob@example.com
- pattern: "**/*.txt"
  access:
    create:
    - charlie@example.com
"""
        terminal_yaml.write_text(terminal_content)
        
        # Check .py file - only bob read (alice admin blocked)
        syft_py = syft_perm.open(child_py)
        self.assertTrue(syft_py.has_read_access("bob@example.com"))
        self.assertFalse(syft_py.has_write_access("bob@example.com"))
        self.assertFalse(syft_py.has_admin_access("alice@example.com"))  # Blocked
        
        # Check .txt file - only charlie create (bob write blocked)
        syft_txt = syft_perm.open(child_txt)
        self.assertTrue(syft_txt.has_create_access("charlie@example.com"))
        self.assertTrue(syft_txt.has_read_access("charlie@example.com"))  # Via hierarchy
        self.assertFalse(syft_txt.has_write_access("charlie@example.com"))
        self.assertFalse(syft_txt.has_write_access("bob@example.com"))  # Blocked
        
        # Check .log file - no permissions (no matching pattern in terminal)
        syft_log = syft_perm.open(child_log)
        self.assertFalse(syft_log.has_read_access("charlie@example.com"))  # Blocked
        self.assertFalse(syft_log.has_read_access("alice@example.com"))
        self.assertFalse(syft_log.has_read_access("bob@example.com"))
    
    def test_terminal_with_non_matching_pattern_blocks_all(self):
        """Terminal at parent with non-matching pattern → child gets no permissions."""
        # Create hierarchy
        parent_dir = Path(self.test_dir) / "parent"
        terminal_dir = parent_dir / "terminal"
        child_dir = terminal_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test file
        child_file = child_dir / "data.json"
        child_file.write_text('{"data": "value"}')
        
        # Parent grants broad permissions
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*"
  access:
    admin:
    - alice@example.com
    write:
    - "*"
"""
        parent_yaml.write_text(parent_content)
        
        # Terminal only has rules for .txt files (not .json)
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_content = """terminal: true
rules:
- pattern: "**/*.txt"
  access:
    read:
    - bob@example.com
"""
        terminal_yaml.write_text(terminal_content)
        
        # Check child file - no permissions (pattern doesn't match)
        syft_child = syft_perm.open(child_file)
        self.assertFalse(syft_child.has_admin_access("alice@example.com"))
        self.assertFalse(syft_child.has_write_access("*"))
        self.assertFalse(syft_child.has_read_access("bob@example.com"))
        self.assertFalse(syft_child.has_read_access("anyone@example.com"))
        
        # Verify reason - should show "No permission found" when no matching pattern in terminal
        has_perm, reasons = syft_child._check_permission_with_reasons("alice@example.com", "read")
        self.assertFalse(has_perm)
        # Check actual reason returned
        self.assertTrue(any("No permission found" in r for r in reasons) or 
                       any("Blocked by terminal" in r for r in reasons))
    
    def test_terminal_reason_tracking(self):
        """Test that terminal blocks are properly tracked in reasons."""
        # Create hierarchy
        parent_dir = Path(self.test_dir) / "parent"
        terminal_dir = parent_dir / "terminal"
        child_dir = terminal_dir / "child"
        child_dir.mkdir(parents=True, exist_ok=True)
        
        # Create test file
        child_file = child_dir / "test.txt"
        child_file.write_text("test")
        
        # Parent grants permissions
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    admin:
    - alice@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Terminal with no matching rules
        terminal_yaml = terminal_dir / "syft.pub.yaml"
        terminal_content = """terminal: true
rules:
- pattern: "*.log"
  access:
    read:
    - bob@example.com
"""
        terminal_yaml.write_text(terminal_content)
        
        # Check permissions and reasons
        syft_child = syft_perm.open(child_file)
        
        # Admin permission check
        has_admin, admin_reasons = syft_child._check_permission_with_reasons("alice@example.com", "admin")
        self.assertFalse(has_admin)
        # Current implementation should show either "No permission found" or "Blocked by terminal"
        self.assertTrue(any("No permission found" in r for r in admin_reasons) or
                       any("Blocked by terminal" in r for r in admin_reasons))
        
        # Use explain_permissions for comprehensive view
        explanation = syft_child.explain_permissions("alice@example.com")
        self.assertIn("ADMIN: ✗ DENIED", explanation)
        self.assertIn("WRITE: ✗ DENIED", explanation)
        self.assertIn("CREATE: ✗ DENIED", explanation)
        self.assertIn("READ: ✗ DENIED", explanation)


if __name__ == "__main__":
    unittest.main()