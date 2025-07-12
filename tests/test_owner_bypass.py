"""Test owner bypass functionality and path-based ownership detection."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm

class TestOwnerBypass(unittest.TestCase):
    """Test various owner bypass scenarios and path-based ownership detection."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["alice@example.com", "bob@example.com", "charlie@example.com"]
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_non_owner_follows_normal_rules(self):
        """Test that users follow normal permission rules when accessing files not under their datasites path."""
        # Create a file under alice's datasites path
        alice_dir = Path(self.test_dir) / "datasites" / "alice@example.com"
        alice_dir.mkdir(parents=True)
        
        alice_file = alice_dir / "alice_data.txt"
        alice_file.write_text("Alice's private data")
        
        # Create permissions that grant read to bob
        yaml_file = alice_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "alice_data.txt",
                "access": {
                    "read": ["bob@example.com"],
                    "write": ["charlie@example.com"]
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the file
        syft_file = syft_perm.open(alice_file)
        
        # Alice should have all permissions (owner)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        
        # Bob should have only read (follows normal rules)
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        
        # Charlie should have write+create+read (hierarchy)
        self.assertTrue(syft_file.has_read_access("charlie@example.com"))
        self.assertTrue(syft_file.has_create_access("charlie@example.com"))
        self.assertTrue(syft_file.has_write_access("charlie@example.com"))
        self.assertFalse(syft_file.has_admin_access("charlie@example.com"))
        
        # Check reasons for alice (owner)
        has_admin, reasons = syft_file._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertEqual(reasons[0], "Owner of path")
        
        # Check reasons for bob (normal rules)
        has_read, reasons = syft_file._check_permission_with_reasons("bob@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("Explicitly granted read" in r for r in reasons))
        
        has_write, reasons = syft_file._check_permission_with_reasons("bob@example.com", "write")
        self.assertFalse(has_write)
        self.assertTrue(any("Pattern 'alice_data.txt' matched" in r for r in reasons))
    
    def test_nested_owner_permissions(self):
        """Test that ownership works in nested subdirectories under datasites/user/."""
        # Create deeply nested structure under bob's datasites
        bob_dir = Path(self.test_dir) / "datasites" / "bob@example.com"
        nested_dir = bob_dir / "projects" / "secret" / "data" / "backup"
        nested_dir.mkdir(parents=True)
        
        # Create file in nested directory
        nested_file = nested_dir / "confidential.txt"
        nested_file.write_text("Top secret data")
        
        # Create permissions at intermediate level that would normally restrict access
        projects_dir = bob_dir / "projects"
        yaml_file = projects_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]  # Only alice can read
                    # No write/admin permissions for anyone
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the nested file
        syft_file = syft_perm.open(nested_file)
        
        # Bob should have all permissions despite restrictive rules (owner bypass)
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        self.assertTrue(syft_file.has_create_access("bob@example.com"))
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        self.assertTrue(syft_file.has_admin_access("bob@example.com"))
        
        # Alice should have only read (follows normal rules)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_create_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Charlie should have no permissions
        self.assertFalse(syft_file.has_read_access("charlie@example.com"))
        self.assertFalse(syft_file.has_create_access("charlie@example.com"))
        self.assertFalse(syft_file.has_write_access("charlie@example.com"))
        self.assertFalse(syft_file.has_admin_access("charlie@example.com"))
        
        # Check bob's owner reasons
        has_admin, reasons = syft_file._check_permission_with_reasons("bob@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertEqual(reasons[0], "Owner of path")
    
    def test_simple_prefix_matching(self):
        """Test that paths starting with 'alice/' grant alice all permissions."""
        # This test checks the current implementation's prefix matching behavior
        # The implementation checks if str(path).startswith(user + "/") or str(path).startswith("/" + user + "/")
        # For this to work with absolute paths, we need to check what the implementation actually does
        
        # Create a file and check the current behavior
        alice_dir = Path(self.test_dir) / "alice"
        docs_dir = alice_dir / "documents"
        docs_dir.mkdir(parents=True)
        
        alice_file = docs_dir / "report.pdf"
        alice_file.write_text("Alice's report")
        
        # Create permissions that would normally restrict access
        yaml_file = docs_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "*.pdf",
                "access": {
                    "read": ["bob@example.com"]  # Only bob can read PDFs
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the file
        syft_file = syft_perm.open(alice_file)
        
        # Check what the path string looks like and test accordingly
        path_str = str(alice_file)
        print(f"Debug: path_str = {path_str}")
        
        # Based on the actual implementation, let's test what actually works
        # The path will be something like /tmp/xxx/alice/documents/report.pdf
        # So we need to test with a username that would match the prefix logic
        
        # Test if the path contains alice anywhere (for documentation purposes)
        path_parts = alice_file.parts
        username_part = None
        for i, part in enumerate(path_parts):
            if part == "alice":
                username_part = part
                break
        
        if username_part:
            # Test with the actual username that appears in the path
            # But the current implementation won't match this because it's an absolute path
            # that doesn't start with "alice/"
            
            # The prefix matching as implemented expects paths like:
            # - "alice/documents/file.txt" 
            # - "/alice/documents/file.txt"
            # Not: "/tmp/something/alice/documents/file.txt"
            
            # With the improved implementation, alice is now correctly detected as owner
            self.assertTrue(syft_file.has_read_access("alice"))  # Alice is owner and gets all permissions
            self.assertTrue(syft_file.has_create_access("alice"))
            self.assertTrue(syft_file.has_write_access("alice"))
            self.assertTrue(syft_file.has_admin_access("alice"))
            
            # Bob should have only read (follows normal rules)
            self.assertTrue(syft_file.has_read_access("bob@example.com"))
            self.assertFalse(syft_file.has_create_access("bob@example.com"))
            self.assertFalse(syft_file.has_write_access("bob@example.com"))
            self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        else:
            self.fail("Could not find alice in path parts")
    
    def test_path_prefix_with_leading_slash(self):
        """Test that paths starting with '/user/' grant user all permissions."""
        # Similar to the previous test, this documents the current implementation limitation
        # The prefix matching only works if the path literally starts with "/user/" or "user/"
        
        charlie_dir = Path(self.test_dir) / "charlie"
        workspace_dir = charlie_dir / "workspace"
        workspace_dir.mkdir(parents=True)
        
        charlie_file = workspace_dir / "code.py"
        charlie_file.write_text("print('Hello World')")
        
        # Create restrictive permissions
        yaml_file = workspace_dir / "syft.pub.yaml"
        yaml_content = {
            "terminal": True,  # Stop all inheritance
            "rules": [{
                "pattern": "*.py",
                "access": {
                    "read": ["alice@example.com"]  # Only alice can read Python files
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the file
        syft_file = syft_perm.open(charlie_file)
        
        # With the improved implementation, charlie is correctly detected as owner
        self.assertTrue(syft_file.has_read_access("charlie"))  # Charlie is owner and gets all permissions
        self.assertTrue(syft_file.has_create_access("charlie"))
        self.assertTrue(syft_file.has_write_access("charlie"))
        self.assertTrue(syft_file.has_admin_access("charlie"))
        
        # Alice should have only read (follows terminal rules)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_create_access("alice@example.com"))
        self.assertFalse(syft_file.has_write_access("alice@example.com"))
        self.assertFalse(syft_file.has_admin_access("alice@example.com"))
        
        # Bob should have no permissions (terminal blocks inheritance)
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        self.assertFalse(syft_file.has_create_access("bob@example.com"))
        self.assertFalse(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
    
    def test_owner_bypass_with_mixed_permissions(self):
        """Test owner bypass works correctly when user also has explicit permissions."""
        # Create file under alice's datasites with alice also having explicit permissions
        alice_dir = Path(self.test_dir) / "datasites" / "alice@example.com" / "shared"
        alice_dir.mkdir(parents=True)
        
        mixed_file = alice_dir / "mixed_access.txt"
        mixed_file.write_text("Mixed permission file")
        
        # Grant alice explicit read permission (lower than owner would get)
        yaml_file = alice_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "mixed_access.txt",
                "access": {
                    "read": ["alice@example.com", "bob@example.com"],
                    "write": ["bob@example.com"]  # Bob has write but alice doesn't explicitly
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the file
        syft_file = syft_perm.open(mixed_file)
        
        # Alice should have all permissions (owner bypass trumps explicit permissions)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_create_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("alice@example.com"))
        self.assertTrue(syft_file.has_admin_access("alice@example.com"))
        
        # Bob should have write+create+read (from explicit permissions)
        self.assertTrue(syft_file.has_read_access("bob@example.com"))
        self.assertTrue(syft_file.has_create_access("bob@example.com"))
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        self.assertFalse(syft_file.has_admin_access("bob@example.com"))
        
        # Check alice's reasons - should show owner bypass, not explicit permissions
        has_write, reasons = syft_file._check_permission_with_reasons("alice@example.com", "write")
        self.assertTrue(has_write)
        self.assertEqual(reasons[0], "Owner of path")
        # Should NOT show explicit grant reasons
        self.assertFalse(any("Explicitly granted" in r for r in reasons))
        
        # Check bob's reasons - should show explicit write grant
        has_write, reasons = syft_file._check_permission_with_reasons("bob@example.com", "write")
        self.assertTrue(has_write)
        self.assertTrue(any("Explicitly granted write" in r for r in reasons))
    
    def test_folder_owner_bypass(self):
        """Test that owner bypass works for folders as well as files."""
        # Create folder under alice's datasites
        alice_dir = Path(self.test_dir) / "datasites" / "alice@example.com"
        project_dir = alice_dir / "my_project"
        project_dir.mkdir(parents=True)
        
        # Create restrictive permissions for the folder
        yaml_file = alice_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [{
                "pattern": "my_project/",
                "access": {
                    "read": ["bob@example.com"]  # Only bob can read
                }
            }]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Open the folder
        syft_folder = syft_perm.open(project_dir)
        
        # Alice should have all permissions (owner)
        self.assertTrue(syft_folder.has_read_access("alice@example.com"))
        self.assertTrue(syft_folder.has_create_access("alice@example.com"))
        self.assertTrue(syft_folder.has_write_access("alice@example.com"))
        self.assertTrue(syft_folder.has_admin_access("alice@example.com"))
        
        # Bob should have only read
        self.assertTrue(syft_folder.has_read_access("bob@example.com"))
        self.assertFalse(syft_folder.has_create_access("bob@example.com"))
        self.assertFalse(syft_folder.has_write_access("bob@example.com"))
        self.assertFalse(syft_folder.has_admin_access("bob@example.com"))
        
        # Check alice's owner reasons
        has_admin, reasons = syft_folder._check_permission_with_reasons("alice@example.com", "admin")
        self.assertTrue(has_admin)
        self.assertEqual(reasons[0], "Owner of path")


if __name__ == "__main__":
    unittest.main()