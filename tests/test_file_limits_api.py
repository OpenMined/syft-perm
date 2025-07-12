"""Test file limits API methods for both SyftFile and SyftFolder."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestFileLimitsAPI(unittest.TestCase):
    """Test cases for file limits setter and getter API methods."""
    
    def setUp(self):
        """Create a temporary directory for test files."""
        self.test_dir = tempfile.mkdtemp(prefix="syft_perm_test_")
    
    def tearDown(self):
        """Clean up test directory."""
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
    
    def test_syft_file_set_and_get_file_limits(self):
        """Test SyftFile set_file_limits and get_file_limits methods."""
        # Create test file
        test_file = Path(self.test_dir) / "test.txt"
        test_file.write_text("test content")
        
        syft_file = syft_perm.open(test_file)
        
        # Test 1: Get limits when none are set
        limits = syft_file.get_file_limits()
        expected = {
            "max_file_size": None,
            "allow_dirs": True,
            "allow_symlinks": True,
            "has_limits": False
        }
        self.assertEqual(limits, expected)
        
        # Test 2: Set basic limits
        syft_file.set_file_limits(max_size=1024, allow_dirs=False, allow_symlinks=False)
        
        limits = syft_file.get_file_limits()
        expected = {
            "max_file_size": 1024,
            "allow_dirs": False,
            "allow_symlinks": False,
            "has_limits": True
        }
        self.assertEqual(limits, expected)
        
        # Test 3: Update only max size (others should remain unchanged)
        syft_file.set_file_limits(max_size=2048)
        
        limits = syft_file.get_file_limits()
        expected = {
            "max_file_size": 2048,
            "allow_dirs": False,  # Should remain from previous setting
            "allow_symlinks": False,  # Should remain from previous setting
            "has_limits": True
        }
        self.assertEqual(limits, expected)
        
        # Test 4: Update other settings, max size should remain
        syft_file.set_file_limits(allow_dirs=True, allow_symlinks=True)
        
        limits = syft_file.get_file_limits()
        expected = {
            "max_file_size": 2048,  # Should remain from previous setting
            "allow_dirs": True,
            "allow_symlinks": True,
            "has_limits": True
        }
        self.assertEqual(limits, expected)
    
    def test_syft_folder_set_and_get_file_limits(self):
        """Test SyftFolder set_file_limits and get_file_limits methods."""
        # Create test folder
        test_folder = Path(self.test_dir) / "test_folder"
        test_folder.mkdir()
        
        syft_folder = syft_perm.open(test_folder)
        
        # Test 1: Get limits when none are set
        limits = syft_folder.get_file_limits()
        expected = {
            "max_file_size": None,
            "allow_dirs": True,
            "allow_symlinks": True,
            "has_limits": False
        }
        self.assertEqual(limits, expected)
        
        # Test 2: Set comprehensive limits
        syft_folder.set_file_limits(max_size=5242880, allow_dirs=True, allow_symlinks=False)  # 5MB
        
        limits = syft_folder.get_file_limits()
        expected = {
            "max_file_size": 5242880,
            "allow_dirs": True,
            "allow_symlinks": False,
            "has_limits": True
        }
        self.assertEqual(limits, expected)
        
        # Test 3: Update all settings
        syft_folder.set_file_limits(max_size=10485760, allow_dirs=False, allow_symlinks=True)  # 10MB
        
        limits = syft_folder.get_file_limits()
        expected = {
            "max_file_size": 10485760,
            "allow_dirs": False,
            "allow_symlinks": True,
            "has_limits": True
        }
        self.assertEqual(limits, expected)
        
        # Test 4: Set only specific parameters (others keep current values)
        syft_folder.set_file_limits(allow_dirs=True)
        
        limits = syft_folder.get_file_limits()
        # max_size should remain unchanged, only allow_dirs should change
        self.assertEqual(limits["max_file_size"], 10485760)  # Unchanged
        self.assertEqual(limits["allow_dirs"], True)  # Changed
        self.assertEqual(limits["allow_symlinks"], True)  # Kept previous value 
        self.assertTrue(limits["has_limits"])
    
    def test_file_limits_with_permissions(self):
        """Test file limits work correctly with existing permissions."""
        # Create test file
        test_file = Path(self.test_dir) / "protected.txt"
        test_file.write_text("protected content")
        
        syft_file = syft_perm.open(test_file)
        
        # Set permissions first
        syft_file.grant_read_access("alice@example.com", force=True)
        syft_file.grant_write_access("bob@example.com", force=True)
        
        # Then set limits
        syft_file.set_file_limits(max_size=1024, allow_dirs=False)
        
        # Verify permissions are preserved
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        
        # Verify limits are set
        limits = syft_file.get_file_limits()
        self.assertEqual(limits["max_file_size"], 1024)
        self.assertFalse(limits["allow_dirs"])
    
    def test_file_limits_yaml_structure(self):
        """Test that file limits are stored correctly in syft.pub.yaml."""
        # Create test file
        test_file = Path(self.test_dir) / "yaml_test.txt"
        test_file.write_text("yaml test")
        
        syft_file = syft_perm.open(test_file)
        
        # Set limits
        syft_file.set_file_limits(max_size=2048, allow_dirs=False, allow_symlinks=True)
        
        # Check that syft.pub.yaml was created and contains correct structure
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        self.assertTrue(yaml_file.exists())
        
        # Read and verify YAML content
        import yaml
        with open(yaml_file, 'r') as f:
            content = yaml.safe_load(f)
        
        # Should have limits section in the rule for the file
        self.assertIn("rules", content)
        self.assertTrue(len(content["rules"]) > 0)
        
        # Find the rule for our file
        rule = content["rules"][0]  # Should be the first (and only) rule
        self.assertEqual(rule["pattern"], "yaml_test.txt")
        self.assertIn("limits", rule)
        
        limits = rule["limits"]
        self.assertEqual(limits["max_file_size"], 2048)
        self.assertFalse(limits["allow_dirs"])
        self.assertTrue(limits["allow_symlinks"])
    
    def test_multiple_files_different_limits(self):
        """Test that different files can have different limits."""
        # Create multiple test files
        file1 = Path(self.test_dir) / "small.txt"
        file2 = Path(self.test_dir) / "large.txt"
        file1.write_text("small file")
        file2.write_text("large file")
        
        syft_file1 = syft_perm.open(file1)
        syft_file2 = syft_perm.open(file2)
        
        # Set different limits
        syft_file1.set_file_limits(max_size=512, allow_dirs=False)
        syft_file2.set_file_limits(max_size=1048576, allow_dirs=True)  # 1MB
        
        # Verify each file has its own limits
        limits1 = syft_file1.get_file_limits()
        limits2 = syft_file2.get_file_limits()
        
        self.assertEqual(limits1["max_file_size"], 512)
        self.assertFalse(limits1["allow_dirs"])
        
        self.assertEqual(limits2["max_file_size"], 1048576)
        self.assertTrue(limits2["allow_dirs"])
    
    def test_folder_limits_inheritance(self):
        """Test that folder limits affect files within the folder."""
        # Create folder and subfolder
        parent_folder = Path(self.test_dir) / "parent"
        child_folder = parent_folder / "child"
        child_folder.mkdir(parents=True)
        
        # Create file in child folder
        test_file = child_folder / "test.txt"
        test_file.write_text("test")
        
        # Set limits on parent folder
        syft_parent = syft_perm.open(parent_folder)
        syft_parent.set_file_limits(max_size=1024, allow_dirs=False)
        
        # Verify parent has limits
        parent_limits = syft_parent.get_file_limits()
        self.assertEqual(parent_limits["max_file_size"], 1024)
        self.assertFalse(parent_limits["allow_dirs"])
        
        # Child folder should have its own limits (empty by default)
        syft_child = syft_perm.open(child_folder)
        child_limits = syft_child.get_file_limits()
        self.assertFalse(child_limits["has_limits"])
    
    def test_default_values_when_no_limits(self):
        """Test that default values are returned when no limits are set."""
        # Create test file without any limits
        test_file = Path(self.test_dir) / "no_limits.txt"
        test_file.write_text("no limits")
        
        syft_file = syft_perm.open(test_file)
        
        limits = syft_file.get_file_limits()
        
        # Should return default values
        self.assertIsNone(limits["max_file_size"])
        self.assertTrue(limits["allow_dirs"])
        self.assertTrue(limits["allow_symlinks"])
        self.assertFalse(limits["has_limits"])
    
    def test_limits_in_html_representation(self):
        """Test that file limits appear in HTML representation."""
        # Create test file and folder
        test_file = Path(self.test_dir) / "html_test.txt"
        test_folder = Path(self.test_dir) / "html_folder"
        test_file.write_text("html test")
        test_folder.mkdir()
        
        syft_file = syft_perm.open(test_file)
        syft_folder = syft_perm.open(test_folder)
        
        # Set limits
        syft_file.set_file_limits(max_size=1024, allow_dirs=False)
        syft_folder.set_file_limits(max_size=2048, allow_symlinks=False)
        
        # Check HTML representation includes limits
        file_html = syft_file._repr_html_()
        folder_html = syft_folder._repr_html_()
        
        # Should contain file limits information
        self.assertIn("File Compliance Check:", file_html)
        self.assertIn("1.00 KB", file_html)  # SyftFile format shows as KB
        self.assertIn("Dirs: ✗", file_html)
        
        self.assertIn("Folder Compliance Check:", folder_html)
        self.assertIn("2.00 KB", folder_html)  # SyftFolder format shows as KB  
        self.assertIn("Blocked", folder_html)


if __name__ == "__main__":
    unittest.main()