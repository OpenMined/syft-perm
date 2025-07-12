"""Test permission resolution order within same directory (pattern specificity)."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm

class TestPermissionResolutionOrder(unittest.TestCase):
    """Test permission resolution order when multiple patterns in same directory match a file."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["user1@example.com", "user2@example.com", "user3@example.com", "user4@example.com"]
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
    
    def test_pattern_specificity_resolution_order(self):
        """Test resolution order: ** < */** < specific/path/** < specific/path/file.txt < **/*.py patterns."""
        # Create directory structure
        test_dir = Path(self.test_dir) / "resolution_test"
        specific_dir = test_dir / "specific" / "path"
        specific_dir.mkdir(parents=True)
        
        # Create test files
        files = {
            "generic_file": test_dir / "readme.md",
            "nested_file": test_dir / "docs" / "guide.md", 
            "specific_nested": specific_dir / "config.json",
            "specific_exact": specific_dir / "file.txt",
            "python_file": test_dir / "script.py",
            "specific_python": specific_dir / "module.py"
        }
        
        # Create directories and files
        for file_path in files.values():
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text("content")
        
        # Create syft.pub.yaml with multiple overlapping patterns following old syftbox specificity
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "**",  # Least specific - matches everything
                    "access": {
                        "read": ["user1@example.com"]
                    }
                },
                {
                    "pattern": "docs/**",  # More specific - matches files under docs/
                    "access": {
                        "write": ["user2@example.com"]
                    }
                },
                {
                    "pattern": "specific/path/**",  # More specific - matches specific path
                    "access": {
                        "admin": ["user3@example.com"]
                    }
                },
                {
                    "pattern": "specific/path/file.txt",  # Most specific - exact file match
                    "access": {
                        "read": ["*"]  # Public read
                    }
                },
                {
                    "pattern": "**/*.py",  # Specific file type pattern
                    "access": {
                        "create": ["user4@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test generic file (readme.md) - only matches ** pattern
        generic_syft = syft_perm.open(files["generic_file"])
        self.assertTrue(generic_syft.has_read_access("user1@example.com"))    # From ** pattern
        self.assertFalse(generic_syft.has_write_access("user2@example.com"))  # docs/** doesn't match
        self.assertFalse(generic_syft.has_admin_access("user3@example.com"))  # specific/path/** doesn't match
        self.assertFalse(generic_syft.has_create_access("user4@example.com")) # **/*.py doesn't match
        
        # Test nested file (docs/guide.md) - matches ** and docs/** patterns, docs/** wins (more specific)
        nested_syft = syft_perm.open(files["nested_file"])
        self.assertFalse(nested_syft.has_read_access("user1@example.com"))    # ** is less specific
        self.assertTrue(nested_syft.has_write_access("user2@example.com"))    # docs/** wins (more specific)
        self.assertTrue(nested_syft.has_create_access("user2@example.com"))   # Via hierarchy
        self.assertTrue(nested_syft.has_read_access("user2@example.com"))     # Via hierarchy
        self.assertFalse(nested_syft.has_admin_access("user3@example.com"))   # specific/path/** doesn't match
        
        # Test specific nested file (specific/path/config.json) - specific/path/** wins
        specific_nested_syft = syft_perm.open(files["specific_nested"])
        self.assertFalse(specific_nested_syft.has_read_access("user1@example.com"))    # ** is less specific
        self.assertFalse(specific_nested_syft.has_write_access("user2@example.com"))   # */** is less specific
        self.assertTrue(specific_nested_syft.has_admin_access("user3@example.com"))    # specific/path/** wins
        self.assertTrue(specific_nested_syft.has_write_access("user3@example.com"))    # Via hierarchy
        self.assertTrue(specific_nested_syft.has_create_access("user3@example.com"))   # Via hierarchy
        self.assertTrue(specific_nested_syft.has_read_access("user3@example.com"))     # Via hierarchy
        
        # Test exact file match (specific/path/file.txt) - exact match wins over all patterns
        exact_syft = syft_perm.open(files["specific_exact"])
        self.assertTrue(exact_syft.has_read_access("user1@example.com"))      # Gets read via public access (*)
        self.assertFalse(exact_syft.has_write_access("user2@example.com"))    # docs/** is less specific  
        self.assertFalse(exact_syft.has_admin_access("user3@example.com"))    # specific/path/** is less specific
        self.assertTrue(exact_syft.has_read_access("*"))                      # Exact match wins: specific/path/file.txt
        self.assertTrue(exact_syft.has_read_access("anyone@example.com"))     # Public read
        
        # Test Python file (script.py) - **/*.py vs ** patterns, **/*.py wins (more specific)
        python_syft = syft_perm.open(files["python_file"])
        self.assertFalse(python_syft.has_read_access("user1@example.com"))    # ** is less specific
        self.assertFalse(python_syft.has_write_access("user2@example.com"))   # */** doesn't match (not nested)
        self.assertFalse(python_syft.has_admin_access("user3@example.com"))   # specific/path/** doesn't match
        self.assertTrue(python_syft.has_create_access("user4@example.com"))   # **/*.py wins
        self.assertTrue(python_syft.has_read_access("user4@example.com"))     # Via hierarchy
        
        # Test specific Python file (specific/path/module.py) - multiple patterns match, most specific wins
        # Patterns that match: **, */** (via specific/path), specific/path/**, **/*.py
        # specific/path/** should be more specific than **/*.py based on old syftbox scoring
        specific_python_syft = syft_perm.open(files["specific_python"])
        self.assertFalse(specific_python_syft.has_read_access("user1@example.com"))    # ** is less specific
        self.assertFalse(specific_python_syft.has_write_access("user2@example.com"))   # */** is less specific
        self.assertTrue(specific_python_syft.has_admin_access("user3@example.com"))    # specific/path/** wins over **/*.py
        self.assertTrue(specific_python_syft.has_write_access("user3@example.com"))    # Via hierarchy
        self.assertTrue(specific_python_syft.has_create_access("user3@example.com"))   # Via hierarchy
        self.assertTrue(specific_python_syft.has_read_access("user3@example.com"))     # Via hierarchy
        self.assertFalse(specific_python_syft.has_create_access("user4@example.com"))  # **/*.py is less specific
    
    def test_size_limits_at_different_pattern_specificities(self):
        """Test size limits when applied to patterns of different specificity."""
        # Create directory structure
        test_dir = Path(self.test_dir) / "limits_test"
        docs_dir = test_dir / "docs"
        docs_dir.mkdir(parents=True)
        
        # Create test files
        files = {
            "small_generic": test_dir / "small.txt",
            "large_generic": test_dir / "large.txt", 
            "small_doc": docs_dir / "small_guide.txt",
            "large_doc": docs_dir / "large_guide.txt"
        }
        
        # Create files with different sizes
        files["small_generic"].write_text("x" * 1000)      # 1KB
        files["large_generic"].write_text("x" * 2000000)   # 2MB
        files["small_doc"].write_text("x" * 500)           # 500B
        files["large_doc"].write_text("x" * 1500000)       # 1.5MB
        
        # Create syft.pub.yaml with size limits at different pattern specificities
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "**",  # Least specific - generous limits
                    "access": {
                        "write": ["user1@example.com"]
                    },
                    "limits": {
                        "max_file_size": 10 * 1024 * 1024,  # 10MB
                        "allow_dirs": True,
                        "allow_symlinks": True
                    }
                },
                {
                    "pattern": "*.txt",  # More specific - smaller limit 
                    "access": {
                        "write": ["user2@example.com"]
                    },
                    "limits": {
                        "max_file_size": 1024 * 1024,  # 1MB
                        "allow_dirs": False,
                        "allow_symlinks": True
                    }
                },
                {
                    "pattern": "docs/*.txt",  # Most specific - smallest limit
                    "access": {
                        "write": ["user3@example.com"]
                    },
                    "limits": {
                        "max_file_size": 512 * 1024,  # 512KB
                        "allow_dirs": False,
                        "allow_symlinks": False
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test small generic file - matches *.txt (more specific than **)
        small_generic_syft = syft_perm.open(files["small_generic"])
        self.assertFalse(small_generic_syft.has_write_access("user1@example.com"))  # ** is less specific
        self.assertTrue(small_generic_syft.has_write_access("user2@example.com"))   # *.txt wins
        self.assertFalse(small_generic_syft.has_write_access("user3@example.com"))  # docs/*.txt doesn't match
        
        # Test large generic file - matches *.txt but file size exceeds its limit (1MB < 2MB)
        # Size limit enforcement blocks access during permission resolution
        large_generic_syft = syft_perm.open(files["large_generic"])
        self.assertFalse(large_generic_syft.has_write_access("user2@example.com"))  # Size limit blocks *.txt rule
        
        # Test small doc file - matches docs/*.txt (most specific)
        small_doc_syft = syft_perm.open(files["small_doc"])
        self.assertFalse(small_doc_syft.has_write_access("user1@example.com"))     # ** is less specific
        self.assertFalse(small_doc_syft.has_write_access("user2@example.com"))     # *.txt is less specific
        self.assertTrue(small_doc_syft.has_write_access("user3@example.com"))      # docs/*.txt wins (most specific)
        
        # Test large doc file - matches docs/*.txt but exceeds its limit (512KB < 1.5MB)
        # Size limit enforcement blocks access during permission resolution
        large_doc_syft = syft_perm.open(files["large_doc"])
        self.assertFalse(large_doc_syft.has_write_access("user3@example.com"))     # Size limit blocks docs/*.txt rule
        
        # Verify that the most specific rule's limits are enforced during permission resolution
        doc_perms = small_doc_syft._get_all_permissions_with_sources()
        self.assertIn("permissions", doc_perms)
        self.assertIn("sources", doc_perms)
        self.assertIn("user3@example.com", doc_perms["permissions"]["write"])
    
    def test_exact_file_vs_extension_patterns(self):
        """Test exact file match vs extension patterns resolution."""
        # Create test directory
        test_dir = Path(self.test_dir) / "exact_vs_extension"
        test_dir.mkdir(parents=True)
        
        # Create test files
        important_file = test_dir / "important.py"
        regular_file = test_dir / "script.py"
        important_file.write_text("important code")
        regular_file.write_text("regular code")
        
        # Create syft.pub.yaml with exact file vs extension patterns
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "**/*.py",  # Extension pattern
                    "access": {
                        "create": ["user1@example.com"]
                    }
                },
                {
                    "pattern": "*.py",  # More specific extension pattern
                    "access": {
                        "write": ["user2@example.com"]
                    }
                },
                {
                    "pattern": "important.py",  # Exact file match (most specific)
                    "access": {
                        "admin": ["user3@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test important.py - exact match wins
        important_syft = syft_perm.open(important_file)
        self.assertFalse(important_syft.has_create_access("user1@example.com"))  # **/*.py is less specific
        self.assertFalse(important_syft.has_write_access("user2@example.com"))   # *.py is less specific
        self.assertTrue(important_syft.has_admin_access("user3@example.com"))    # important.py wins (exact match)
        self.assertTrue(important_syft.has_write_access("user3@example.com"))    # Via hierarchy
        self.assertTrue(important_syft.has_create_access("user3@example.com"))   # Via hierarchy
        self.assertTrue(important_syft.has_read_access("user3@example.com"))     # Via hierarchy
        
        # Test script.py - *.py wins over **/*.py
        regular_syft = syft_perm.open(regular_file)
        self.assertFalse(regular_syft.has_create_access("user1@example.com"))    # **/*.py is less specific
        self.assertTrue(regular_syft.has_write_access("user2@example.com"))      # *.py wins
        self.assertTrue(regular_syft.has_create_access("user2@example.com"))     # Via hierarchy
        self.assertTrue(regular_syft.has_read_access("user2@example.com"))       # Via hierarchy
        self.assertFalse(regular_syft.has_admin_access("user3@example.com"))     # important.py doesn't match
    
    def test_directory_vs_file_patterns(self):
        """Test directory patterns vs file patterns resolution."""
        # Create directory structure
        test_dir = Path(self.test_dir) / "dir_vs_file"
        subdir = test_dir / "config"
        subdir.mkdir(parents=True)
        
        # Create test files and directory
        files = {
            "dir_itself": subdir,  # Directory
            "file_in_dir": subdir / "settings.json",  # File in directory
            "dir_match_file": test_dir / "config.txt"  # File that matches directory name pattern
        }
        
        files["file_in_dir"].write_text('{"setting": "value"}')
        files["dir_match_file"].write_text("config content")
        
        # Create syft.pub.yaml with directory vs file patterns
        yaml_file = test_dir / "syft.pub.yaml"
        yaml_content = {
            "rules": [
                {
                    "pattern": "config",  # Matches directory and file with name "config"
                    "access": {
                        "read": ["user1@example.com"]
                    }
                },
                {
                    "pattern": "config/*",  # Matches files inside config directory
                    "access": {
                        "write": ["user2@example.com"]
                    }
                },
                {
                    "pattern": "config.txt",  # Exact file match
                    "access": {
                        "admin": ["user3@example.com"]
                    }
                }
            ]
        }
        with open(yaml_file, 'w') as f:
            yaml.dump(yaml_content, f)
        
        # Test directory itself - matches "config" pattern
        dir_syft = syft_perm.open(files["dir_itself"])
        self.assertTrue(dir_syft.has_read_access("user1@example.com"))     # config pattern matches
        self.assertFalse(dir_syft.has_write_access("user2@example.com"))   # config/* doesn't match directory itself
        self.assertFalse(dir_syft.has_admin_access("user3@example.com"))   # config.txt doesn't match
        
        # Test file in directory - matches "config/*" pattern (most specific)
        file_in_dir_syft = syft_perm.open(files["file_in_dir"])
        self.assertFalse(file_in_dir_syft.has_read_access("user1@example.com"))   # config is less specific
        self.assertTrue(file_in_dir_syft.has_write_access("user2@example.com"))   # config/* wins
        self.assertTrue(file_in_dir_syft.has_create_access("user2@example.com"))  # Via hierarchy
        self.assertTrue(file_in_dir_syft.has_read_access("user2@example.com"))    # Via hierarchy
        self.assertFalse(file_in_dir_syft.has_admin_access("user3@example.com"))  # config.txt doesn't match
        
        # Test file matching directory name pattern - exact match wins
        dir_match_file_syft = syft_perm.open(files["dir_match_file"])
        self.assertFalse(dir_match_file_syft.has_read_access("user1@example.com"))  # config is less specific
        self.assertFalse(dir_match_file_syft.has_write_access("user2@example.com")) # config/* doesn't match
        self.assertTrue(dir_match_file_syft.has_admin_access("user3@example.com"))  # config.txt wins (exact match)
        self.assertTrue(dir_match_file_syft.has_write_access("user3@example.com"))  # Via hierarchy
        self.assertTrue(dir_match_file_syft.has_create_access("user3@example.com")) # Via hierarchy
        self.assertTrue(dir_match_file_syft.has_read_access("user3@example.com"))   # Via hierarchy


if __name__ == "__main__":
    unittest.main()