"""Test files with ** glob pattern permissions."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm


class TestGlobPatterns(unittest.TestCase):
    """Test cases for files with ** glob pattern permissions."""
    
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
    
    def test_double_star_matches_nested_files(self):
        """Test ** pattern matches files at any depth."""
        # Create nested directory structure with files at different levels
        paths = [
            "file1.txt",
            "dir1/file2.txt",
            "dir1/dir2/file3.txt",
            "dir1/dir2/dir3/file4.txt",
            "other/deep/path/file5.txt"
        ]
        
        for path in paths:
            full_path = Path(self.test_dir) / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(f"content of {path}")
        
        # Create syft.pub.yaml with ** pattern
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check all txt files have permission regardless of depth
        for path in paths:
            syft_file = syft_perm.open(Path(self.test_dir) / path)
            self.assertTrue(syft_file.has_read_access("alice@example.com"),
                          f"Alice should read {path}")
            self.assertFalse(syft_file.has_write_access("alice@example.com"))
            self.assertFalse(syft_file.has_admin_access("alice@example.com"))
            
            # Others have no access
            self.assertFalse(syft_file.has_read_access("bob@example.com"))
    
    def test_double_star_vs_single_star_specificity(self):
        """Test pattern matching with both ** and * patterns."""
        # Create files at different levels
        root_file = Path(self.test_dir) / "root.txt"
        nested_file = Path(self.test_dir) / "subdir" / "nested.txt"
        root_file.write_text("root content")
        nested_file.parent.mkdir(parents=True, exist_ok=True)
        nested_file.write_text("nested content")
        
        # Create syft.pub.yaml with more specific pattern first
        # Note: Current implementation uses first-match-wins, not specificity ordering
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - bob@example.com
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check root file matches first pattern
        syft_root = syft_perm.open(root_file)
        self.assertTrue(syft_root.has_read_access("bob@example.com"),
                       "Bob should read root file (first matching pattern)")
        self.assertFalse(syft_root.has_read_access("alice@example.com"),
                        "Alice should not read root file")
        
        # Check nested file only matches ** pattern
        syft_nested = syft_perm.open(nested_file)
        self.assertTrue(syft_nested.has_read_access("alice@example.com"),
                       "Alice should read nested file")
        self.assertFalse(syft_nested.has_read_access("bob@example.com"),
                        "Bob should not read nested file")
    
    def test_double_star_with_extension_filtering(self):
        """Test ** pattern with specific file extensions."""
        # Create files with different extensions
        files = {
            "doc1.txt": "text content",
            "doc2.pdf": "pdf content",
            "code/script.py": "python code",
            "code/lib/module.py": "module code",
            "data/file.csv": "csv data"
        }
        
        for path, content in files.items():
            full_path = Path(self.test_dir) / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
        
        # Create syft.pub.yaml with extension-specific patterns
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**/*.py"
  access:
    read:
    - alice@example.com
    write:
    - alice@example.com
- pattern: "**/*.txt"
  access:
    read:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check Python files have alice permissions
        for py_file in ["code/script.py", "code/lib/module.py"]:
            syft_file = syft_perm.open(Path(self.test_dir) / py_file)
            self.assertTrue(syft_file.has_read_access("alice@example.com"))
            self.assertTrue(syft_file.has_write_access("alice@example.com"))
            self.assertFalse(syft_file.has_read_access("bob@example.com"))
        
        # Check txt file has bob permission
        syft_txt = syft_perm.open(Path(self.test_dir) / "doc1.txt")
        self.assertTrue(syft_txt.has_read_access("bob@example.com"))
        self.assertFalse(syft_txt.has_write_access("bob@example.com"))
        self.assertFalse(syft_txt.has_read_access("alice@example.com"))
        
        # Check other files have no permissions
        for other in ["doc2.pdf", "data/file.csv"]:
            syft_file = syft_perm.open(Path(self.test_dir) / other)
            self.assertFalse(syft_file.has_read_access("alice@example.com"))
            self.assertFalse(syft_file.has_read_access("bob@example.com"))
    
    def test_double_star_pattern_in_subdirectory(self):
        """Test ** pattern defined in subdirectory."""
        # Create nested structure
        project_dir = Path(self.test_dir) / "project"
        src_dir = project_dir / "src"
        test_dir = project_dir / "tests"
        
        files = [
            src_dir / "main.py",
            src_dir / "utils" / "helper.py",
            test_dir / "test_main.py",
            test_dir / "unit" / "test_helper.py"
        ]
        
        for file_path in files:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text("code")
        
        # Create syft.pub.yaml in project directory
        yaml_file = project_dir / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "src/**/*.py"
  access:
    read:
    - alice@example.com
    write:
    - alice@example.com
- pattern: "tests/**/*.py"
  access:
    read:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check src files have alice permissions
        for src_file in [src_dir / "main.py", src_dir / "utils" / "helper.py"]:
            syft_file = syft_perm.open(src_file)
            self.assertTrue(syft_file.has_read_access("alice@example.com"))
            self.assertTrue(syft_file.has_write_access("alice@example.com"))
            self.assertFalse(syft_file.has_read_access("bob@example.com"))
        
        # Check test files have bob permissions
        for test_file in [test_dir / "test_main.py", test_dir / "unit" / "test_helper.py"]:
            syft_file = syft_perm.open(test_file)
            self.assertTrue(syft_file.has_read_access("bob@example.com"))
            self.assertFalse(syft_file.has_write_access("bob@example.com"))
            self.assertFalse(syft_file.has_read_access("alice@example.com"))
    
    def test_double_star_matches_all_files(self):
        """Test ** without extension matches all files."""
        # Create various files
        files = [
            "README.md",
            "config.json",
            "src/app.js",
            "docs/guide.pdf",
            "tests/data/sample.csv"
        ]
        
        for path in files:
            full_path = Path(self.test_dir) / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text("content")
        
        # Create syft.pub.yaml with ** pattern (no extension)
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**"
  access:
    read:
    - "*"
"""
        yaml_file.write_text(yaml_content)
        
        # Check all files have public read
        for path in files:
            syft_file = syft_perm.open(Path(self.test_dir) / path)
            self.assertTrue(syft_file.has_read_access("alice@example.com"))
            self.assertTrue(syft_file.has_read_access("bob@example.com"))
            self.assertTrue(syft_file.has_read_access("anyone@random.org"))
    
    def test_double_star_inheritance_override(self):
        """Test child directory can override parent's ** pattern."""
        # Create nested structure
        parent_dir = Path(self.test_dir) / "parent"
        child_dir = parent_dir / "child"
        grandchild_dir = child_dir / "grandchild"
        
        # Create files at each level
        parent_file = parent_dir / "parent.txt"
        child_file = child_dir / "child.txt"
        grandchild_file = grandchild_dir / "grandchild.txt"
        
        for file_path in [parent_file, child_file, grandchild_file]:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text("content")
        
        # Parent grants ** access to alice
        parent_yaml = parent_dir / "syft.pub.yaml"
        parent_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
"""
        parent_yaml.write_text(parent_content)
        
        # Child overrides with specific permission for bob
        child_yaml = child_dir / "syft.pub.yaml"
        child_content = """rules:
- pattern: "*.txt"
  access:
    read:
    - bob@example.com
- pattern: "**/*.txt"
  access:
    read:
    - charlie@example.com
"""
        child_yaml.write_text(child_content)
        
        # Check parent file has alice permission
        syft_parent = syft_perm.open(parent_file)
        self.assertTrue(syft_parent.has_read_access("alice@example.com"))
        self.assertFalse(syft_parent.has_read_access("bob@example.com"))
        
        # Check child file has bob permission (override)
        syft_child = syft_perm.open(child_file)
        self.assertTrue(syft_child.has_read_access("bob@example.com"))
        self.assertFalse(syft_child.has_read_access("alice@example.com"))
        
        # Check grandchild inherits from child's ** pattern
        syft_grandchild = syft_perm.open(grandchild_file)
        self.assertTrue(syft_grandchild.has_read_access("charlie@example.com"))
        self.assertFalse(syft_grandchild.has_read_access("alice@example.com"))
        self.assertFalse(syft_grandchild.has_read_access("bob@example.com"))
    
    def test_double_star_with_directory_prefix(self):
        """Test ** pattern with directory prefix like docs/**."""
        # Create files in different directories
        files = {
            "README.md": "readme",
            "docs/guide.md": "guide",
            "docs/api/reference.md": "api ref",
            "docs/examples/tutorial.md": "tutorial",
            "src/docs/code.md": "not in docs root",
            "other/file.md": "other"
        }
        
        for path, content in files.items():
            full_path = Path(self.test_dir) / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(content)
        
        # Create syft.pub.yaml with docs/** pattern
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "docs/**"
  access:
    read:
    - alice@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check only files under docs/ have permission
        docs_files = ["docs/guide.md", "docs/api/reference.md", "docs/examples/tutorial.md"]
        for path in docs_files:
            syft_file = syft_perm.open(Path(self.test_dir) / path)
            self.assertTrue(syft_file.has_read_access("alice@example.com"),
                          f"Alice should read {path}")
        
        # Check files NOT under docs/ have no permission
        non_docs = ["README.md", "src/docs/code.md", "other/file.md"]
        for path in non_docs:
            syft_file = syft_perm.open(Path(self.test_dir) / path)
            self.assertFalse(syft_file.has_read_access("alice@example.com"),
                           f"Alice should not read {path}")
    
    def test_double_star_with_terminal_node(self):
        """Test ** pattern behavior with terminal nodes."""
        # Create deep structure
        base_dir = Path(self.test_dir) / "base"
        secure_dir = base_dir / "secure"
        public_dir = base_dir / "public"
        
        # Create files
        files = [
            secure_dir / "secret.txt",
            secure_dir / "data" / "private.txt",
            public_dir / "info.txt",
            public_dir / "docs" / "guide.txt"
        ]
        
        for file_path in files:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text("content")
        
        # Base has ** pattern for all
        base_yaml = base_dir / "syft.pub.yaml"
        base_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - "*"
"""
        base_yaml.write_text(base_content)
        
        # Secure is terminal with restricted access
        secure_yaml = secure_dir / "syft.pub.yaml"
        secure_content = """terminal: true
rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
    admin:
    - alice@example.com
"""
        secure_yaml.write_text(secure_content)
        
        # Check secure files only accessible to alice
        for secure_file in [secure_dir / "secret.txt", secure_dir / "data" / "private.txt"]:
            syft_file = syft_perm.open(secure_file)
            self.assertTrue(syft_file.has_read_access("alice@example.com"))
            self.assertTrue(syft_file.has_admin_access("alice@example.com"))
            self.assertFalse(syft_file.has_read_access("bob@example.com"))
        
        # Check public files accessible to all
        for public_file in [public_dir / "info.txt", public_dir / "docs" / "guide.txt"]:
            syft_file = syft_perm.open(public_file)
            self.assertTrue(syft_file.has_read_access("alice@example.com"))
            self.assertTrue(syft_file.has_read_access("bob@example.com"))
            self.assertTrue(syft_file.has_read_access("anyone@test.com"))
    
    def test_double_star_edge_cases(self):
        """Test edge cases with ** patterns."""
        # Create edge case files
        edge_files = [
            ".hidden/file.txt",  # Hidden directory
            "file with spaces.txt",  # Spaces in name
            "dir.with.dots/file.txt",  # Dots in directory
            "UPPERCASE/FILE.TXT",  # Case sensitivity
        ]
        
        for path in edge_files:
            full_path = Path(self.test_dir) / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text("edge case")
        
        # Create syft.pub.yaml with ** pattern
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "**/*.txt"
  access:
    read:
    - alice@example.com
- pattern: "**/*.TXT"
  access:
    read:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check hidden directory file
        syft_hidden = syft_perm.open(Path(self.test_dir) / ".hidden/file.txt")
        self.assertTrue(syft_hidden.has_read_access("alice@example.com"))
        
        # Check file with spaces
        syft_spaces = syft_perm.open(Path(self.test_dir) / "file with spaces.txt")
        self.assertTrue(syft_spaces.has_read_access("alice@example.com"))
        
        # Check directory with dots
        syft_dots = syft_perm.open(Path(self.test_dir) / "dir.with.dots/file.txt")
        self.assertTrue(syft_dots.has_read_access("alice@example.com"))
        
        # Check case sensitivity (assuming case-sensitive filesystem)
        syft_upper = syft_perm.open(Path(self.test_dir) / "UPPERCASE/FILE.TXT")
        self.assertTrue(syft_upper.has_read_access("bob@example.com"))
        self.assertFalse(syft_upper.has_read_access("alice@example.com"))
    
    def test_folders_with_double_star_patterns(self):
        """Test folder permissions with ** patterns."""
        # Create folder structure
        folders = [
            "projects",
            "projects/web",
            "projects/web/frontend",
            "projects/api",
            "archive/old"
        ]
        
        for folder in folders:
            (Path(self.test_dir) / folder).mkdir(parents=True, exist_ok=True)
        
        # Create syft.pub.yaml with folder patterns
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "projects/**"
  access:
    read:
    - alice@example.com
    write:
    - alice@example.com
- pattern: "archive/**"
  access:
    read:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Check projects folders have alice permissions
        for proj_folder in ["projects/web", "projects/web/frontend", "projects/api"]:
            syft_folder = syft_perm.open(Path(self.test_dir) / proj_folder)
            self.assertTrue(syft_folder.has_read_access("alice@example.com"),
                          f"Alice should access {proj_folder}")
            self.assertTrue(syft_folder.has_write_access("alice@example.com"))
            self.assertFalse(syft_folder.has_read_access("bob@example.com"))
        
        # Check archive folder has bob permission
        syft_archive = syft_perm.open(Path(self.test_dir) / "archive/old")
        self.assertTrue(syft_archive.has_read_access("bob@example.com"))
        self.assertFalse(syft_archive.has_write_access("bob@example.com"))
        self.assertFalse(syft_archive.has_read_access("alice@example.com"))
    
    def test_multiple_double_star_in_single_pattern(self):
        """Test patterns with multiple ** segments (e.g., src/**/docs/**/test/*.py)."""
        # Create complex nested structure matching the pattern
        complex_paths = [
            "src/main/docs/api/test/test_api.py",
            "src/utils/docs/guide/test/test_guide.py", 
            "src/core/internal/docs/security/test/test_auth.py",
            "src/legacy/docs/test/basic.py",
            "other/src/docs/test/not_matching.py",  # Doesn't start with src/
            "src/no_docs/test/also_not_matching.py",  # Missing docs/
            "src/tools/docs/no_test/not_matching.py",  # Missing test/
            "src/web/docs/ui/test/final.js",  # Wrong extension
        ]
        
        for path in complex_paths:
            full_path = Path(self.test_dir) / path
            full_path.parent.mkdir(parents=True, exist_ok=True)
            full_path.write_text(f"content of {path}")
        
        # Create syft.pub.yaml with multiple ** pattern
        yaml_file = Path(self.test_dir) / "syft.pub.yaml"
        yaml_content = """rules:
- pattern: "src/**/docs/**/test/*.py"
  access:
    read:
    - alice@example.com
    write:
    - alice@example.com
- pattern: "src/**/test/*.py"
  access:
    read:
    - bob@example.com
"""
        yaml_file.write_text(yaml_content)
        
        # Files that should match the complex pattern (alice access)
        matching_files = [
            "src/main/docs/api/test/test_api.py",
            "src/utils/docs/guide/test/test_guide.py",
            "src/core/internal/docs/security/test/test_auth.py",
            "src/legacy/docs/test/basic.py"  # docs/**/test matches docs/test
        ]
        
        for path in matching_files:
            syft_file = syft_perm.open(Path(self.test_dir) / path)
            self.assertTrue(syft_file.has_read_access("alice@example.com"),
                          f"Alice should read {path} (matches src/**/docs/**/test/*.py)")
            self.assertTrue(syft_file.has_write_access("alice@example.com"))
            # Bob should not have access since alice's pattern matches first
            self.assertFalse(syft_file.has_read_access("bob@example.com"))
        
        # Files that don't match the complex pattern but match simpler one (bob access)
        simpler_matches = [
            "src/no_docs/test/also_not_matching.py"  # This actually should match src/**/test/*.py
        ]
        
        for path in simpler_matches:
            syft_file = syft_perm.open(Path(self.test_dir) / path)
            self.assertTrue(syft_file.has_read_access("bob@example.com"),
                          f"Bob should read {path} (matches src/**/test/*.py)")
            self.assertFalse(syft_file.has_write_access("bob@example.com"))
            self.assertFalse(syft_file.has_read_access("alice@example.com"))
        
        # Files that don't match any pattern
        non_matching = [
            "other/src/docs/test/not_matching.py",  # Doesn't start with src/
            "src/tools/docs/no_test/not_matching.py",  # Missing test/ 
            "src/web/docs/ui/test/final.js"  # Wrong extension
        ]
        
        for path in non_matching:
            syft_file = syft_perm.open(Path(self.test_dir) / path)
            self.assertFalse(syft_file.has_read_access("alice@example.com"),
                           f"Alice should not read {path}")
            self.assertFalse(syft_file.has_read_access("bob@example.com"),
                           f"Bob should not read {path}")


if __name__ == "__main__":
    unittest.main()