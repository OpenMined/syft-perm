"""Test edge cases and error conditions for permission system."""

import unittest
import tempfile
import shutil
from pathlib import Path
import yaml
import json

import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm
from syft_perm._impl import _permission_cache


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error conditions."""
    
    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        # Clear cache before each test
        _permission_cache.clear()
    
    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)
        # Clear cache after each test
        _permission_cache.clear()
    
    def test_circular_inheritance_prevention(self):
        """Test that circular inheritance doesn't cause infinite loops."""
        # This test verifies that walking up the directory tree stops at filesystem root
        # and doesn't get stuck in loops (which shouldn't happen in a normal filesystem)
        
        # Create a very deep structure that approaches potential loop conditions
        current_dir = Path(self.test_dir)
        
        # Create a chain that could theoretically loop if there were symlinks
        # but we're testing the normal case where parent traversal stops at root
        levels = ["a", "b", "c", "a", "b", "c"]  # Same names but different actual directories
        
        for level in levels:
            current_dir = current_dir / level
            current_dir.mkdir(exist_ok=True)
            
            # Add a syft.pub.yaml at each level
            yaml_path = current_dir / "syft.pub.yaml"
            rules = {
                "rules": [{
                    "pattern": "**",
                    "access": {
                        "read": [f"user_{level}@example.com"]
                    }
                }]
            }
            with open(yaml_path, 'w') as f:
                yaml.dump(rules, f)
        
        # Create a test file at the deepest level
        test_file = current_dir / "test.txt"
        test_file.write_text("test content")
        
        # This should complete without infinite loop
        syft_file = syft_perm.open(test_file)
        
        # Should use nearest-node algorithm: only the most specific (deepest) matching rule applies
        # The deepest directory with a matching rule is the final 'c' directory
        self.assertFalse(syft_file.has_read_access("user_a@example.com"))  # Not nearest
        self.assertFalse(syft_file.has_read_access("user_b@example.com"))  # Not nearest  
        self.assertTrue(syft_file.has_read_access("user_c@example.com"))   # Nearest matching rule
    
    def test_missing_intermediate_directories(self):
        """Test permissions work correctly when intermediate directories don't exist or lack permissions."""
        # Create grandparent
        grandparent = Path(self.test_dir) / "grandparent"
        grandparent.mkdir()
        
        grandparent_yaml = grandparent / "syft.pub.yaml"
        rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(grandparent_yaml, 'w') as f:
            yaml.dump(rules, f)
        
        # Skip creating parent directory and permissions
        # Create child directly
        child_dir = grandparent / "missing_parent" / "child"
        child_dir.mkdir(parents=True)
        
        test_file = child_dir / "test.txt"
        test_file.write_text("test content")
        
        # Should still inherit from grandparent despite missing intermediate permissions
        syft_file = syft_perm.open(test_file)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        
        # Check reasons mention the grandparent, not the missing parent
        has_read, reasons = syft_file._check_permission_with_reasons("alice@example.com", "read")
        self.assertTrue(has_read)
        self.assertTrue(any("grandparent" in r for r in reasons))
    
    def test_corrupt_yaml_files_in_chain(self):
        """Test that corrupt YAML files are skipped gracefully."""
        # Create parent with valid permissions
        parent_dir = Path(self.test_dir) / "parent"
        parent_dir.mkdir()
        
        parent_yaml = parent_dir / "syft.pub.yaml"
        rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(parent_yaml, 'w') as f:
            yaml.dump(rules, f)
        
        # Create child with corrupt YAML
        child_dir = parent_dir / "child"
        child_dir.mkdir()
        
        child_yaml = child_dir / "syft.pub.yaml"
        child_yaml.write_text("invalid: yaml: content: [unclosed")
        
        # Create grandchild with valid permissions
        grandchild_dir = child_dir / "grandchild"
        grandchild_dir.mkdir()
        
        grandchild_yaml = grandchild_dir / "syft.pub.yaml"
        gc_rules = {
            "rules": [{
                "pattern": "test.txt",
                "access": {
                    "write": ["bob@example.com"]
                }
            }]
        }
        with open(grandchild_yaml, 'w') as f:
            yaml.dump(gc_rules, f)
        
        # Create test file
        test_file = grandchild_dir / "test.txt"
        test_file.write_text("test content")
        
        # Should work despite corrupt YAML in middle
        syft_file = syft_perm.open(test_file)
        
        # Bob should have write from grandchild (nearest matching rule)
        self.assertTrue(syft_file.has_write_access("bob@example.com"))
        
        # Alice should NOT have read because nearest-node algorithm uses grandchild rule only
        # The corrupt child YAML is properly skipped, but grandchild rule is more specific than parent
        self.assertFalse(syft_file.has_read_access("alice@example.com"))
    
    def test_very_deep_nesting_10_plus_levels(self):
        """Test permissions work correctly with very deep nesting (10+ levels)."""
        # Create 15 levels deep
        current_dir = Path(self.test_dir)
        level_names = [f"level_{i:02d}" for i in range(15)]
        
        for i, level_name in enumerate(level_names):
            current_dir = current_dir / level_name
            current_dir.mkdir()
            
            # Add permissions every 3 levels
            if i % 3 == 0:
                yaml_path = current_dir / "syft.pub.yaml"
                rules = {
                    "rules": [{
                        "pattern": "**",
                        "access": {
                            "read": [f"user_level_{i}@example.com"]
                        }
                    }]
                }
                with open(yaml_path, 'w') as f:
                    yaml.dump(rules, f)
        
        # Create test file at deepest level
        test_file = current_dir / "deep_test.txt"
        test_file.write_text("very deep content")
        
        # Should complete in reasonable time
        syft_file = syft_perm.open(test_file)
        
        # Should use nearest-node algorithm: only the deepest matching rule applies
        # Level 12 is the nearest node with matching rules
        self.assertFalse(syft_file.has_read_access("user_level_0@example.com"))  # Not nearest
        self.assertFalse(syft_file.has_read_access("user_level_3@example.com"))  # Not nearest
        self.assertFalse(syft_file.has_read_access("user_level_6@example.com"))  # Not nearest
        self.assertFalse(syft_file.has_read_access("user_level_9@example.com"))  # Not nearest
        self.assertTrue(syft_file.has_read_access("user_level_12@example.com"))  # Nearest matching rule
        
        # Should not have permissions from levels that didn't define them
        self.assertFalse(syft_file.has_read_access("user_level_1@example.com"))
        self.assertFalse(syft_file.has_read_access("user_level_2@example.com"))
    
    def test_special_characters_in_paths_and_emails(self):
        """Test special characters in file paths and email addresses."""
        # Create directories and files with special characters
        special_dirs = [
            "dir with spaces",
            "dir-with-hyphens",
            "dir_with_underscores",
            "dir.with.dots",
            "dir+with+plus",
            "dir(with)parens",
            "dir[with]brackets",
            "dir{with}braces",
            "dir@with@at",
            "dir$with$dollar"
        ]
        
        special_emails = [
            "user+tag@example.com",
            "user.name@example.com", 
            "user-name@example.com",
            "user_name@example.com",
            "123user@example.com",
            "user123@example.com"
        ]
        
        base_dir = Path(self.test_dir) / "special_chars"
        base_dir.mkdir()
        
        # Create YAML with special character emails
        yaml_path = base_dir / "syft.pub.yaml"
        rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": special_emails
                }
            }]
        }
        with open(yaml_path, 'w') as f:
            yaml.dump(rules, f)
        
        # Create directories and files with special characters
        for special_dir in special_dirs:
            dir_path = base_dir / special_dir
            dir_path.mkdir()
            
            file_path = dir_path / f"file in {special_dir}.txt"
            file_path.write_text(f"content in {special_dir}")
            
            # Test permissions work
            syft_file = syft_perm.open(file_path)
            
            for email in special_emails:
                self.assertTrue(syft_file.has_read_access(email),
                              f"Email {email} should have access to file in {special_dir}")
    
    def test_case_sensitivity_in_pattern_matching(self):
        """Test that pattern matching is case sensitive."""
        # Create files with different cases
        test_files = [
            "test.TXT",
            "test.txt", 
            "TEST.txt",
            "Test.Txt",
            "readme.MD",
            "readme.md",
            "README.md"
        ]
        
        base_dir = Path(self.test_dir) / "case_test"
        base_dir.mkdir()
        
        for filename in test_files:
            file_path = base_dir / filename
            file_path.write_text(f"content of {filename}")
        
        # Create YAML with case-sensitive patterns
        yaml_path = base_dir / "syft.pub.yaml"
        rules = {
            "rules": [
                {
                    "pattern": "*.txt",  # Only lowercase .txt
                    "access": {
                        "read": ["lowercase@example.com"]
                    }
                },
                {
                    "pattern": "*.TXT",  # Only uppercase .TXT
                    "access": {
                        "read": ["uppercase@example.com"] 
                    }
                },
                {
                    "pattern": "*.md",  # Only lowercase .md
                    "access": {
                        "read": ["markdown@example.com"]
                    }
                }
            ]
        }
        with open(yaml_path, 'w') as f:
            yaml.dump(rules, f)
        
        # Test case sensitivity
        # test.txt should match *.txt
        syft_txt = syft_perm.open(base_dir / "test.txt")
        self.assertTrue(syft_txt.has_read_access("lowercase@example.com"))
        self.assertFalse(syft_txt.has_read_access("uppercase@example.com"))
        
        # test.TXT should match *.TXT
        syft_TXT = syft_perm.open(base_dir / "test.TXT")
        self.assertTrue(syft_TXT.has_read_access("uppercase@example.com"))
        self.assertFalse(syft_TXT.has_read_access("lowercase@example.com"))
        
        # TEST.txt should match *.txt (case-sensitive: extension matches) but not *.TXT
        syft_mixed = syft_perm.open(base_dir / "TEST.txt")
        self.assertTrue(syft_mixed.has_read_access("lowercase@example.com"))  # *.txt matches TEST.txt
        self.assertFalse(syft_mixed.has_read_access("uppercase@example.com"))  # *.TXT does not match TEST.txt
        
        # readme.md should match *.md
        syft_md = syft_perm.open(base_dir / "readme.md")
        self.assertTrue(syft_md.has_read_access("markdown@example.com"))
        
        # readme.MD should not match *.md
        syft_MD = syft_perm.open(base_dir / "readme.MD")
        self.assertFalse(syft_MD.has_read_access("markdown@example.com"))
    
    def test_cache_overflow_behavior(self):
        """Test cache behavior when exceeding 10,000 entries."""
        # The cache is LRU with max_size=10000
        # We'll create more than 10000 unique file paths and check cache behavior
        
        base_dir = Path(self.test_dir) / "cache_test"
        base_dir.mkdir()
        
        # Create a simple permission structure
        yaml_path = base_dir / "syft.pub.yaml"
        rules = {
            "rules": [{
                "pattern": "**",
                "access": {
                    "read": ["user@example.com"]
                }
            }]
        }
        with open(yaml_path, 'w') as f:
            yaml.dump(rules, f)
        
        # Create many files to overflow cache
        cache_size = _permission_cache.max_size
        overflow_count = cache_size + 100
        
        # Create directories and files
        files_created = []
        for i in range(overflow_count):
            # Create nested structure to ensure unique cache keys
            dir_path = base_dir / f"dir_{i // 100}" / f"subdir_{i % 100}"
            dir_path.mkdir(parents=True, exist_ok=True)
            
            file_path = dir_path / f"file_{i}.txt"
            file_path.write_text(f"content {i}")
            files_created.append(file_path)
        
        # Access all files to fill cache beyond capacity
        for file_path in files_created:
            syft_file = syft_perm.open(file_path)
            # This should cache the permissions
            self.assertTrue(syft_file.has_read_access("user@example.com"))
        
        # Cache should have evicted oldest entries
        # The exact cache size should be at or below max_size
        self.assertLessEqual(len(_permission_cache.cache), cache_size)
        
        # Early files might be evicted, but recent ones should still be cached
        # Test that we can still access permissions correctly
        recent_files = files_created[-50:]  # Last 50 files
        for file_path in recent_files:
            syft_file = syft_perm.open(file_path)
            self.assertTrue(syft_file.has_read_access("user@example.com"))
    
    def test_large_file_size_limit_values(self):
        """Test very large file size limits (approaching 2^63-1)."""
        # Test with various large values
        large_limits = [
            2**31 - 1,    # Max 32-bit signed int
            2**32 - 1,    # Max 32-bit unsigned int  
            2**63 - 1,    # Max 64-bit signed int
        ]
        
        base_dir = Path(self.test_dir) / "large_limits"
        base_dir.mkdir()
        
        for i, limit in enumerate(large_limits):
            # Create directory for this test case
            test_dir = base_dir / f"limit_{i}"
            test_dir.mkdir()
            
            # Create YAML with large limit (must be named syft.pub.yaml)
            yaml_path = test_dir / "syft.pub.yaml"
            rules = {
                "rules": [{
                    "pattern": "file.txt",
                    "access": {
                        "read": ["user@example.com"]
                    },
                    "limits": {
                        "max_file_size": limit
                    }
                }]
            }
            with open(yaml_path, 'w') as f:
                yaml.dump(rules, f)
            
            # Create small test file
            file_path = test_dir / "file.txt"
            file_path.write_text("small content")
            
            # Should work with large limits
            syft_file = syft_perm.open(file_path)
            self.assertTrue(syft_file.has_read_access("user@example.com"))
    
    def test_permission_check_during_cache_invalidation(self):
        """Test that permission checks work correctly during cache invalidation."""
        base_dir = Path(self.test_dir) / "invalidation_test"
        base_dir.mkdir()
        
        # Create initial permissions
        yaml_path = base_dir / "syft.pub.yaml"
        rules = {
            "rules": [{
                "pattern": "test.txt",
                "access": {
                    "read": ["alice@example.com"]
                }
            }]
        }
        with open(yaml_path, 'w') as f:
            yaml.dump(rules, f)
        
        # Create test file
        test_file = base_dir / "test.txt"
        test_file.write_text("test content")
        
        # Access file to cache permissions
        syft_file = syft_perm.open(test_file)
        self.assertTrue(syft_file.has_read_access("alice@example.com"))
        self.assertFalse(syft_file.has_read_access("bob@example.com"))
        
        # Modify permissions while cache is populated
        new_rules = {
            "rules": [{
                "pattern": "test.txt",
                "access": {
                    "read": ["bob@example.com"]  # Change to bob
                }
            }]
        }
        with open(yaml_path, 'w') as f:
            yaml.dump(new_rules, f)
        
        # Grant new permission (should invalidate cache)
        syft_file.grant_write_access("charlie@example.com", force=True)
        
        # Check that cache was invalidated and new permissions apply
        # Re-read the file to get fresh instance
        syft_file_new = syft_perm.open(test_file)
        
        # Should reflect the manual change to YAML (bob now has read)
        # AND the programmatic change (charlie has write)
        self.assertTrue(syft_file_new.has_read_access("bob@example.com"))
        self.assertTrue(syft_file_new.has_write_access("charlie@example.com"))
        
        # Alice should no longer have access (removed in manual edit)
        self.assertFalse(syft_file_new.has_read_access("alice@example.com"))
    
    def test_malformed_yaml_edge_cases(self):
        """Test various malformed YAML scenarios."""
        malformed_yamls = [
            "",  # Empty file
            "not yaml at all",  # Not YAML
            "null",  # Just null
            "rules: null",  # Null rules
            "rules: []",  # Empty rules
            "rules:\n- invalid",  # Invalid rule structure
            "rules:\n- pattern: test\n  access: null",  # Null access
            "rules:\n- pattern: test\n  access:\n    read: not_a_list",  # Invalid read format
        ]
        
        base_dir = Path(self.test_dir) / "malformed_test"
        base_dir.mkdir()
        
        # Create test file
        test_file = base_dir / "test.txt"
        test_file.write_text("test content")
        
        for i, yaml_content in enumerate(malformed_yamls):
            yaml_path = base_dir / "syft.pub.yaml"
            yaml_path.write_text(yaml_content)
            
            # Should not crash, should gracefully handle malformed YAML
            try:
                syft_file = syft_perm.open(test_file)
                # Should work but have no permissions due to malformed YAML
                self.assertFalse(syft_file.has_read_access("user@example.com"))
            except Exception as e:
                self.fail(f"Malformed YAML {i} caused exception: {e}")
            
            # Clean up for next iteration
            yaml_path.unlink()


if __name__ == "__main__":
    unittest.main()