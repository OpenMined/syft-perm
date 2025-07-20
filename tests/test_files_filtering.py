"""Test filtering functionality for sp.files."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import syft_perm as sp  # noqa: E402
from syft_perm._public import Files, FilteredFiles  # noqa: E402


class TestFilesFiltering(unittest.TestCase):
    """Test sp.files filtering functionality."""

    def setUp(self):
        """Create a temporary directory for testing."""
        self.test_dir = tempfile.mkdtemp()
        self.test_users = ["alice@example.com", "bob@example.com", "charlie@example.com"]

    def tearDown(self):
        """Clean up the temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_slice_notation(self):
        """Test sp.files[x:y] slice notation."""
        # Mock _scan_files to return predictable test data
        test_files = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "file2.txt",
                "path": "/path/file2.txt",
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
            {
                "name": "file3.txt",
                "path": "/path/file3.txt",
                "modified": 3000,
                "datasite_owner": "charlie@example.com",
            },
            {
                "name": "file4.txt",
                "path": "/path/file4.txt",
                "modified": 4000,
                "datasite_owner": "alice@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Test slice notation
                result = sp.files[1:3]

                # Should be FilteredFiles instance
                self.assertIsInstance(result, FilteredFiles)

                # Should contain 2 files (newest first, so file4 and file3)
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 2)
                self.assertEqual(filtered_files[0]["name"], "file4.txt")  # Newest
                self.assertEqual(filtered_files[1]["name"], "file3.txt")  # Second newest

    def test_slice_notation_edge_cases(self):
        """Test slice notation edge cases."""
        test_files = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "file2.txt",
                "path": "/path/file2.txt",
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Test slice with None values
                result = sp.files[1:]
                self.assertEqual(len(result._filtered_files), 2)

                # Test slice beyond range
                result = sp.files[1:10]
                self.assertEqual(len(result._filtered_files), 2)

                # Test invalid indexing
                with self.assertRaises(TypeError):
                    _ = sp.files[1]  # Not slice notation

    def test_search_method_files_parameter(self):
        """Test sp.files.search() with files parameter."""
        test_files = [
            {
                "name": "test_file.txt",
                "path": "/path/test_file.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "other_file.txt",
                "path": "/path/other_file.txt",
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
            {
                "name": "test_document.pdf",
                "path": "/path/test_document.pdf",
                "modified": 3000,
                "datasite_owner": "charlie@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Search for files containing "test"
                result = sp.files.search(files="test")

                # Should be FilteredFiles instance
                self.assertIsInstance(result, FilteredFiles)

                # Should contain 2 files with "test" in name
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 2)
                file_names = [f["name"] for f in filtered_files]
                self.assertIn("test_file.txt", file_names)
                self.assertIn("test_document.pdf", file_names)

    def test_search_method_admin_parameter(self):
        """Test sp.files.search() with admin parameter."""
        test_files = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "file2.txt",
                "path": "/path/file2.txt",
                "modified": 2000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "file3.txt",
                "path": "/path/file3.txt",
                "modified": 3000,
                "datasite_owner": "bob@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Search for files by admin
                result = sp.files.search(admin="alice@example.com")

                # Should contain 2 files owned by alice
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 2)
                for file in filtered_files:
                    self.assertEqual(file["datasite_owner"], "alice@example.com")

    def test_search_method_combined_parameters(self):
        """Test sp.files.search() with both files and admin parameters."""
        test_files = [
            {
                "name": "test_file.txt",
                "path": "/path/test_file.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "test_document.pdf",
                "path": "/path/test_document.pdf",
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
            {
                "name": "other_file.txt",
                "path": "/path/other_file.txt",
                "modified": 3000,
                "datasite_owner": "alice@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Search for files containing "test" by alice
                result = sp.files.search(files="test", admin="alice@example.com")

                # Should contain only 1 file (test_file.txt by alice)
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 1)
                self.assertEqual(filtered_files[0]["name"], "test_file.txt")
                self.assertEqual(filtered_files[0]["datasite_owner"], "alice@example.com")

    def test_search_quoted_phrases(self):
        """Test search with quoted phrases."""
        test_files = [
            {
                "name": "my test file.txt",
                "path": "/path/my test file.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "my_test_file.txt",
                "path": "/path/my_test_file.txt",
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
            {
                "name": "test file other.txt",
                "path": "/path/test file other.txt",
                "modified": 3000,
                "datasite_owner": "charlie@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Search with quoted phrase
                result = sp.files.search(files='"test file"')

                # Should match files with exact phrase "test file"
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 2)
                file_names = [f["name"] for f in filtered_files]
                self.assertIn("my test file.txt", file_names)
                self.assertIn("test file other.txt", file_names)
                self.assertNotIn("my_test_file.txt", file_names)  # Doesn't contain exact phrase

    def test_filter_method_folders(self):
        """Test sp.files.filter() with folders parameter."""
        test_files = [
            {
                "name": "alice@example.com/file1.txt",
                "path": "/path/alice@example.com/file1.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "alice@example.com/data/file2.txt",
                "path": "/path/alice@example.com/data/file2.txt",
                "modified": 2000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "bob@example.com/file3.txt",
                "path": "/path/bob@example.com/file3.txt",
                "modified": 3000,
                "datasite_owner": "bob@example.com",
            },
            {
                "name": "alice@example.com/other/file4.txt",
                "path": "/path/alice@example.com/other/file4.txt",
                "modified": 4000,
                "datasite_owner": "alice@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Filter by folder path
                result = sp.files.filter(folders=["alice@example.com/data"])

                # Should contain only files in alice's data folder
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 1)
                self.assertEqual(filtered_files[0]["name"], "alice@example.com/data/file2.txt")

    def test_filter_method_multiple_folders(self):
        """Test sp.files.filter() with multiple folder paths."""
        test_files = [
            {
                "name": "alice@example.com/file1.txt",
                "path": "/path/alice@example.com/file1.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "alice@example.com/data/file2.txt",
                "path": "/path/alice@example.com/data/file2.txt",
                "modified": 2000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "bob@example.com/file3.txt",
                "path": "/path/bob@example.com/file3.txt",
                "modified": 3000,
                "datasite_owner": "bob@example.com",
            },
            {
                "name": "charlie@example.com/docs/file4.txt",
                "path": "/path/charlie@example.com/docs/file4.txt",
                "modified": 4000,
                "datasite_owner": "charlie@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Filter by multiple folder paths
                result = sp.files.filter(folders=["alice@example.com/data", "charlie@example.com"])

                # Should contain files from both specified folders
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 2)
                file_names = [f["name"] for f in filtered_files]
                self.assertIn("alice@example.com/data/file2.txt", file_names)
                self.assertIn("charlie@example.com/docs/file4.txt", file_names)

    def test_filter_method_syft_prefix(self):
        """Test sp.files.filter() handles syft:// prefix."""
        test_files = [
            {
                "name": "alice@example.com/file1.txt",
                "path": "/path/alice@example.com/file1.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "bob@example.com/file2.txt",
                "path": "/path/bob@example.com/file2.txt",
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_files):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Filter with syft:// prefix
                result = sp.files.filter(folders=["syft://alice@example.com"])

                # Should strip prefix and match correctly
                filtered_files = result._filtered_files
                self.assertEqual(len(filtered_files), 1)
                self.assertEqual(filtered_files[0]["name"], "alice@example.com/file1.txt")

    def test_parse_search_terms(self):
        """Test _parse_search_terms method."""
        # Test simple terms
        terms = sp.files._parse_search_terms("hello world")
        self.assertEqual(terms, ["hello", "world"])

        # Test quoted phrase with double quotes
        terms = sp.files._parse_search_terms('hello "quoted phrase" world')
        self.assertEqual(terms, ["hello", "quoted phrase", "world"])

        # Test quoted phrase with single quotes
        terms = sp.files._parse_search_terms("hello 'quoted phrase' world")
        self.assertEqual(terms, ["hello", "quoted phrase", "world"])

        # Test mixed quotes
        terms = sp.files._parse_search_terms("\"double quote\" 'single quote' normal")
        self.assertEqual(terms, ["double quote", "single quote", "normal"])

    def test_matches_search_terms(self):
        """Test _matches_search_terms method."""
        test_file = {
            "name": "alice@example.com/test_document.pdf",
            "datasite_owner": "alice@example.com",
        }

        # Test matching terms
        self.assertTrue(sp.files._matches_search_terms(test_file, ["test"]))
        self.assertTrue(sp.files._matches_search_terms(test_file, ["alice"]))
        self.assertTrue(sp.files._matches_search_terms(test_file, ["test", "alice"]))

        # Test non-matching terms
        self.assertFalse(sp.files._matches_search_terms(test_file, ["nonexistent"]))
        self.assertFalse(
            sp.files._matches_search_terms(test_file, ["test", "bob"])
        )  # bob not in file

    def test_filtered_files_scan_files(self):
        """Test FilteredFiles._scan_files returns pre-filtered files."""
        test_files = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "file2.txt",
                "path": "/path/file2.txt",
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
        ]

        filtered = FilteredFiles(test_files)
        scanned_files = filtered._scan_files()

        # Should return the exact same files that were passed in
        self.assertEqual(scanned_files, test_files)

    def test_filetype_filtering(self):
        """Test filtering by filetype (file vs folder)."""
        # Mock _scan_files to return mixed files and folders
        test_items = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "is_dir": False,
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "folder1",
                "path": "/path/folder1",
                "is_dir": True,
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
            {
                "name": "file2.csv",
                "path": "/path/file2.csv",
                "is_dir": False,
                "modified": 3000,
                "datasite_owner": "charlie@example.com",
            },
            {
                "name": "folder2",
                "path": "/path/folder2",
                "is_dir": True,
                "modified": 4000,
                "datasite_owner": "alice@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_items):
            with patch.object(sp.files, "_check_server", return_value=None):
                # Test filtering for files only
                files_only = sp.files.search(filetype="file")
                self.assertIsInstance(files_only, FilteredFiles)
                self.assertEqual(len(files_only._filtered_files), 2)
                for item in files_only._filtered_files:
                    self.assertFalse(item["is_dir"])

                # Test filtering for folders only
                folders_only = sp.files.search(filetype="folder")
                self.assertIsInstance(folders_only, FilteredFiles)
                self.assertEqual(len(folders_only._filtered_files), 2)
                for item in folders_only._filtered_files:
                    self.assertTrue(item["is_dir"])

    def test_files_singleton(self):
        """Test that sp.files returns only files."""
        test_items = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "is_dir": False,
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "folder1",
                "path": "/path/folder1",
                "is_dir": True,
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
        ]

        with patch.object(sp.files, "_scan_files", return_value=test_items):
            # sp.files should only return files
            all_files = sp.files.all()
            # This will return filtered files only if the singleton was properly configured
            for item in all_files:
                self.assertFalse(item.get("is_dir", False))

    def test_folders_singleton(self):
        """Test that sp.folders returns only folders."""
        test_items = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "is_dir": False,
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "folder1",
                "path": "/path/folder1",
                "is_dir": True,
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
        ]

        with patch.object(sp.folders, "_scan_files", return_value=test_items):
            # sp.folders should only return folders
            all_folders = sp.folders.all()
            # This will return filtered folders only if the singleton was properly configured
            for item in all_folders:
                self.assertTrue(item.get("is_dir", False))

    def test_files_and_folders_singleton(self):
        """Test that sp.files_and_folders returns both files and folders."""
        test_items = [
            {
                "name": "file1.txt",
                "path": "/path/file1.txt",
                "is_dir": False,
                "modified": 1000,
                "datasite_owner": "alice@example.com",
            },
            {
                "name": "folder1",
                "path": "/path/folder1",
                "is_dir": True,
                "modified": 2000,
                "datasite_owner": "bob@example.com",
            },
        ]

        with patch.object(sp.files_and_folders, "_scan_files", return_value=test_items):
            # sp.files_and_folders should return both
            all_items = sp.files_and_folders.all()
            self.assertEqual(len(all_items), 2)
            # Verify we have both types
            has_file = any(not item.get("is_dir", False) for item in all_items)
            has_folder = any(item.get("is_dir", False) for item in all_items)
            self.assertTrue(has_file)
            self.assertTrue(has_folder)


if __name__ == "__main__":
    unittest.main()
