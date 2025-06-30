#!/usr/bin/env python3
"""
Tests for syft-perm permission utilities
"""

import pytest
import tempfile
import yaml
from pathlib import Path

from syft_perm import set_file_permissions, get_file_permissions, remove_file_permissions


class TestPermissions:
    
    def test_set_and_get_basic_permissions(self):
        """Test setting and getting basic file permissions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "test.txt"
            test_file.write_text("test content")
            
            # Set permissions
            set_file_permissions(
                str(test_file),
                read_users=["alice@example.com", "bob@example.com"],
                write_users=["alice@example.com"]
            )
            
            # Check that syft.pub.yaml was created
            syft_pub = temp_path / "syft.pub.yaml"
            assert syft_pub.exists()
            
            # Get permissions
            permissions = get_file_permissions(str(test_file))
            assert permissions is not None
            assert "read" in permissions
            assert "write" in permissions
            assert "alice@example.com" in permissions["read"]
            assert "bob@example.com" in permissions["read"]
            assert permissions["write"] == ["alice@example.com"]
    
    def test_public_permissions(self):
        """Test setting public permissions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "public_test.txt"
            test_file.write_text("public content")
            
            # Set public read permissions
            set_file_permissions(
                str(test_file),
                read_users=["public"],
                write_users=["alice@example.com"]
            )
            
            permissions = get_file_permissions(str(test_file))
            assert permissions is not None
            assert permissions["read"] == ["*"]  # "public" should be converted to "*"
            assert permissions["write"] == ["alice@example.com"]
    
    def test_admin_permissions(self):
        """Test setting admin permissions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "admin_test.txt"
            test_file.write_text("admin content")
            
            # Set permissions with admin
            set_file_permissions(
                str(test_file),
                read_users=["alice@example.com"],
                write_users=["alice@example.com"],
                admin_users=["admin@example.com"]
            )
            
            permissions = get_file_permissions(str(test_file))
            assert permissions is not None
            assert "admin" in permissions
            assert permissions["admin"] == ["admin@example.com"]
    
    def test_remove_permissions(self):
        """Test removing file permissions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "remove_test.txt"
            test_file.write_text("remove content")
            
            # Set permissions
            set_file_permissions(
                str(test_file),
                read_users=["alice@example.com"]
            )
            
            # Verify permissions exist
            permissions = get_file_permissions(str(test_file))
            assert permissions is not None
            
            # Remove permissions
            remove_file_permissions(str(test_file))
            
            # Verify permissions are gone
            permissions = get_file_permissions(str(test_file))
            assert permissions is None
    
    def test_multiple_files_same_directory(self):
        """Test managing permissions for multiple files in the same directory"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Create multiple files
            file1 = temp_path / "file1.txt"
            file2 = temp_path / "file2.txt"
            file1.write_text("content 1")
            file2.write_text("content 2")
            
            # Set different permissions for each file
            set_file_permissions(str(file1), read_users=["alice@example.com"])
            set_file_permissions(str(file2), read_users=["bob@example.com"])
            
            # Check permissions
            perms1 = get_file_permissions(str(file1))
            perms2 = get_file_permissions(str(file2))
            
            assert perms1["read"] == ["alice@example.com"]
            assert perms2["read"] == ["bob@example.com"]
    
    def test_update_existing_permissions(self):
        """Test updating permissions for a file that already has permissions"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "update_test.txt"
            test_file.write_text("update content")
            
            # Set initial permissions
            set_file_permissions(
                str(test_file),
                read_users=["alice@example.com"]
            )
            
            # Update permissions
            set_file_permissions(
                str(test_file),
                read_users=["bob@example.com", "charlie@example.com"],
                write_users=["bob@example.com"]
            )
            
            # Check updated permissions
            permissions = get_file_permissions(str(test_file))
            assert "alice@example.com" not in permissions["read"]  # Should be replaced
            assert "bob@example.com" in permissions["read"]
            assert "charlie@example.com" in permissions["read"]
            assert permissions["write"] == ["bob@example.com"]
    
    def test_nonexistent_file_permissions(self):
        """Test getting permissions for a file that doesn't exist"""
        permissions = get_file_permissions("/nonexistent/file.txt")
        assert permissions is None
    
    def test_empty_permissions(self):
        """Test handling empty permission lists"""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            test_file = temp_path / "empty_test.txt"
            test_file.write_text("empty content")
            
            # Set empty permissions (should not create syft.pub.yaml)
            set_file_permissions(str(test_file), read_users=[])
            
            # Check that no permissions were set
            permissions = get_file_permissions(str(test_file))
            assert permissions is None
            
            # Check that syft.pub.yaml was not created
            syft_pub = temp_path / "syft.pub.yaml"
            assert not syft_pub.exists()


if __name__ == "__main__":
    pytest.main([__file__]) 