#!/usr/bin/env python3
"""
Basic usage example for syft-perm

This example shows how to use the syft-perm utilities to manage file permissions.
"""

from syft_perm import set_file_permissions, get_file_permissions, remove_file_permissions
from pathlib import Path
import tempfile
import os

def main():
    print("🔐 SyftPerm Basic Usage Example")
    print("=" * 40)
    
    # Create a temporary directory for our example
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create a test file
        test_file = temp_path / "example.txt"
        test_file.write_text("This is a test file for permission management.")
        
        print(f"📁 Created test file: {test_file}")
        
        # Example 1: Set basic permissions
        print("\n1. Setting basic permissions...")
        set_file_permissions(
            str(test_file),
            read_users=["alice@example.com", "bob@example.com"],
            write_users=["alice@example.com"]
        )
        print("✅ Set read access for alice and bob, write access for alice only")
        
        # Check that syft.pub.yaml was created
        syft_pub = temp_path / "syft.pub.yaml"
        if syft_pub.exists():
            print(f"✅ Created permission file: {syft_pub}")
            print("   Content:")
            print("   " + "\n   ".join(syft_pub.read_text().splitlines()))
        
        # Example 2: Read permissions
        print("\n2. Reading permissions...")
        permissions = get_file_permissions(str(test_file))
        if permissions:
            print(f"✅ Current permissions: {permissions}")
        else:
            print("❌ No permissions found")
        
        # Example 3: Set public permissions
        print("\n3. Setting public permissions...")
        set_file_permissions(
            str(test_file),
            read_users=["public"],  # Anyone can read
            write_users=["alice@example.com"]  # Only alice can write
        )
        
        permissions = get_file_permissions(str(test_file))
        print(f"✅ Updated permissions: {permissions}")
        
        # Example 4: Add admin permissions
        print("\n4. Adding admin permissions...")
        set_file_permissions(
            str(test_file),
            read_users=["public"],
            write_users=["alice@example.com"],
            admin_users=["admin@example.com"]
        )
        
        permissions = get_file_permissions(str(test_file))
        print(f"✅ Permissions with admin: {permissions}")
        
        # Example 5: Remove permissions
        print("\n5. Removing permissions...")
        remove_file_permissions(str(test_file))
        
        permissions = get_file_permissions(str(test_file))
        if permissions is None:
            print("✅ Permissions removed successfully")
        else:
            print(f"❌ Permissions still exist: {permissions}")
        
        # Example 6: Multiple files
        print("\n6. Managing multiple files...")
        
        # Create multiple test files
        files = []
        for i in range(3):
            file_path = temp_path / f"file_{i}.txt"
            file_path.write_text(f"Content of file {i}")
            files.append(file_path)
        
        # Set different permissions for each file
        permissions_config = [
            (["public"], []),  # Public read, no write
            (["alice@example.com"], ["alice@example.com"]),  # Alice only
            (["alice@example.com", "bob@example.com"], ["bob@example.com"])  # Shared
        ]
        
        for file_path, (read_users, write_users) in zip(files, permissions_config):
            set_file_permissions(str(file_path), read_users, write_users)
            perms = get_file_permissions(str(file_path))
            print(f"✅ {file_path.name}: {perms}")
        
        print("\n🎉 Example completed successfully!")
        print(f"📋 Check the syft.pub.yaml file at: {syft_pub}")

if __name__ == "__main__":
    main() 