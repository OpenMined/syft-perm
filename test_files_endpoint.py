#!/usr/bin/env python3
"""Test script for the new .files endpoint"""


import requests

import syft_perm as sp

# Start the server
server_url = sp.start_permission_server()
print(f"Server started at: {server_url}")

# Test the files endpoint
print("\n=== Testing .files endpoint ===")

# 1. Get all files with permissions
print("\n1. Getting all files with permissions:")
response = requests.get(f"{server_url}/files")
if response.status_code == 200:
    data = response.json()
    print(f"   Total files found: {data['total_count']}")
    print(f"   Has more pages: {data['has_more']}")
    print(f"   SyftBox path: {data['syftbox_path']}")
    print(f"   Files returned: {len(data['files'])}")

    if data["files"]:
        print("\n   First 3 files:")
        for i, file in enumerate(data["files"][:3]):
            print(f"   {i+1}. {file['name']} ({'dir' if file['is_dir'] else 'file'})")
            print(f"      Path: {file['path']}")
            print(f"      Permissions: {file['permissions']}")
            print()
else:
    print(f"   Error: {response.status_code} - {response.text}")

# 2. Test pagination
print("\n2. Testing pagination (limit=5, offset=0):")
response = requests.get(f"{server_url}/files?limit=5&offset=0")
if response.status_code == 200:
    data = response.json()
    print(f"   Files on page 1: {len(data['files'])}")
    print(f"   Total count: {data['total_count']}")
    print(f"   Has more: {data['has_more']}")

# 3. Test search
print("\n3. Testing search (search='test'):")
response = requests.get(f"{server_url}/files?search=test")
if response.status_code == 200:
    data = response.json()
    print(f"   Files matching 'test': {len(data['files'])}")
    for file in data["files"][:3]:
        print(f"   - {file['name']}")

# 4. Using the convenience function
print("\n4. Using get_files_url convenience function:")
files_url = sp.get_files_url(limit=10, offset=0, search="yaml")
print(f"   Generated URL: {files_url}")

print("\n=== API Response Format ===")
print(
    """
{
    "files": [
        {
            "path": "/path/to/file",
            "name": "filename",
            "is_dir": false,
            "size": 1234,
            "modified": 1234567890.0,
            "permissions": {
                "read": ["user1@example.com"],
                "write": ["user2@example.com"],
                "create": [],
                "admin": []
            },
            "has_yaml": false
        }
    ],
    "total_count": 100,
    "offset": 0,
    "limit": 50,
    "has_more": true,
    "syftbox_path": "/Users/username/SyftBox"
}
"""
)
