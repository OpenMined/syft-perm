#!/usr/bin/env python3
"""
Example of using the new .files endpoint in syft-perm

This endpoint provides a paginated list of files with permissions
from the SyftBox directory, similar to the old syft-objects widget.
"""

import requests

import syft_perm as sp

# Start the permission server
server_url = sp.start_permission_server()
print(f"Permission server running at: {server_url}")
print(f"API docs available at: {server_url}/docs")

# Example 1: Get all files with permissions (default pagination)
print("\n" + "=" * 60)
print("Example 1: Get all files with permissions")
print("=" * 60)

response = requests.get(f"{server_url}/files")
data = response.json()

print(f"Total files with permissions: {data['total_count']}")
print(f"Files in this page: {len(data['files'])}")
print(f"Has more pages: {data['has_more']}")
print(f"SyftBox directory: {data['syftbox_path']}")

# Example 2: Pagination
print("\n" + "=" * 60)
print("Example 2: Pagination (page size = 10)")
print("=" * 60)

# Page 1
response = requests.get(f"{server_url}/files?limit=10&offset=0")
page1 = response.json()
print(f"Page 1: {len(page1['files'])} files (offset=0)")

# Page 2
response = requests.get(f"{server_url}/files?limit=10&offset=10")
page2 = response.json()
print(f"Page 2: {len(page2['files'])} files (offset=10)")

# Example 3: Search functionality
print("\n" + "=" * 60)
print("Example 3: Search for files containing 'test'")
print("=" * 60)

response = requests.get(f"{server_url}/files?search=test")
search_results = response.json()

print(f"Files matching 'test': {len(search_results['files'])}")
for file in search_results["files"][:5]:  # Show first 5
    size_str = f"{file['size']} bytes" if not file["is_dir"] else "directory"
    print(f"  - {file['name']} ({size_str})")

# Example 4: Using the convenience function
print("\n" + "=" * 60)
print("Example 4: Using get_files_url() convenience function")
print("=" * 60)

# Generate URL with parameters
files_url = sp.get_files_url(limit=20, offset=0, search="yaml")
print(f"Generated URL: {files_url}")

# You can use this URL directly with any HTTP client
response = requests.get(files_url)
yaml_files = response.json()
print(f"Files containing 'yaml': {len(yaml_files['files'])}")

# Example 5: Understanding the response format
print("\n" + "=" * 60)
print("Example 5: File information structure")
print("=" * 60)

if data["files"]:
    example_file = data["files"][0]
    print("Example file structure:")
    print(f"  Path: {example_file['path']}")
    print(f"  Name: {example_file['name']}")
    print(f"  Is Directory: {example_file['is_dir']}")
    print(f"  Size: {example_file['size']} bytes")
    print(f"  Modified: {example_file['modified']} (Unix timestamp)")
    print(f"  Has YAML config: {example_file['has_yaml']}")
    print("  Permissions:")
    for perm_type, users in example_file["permissions"].items():
        if users:
            print(f"    {perm_type}: {', '.join(users)}")

# Example 6: Practical use case - Find all directories with admin permissions
print("\n" + "=" * 60)
print("Example 6: Find directories where someone has admin access")
print("=" * 60)

response = requests.get(f"{server_url}/files?limit=1000")  # Get more files
all_files = response.json()

admin_dirs = [
    file for file in all_files["files"] if file["is_dir"] and file["permissions"].get("admin", [])
]

print(f"Directories with admin permissions: {len(admin_dirs)}")
for dir_info in admin_dirs[:5]:  # Show first 5
    admins = ", ".join(dir_info["permissions"]["admin"])
    print(f"  - {dir_info['name']}: {admins}")

print("\n" + "=" * 60)
print("API Endpoint: GET /files")
print("Parameters:")
print("  - limit: Number of items per page (1-1000, default: 50)")
print("  - offset: Starting index (default: 0)")
print("  - search: Search term for file names (optional)")
print("=" * 60)
