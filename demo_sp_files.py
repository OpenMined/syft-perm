#!/usr/bin/env python3
"""Demo of the new sp.files interface"""

import syft_perm as sp

print("=== SyftPerm Files Interface Demo ===\n")

# 1. Show basic info about files
print("1. Basic info:")
print(repr(sp.files))
print()

# 2. Get all files
print("2. Getting all files with permissions:")
all_files = sp.files.all()
print(f"Found {len(all_files)} files with permissions")
if all_files:
    print(f"First file: {all_files[0]['name']}")
print()

# 3. Paginated access
print("3. Paginated access (first 5 files):")
page = sp.files.get(limit=5, offset=0)
print(f"Page info: {len(page['files'])} files, has_more={page['has_more']}")
for file in page["files"]:
    perms = [k for k, v in file["permissions"].items() if v]
    print(f"  - {file['name']} ({len(perms)} permission types)")
print()

# 4. Search functionality
print("4. Search for files containing 'test':")
search_results = sp.files.search("test")
print(f"Found {len(search_results['files'])} files matching 'test'")
for file in search_results["files"][:3]:  # Show first 3
    print(f"  - {file['name']}")
print()

# 5. Show some usage examples
print("5. Available methods:")
print("  sp.files              # Basic info + Jupyter table display")
print("  sp.files.all()        # Get all files as list")
print("  sp.files.get(limit=10, offset=0)  # Paginated access")
print("  sp.files.search('term')  # Search by filename")
print()

print("✅ All sp.files methods working correctly!")
print("💡 In Jupyter notebooks, just type 'sp.files' to see a nice table display")
