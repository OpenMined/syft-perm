#!/usr/bin/env python3
"""Test editor permissions with server running."""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

import syft_perm

# Open the guestbook file
guestbook_path = Path.home() / "SyftBox/datasites/andrew@openmined.org/guestbook.txt"
print(f"Opening: {guestbook_path}")

f = syft_perm.open(guestbook_path)

# Check permissions
print(f"\nPermissions for andrew@openmined.org:")
print(f"  Has read: {f.has_read_access('andrew@openmined.org')}")
print(f"  Has write: {f.has_write_access('andrew@openmined.org')}")
print(f"  Has admin: {f.has_admin_access('andrew@openmined.org')}")

print(f"\nPermissions for public:")
print(f"  Has read: {f.has_read_access('public')}")
print(f"  Has write: {f.has_write_access('public')}")

print(f"\nAll permissions:")
perms = f._get_all_permissions()
for perm_type, users in perms.items():
    if users:
        print(f"  {perm_type}: {users}")

# Now test the server endpoint directly
print("\n=== Testing server endpoint ===")
try:
    from syft_perm.filesystem_editor import get_current_user_email
    from syft_perm.filesystem_editor.manager import FileSystemManager
    
    fs_manager = FileSystemManager()
    current_user = get_current_user_email()
    print(f"Current user: {current_user}")
    
    # Call read_file which is what the editor uses
    file_data = fs_manager.read_file(str(guestbook_path), user_email=current_user)
    
    print(f"\nFile data from manager:")
    print(f"  can_write: {file_data['can_write']}")
    print(f"  can_admin: {file_data['can_admin']}")
    print(f"  write_users: {file_data['write_users']}")
    
except Exception as e:
    print(f"Error testing server endpoint: {e}")
    import traceback
    traceback.print_exc()

print("\n=== Testing editor URL ===")
try:
    from syft_perm import _get_file_editor_url
    
    editor_url = _get_file_editor_url(guestbook_path)
    print(f"Editor URL: {editor_url}")
    
    # Check if syft_user is in URL
    if "syft_user=" in editor_url:
        print("✓ syft_user parameter is included in URL")
    else:
        print("✗ syft_user parameter is NOT included in URL")
        
except Exception as e:
    print(f"Error getting editor URL: {e}")