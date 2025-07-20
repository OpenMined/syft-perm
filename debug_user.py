#!/usr/bin/env python3
"""Debug current user detection."""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

from syft_perm.filesystem_editor.utils import get_current_user_email

print("=== Debugging get_current_user_email() ===")
print()

# Check environment variable
env_email = os.environ.get("SYFTBOX_USER_EMAIL")
print(f"SYFTBOX_USER_EMAIL env var: {env_email}")

# Check config file
config_path = Path(os.path.expanduser("~/.syftbox/config.json"))
print(f"Config file exists: {config_path.exists()}")
if config_path.exists():
    import json
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            print(f"Config email: {config.get('email')}")
    except Exception as e:
        print(f"Error reading config: {e}")

# Check datasites
datasites_path = Path(os.path.expanduser("~/SyftBox/datasites"))
print(f"Datasites path exists: {datasites_path.exists()}")
if datasites_path.exists():
    datasites = list(datasites_path.iterdir())
    print(f"Datasites found: {[d.name for d in datasites if d.is_dir()]}")

# Call the function
print()
print(f"get_current_user_email() returns: {get_current_user_email()}")

# Also check if the file is public writable
print()
print("=== Checking guestbook.txt permissions ===")
import syft_perm

guestbook_path = Path.home() / "SyftBox/datasites/andrew@openmined.org/guestbook.txt"
if guestbook_path.exists():
    f = syft_perm.open(guestbook_path)
    print(f"Has write access for 'public': {f.has_write_access('public')}")
    print(f"Has write access for '*': {f.has_write_access('*')}")
    print(f"Has write access for None: {f.has_write_access(None)}")
    
    # Get all permissions
    perms = f._get_all_permissions()
    print(f"Write users: {perms.get('write', [])}")
else:
    print(f"Guestbook file not found at {guestbook_path}")