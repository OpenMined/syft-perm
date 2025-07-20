#!/usr/bin/env python3
"""Test why syft_perm.files isn't cloning syft-perm."""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, 'src')

# First check if syft-perm already exists
syftbox_path = Path.home() / "SyftBox"
syft_perm_path = syftbox_path / "apps" / "syft-perm"

print(f"SyftBox path: {syftbox_path}")
print(f"syft-perm path: {syft_perm_path}")
print(f"syft-perm exists: {syft_perm_path.exists()}")

# Remove it if it exists to test cloning
if syft_perm_path.exists():
    print("\nRemoving existing syft-perm to test cloning...")
    import shutil
    shutil.rmtree(syft_perm_path)
    print("Removed!")

# Now import and use syft_perm.files
print("\nImporting syft_perm...")
import syft_perm

print("\nAccessing syft_perm.files (this should trigger cloning)...")
files = syft_perm.files

# The cloning happens in a background thread, so wait a bit
print("Waiting 5 seconds for background cloning...")
time.sleep(5)

# Check if it was cloned
if syft_perm_path.exists():
    print(f"✓ syft-perm was cloned to {syft_perm_path}")
else:
    print(f"✗ syft-perm was NOT cloned to {syft_perm_path}")
    
    # Check if apps directory exists
    apps_dir = syftbox_path / "apps"
    if not apps_dir.exists():
        print(f"  - Apps directory doesn't exist: {apps_dir}")
    else:
        print(f"  - Apps directory exists: {apps_dir}")
        print(f"  - Contents: {list(apps_dir.iterdir())}")