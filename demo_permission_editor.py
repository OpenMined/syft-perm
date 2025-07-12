#!/usr/bin/env python3
"""Demo script showing the Google Drive-style permission editor."""

import tempfile
import shutil
from pathlib import Path
import yaml

def main():
    """Demo the permission editor functionality."""
    
    print("🚀 SyftPerm Permission Editor Demo")
    print("=" * 50)
    
    # Create a demo directory and file
    demo_dir = Path("./demo_permissions")
    demo_dir.mkdir(exist_ok=True)
    
    # Create a demo file
    demo_file = demo_dir / "important_document.txt"
    demo_file.write_text("""
# Important Document

This is a demo document for testing the SyftPerm permission editor.
You can use the web interface to manage who can read, create, write, or admin this file.
""")
    
    # Create initial permissions
    yaml_file = demo_dir / "syft.pub.yaml"
    initial_permissions = {
        "rules": [{
            "pattern": "*.txt",
            "access": {
                "read": ["alice@example.com"],
                "write": ["bob@example.com"]
            },
            "limits": {
                "max_file_size": 10000,  # 10KB
                "allow_dirs": True,
                "allow_symlinks": False
            }
        }]
    }
    
    with open(yaml_file, 'w') as f:
        yaml.dump(initial_permissions, f, default_flow_style=False)
    
    print(f"📁 Demo files created in: {demo_dir.absolute()}")
    print(f"📄 Demo file: {demo_file.absolute()}")
    
    # Import syft_perm (this auto-starts the server)
    print("\n🔧 Starting permission editor server...")
    import syft_perm
    
    # Get editor URLs
    file_editor = syft_perm.get_editor_url(demo_file)
    folder_editor = syft_perm.get_editor_url(demo_dir)
    
    print(f"\n🌐 Permission Editor URLs:")
    print(f"   📄 File Editor:   {file_editor}")
    print(f"   📂 Folder Editor: {folder_editor}")
    
    print(f"\n🎯 What you can do:")
    print(f"   • Add/remove users (try any email address)")
    print(f"   • Toggle permissions (read/create/write/admin)")
    print(f"   • View compliance status vs file limits")
    print(f"   • See real-time permission changes")
    
    print(f"\n💡 Try these test users:")
    print(f"   • alice@example.com (currently has read)")
    print(f"   • bob@example.com (currently has write)")
    print(f"   • charlie@example.com (no permissions)")
    print(f"   • public@example.com")
    print(f"   • * (for public access)")
    
    print(f"\n🔍 Current permissions:")
    demo_syft_file = syft_perm.open(demo_file)
    perms = demo_syft_file._get_all_permissions()
    for perm_type, users in perms.items():
        if users:
            print(f"   {perm_type.capitalize()}: {', '.join(users)}")
    
    print(f"\n" + "=" * 50)
    print(f"🎉 Demo ready! Open the URLs above in your browser.")
    print(f"📝 Edit the permissions and refresh to see changes.")
    print(f"🧹 Clean up: Remove the '{demo_dir}' folder when done.")
    print(f"=" * 50)

if __name__ == "__main__":
    main()