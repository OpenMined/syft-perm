[![CI](https://github.com/OpenMined/syft-perm/actions/workflows/test.yml/badge.svg)](https://github.com/OpenMined/syft-perm/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/syft-perm.svg)](https://pypi.org/project/syft-perm/)
[![PyPI downloads](https://img.shields.io/pypi/dm/syft-perm.svg)](https://pypi.org/project/syft-perm/)
[![Python versions](https://img.shields.io/pypi/pyversions/syft-perm.svg)](https://pypi.org/project/syft-perm/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License](https://img.shields.io/github/license/OpenMined/syft-perm.svg)](https://github.com/OpenMined/syft-perm/blob/main/LICENSE)

# SyftPerm

**File permission management for SyftBox made simple.**

SyftPerm provides intuitive Python APIs for managing SyftBox file permissions with powerful pattern matching, inheritance, and debugging capabilities.

## 📚 **[Complete Documentation](https://openmined.github.io/syft-perm/)**

## Installation

```bash
pip install syft-perm
```

## Quick Start - Learn the Entire API in 2 Minutes

```python
import syft_perm as sp

# 1. Opening files and folders
file = sp.open("data.csv")                    # Open a file
folder = sp.open("my_project/")                # Open a folder
remote = sp.open("syft://alice@datasite.org/data.csv")  # Remote files

# 2. Granting permissions (each level includes all lower permissions)
file.grant_read_access("bob@company.com")      # Can view
file.grant_create_access("alice@company.com")  # Can view + create new files
file.grant_write_access("team@company.com")    # Can view + create + modify
file.grant_admin_access("admin@company.com")   # Full control

# 3. Revoking permissions
file.revoke_write_access("team@company.com")   # Remove write (keeps read/create)
file.revoke_admin_access("admin@company.com")  # Remove admin privileges

# 4. Checking permissions
if file.has_read_access("bob@company.com"):
    print("Bob can read this file")
    
if file.has_admin_access("admin@company.com"):
    print("Admin has full control")

# 5. Understanding permissions with explain
explanation = file.explain_permissions("bob@company.com")
print(explanation)  # Shows why bob has/doesn't have access

# 6. Working with the Files API
all_files = sp.files.all()                     # Get all permissioned files
paginated = sp.files.get(limit=10, offset=0)   # Get first 10 files
filtered = sp.files.search(admin="me@datasite.org")  # My admin files
sliced = sp.files[0:5]                          # First 5 files using slice

# 7. Moving files while preserving permissions
new_file = file.move_file_and_its_permissions("archive/data.csv")
new_folder = folder.move_folder_and_permissions("projects/archived/")

# 8. Interactive features (Jupyter/web)
file.share()                                    # Show sharing widget
```

### Permission Hierarchy Explained
- **Read**: View file contents
- **Create**: Read + create new files in folders
- **Write**: Read + Create + modify existing files  
- **Admin**: Read + Create + Write + manage permissions

### Pro Tips
```python
# Force permission changes (bypass safety checks)
file.grant_admin_access("user@example.com", force=True)

# Check terminal flag for advanced file handling
if file.get_terminal():
    print("This file has terminal flag set")
```

## Permission Hierarchy

- **Read** - View file contents
- **Create** - Read + create new files  
- **Write** - Read + Create + modify existing files
- **Admin** - Read + Create + Write + manage permissions

## Learn More

- **[5-Minute Quick Start](https://openmined.github.io/syft-perm/quickstart.html)** - Get productive immediately
- **[Comprehensive Tutorials](https://openmined.github.io/syft-perm/tutorials/)** - Master advanced features
- **[API Reference](https://openmined.github.io/syft-perm/api/)** - Complete Python API docs

## Requirements

- Python 3.9+
- Works on Windows, macOS, and Linux

## Contributing

1. Check out our [GitHub Issues](https://github.com/OpenMined/syft-perm/issues)
2. Read the [Contributing Guide](CONTRIBUTING.md)
3. Join the [OpenMined Community](https://openmined.org/)

## License

Apache 2.0 License - see [LICENSE](LICENSE) file for details.
