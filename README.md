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

## Quick Start

```python
import syft_perm as sp

# Open a file or folder
file = sp.open("my_data.txt")

# Grant permissions (higher levels include lower ones)
file.grant_read_access("reviewer@external.org")
file.grant_write_access("colleague@company.com")  # Gets read + write
file.grant_admin_access("boss@company.com")       # Gets everything

# Use patterns for multiple files
project = sp.open("my_project/")
project.grant_write_access("*.py", "dev@company.com")
project.grant_read_access("docs/**/*.md", "*")  # Public docs

# Debug permissions
print(file.explain_permissions("colleague@company.com"))

# Check access
if file.has_write_access("colleague@company.com"):
    print("Colleague can modify this file")

# Display beautiful permission tables in Jupyter notebooks
file._repr_html_()  # Shows permissions table with compliance info
```

## Permission Hierarchy

- **Read** - View file contents
- **Create** - Read + create new files  
- **Write** - Read + Create + modify existing files
- **Admin** - Read + Create + Write + manage permissions

## Key Features

- **🎯 Intuitive Permission Hierarchy** - Higher permissions include all lower ones
- **🌟 Powerful Pattern Matching** - Use `*.py`, `docs/**/*.md` to control multiple files
- **🔍 Nearest-Node Algorithm** - Predictable inheritance from closest permission rules
- **🐛 Built-in Debugging** - Trace exactly why permissions work or don't work
- **📁 Folder-Level Efficiency** - Set permissions once on directories, files inherit automatically
- **🎮 Interactive Web Editor** - Google Drive-style permission management interface

## Beautiful Table Display

SyftPerm provides rich table displays for Jupyter notebooks:

```python
# Display permissions table with compliance information
file._repr_html_()  # Shows user permissions, file limits, and compliance status

# The table includes:
# • User permissions (Read/Create/Write/Admin)
# • File size vs limits
# • File type compliance (directories, symlinks)
# • Overall compliance status
# • Direct link to web editor
```

## Web Editor

For non-technical users, SyftPerm includes a web interface:

```python
# Get editor URL for any file or folder
url = sp.get_editor_url("my_project/")
print(f"Edit permissions at: {url}")
```

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

MIT License - see [LICENSE](LICENSE) file for details.
