# SyftPerm

**File permission management for SyftBox made simple.**

SyftPerm provides intuitive Python APIs for managing SyftBox file permissions with powerful pattern matching, inheritance, and debugging capabilities.

## 📚 **[Complete Documentation](https://openmined.github.io/syft-perm/)**

**👆 Visit our comprehensive documentation website for tutorials, API reference, and examples.**

## Quick Links

- 🚀 **[5-Minute Quick Start](https://openmined.github.io/syft-perm/quickstart.html)** - Get productive immediately
- 📖 **[Comprehensive Tutorials](https://openmined.github.io/syft-perm/tutorials/)** - Master advanced features
- 🔧 **[API Reference](https://openmined.github.io/syft-perm/api/)** - Complete Python API docs
- ⚙️ **[Installation Guide](https://openmined.github.io/syft-perm/installation.html)** - Setup instructions

## Overview

SyftPerm transforms complex SyftBox permission management into simple, readable Python code. Set permissions on individual files or entire folder hierarchies with powerful glob patterns, debug permission issues with built-in tools, and manage permissions through a beautiful web interface.

### Key Features

- **🎯 Intuitive Permission Hierarchy** - Read → Create → Write → Admin levels that build naturally
- **🌟 Powerful Pattern Matching** - Use `*.py`, `docs/**/*.md` to control hundreds of files with one rule
- **🔍 Nearest-Node Algorithm** - Predictable inheritance that finds the "closest" permission rules
- **🐛 Built-in Debugging** - Trace exactly why permissions work or don't work
- **📁 Folder-Level Efficiency** - Set permissions once on directories, files inherit automatically
- **🎮 Interactive Web Editor** - Google Drive-style permission management interface

## Installation

```bash
# Basic installation
pip install syft-perm

# Full installation with web editor and rich display
pip install "syft-perm[server,display]"
```

## Quick Example

```python
import syft_perm

# Open a file or folder
file = syft_perm.open("my_data.txt")
project = syft_perm.open("my_project/")

# Grant permissions with the hierarchy (higher includes lower)
file.grant_read_access("reviewer@external.org")
file.grant_write_access("colleague@company.com")  # Gets read + write
file.grant_admin_access("boss@company.com")       # Gets everything

# Use powerful patterns for multiple files
project.grant_write_access("*.py", "dev@company.com")
project.grant_read_access("docs/**/*.md", "*")  # Public docs

# Debug permissions easily
print(file.explain_permissions("colleague@company.com"))
# Output: "colleague@company.com has WRITE access: Explicitly granted write in ."

# Check access programmatically  
if file.has_write_access("colleague@company.com"):
    print("Colleague can modify this file")

# Use the web editor for non-technical users
editor_url = syft_perm.get_editor_url("my_project/")
print(f"Manage permissions at: {editor_url}")
```

## Permission Hierarchy

SyftPerm uses a 4-level hierarchy where higher permissions include all lower ones:

- **Read** - View file contents
- **Create** - Read + create new files  
- **Write** - Read + Create + modify existing files
- **Admin** - Read + Create + Write + manage permissions

```python
# Grant write access - user automatically gets read and create too
file.grant_write_access("alice@example.com")

print(file.has_read_access("alice@example.com"))    # True
print(file.has_create_access("alice@example.com"))  # True  
print(file.has_write_access("alice@example.com"))   # True
print(file.has_admin_access("alice@example.com"))   # False
```

## Pattern Matching

Control multiple files with glob patterns:

```python
project = syft_perm.open("research_project/")

# File extensions
project.grant_write_access("*.py", "developers@team.com")
project.grant_read_access("*.md", "*")  # Public documentation

# Recursive patterns with **
project.grant_read_access("data/**/*.csv", "analysts@team.com")
project.grant_admin_access("src/**", "leads@team.com")

# Specific patterns
project.grant_write_access("tests/test_*.py", "qa@team.com")
```

## Folder Inheritance

Set permissions on folders and files automatically inherit:

```python
# Set permissions once on the folder
project = syft_perm.open("climate_research/")
project.grant_read_access("external_reviewers@university.edu")
project.grant_write_access("research_team@university.edu")

# ALL files in the project now have these permissions
# Even files created later will inherit them automatically
```

## Debugging

Never guess why permissions work or don't work:

```python
file = syft_perm.open("project/src/analysis.py")

# Get human-readable explanation
explanation = file.explain_permissions("alice@example.com")
print(explanation)

# Get detailed reasoning for debugging
has_access, reasons = file._check_permission_with_reasons("alice@example.com", "write")
print(f"Has write access: {has_access}")
for reason in reasons:
    print(f"  - {reason}")
```

## Web-Based Permission Editor

For non-technical team members, SyftPerm includes a beautiful web interface:

```python
# Get editor URL for any file or folder
url = syft_perm.get_editor_url("my_project/")
print(f"Edit permissions at: {url}")

# Server starts automatically when needed
# Or start manually: syft_perm.start_permission_server()
```

## Learn More

### 🚀 New to SyftPerm?
Start with our **[5-Minute Quick Start](https://openmined.github.io/syft-perm/quickstart.html)** to learn the essentials.

### 📚 Want to Master It?
Work through our **[Comprehensive Tutorial Series](https://openmined.github.io/syft-perm/tutorials/)**:
1. **Fundamentals** - Core concepts and hierarchy
2. **Patterns & Matching** - Glob patterns and specificity  
3. **Inheritance & Hierarchy** - Multi-level permission flow
4. **Terminal Nodes & Limits** - Advanced control features
5. **Mastery & Complex Scenarios** - Expert techniques

### 🔧 Need API Details?
Browse our **[Complete API Reference](https://openmined.github.io/syft-perm/api/)** with examples and parameters.

## Real-World Use Cases

- **🔬 Research Collaboration** - External reviewers, junior researchers, senior staff, PIs
- **💼 Enterprise Data Science** - Different teams accessing different file types  
- **📊 Data Publishing** - Public datasets with controlled modification rights
- **🏗️ Software Projects** - Developers, QA, documentation writers, managers

## Requirements

- Python 3.9+
- Works on Windows, macOS, and Linux
- Optional: FastAPI for web editor (`pip install "syft-perm[server]"`)
- Optional: Rich display formatting (`pip install "syft-perm[display]"`)

## Contributing

1. Check out our [GitHub Issues](https://github.com/OpenMined/syft-perm/issues)
2. Read the [Contributing Guide](CONTRIBUTING.md)
3. Join the [OpenMined Community](https://openmined.org/)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Related Projects

- **[SyftBox](https://syftbox.net/)** - The privacy-first data science platform
- **[OpenMined](https://openmined.org/)** - Privacy-preserving AI community
- **[PySyft](https://github.com/OpenMined/PySyft)** - Federated learning framework