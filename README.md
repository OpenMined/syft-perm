# syft-perm

Minimal utilities for managing SyftBox file permissions.

## Overview

`syft-perm` provides simple, focused utilities for reading, setting, and removing file permissions in SyftBox environments. It handles the creation and management of `syft.pub.yaml` permission files.

## Installation

```bash
pip install syft-perm
```

For SyftBox integration:
```bash
pip install syft-perm[syftbox]
```

## Usage

### Basic Permission Management

```python
from syft_perm import set_file_permissions, get_file_permissions, remove_file_permissions

# Set permissions for a file
set_file_permissions(
    "path/to/file.txt",
    read_users=["alice@example.com", "bob@example.com"],
    write_users=["alice@example.com"]
)

# Get current permissions
permissions = get_file_permissions("path/to/file.txt")
print(permissions)  # {'read': ['alice@example.com', 'bob@example.com'], 'write': ['alice@example.com']}

# Remove permissions
remove_file_permissions("path/to/file.txt")
```

### SyftBox URL Support

Works with both local paths and `syft://` URLs:

```python
# Local path
set_file_permissions("/local/path/file.txt", read_users=["public"])

# SyftBox URL (requires syft-core)
set_file_permissions("syft://alice@example.com/public/data.csv", read_users=["bob@example.com"])
```

### Public Access

Use `"public"` or `"*"` for public access:

```python
set_file_permissions(
    "public_file.txt",
    read_users=["public"],  # Anyone can read
    write_users=["alice@example.com"]  # Only alice can write
)
```

## API Reference

### `set_file_permissions(file_path_or_syfturl, read_users, write_users=None, admin_users=None)`

Set permissions for a file by updating the corresponding `syft.pub.yaml` file.

**Parameters:**
- `file_path_or_syfturl`: Local file path or `syft://` URL
- `read_users`: List of users who can read the file
- `write_users`: List of users who can write the file (optional)
- `admin_users`: List of users who have admin access (optional, defaults to write_users)

### `get_file_permissions(file_path_or_syfturl)`

Read current permissions for a file from `syft.pub.yaml`.

**Returns:** Dictionary with access permissions, or `None` if not found.

### `remove_file_permissions(file_path_or_syfturl)`

Remove permissions for a file from `syft.pub.yaml`.

## Requirements

- Python 3.8+
- PyYAML 6.0+
- syft-core (optional, for `syft://` URL support)

## License

MIT License - see LICENSE file for details. 