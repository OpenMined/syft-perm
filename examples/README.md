# SyftPerm Examples

This directory contains example scripts demonstrating various features of syft-perm.

## Files Endpoint Example

The `files_endpoint_example.py` script demonstrates the new `.files` endpoint that provides paginated access to files with permissions in your SyftBox directory.

### Features:
- Paginated file listing
- Search functionality
- Permission filtering
- Sorting by modification time

### Usage:
```bash
python files_endpoint_example.py
```

### API Endpoint:
```
GET /files?limit=50&offset=0&search=test
```

### Response Format:
```json
{
    "files": [
        {
            "path": "/full/path/to/file",
            "name": "filename.txt",
            "is_dir": false,
            "size": 1234,
            "modified": 1234567890.0,
            "permissions": {
                "read": ["user@example.com"],
                "write": [],
                "create": [],
                "admin": []
            },
            "has_yaml": false
        }
    ],
    "total_count": 100,
    "offset": 0,
    "limit": 50,
    "has_more": true,
    "syftbox_path": "/Users/username/SyftBox"
}
```

This endpoint is designed to work similarly to the pagination in the old syft-objects widget, making it easy to build UI components that display permissioned files.