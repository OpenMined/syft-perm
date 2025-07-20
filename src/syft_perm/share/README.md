# Share Widget

The share widget provides interfaces for managing file permissions, including both a share modal and a Google Drive-style permission editor.

## Components

- `modal.py` - Share modal for quick permission management
- `permission_editor.py` - Google Drive-style permission editor interface
- `routes.py` - FastAPI endpoints for both interfaces
- `__init__.py` - Module exports

## Endpoints

- `GET /share-modal` - Share modal interface
- `GET /editor/{path}` - Google Drive-style permission editor

## Features

- Quick permission sharing via modal
- Comprehensive permission management interface
- User search and permission level selection
- Real-time permission updates
- Integration with SyftBox permission system