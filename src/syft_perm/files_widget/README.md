# Files Widget

The files widget provides an interactive file browser interface for SyftBox with permission management capabilities.

## Components

- `widget.py` - Main HTML generation for the files widget interface
- `routes.py` - FastAPI endpoints for serving the widget
- `__init__.py` - Module exports

## Endpoints

- `GET /files-widget` - Main widget interface with filtering options

## Features

- File/folder browsing with permission visibility
- Search and filtering capabilities
- Pagination support
- Integration with SyftBox permission system