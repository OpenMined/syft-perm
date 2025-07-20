# File Editor

The file editor provides a web-based code editor interface with permission-aware file operations.

## Components

- `editor.py` - Main HTML generation for the file editor interface
- `routes.py` - FastAPI endpoints for serving the editor
- `__init__.py` - Module exports

## Endpoints

- `GET /file-editor` - Editor interface without initial file
- `GET /file-editor/{path}` - Editor interface with specific file loaded

## Features

- Syntax highlighting for multiple languages
- Permission-aware file operations
- Create/edit/save files with permission checks
- Dark/light theme support
- Integration with SyftBox permission system