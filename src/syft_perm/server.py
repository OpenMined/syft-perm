"""FastAPI server for syft-perm permission editor."""

import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import open as syft_open
from ._syftbox import client as syftbox_client
from ._utils import get_syftbox_datasites

_SERVER_AVAILABLE = False
try:
    import uvicorn  # type: ignore[import-untyped]
    from fastapi import FastAPI as _FastAPI  # type: ignore[import-untyped]
    from fastapi import HTTPException as _HTTPException  # type: ignore[import-untyped]
    from fastapi import Query as _Query  # type: ignore[import-untyped]
    from fastapi.middleware.cors import CORSMiddleware  # type: ignore[import-untyped]
    from fastapi.responses import HTMLResponse as _HTMLResponse  # type: ignore[import-untyped]
    from pydantic import BaseModel as _BaseModel  # type: ignore[import-untyped]

    _SERVER_AVAILABLE = True
except ImportError:
    _SERVER_AVAILABLE = False


# Type aliases for convenience
FastAPI = _FastAPI
HTTPException = _HTTPException
HTMLResponse = _HTMLResponse
Query = _Query


# Only create the FastAPI app if server dependencies are available
if _SERVER_AVAILABLE:

    class PermissionUpdate(_BaseModel):
        """Model for permission update requests."""

        path: str
        user: str
        permission: str  # read, create, write, admin
        action: str  # grant, revoke

    class PermissionResponse(_BaseModel):
        """Model for permission response."""

        path: str
        permissions: Dict[str, List[str]]
        compliance: Dict[str, Any]
        datasites: List[str]

    class FileInfo(_BaseModel):
        """Model for file information in the files list."""

        path: str
        name: str
        is_dir: bool
        size: Optional[int]
        modified: Optional[float]
        permissions: Dict[str, List[str]]
        has_yaml: bool

    class FilesResponse(_BaseModel):
        """Model for paginated files response."""

        files: List[FileInfo]
        total_count: int
        offset: int
        limit: int
        has_more: bool
        syftbox_path: Optional[str]

    app = FastAPI(
        title="SyftPerm Permission Editor",
        description="Google Drive-style permission editor for SyftBox",
        version="1.0.0",
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/")  # type: ignore[misc]
    async def root() -> Dict[str, str]:
        """Root endpoint with basic info."""
        return {"message": "SyftPerm Permission Editor", "docs": "/docs"}

    @app.get("/permissions/{path:path}", response_model=PermissionResponse)  # type: ignore[misc]
    async def get_permissions(path: str) -> PermissionResponse:
        """Get permissions for a file or folder."""
        try:
            # Resolve the path
            file_path = Path(path)
            if not file_path.exists():
                raise HTTPException(status_code=404, detail=f"Path not found: {path}")

            # Open with syft-perm
            syft_obj = syft_open(file_path)

            # Get current permissions
            permissions = syft_obj._get_all_permissions()

            # Get compliance information
            if hasattr(syft_obj, "get_file_limits"):
                limits = syft_obj.get_file_limits()
                compliance = {
                    "has_limits": limits["has_limits"],
                    "max_file_size": limits["max_file_size"],
                    "allow_dirs": limits["allow_dirs"],
                    "allow_symlinks": limits["allow_symlinks"],
                }

                # Add compliance status for files
                if hasattr(syft_obj, "_size"):
                    file_size = syft_obj._size
                    compliance["current_size"] = file_size
                    compliance["size_compliant"] = (
                        limits["max_file_size"] is None or file_size <= limits["max_file_size"]
                    )
            else:
                compliance = {"has_limits": False}

            # Get available datasites
            datasites = get_syftbox_datasites()

            return PermissionResponse(
                path=str(file_path),
                permissions=permissions,
                compliance=compliance,
                datasites=datasites,
            )

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/permissions/update")  # type: ignore[misc]
    async def update_permission(update: PermissionUpdate) -> Dict[str, Any]:
        """Update permissions for a file or folder."""
        try:
            # Resolve the path
            file_path = Path(update.path)
            if not file_path.exists():
                raise HTTPException(status_code=404, detail=f"Path not found: {update.path}")

            # Open with syft-perm
            syft_obj = syft_open(file_path)

            # Apply the permission change
            if update.action == "grant":
                if update.permission == "read":
                    syft_obj.grant_read_access(update.user)
                elif update.permission == "create":
                    syft_obj.grant_create_access(update.user)
                elif update.permission == "write":
                    syft_obj.grant_write_access(update.user)
                elif update.permission == "admin":
                    syft_obj.grant_admin_access(update.user)
                else:
                    raise HTTPException(
                        status_code=400, detail=f"Invalid permission: {update.permission}"
                    )

            elif update.action == "revoke":
                if update.permission == "read":
                    syft_obj.revoke_read_access(update.user)
                elif update.permission == "create":
                    syft_obj.revoke_create_access(update.user)
                elif update.permission == "write":
                    syft_obj.revoke_write_access(update.user)
                elif update.permission == "admin":
                    syft_obj.revoke_admin_access(update.user)
                else:
                    raise HTTPException(
                        status_code=400, detail=f"Invalid permission: {update.permission}"
                    )

            else:
                raise HTTPException(status_code=400, detail=f"Invalid action: {update.action}")

            # Return updated permissions
            updated_permissions = syft_obj._get_all_permissions()
            return {"success": True, "permissions": updated_permissions}

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/datasites")  # type: ignore[misc]
    async def get_datasites() -> Dict[str, Any]:
        """Get list of available datasites for autocompletion."""
        try:
            datasites = get_syftbox_datasites()
            return {"datasites": datasites}
        except Exception as e:
            return {"datasites": [], "error": str(e)}

    @app.get("/files", response_model=FilesResponse)  # type: ignore[misc]
    async def get_files(
        limit: int = Query(50, ge=1, le=1000, description="Number of items per page"),
        offset: int = Query(0, ge=0, description="Starting index"),
        search: Optional[str] = Query(None, description="Search term for file names"),
    ) -> FilesResponse:
        """Get paginated list of files with permissions from SyftBox directory."""
        try:
            # Get SyftBox directory path
            syftbox_path = None
            if syftbox_client:
                syftbox_path = str(syftbox_client.datadir)
            else:
                # Fallback to environment variable or home directory
                syftbox_path = os.environ.get("SYFTBOX_PATH", str(Path.home() / "SyftBox"))

            syftbox_dir = Path(syftbox_path)
            if not syftbox_dir.exists():
                raise HTTPException(
                    status_code=404, detail=f"SyftBox directory not found: {syftbox_path}"
                )

            # Collect all files with permissions
            all_files = []

            def scan_directory(dir_path: Path, base_path: Path) -> None:
                """Recursively scan directory for files with permissions."""
                try:
                    for item in dir_path.iterdir():
                        # Skip hidden files and system directories
                        if item.name.startswith("."):
                            continue

                        # Skip syft.pub.yaml files themselves
                        if item.name == "syft.pub.yaml":
                            continue

                        # Apply search filter if provided
                        if search and search.lower() not in item.name.lower():
                            if item.is_dir():
                                # Still scan subdirectories even if parent doesn't match
                                scan_directory(item, base_path)
                            continue

                        try:
                            # Get permissions for this file/folder
                            syft_obj = syft_open(item)
                            permissions = syft_obj._get_all_permissions()

                            # Check if this item has any permissions defined
                            has_any_permissions = any(
                                users for users in permissions.values() if users
                            )

                            # Check if there's a syft.pub.yaml in this directory
                            has_yaml = (item / "syft.pub.yaml").exists() if item.is_dir() else False

                            # Only include items with permissions or yaml config
                            if has_any_permissions or has_yaml:
                                file_info = {
                                    "path": str(item),
                                    "name": item.name,
                                    "is_dir": item.is_dir(),
                                    "size": item.stat().st_size if item.is_file() else None,
                                    "modified": item.stat().st_mtime,
                                    "permissions": permissions,
                                    "has_yaml": has_yaml,
                                }
                                all_files.append(file_info)

                        except Exception:
                            # Skip files we can't access
                            pass

                        # Recursively scan subdirectories
                        if item.is_dir():
                            scan_directory(item, base_path)

                except PermissionError:
                    # Skip directories we can't access
                    pass

            # Start scanning from SyftBox directory
            scan_directory(syftbox_dir, syftbox_dir)

            # Sort by modified time (newest first) like the syft-objects widget
            all_files.sort(key=lambda x: x["modified"] or 0, reverse=True)

            # Apply pagination
            total_count = len(all_files)
            start_idx = offset
            end_idx = offset + limit
            paginated_files = all_files[start_idx:end_idx]

            # Convert to FileInfo objects
            files = [FileInfo(**file_data) for file_data in paginated_files]

            return FilesResponse(
                files=files,
                total_count=total_count,
                offset=offset,
                limit=limit,
                has_more=end_idx < total_count,
                syftbox_path=syftbox_path,
            )

        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/editor/{path:path}", response_class=HTMLResponse)  # type: ignore[misc]
    async def permission_editor(path: str) -> str:
        """Serve the Google Drive-style permission editor."""
        return get_editor_html(path)


def get_editor_html(path: str) -> str:
    """Generate the Google Drive-style permission editor HTML."""
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Permission Editor - {path}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }}

        .container {{
            max-width: 800px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}

        .header {{
            background: #1976d2;
            color: white;
            padding: 20px;
        }}

        .header h1 {{
            font-size: 24px;
            margin-bottom: 5px;
        }}

        .header .path {{
            opacity: 0.9;
            font-size: 14px;
        }}

        .content {{
            padding: 20px;
        }}

        .section {{
            margin-bottom: 30px;
        }}

        .section h2 {{
            font-size: 18px;
            margin-bottom: 15px;
            color: #333;
        }}

        .add-user {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            align-items: center;
        }}

        .add-user input {{
            flex: 1;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
        }}

        .add-user select {{
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 14px;
            min-width: 120px;
        }}

        .add-user button {{
            padding: 12px 20px;
            background: #1976d2;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }}

        .add-user button:hover {{
            background: #1565c0;
        }}

        .permissions-list {{
            border: 1px solid #ddd;
            border-radius: 4px;
            overflow: hidden;
        }}

        .permission-item {{
            display: flex;
            align-items: center;
            padding: 15px;
            border-bottom: 1px solid #eee;
        }}

        .permission-item:last-child {{
            border-bottom: none;
        }}

        .user-info {{
            flex: 1;
        }}

        .user-name {{
            font-weight: 500;
            font-size: 14px;
            color: #333;
        }}

        .user-permissions {{
            font-size: 12px;
            color: #666;
            margin-top: 2px;
        }}

        .permission-controls {{
            display: flex;
            gap: 5px;
        }}

        .permission-badge {{
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .permission-badge.active {{
            background: #1976d2;
            color: white;
        }}

        .permission-badge.inactive {{
            background: #f0f0f0;
            color: #666;
            border: 1px solid #ddd;
        }}

        .permission-badge:hover {{
            opacity: 0.8;
        }}

        .compliance-section {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            border-left: 4px solid #1976d2;
        }}

        .compliance-item {{
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
        }}

        .compliance-item:last-child {{
            margin-bottom: 0;
        }}

        .status-ok {{
            color: #2e7d32;
            font-weight: 500;
        }}

        .status-error {{
            color: #d32f2f;
            font-weight: 500;
        }}

        .autocomplete {{
            position: relative;
        }}

        .autocomplete-suggestions {{
            position: absolute;
            top: 100%;
            left: 0;
            right: 0;
            background: white;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 4px 4px;
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            display: none;
        }}

        .autocomplete-suggestion {{
            padding: 10px;
            cursor: pointer;
            border-bottom: 1px solid #eee;
        }}

        .autocomplete-suggestion:hover {{
            background: #f5f5f5;
        }}

        .autocomplete-suggestion:last-child {{
            border-bottom: none;
        }}

        .loading {{
            text-align: center;
            padding: 20px;
            color: #666;
        }}

        .error {{
            background: #ffebee;
            color: #c62828;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Permission Editor</h1>
            <div class="path">{path}</div>
        </div>

        <div class="content">
            <div id="error-message" class="error" style="display: none;"></div>

            <div class="section">
                <h2>Add User</h2>
                <div class="add-user">
                    <div class="autocomplete">
                        <input type="text" id="user-input"
                               placeholder="Enter email or datasite..." autocomplete="off">
                        <div id="autocomplete-suggestions" class="autocomplete-suggestions"></div>
                    </div>
                    <select id="permission-select">
                        <option value="read">Read</option>
                        <option value="create">Create</option>
                        <option value="write">Write</option>
                        <option value="admin">Admin</option>
                    </select>
                    <button onclick="addPermission()">Add</button>
                </div>
            </div>

            <div class="section">
                <h2>Current Permissions</h2>
                <div id="permissions-list" class="loading">Loading permissions...</div>
            </div>

            <div class="section">
                <h2>Compliance Status</h2>
                <div id="compliance-info" class="compliance-section">
                    <div class="loading">Loading compliance info...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentData = null;
        let datasites = [];

        // Load initial data
        async function loadData() {{
            try {{
                const response = await fetch(`/permissions/{path}`);
                if (!response.ok) {{
                    throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                }}
                currentData = await response.json();
                updateUI();
                loadDatasites();
            }} catch (error) {{
                showError(`Failed to load permissions: ${{error.message}}`);
            }}
        }}

        async function loadDatasites() {{
            try {{
                const response = await fetch('/datasites');
                const data = await response.json();
                datasites = data.datasites || [];
            }} catch (error) {{
                console.warn('Failed to load datasites:', error);
            }}
        }}

        function showError(message) {{
            const errorDiv = document.getElementById('error-message');
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }}

        function hideError() {{
            document.getElementById('error-message').style.display = 'none';
        }}

        function updateUI() {{
            hideError();
            updatePermissionsList();
            updateComplianceInfo();
        }}

        function updatePermissionsList() {{
            const container = document.getElementById('permissions-list');
            if (!currentData || !currentData.permissions) {{
                container.innerHTML = '<div class="loading">No permissions data</div>';
                return;
            }}

            const permissions = currentData.permissions;
            const allUsers = new Set();

            // Collect all users
            Object.values(permissions).forEach(users => {{
                users.forEach(user => allUsers.add(user));
            }});

            if (allUsers.size === 0) {{
                container.innerHTML = '<div style="padding: 20px; text-align: center; ' +
                    'color: #666;">No permissions set</div>';
                return;
            }}

            container.innerHTML = '';
            container.className = 'permissions-list';

            allUsers.forEach(user => {{
                const item = document.createElement('div');
                item.className = 'permission-item';

                const userPerms = [];
                const p = permissions;  // Shorter alias
                if (p.read && p.read.includes(user)) userPerms.push('Read');
                if (p.create && p.create.includes(user)) {{
                    userPerms.push('Create');
                }}
                if (p.write && p.write.includes(user)) userPerms.push('Write');
                if (p.admin && p.admin.includes(user)) userPerms.push('Admin');

                const readActive = p.read && p.read.includes(user) ? 'active' : 'inactive';
                const createActive = p.create && p.create.includes(user) ? 'active' : 'inactive';
                const writeActive = p.write && p.write.includes(user) ? 'active' : 'inactive';
                const adminActive = p.admin && p.admin.includes(user) ? 'active' : 'inactive';

                item.innerHTML = `
                    <div class="user-info">
                        <div class="user-name">${{user}}</div>
                        <div class="user-permissions">${{userPerms.join(', ')}}</div>
                    </div>
                    <div class="permission-controls">
                        <span class="permission-badge ${{readActive}}"
                              onclick="togglePermission('${{user}}', 'read')">Read</span>
                        <span class="permission-badge ${{createActive}}"
                              onclick="togglePermission('${{user}}', 'create')">Create</span>
                        <span class="permission-badge ${{writeActive}}"
                              onclick="togglePermission('${{user}}', 'write')">Write</span>
                        <span class="permission-badge ${{adminActive}}"
                              onclick="togglePermission('${{user}}', 'admin')">Admin</span>
                    </div>
                `;

                container.appendChild(item);
            }});
        }}

        function updateComplianceInfo() {{
            const container = document.getElementById('compliance-info');
            if (!currentData || !currentData.compliance) {{
                container.innerHTML = '<div>No compliance data available</div>';
                return;
            }}

            const compliance = currentData.compliance;
            let html = '';

            if (compliance.has_limits) {{
                if (compliance.max_file_size !== null) {{
                    const sizeStatus = compliance.size_compliant ? 'status-ok' : 'status-error';
                    const sizeText = compliance.size_compliant ?
                        '✓ Within limit' : '✗ Exceeds limit';
                    html += `
                        <div class="compliance-item">
                            <span>File Size: ${{formatFileSize(compliance.current_size)}} /
                                  ${{formatFileSize(compliance.max_file_size)}}</span>
                            <span class="${{sizeStatus}}">${{sizeText}}</span>
                        </div>
                    `;
                }}

                html += `
                    <div class="compliance-item">
                        <span>Directories Allowed</span>
                        <span class="${{compliance.allow_dirs ? 'status-ok' : 'status-error'}}">
                            ${{compliance.allow_dirs ? '✓ Yes' : '✗ No'}}
                        </span>
                    </div>
                    <div class="compliance-item">
                        <span>Symlinks Allowed</span>
                        <span class="${{compliance.allow_symlinks ? 'status-ok' : 'status-error'}}">
                            ${{compliance.allow_symlinks ? '✓ Yes' : '✗ No'}}
                        </span>
                    </div>
                `;
            }} else {{
                html = '<div>No file limits configured</div>';
            }}

            container.innerHTML = html;
        }}

        function formatFileSize(bytes) {{
            if (bytes === null || bytes === undefined) return 'Unknown';
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }}

        async function togglePermission(user, permission) {{
            const currentPermissions = currentData.permissions[permission] || [];
            const hasPermission = currentPermissions.includes(user);
            const action = hasPermission ? 'revoke' : 'grant';

            try {{
                const response = await fetch('/permissions/update', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        path: '{path}',
                        user: user,
                        permission: permission,
                        action: action
                    }})
                }});

                if (!response.ok) {{
                    throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                }}

                const result = await response.json();
                currentData.permissions = result.permissions;
                updatePermissionsList();
            }} catch (error) {{
                showError(`Failed to update permission: ${{error.message}}`);
            }}
        }}

        async function addPermission() {{
            const userInput = document.getElementById('user-input');
            const permissionSelect = document.getElementById('permission-select');

            const user = userInput.value.trim();
            const permission = permissionSelect.value;

            if (!user) {{
                showError('Please enter a user email or datasite');
                return;
            }}

            try {{
                const response = await fetch('/permissions/update', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        path: '{path}',
                        user: user,
                        permission: permission,
                        action: 'grant'
                    }})
                }});

                if (!response.ok) {{
                    throw new Error(`HTTP ${{response.status}}: ${{response.statusText}}`);
                }}

                const result = await response.json();
                currentData.permissions = result.permissions;
                updatePermissionsList();
                userInput.value = '';
            }} catch (error) {{
                showError(`Failed to add permission: ${{error.message}}`);
            }}
        }}

        // Autocomplete functionality
        function setupAutocomplete() {{
            const input = document.getElementById('user-input');
            const suggestions = document.getElementById('autocomplete-suggestions');

            input.addEventListener('input', function() {{
                const value = this.value.toLowerCase();
                if (value.length < 1) {{
                    suggestions.style.display = 'none';
                    return;
                }}

                const filtered = datasites.filter(site =>
                    site.toLowerCase().includes(value)
                );

                if (filtered.length > 0) {{
                    suggestions.innerHTML = filtered.map(site =>
                        `<div class="autocomplete-suggestion" ` +
                        `onclick="selectSuggestion('${{site}}')">${{site}}</div>`
                    ).join('');
                    suggestions.style.display = 'block';
                }} else {{
                    suggestions.style.display = 'none';
                }}
            }});

            // Hide suggestions when clicking outside
            document.addEventListener('click', function(e) {{
                if (!input.contains(e.target) && !suggestions.contains(e.target)) {{
                    suggestions.style.display = 'none';
                }}
            }});
        }}

        function selectSuggestion(value) {{
            document.getElementById('user-input').value = value;
            document.getElementById('autocomplete-suggestions').style.display = 'none';
        }}

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {{
            loadData();
            setupAutocomplete();

            // Allow Enter key to add permission
            document.getElementById('user-input').addEventListener('keypress', function(e) {{
                if (e.key === 'Enter') {{
                    addPermission();
                }}
            }});
        }});
    </script>
</body>
</html>
    """


# Server management
_server_thread: Optional[threading.Thread] = None
_server_port = 8765


def start_server(port: int = 8765, host: str = "127.0.0.1") -> str:
    """Start the FastAPI server in a background thread."""
    if not _SERVER_AVAILABLE:
        raise ImportError(
            "Server dependencies not available. Install with: pip install 'syft-perm[server]'"
        )

    global _server_thread
    global _server_port

    if _server_thread and _server_thread.is_alive():
        server_url = f"http://{host}:{_server_port}"
        # Check if server is actually responding
        from ._auto_recovery import ensure_server_running

        success, error = ensure_server_running(server_url)
        if success:
            return server_url
        # If not successful, continue to start a new server

    _server_port = port

    def run_server() -> None:
        uvicorn.run(app, host=host, port=port, log_level="warning")

    _server_thread = threading.Thread(target=run_server, daemon=True)
    _server_thread.start()

    # Give the server a moment to start
    time.sleep(1)

    return f"http://{host}:{port}"


def get_server_url() -> Optional[str]:
    """Get the URL of the running server, if any."""
    if _server_thread and _server_thread.is_alive():
        return f"http://127.0.0.1:{_server_port}"
    return None


def get_editor_url(path: str) -> str:
    """Get the URL for the permission editor for a specific path."""
    if not _SERVER_AVAILABLE:
        return (
            f"file://{path}  # Server not available - install with: pip install 'syft-perm[server]'"
        )

    server_url = get_server_url()
    if not server_url:
        server_url = start_server()

    return f"{server_url}/editor/{path}"
