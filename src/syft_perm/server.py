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

    # Global progress tracking
    scan_progress = {
        "current": 0,
        "total": 0,
        "status": "idle",
        "message": ""
    }
    
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
    
    @app.get("/files-widget", response_class=HTMLResponse)  # type: ignore[misc]
    async def files_widget() -> str:
        """Serve the files widget interface."""
        # Generate the widget HTML directly for web serving
        return get_files_widget_html()
    
    @app.get("/api/scan-progress")  # type: ignore[misc]
    async def get_scan_progress() -> Dict[str, Any]:
        """Get current scan progress."""
        return scan_progress.copy()
    
    @app.get("/api/files-data")  # type: ignore[misc]
    async def get_files_data() -> Dict[str, Any]:
        """Get files data for the widget."""
        import asyncio
        from . import files as sp_files
        
        # Reset progress
        scan_progress["status"] = "scanning"
        scan_progress["current"] = 0
        scan_progress["total"] = 0
        scan_progress["message"] = "Starting scan..."
        
        # Define progress callback with rate limiting
        last_update_time = time.time()
        
        def progress_callback(current: int, total: int, message: str):
            nonlocal last_update_time
            current_time = time.time()
            
            # Rate limit: ensure at least 1ms between datasites (1000 per second max)
            time_since_last = current_time - last_update_time
            if time_since_last < 0.001:  # 1ms = 0.001s
                time.sleep(0.001 - time_since_last)
            
            scan_progress["current"] = current
            scan_progress["total"] = total
            
            # Update message less frequently to avoid showing individual datasite names
            if current == 0:
                scan_progress["message"] = "Starting scan..."
            elif current == total:
                scan_progress["message"] = f"Completed scanning {total} datasites"
            elif current % 10 == 0:  # Update every 10 datasites
                scan_progress["message"] = f"Scanning datasites... ({current}/{total})"
            # Keep existing message for other updates
            
            last_update_time = time.time()
        
        # Run scan in a thread to not block async endpoint
        loop = asyncio.get_event_loop()
        all_files = await loop.run_in_executor(
            None, 
            lambda: sp_files._scan_files(progress_callback=progress_callback)
        )
        
        # Mark as complete
        scan_progress["status"] = "complete"
        scan_progress["message"] = "Scan complete"
        
        # Return the data as JSON
        return {
            "files": all_files,
            "total": len(all_files)
        }


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


def get_files_widget_html() -> str:
    """Generate the files widget HTML for web serving."""
    import html as html_module
    import json
    import random
    import uuid
    from datetime import datetime
    from pathlib import Path
    
    # Import needed functions
    from . import files as sp_files
    from . import is_dark
    
    container_id = f"syft_files_{uuid.uuid4().hex[:8]}"
    
    # Check if Jupyter is in dark mode
    is_dark_mode = is_dark()
    
    # Non-obvious tips for users
    tips = [
        'Use quotation marks to search for exact phrases like "machine learning"',
        'Multiple words without quotes searches for files containing ALL words',
        'Press Tab in search boxes for auto-completion suggestions',
        'Tab completion in Admin filter shows all available datasite emails',
        'Use sp.files.page(5) to jump directly to page 5',
        'Click any row to copy its syft:// path to clipboard',
        'Try sp.files.search("keyword") for programmatic filtering',
        'Use sp.files.filter(extension=".csv") to find specific file types',
        'Chain filters: sp.files.filter(extension=".py").search("test")',
        'Escape special characters with backslash when searching',
        'ASCII loading bar only appears with print(sp.files), not in Jupyter',
        'Loading progress: first 10% is setup, 10-100% is file scanning',
        'Press Escape to close the tab-completion dropdown',
        'Use sp.open("syft://path") to access files programmatically',
        'Search for dates in various formats: 2024-01-15, Jan-15, etc',
        'Admin filter supports partial matching - type "gmail" for all Gmail users',
        'File sizes show as B, KB, MB, or GB automatically',
        'The # column shows files in chronological order by modified date',
        'Empty search returns all files - useful for resetting filters',
        'Search works across file names, paths, and extensions at once'
    ]
    
    # Pick a random tip for footer
    footer_tip = random.choice(tips)
    show_footer_tip = random.random() < 0.5  # 50% chance
    
    # Don't scan files initially - let JavaScript handle it
    
    # Generate CSS based on theme - matching Jupyter widget exactly
    if is_dark_mode:
        # Dark mode colors from Jupyter widget
        bg_color = "#1e1e1e"
        text_color = "#d4d4d4"
        border_color = "#3e3e42"
        controls_bg = "#252526"
        input_bg = "#1e1e1e"
        input_border = "#3e3e42"
        table_header_bg = "#252526"
        hover_bg = "rgba(255, 255, 255, 0.05)"
        row_border = "#2d2d30"
        pagination_bg = "rgba(255, 255, 255, 0.02)"
        page_info_color = "#9ca3af"
        status_color = "#6b7280"
    else:
        # Light mode colors
        bg_color = "#ffffff"
        text_color = "#000000"
        border_color = "#e5e7eb"
        controls_bg = "#f8f9fa"
        input_bg = "#ffffff"
        input_border = "#d1d5db"
        table_header_bg = "#f8f9fa"
        hover_bg = "rgba(0, 0, 0, 0.03)"
        row_border = "#f3f4f6"
        pagination_bg = "rgba(0, 0, 0, 0.02)"
        page_info_color = "#6b7280"
        status_color = "#9ca3af"
    
    # Generate complete HTML with the widget
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SyftBox Files</title>
    <style>
    body {{
        background-color: {'#1e1e1e' if is_dark_mode else '#ffffff'};
        color: {text_color};
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }}
    
    @keyframes float {{
        0%, 100% {{ transform: translateY(0px); }}
        50% {{ transform: translateY(-8px); }}
    }}
    
    .syftbox-logo {{
        animation: float 3s ease-in-out infinite;
        filter: drop-shadow(0 4px 12px rgba(0, 0, 0, 0.15));
    }}
    
    .progress-bar-gradient {{
        background: linear-gradient(90deg, #3b82f6 0%, #10b981 100%);
        transition: width 0.4s ease-out;
        border-radius: 3px;
    }}
    
    #{container_id} * {{
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }}

    #{container_id} {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 12px;
        background: {bg_color};
        color: {text_color};
        display: flex;
        flex-direction: column;
        width: 100%;
        height: 100vh;
        margin: 0;
        border: 1px solid {border_color};
        border-radius: 8px;
        overflow: hidden;
    }}

    #{container_id} .search-controls {{
        display: flex;
        gap: 0.5rem;
        flex-wrap: wrap;
        padding: 0.75rem;
        background: {controls_bg};
        border-bottom: 1px solid {border_color};
        flex-shrink: 0;
    }}

    #{container_id} .search-controls input {{
        flex: 1;
        min-width: 200px;
        padding: 0.5rem;
        border: 1px solid {input_border};
        border-radius: 0.25rem;
        font-size: 0.875rem;
        background: {input_bg};
        color: {text_color};
    }}

    #{container_id} .table-container {{
        flex: 1;
        overflow-y: auto;
        overflow-x: auto;
        background: {bg_color};
        min-height: 0;
    }}

    #{container_id} table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 0.75rem;
        table-layout: fixed;
    }}

    #{container_id} thead {{
        background: {table_header_bg};
        border-bottom: 1px solid {border_color};
    }}

    #{container_id} th {{
        text-align: left;
        padding: 0.375rem 0.25rem;
        font-weight: 500;
        font-size: 0.75rem;
        border-bottom: 1px solid {border_color};
        position: sticky;
        top: 0;
        background: {table_header_bg};
        z-index: 10;
        color: {text_color};
    }}

    #{container_id} td {{
        padding: 0.375rem 0.25rem;
        border-bottom: 1px solid {row_border};
        vertical-align: top;
        font-size: 0.75rem;
        text-align: left;
        color: {text_color};
    }}

    #{container_id} td:first-child {{
        padding-left: 0.5rem;
    }}

    #{container_id} tbody tr {{
        transition: background-color 0.15s;
        cursor: pointer;
    }}

    #{container_id} tbody tr:hover {{
        background: {hover_bg};
    }}

    @keyframes rainbow {{
        0% {{ background-color: #ffe9ec; }}
        14.28% {{ background-color: #fff4ea; }}
        28.57% {{ background-color: #ffffea; }}
        42.86% {{ background-color: #eaffef; }}
        57.14% {{ background-color: #eaf6ff; }}
        71.43% {{ background-color: #f5eaff; }}
        85.71% {{ background-color: #ffeaff; }}
        100% {{ background-color: #ffe9ec; }}
    }}

    @keyframes rainbow-dark {{
        0% {{ background-color: #3d2c2e; }}
        14.28% {{ background-color: #3d352c; }}
        28.57% {{ background-color: #3d3d2c; }}
        42.86% {{ background-color: #2c3d31; }}
        57.14% {{ background-color: #2c363d; }}
        71.43% {{ background-color: #352c3d; }}
        85.71% {{ background-color: #3d2c3d; }}
        100% {{ background-color: #3d2c2e; }}
    }}

    #{container_id} .rainbow-flash {{
        animation: {'rainbow-dark' if is_dark_mode else 'rainbow'} 0.8s ease-in-out;
    }}

    #{container_id} .pagination {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.5rem;
        border-top: 1px solid {border_color};
        background: {pagination_bg};
        flex-shrink: 0;
    }}

    #{container_id} .pagination button {{
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        border: 1px solid {border_color};
        background: {'#2d2d30' if is_dark_mode else 'white'};
        color: {text_color};
        cursor: pointer;
        transition: all 0.15s;
    }}

    #{container_id} .pagination button:hover:not(:disabled) {{
        background: {'#3e3e42' if is_dark_mode else '#f3f4f6'};
    }}

    #{container_id} .pagination button:disabled {{
        opacity: 0.5;
        cursor: not-allowed;
    }}

    #{container_id} .pagination .page-info {{
        font-size: 0.75rem;
        color: {page_info_color};
    }}

    #{container_id} .pagination .status {{
        font-size: 0.75rem;
        color: {status_color};
        font-style: italic;
        opacity: 0.8;
        text-align: center;
        flex: 1;
    }}

    #{container_id} .pagination .pagination-controls {{
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }}

    #{container_id} .truncate {{
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }}

    #{container_id} .btn {{
        padding: 0.125rem 0.375rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        border: none;
        cursor: not-allowed;
        display: inline-flex;
        align-items: center;
        gap: 0.125rem;
        transition: all 0.15s;
        opacity: 0.5;
    }}

    #{container_id} .btn:hover {{
        opacity: 0.5;
    }}

    #{container_id} .btn-blue {{
        background: {'#1e3a5f' if is_dark_mode else '#dbeafe'};
        color: {'#60a5fa' if is_dark_mode else '#3b82f6'};
    }}

    #{container_id} .btn-purple {{
        background: {'#3b2e4d' if is_dark_mode else '#e9d5ff'};
        color: {'#c084fc' if is_dark_mode else '#a855f7'};
    }}

    #{container_id} .btn-red {{
        background: {'#4d2828' if is_dark_mode else '#fee2e2'};
        color: {'#f87171' if is_dark_mode else '#ef4444'};
    }}

    #{container_id} .btn-green {{
        background: {'#1e4032' if is_dark_mode else '#d1fae5'};
        color: {'#34d399' if is_dark_mode else '#10b981'};
    }}

    #{container_id} .btn-gray {{
        background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
        color: {'#9ca3af' if is_dark_mode else '#6b7280'};
    }}

    #{container_id} .icon {{
        width: 0.5rem;
        height: 0.5rem;
    }}
    
    #{container_id} .autocomplete-dropdown {{
        position: absolute;
        background: {'#1e1e1e' if is_dark_mode else 'white'};
        border: 1px solid {border_color};
        border-radius: 0.25rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        max-height: 200px;
        overflow-y: auto;
        z-index: 1000;
        display: none;
    }}
    
    #{container_id} .autocomplete-dropdown.show {{
        display: block;
    }}
    
    #{container_id} .autocomplete-option {{
        padding: 0.5rem;
        cursor: pointer;
        font-size: 0.875rem;
        color: {text_color};
    }}
    
    #{container_id} .autocomplete-option:hover,
    #{container_id} .autocomplete-option.selected {{
        background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
    }}

    #{container_id} .type-badge {{
        display: inline-block;
        padding: 0.125rem 0.375rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
        font-weight: 500;
        background: {'#1e1e1e' if is_dark_mode else '#ffffff'};
        color: {'#d1d5db' if is_dark_mode else '#374151'};
        text-align: center;
        white-space: nowrap;
    }}

    #{container_id} .admin-email {{
        display: flex;
        align-items: center;
        gap: 0.25rem;
        font-family: monospace;
        font-size: 0.75rem;
        color: {'#d1d5db' if is_dark_mode else '#374151'};
    }}

    #{container_id} .date-text {{
        display: flex;
        align-items: center;
        gap: 0.25rem;
        font-size: 0.75rem;
        color: {'#9ca3af' if is_dark_mode else '#4b5563'};
    }}
    </style>
</head>
<body>
    <!-- Loading container -->
    <div id="loading-container-{container_id}" style="height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; background-color: {bg_color};">
        <!-- SyftBox Logo -->
        <svg class="syftbox-logo" width="120" height="139" viewBox="0 0 311 360" fill="none" xmlns="http://www.w3.org/2000/svg">
            <g clip-path="url(#clip0_7523_4240)">
                <path d="M311.414 89.7878L155.518 179.998L-0.378906 89.7878L155.518 -0.422485L311.414 89.7878Z" fill="url(#paint0_linear_7523_4240)"></path>
                <path d="M311.414 89.7878V270.208L155.518 360.423V179.998L311.414 89.7878Z" fill="url(#paint1_linear_7523_4240)"></path>
                <path d="M155.518 179.998V360.423L-0.378906 270.208V89.7878L155.518 179.998Z" fill="url(#paint2_linear_7523_4240)"></path>
            </g>
            <defs>
                <linearGradient id="paint0_linear_7523_4240" x1="-0.378904" y1="89.7878" x2="311.414" y2="89.7878" gradientUnits="userSpaceOnUse">
                    <stop stop-color="#DC7A6E"></stop>
                    <stop offset="0.251496" stop-color="#F6A464"></stop>
                    <stop offset="0.501247" stop-color="#FDC577"></stop>
                    <stop offset="0.753655" stop-color="#EFC381"></stop>
                    <stop offset="1" stop-color="#B9D599"></stop>
                </linearGradient>
                <linearGradient id="paint1_linear_7523_4240" x1="309.51" y1="89.7878" x2="155.275" y2="360.285" gradientUnits="userSpaceOnUse">
                    <stop stop-color="#BFCD94"></stop>
                    <stop offset="0.245025" stop-color="#B2D69E"></stop>
                    <stop offset="0.504453" stop-color="#8DCCA6"></stop>
                    <stop offset="0.745734" stop-color="#5CB8B7"></stop>
                    <stop offset="1" stop-color="#4CA5B8"></stop>
                </linearGradient>
                <linearGradient id="paint2_linear_7523_4240" x1="-0.378906" y1="89.7878" x2="155.761" y2="360.282" gradientUnits="userSpaceOnUse">
                    <stop stop-color="#D7686D"></stop>
                    <stop offset="0.225" stop-color="#C64B77"></stop>
                    <stop offset="0.485" stop-color="#A2638E"></stop>
                    <stop offset="0.703194" stop-color="#758AA8"></stop>
                    <stop offset="1" stop-color="#639EAF"></stop>
                </linearGradient>
                <clipPath id="clip0_7523_4240">
                    <rect width="311" height="360" fill="white"></rect>
                </clipPath>
            </defs>
        </svg>
        
        <div style="font-size: 20px; font-weight: 600; color: {text_color}; margin-top: 2rem; text-align: center;">
            loading your view of <br />the internet of private data...
        </div>
        
        <div style="width: 340px; height: 6px; background-color: {'#2d2d30' if is_dark_mode else '#e5e5e5'}; border-radius: 3px; margin: 1.5rem auto; overflow: hidden;">
            <div id="loading-bar-{container_id}" class="progress-bar-gradient" style="width: 0%; height: 100%;"></div>
        </div>
        
        <div id="loading-status-{container_id}" style="color: {status_color}; font-size: 0.875rem; margin-top: 0.5rem;">
            Initializing...
        </div>
        
        <div style="margin-top: 3rem; padding: 0 2rem; max-width: 500px; text-align: center;">
            <div style="color: {page_info_color}; font-size: 0.875rem; font-style: italic;">
                💡 Tip: {footer_tip}
            </div>
        </div>
    </div>

    <!-- Main widget container (hidden initially) -->
    <div id="{container_id}" style="display: none;">
        <div class="search-controls">
            <input id="{container_id}-search" placeholder="🔍 Search files..." style="flex: 1;">
            <input id="{container_id}-admin-filter" placeholder="Filter by Admin..." style="flex: 1;">
            <button class="btn btn-green">New</button>
            <button class="btn btn-blue">Select All</button>
            <button class="btn btn-gray">Refresh</button>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 2rem; padding-left: 0.5rem;"><input type="checkbox" id="{container_id}-select-all" onclick="toggleSelectAll_{container_id}()"></th>
                        <th style="width: 2.5rem; cursor: pointer;" onclick="sortTable_{container_id}('index')"># ↕</th>
                        <th style="width: 25rem; cursor: pointer;" onclick="sortTable_{container_id}('name')">URL ↕</th>
                        <th style="width: 8rem; cursor: pointer;" onclick="sortTable_{container_id}('modified')">Modified ↕</th>
                        <th style="width: 5rem; cursor: pointer;" onclick="sortTable_{container_id}('type')">Type ↕</th>
                        <th style="width: 4rem; cursor: pointer;" onclick="sortTable_{container_id}('size')">Size ↕</th>
                        <th style="width: 12rem; cursor: pointer;" onclick="sortTable_{container_id}('permissions')">Permissions ↕</th>
                        <th style="width: 10rem;">Actions</th>
                    </tr>
                </thead>
                <tbody id="{container_id}-tbody">
                    <!-- Table rows will be populated by JavaScript -->
                </tbody>
            </table>
        </div>

        <div class="pagination">
            <div></div>
            <span class="status" id="{container_id}-status">Loading...</span>
            <div class="pagination-controls">
                <button onclick="changePage_{container_id}(-1)" id="{container_id}-prev-btn" disabled>Previous</button>
                <span class="page-info" id="{container_id}-page-info">Page 1 of 1</span>
                <button onclick="changePage_{container_id}(1)" id="{container_id}-next-btn">Next</button>
            </div>
        </div>
    </div>

    <script>
    (function() {{
        // Initialize variables
        var allFiles = [];
        var filteredFiles = [];
        var currentPage = 1;
        var itemsPerPage = 50;
        var sortColumn = 'modified';  // Default sort by modified date
        var sortDirection = 'desc';    // Default descending (newest first)
        var chronologicalIds = {{}};
        
        // Update progress
        function updateProgress(percent, status) {{
            var loadingBar = document.getElementById('loading-bar-{container_id}');
            var loadingStatus = document.getElementById('loading-status-{container_id}');
            
            if (loadingBar) {{
                loadingBar.style.width = percent + '%';
            }}
            if (loadingStatus) {{
                loadingStatus.innerHTML = status;
            }}
        }}
        
        // Load files data asynchronously
        async function loadFiles() {{
            try {{
                // Initial progress
                updateProgress(10, 'Finding SyftBox directory...');
                
                // Start fetching files data (this will trigger the scan)
                const filesPromise = fetch('/api/files-data');
                
                // Poll for progress updates
                let progressInterval = setInterval(async () => {{
                    try {{
                        const progressResponse = await fetch('/api/scan-progress');
                        const progress = await progressResponse.json();
                        
                        if (progress.status === 'scanning' && progress.total > 0) {{
                            // Calculate percentage based on actual scan progress
                            const percent = Math.min(90, 10 + (progress.current / progress.total) * 80);
                            updateProgress(percent, progress.message || 'Scanning datasites...');
                        }}
                    }} catch (e) {{
                        console.error('Error fetching progress:', e);
                    }}
                }}, 200); // Poll every 200ms
                
                // Wait for files data
                const response = await filesPromise;
                const data = await response.json();
                
                // Stop polling
                clearInterval(progressInterval);
                
                updateProgress(90, 'Processing ' + data.total + ' files...');
                
                // Store files data
                allFiles = data.files;
                filteredFiles = allFiles.slice();
                
                // Create chronological IDs (oldest = 1, newest = highest)
                var sortedByDate = allFiles.slice().sort(function(a, b) {{
                    return (a.modified || 0) - (b.modified || 0);  // Ascending order (oldest first)
                }});
                
                chronologicalIds = {{}};
                sortedByDate.forEach(function(file, index) {{
                    var fileKey = file.name + '|' + file.path;
                    chronologicalIds[fileKey] = index;  // Start from 0
                }});
                
                // Add chronological IDs to files
                allFiles.forEach(function(file) {{
                    var fileKey = file.name + '|' + file.path;
                    file.chronoId = chronologicalIds[fileKey] || 0;
                }});
                
                updateProgress(100, 'Complete!');
                
                // Sort files by modified date (newest first) before initial render
                filteredFiles.sort(function(a, b) {{
                    var aVal = a.modified || 0;
                    var bVal = b.modified || 0;
                    return bVal - aVal;  // Descending order (newest first)
                }});
                
                // Hide loading screen and show widget
                setTimeout(function() {{
                    document.getElementById('loading-container-{container_id}').style.display = 'none';
                    document.getElementById('{container_id}').style.display = 'flex';
                    
                    // Initial render
                    renderTable();
                    updateStatus();
                }}, 500);
                
            }} catch (error) {{
                console.error('Error loading files:', error);
                updateProgress(0, 'Error loading files. Please refresh the page.');
            }}
        }}
        
        var showFooterTip = {'true' if show_footer_tip else 'false'};
        var footerTip = {json.dumps(footer_tip)};

        // All the JavaScript functions from the template
        function escapeHtml(text) {{
            var div = document.createElement('div');
            div.textContent = text || '';
            return div.innerHTML;
        }}

        function formatDate(timestamp) {{
            var date = new Date(timestamp * 1000);
            return (date.getMonth() + 1).toString().padStart(2, '0') + '/' +
                   date.getDate().toString().padStart(2, '0') + '/' +
                   date.getFullYear() + ' ' +
                   date.getHours().toString().padStart(2, '0') + ':' +
                   date.getMinutes().toString().padStart(2, '0');
        }}

        function formatSize(size) {{
            if (size > 1024 * 1024) {{
                return (size / (1024 * 1024)).toFixed(1) + ' MB';
            }} else if (size > 1024) {{
                return (size / 1024).toFixed(1) + ' KB';
            }} else {{
                return size + ' B';
            }}
        }}

        function showStatus(message) {{
            var statusEl = document.getElementById('{container_id}-status');
            if (statusEl) statusEl.textContent = message;
        }}
        
        function calculateTotalSize() {{
            var totalSize = 0;
            filteredFiles.forEach(function(file) {{
                if (!file.is_dir) {{
                    totalSize += file.size || 0;
                }}
            }});
            return totalSize;
        }}
        
        function updateStatus() {{
            var fileCount = 0;
            var folderCount = 0;
            
            filteredFiles.forEach(function(item) {{
                if (item.is_dir) {{
                    folderCount++;
                }} else {{
                    fileCount++;
                }}
            }});
            
            var totalSize = calculateTotalSize();
            var sizeStr = formatSize(totalSize);
            
            var searchValue = document.getElementById('{container_id}-search').value;
            var adminFilter = document.getElementById('{container_id}-admin-filter').value;
            var isSearching = searchValue !== '' || adminFilter !== '';
            
            var statusText = fileCount + ' files';
            if (folderCount > 0) {{
                statusText += ', ' + folderCount + ' folders';
            }}
            statusText += ' • Total size: ' + sizeStr;
            
            if (!isSearching && showFooterTip) {{
                statusText += ' • 💡 ' + footerTip;
            }}
            
            showStatus(statusText);
        }}

        function renderTable() {{
            var tbody = document.getElementById('{container_id}-tbody');
            var totalFiles = filteredFiles.length;
            var totalPages = Math.max(1, Math.ceil(totalFiles / itemsPerPage));
            
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;
            
            document.getElementById('{container_id}-prev-btn').disabled = currentPage === 1;
            document.getElementById('{container_id}-next-btn').disabled = currentPage === totalPages;
            document.getElementById('{container_id}-page-info').textContent = 'Page ' + currentPage + ' of ' + totalPages;
            
            if (totalFiles === 0) {{
                tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; padding: 40px;">No files found</td></tr>';
                return;
            }}
            
            var start = (currentPage - 1) * itemsPerPage;
            var end = Math.min(start + itemsPerPage, totalFiles);
            
            var html = '';
            for (var i = start; i < end; i++) {{
                var file = filteredFiles[i];
                var fileName = file.name.split('/').pop();
                var filePath = file.name;
                var fullSyftPath = 'syft://' + filePath;
                var datasiteOwner = file.datasite_owner || 'unknown';
                var modified = formatDate(file.modified || 0);
                var fileExt = file.extension || '.txt';
                var sizeStr = formatSize(file.size || 0);
                var isDir = file.is_dir || false;
                
                var chronoId = file.chronoId !== undefined ? file.chronoId : i;
                
                html += '<tr onclick="copyPath_{container_id}(\\'syft://' + filePath + '\\', this)">' +
                    '<td><input type="checkbox" onclick="event.stopPropagation(); updateSelectAllState_{container_id}()"></td>' +
                    '<td>' + chronoId + '</td>' +
                    '<td><div class="truncate" style="font-weight: 500;" title="' + escapeHtml(fullSyftPath) + '">' + escapeHtml(fullSyftPath) + '</div></td>' +
                    '<td>' +
                        '<div class="date-text">' +
                            '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                                '<rect width="18" height="18" x="3" y="4" rx="2" ry="2"></rect>' +
                                '<line x1="16" x2="16" y1="2" y2="6"></line>' +
                                '<line x1="8" x2="8" y1="2" y2="6"></line>' +
                                '<line x1="3" x2="21" y1="10" y2="10"></line>' +
                            '</svg>' +
                            '<span class="truncate">' + modified + '</span>' +
                        '</div>' +
                    '</td>' +
                    '<td><span class="type-badge">' + (isDir ? 'folder' : fileExt) + '</span></td>' +
                    '<td><span style="color: #6b7280;">' + sizeStr + '</span></td>' +
                    '<td>' +
                        '<div style="display: flex; flex-direction: column; gap: 0.125rem; font-size: 0.625rem; color: #6b7280;">';
                
                var perms = file.permissions_summary || [];
                if (perms.length > 0) {{
                    for (var j = 0; j < Math.min(perms.length, 3); j++) {{
                        html += '<span>' + escapeHtml(perms[j]) + '</span>';
                    }}
                    if (perms.length > 3) {{
                        html += '<span>+' + (perms.length - 3) + ' more...</span>';
                    }}
                }} else {{
                    html += '<span style="color: #9ca3af;">No permissions</span>';
                }}
                
                html += '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div style="display: flex; gap: 0.125rem;">' +
                            '<button class="btn btn-gray" title="Open in editor">File</button>' +
                            '<button class="btn btn-blue" title="View file info">Info</button>' +
                            '<button class="btn btn-purple" title="Copy path">Copy</button>' +
                            '<button class="btn btn-red" title="Delete file">' +
                                '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                                    '<path d="M3 6h18"></path>' +
                                    '<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>' +
                                    '<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>' +
                                    '<line x1="10" x2="10" y1="11" y2="17"></line>' +
                                    '<line x1="14" x2="14" y1="11" y2="17"></line>' +
                                '</svg>' +
                            '</button>' +
                        '</div>' +
                    '</td>' +
                '</tr>';
            }}
            
            tbody.innerHTML = html;
        }}

        // Search files
        window.searchFiles_{container_id} = function() {{
            var searchTerm = document.getElementById('{container_id}-search').value.toLowerCase();
            var adminFilter = document.getElementById('{container_id}-admin-filter').value.toLowerCase();
            
            // Parse search terms
            var searchTerms = [];
            var currentTerm = '';
            var inQuotes = false;
            var quoteChar = '';
            
            for (var i = 0; i < searchTerm.length; i++) {{
                var char = searchTerm[i];
                
                if ((char === '"' || char === "'") && !inQuotes) {{
                    inQuotes = true;
                    quoteChar = char;
                }} else if (char === quoteChar && inQuotes) {{
                    inQuotes = false;
                    if (currentTerm.length > 0) {{
                        searchTerms.push(currentTerm);
                        currentTerm = '';
                    }}
                    quoteChar = '';
                }} else if (char === ' ' && !inQuotes) {{
                    if (currentTerm.length > 0) {{
                        searchTerms.push(currentTerm);
                        currentTerm = '';
                    }}
                }} else {{
                    currentTerm += char;
                }}
            }}
            
            if (currentTerm.length > 0) {{
                searchTerms.push(currentTerm);
            }}
            
            filteredFiles = allFiles.filter(function(file) {{
                var adminMatch = adminFilter === '' || (file.datasite_owner || '').toLowerCase().includes(adminFilter);
                if (!adminMatch) return false;
                
                if (searchTerms.length === 0) return true;
                
                return searchTerms.every(function(term) {{
                    var searchableContent = [
                        file.name,
                        file.datasite_owner || '',
                        file.extension || '',
                        formatSize(file.size || 0),
                        formatDate(file.modified || 0),
                        file.is_dir ? 'folder' : 'file',
                        (file.permissions_summary || []).join(' ')
                    ].join(' ').toLowerCase();
                    
                    return searchableContent.includes(term);
                }});
            }});
            
            currentPage = 1;
            renderTable();
            updateStatus();
        }};

        // Change page
        window.changePage_{container_id} = function(direction) {{
            var totalPages = Math.max(1, Math.ceil(filteredFiles.length / itemsPerPage));
            currentPage += direction;
            if (currentPage < 1) currentPage = 1;
            if (currentPage > totalPages) currentPage = totalPages;
            renderTable();
        }};

        // Copy path
        window.copyPath_{container_id} = function(path, rowElement) {{
            var command = 'sp.open("' + path + '")';
            
            navigator.clipboard.writeText(command).then(function() {{
                if (rowElement) {{
                    rowElement.classList.add('rainbow-flash');
                    setTimeout(function() {{
                        rowElement.classList.remove('rainbow-flash');
                    }}, 800);
                }}
                
                showStatus('Copied to clipboard: ' + command);
                setTimeout(function() {{
                    updateStatus();
                }}, 2000);
            }}).catch(function() {{
                showStatus('Failed to copy to clipboard');
            }});
        }};

        // Toggle select all
        window.toggleSelectAll_{container_id} = function() {{
            var selectAllCheckbox = document.getElementById('{container_id}-select-all');
            var checkboxes = document.querySelectorAll('#{container_id} tbody input[type="checkbox"]');
            checkboxes.forEach(function(cb) {{ 
                cb.checked = selectAllCheckbox.checked; 
            }});
            showStatus(selectAllCheckbox.checked ? 'All visible files selected' : 'Selection cleared');
        }};
        
        // Update select all state
        window.updateSelectAllState_{container_id} = function() {{
            var checkboxes = document.querySelectorAll('#{container_id} tbody input[type="checkbox"]');
            var selectAllCheckbox = document.getElementById('{container_id}-select-all');
            var allChecked = true;
            var someChecked = false;
            
            checkboxes.forEach(function(cb) {{
                if (!cb.checked) allChecked = false;
                if (cb.checked) someChecked = true;
            }});
            
            selectAllCheckbox.checked = allChecked;
            selectAllCheckbox.indeterminate = !allChecked && someChecked;
        }};

        // Sort table
        window.sortTable_{container_id} = function(column) {{
            if (sortColumn === column) {{
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            }} else {{
                sortColumn = column;
                sortDirection = 'asc';
            }}
            
            filteredFiles.sort(function(a, b) {{
                var aVal, bVal;
                
                switch(column) {{
                    case 'index':
                        aVal = a.modified || 0;
                        bVal = b.modified || 0;
                        var temp = aVal;
                        aVal = -bVal;
                        bVal = -temp;
                        break;
                    case 'name':
                        aVal = a.name.toLowerCase();
                        bVal = b.name.toLowerCase();
                        break;
                    case 'modified':
                        aVal = a.modified || 0;
                        bVal = b.modified || 0;
                        break;
                    case 'type':
                        aVal = (a.extension || '').toLowerCase();
                        bVal = (b.extension || '').toLowerCase();
                        break;
                    case 'size':
                        aVal = a.size || 0;
                        bVal = b.size || 0;
                        break;
                    case 'permissions':
                        aVal = (a.permissions_summary || []).length;
                        bVal = (b.permissions_summary || []).length;
                        break;
                    default:
                        return 0;
                }}
                
                if (aVal < bVal) return sortDirection === 'asc' ? -1 : 1;
                if (aVal > bVal) return sortDirection === 'asc' ? 1 : -1;
                return 0;
            }});
            
            currentPage = 1;
            renderTable();
        }};

        // Add real-time search
        document.getElementById('{container_id}-search').addEventListener('input', function() {{
            searchFiles_{container_id}();
        }});
        document.getElementById('{container_id}-admin-filter').addEventListener('input', function() {{
            searchFiles_{container_id}();
        }});
        
        // Start loading files when page loads
        loadFiles();
    }})();
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

    # First check if there's a configured port
    configured_port = _get_configured_port()
    if configured_port:
        # Verify the server is running on this port
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://localhost:{configured_port}/", timeout=0.5) as response:
                if response.status == 200:
                    return f"http://localhost:{configured_port}/editor/{path}"
        except Exception:
            pass

    # Fall back to default behavior
    server_url = get_server_url()
    if not server_url:
        server_url = start_server()

    return f"{server_url}/editor/{path}"


def _get_configured_port() -> Optional[int]:
    """Get the configured port from ~/.syftperm/config.json if it exists."""
    try:
        import json
        from pathlib import Path
        
        config_path = Path.home() / ".syftperm" / "config.json"
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config.get('port')
    except Exception:
        pass
    return None


def get_files_widget_url() -> str:
    """Get the URL for the files widget interface."""
    if not _SERVER_AVAILABLE:
        return "Server not available - install with: pip install 'syft-perm[server]'"

    # First check if there's a configured port
    configured_port = _get_configured_port()
    if configured_port:
        # Verify the server is running on this port
        try:
            import urllib.request
            with urllib.request.urlopen(f"http://localhost:{configured_port}/", timeout=0.5) as response:
                if response.status == 200:
                    return f"http://localhost:{configured_port}/files-widget"
        except Exception:
            pass

    # Fall back to default behavior
    server_url = get_server_url()
    if not server_url:
        server_url = start_server()

    return f"{server_url}/files-widget"
