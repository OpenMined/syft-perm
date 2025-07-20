"""FastAPI server for syft-perm permission editor."""

import asyncio
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import open as syft_open
from ._auto_recovery import ensure_server_running
from ._syftbox import client as syftbox_client
from ._utils import get_syftbox_datasites
from .filesystem_editor import get_current_user_email  # noqa: F401
from .server_templates.files_widget import get_files_widget_html
from .server_templates.permission_editor import get_editor_html

_SERVER_AVAILABLE = False
try:
    import uvicorn  # type: ignore[import-untyped]
    from fastapi import FastAPI as _FastAPI  # type: ignore[import-untyped]
    from fastapi import HTTPException as _HTTPException  # type: ignore[import-untyped]
    from fastapi import Query as _Query  # type: ignore[import-untyped]
    from fastapi import WebSocket as _WebSocket  # type: ignore[import-untyped]
    from fastapi import WebSocketDisconnect as _WebSocketDisconnect  # type: ignore[import-untyped]
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
WebSocket = _WebSocket
WebSocketDisconnect = _WebSocketDisconnect


# Set up logging
logger = logging.getLogger("uvicorn.error")

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
        permissions: Dict[
            str, Any
        ]  # Can be Dict[str, List[str]] or Dict[str, Dict] depending on include_reasons
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
    scan_progress = {"current": 0, "total": 0, "status": "idle", "message": ""}

    # WebSocket connection management
    active_websockets: List[WebSocket] = []
    websocket_lock = threading.Lock()

    # Global event loop for WebSocket operations
    websocket_loop = None

    def get_websocket_loop():
        global websocket_loop
        if websocket_loop is None or not websocket_loop.is_running():
            websocket_loop = asyncio.new_event_loop()

            def run_loop():
                asyncio.set_event_loop(websocket_loop)
                websocket_loop.run_forever()

            thread = threading.Thread(target=run_loop, daemon=True)
            thread.start()
            # Give the loop time to start
            time.sleep(0.1)
        return websocket_loop

    async def broadcast_file_change(action: str, file_path: str):
        """Broadcast file change to all connected WebSocket clients."""
        import json
        from pathlib import Path

        # Skip hidden files and non-datasite files
        path = Path(file_path)
        if path.name.startswith("."):
            return

        # Get file metadata
        try:
            # Find relative path from datasites directory
            datasites_parent = None
            for parent in path.parents:
                if parent.name == "datasites":
                    datasites_parent = parent
                    break

            if not datasites_parent:
                return

            relative_path = path.relative_to(datasites_parent)
            datasite_owner = str(relative_path).split("/")[0] if "/" in str(relative_path) else ""

            # Build file info similar to _scan_files
            file_info = {
                "name": str(relative_path),
                "path": str(path),
                "is_dir": path.is_dir() if action != "deleted" else False,
                "size": path.stat().st_size if action != "deleted" and path.exists() else 0,
                "modified": (
                    path.stat().st_mtime if action != "deleted" and path.exists() else time.time()
                ),
                "extension": path.suffix if not path.is_dir() else "folder",
                "datasite_owner": datasite_owner,
                "permissions": {},
                "has_yaml": False,
                "permissions_summary": [],
            }

            # Try to get permissions for non-deleted files
            if action != "deleted" and path.exists() and not path.is_dir():
                try:
                    syft_obj = syft_open(path)
                    permissions = syft_obj._permissions_dict.copy()
                    file_info["permissions"] = permissions
                    file_info["has_yaml"] = hasattr(syft_obj, "_has_yaml") and syft_obj._has_yaml

                    # Build permissions summary
                    user_highest_perm = {}
                    for perm_level in ["admin", "write", "create", "read"]:
                        users = permissions.get(perm_level, [])
                        for user in users:
                            if user not in user_highest_perm:
                                user_highest_perm[user] = perm_level

                    perm_groups = {}
                    for user, perm in user_highest_perm.items():
                        if perm not in perm_groups:
                            perm_groups[perm] = []
                        perm_groups[perm].append(user)

                    permissions_summary = []
                    for perm_level in ["admin", "write", "create", "read"]:
                        if perm_level in perm_groups:
                            users = perm_groups[perm_level]
                            if len(users) > 2:
                                user_list = f"{users[0]}, {users[1]}, +{len(users)-2}"
                            else:
                                user_list = ", ".join(users)
                            permissions_summary.append(f"{perm_level}: {user_list}")
                    file_info["permissions_summary"] = permissions_summary
                except Exception:
                    pass

            message = json.dumps({"action": action, "file": file_info})

            # Broadcast to all connected clients
            with websocket_lock:
                if len(active_websockets) > 0:
                    logger.info(
                        f"[FILE WATCHER] Broadcasting to {len(active_websockets)} WebSocket clients"
                    )
                    disconnected = []
                    for ws in active_websockets:
                        try:
                            # Send message asynchronously
                            await ws.send_text(message)
                            logger.info(
                                f"[FILE WATCHER] Successfully sent update for {action}: {file_path}"
                            )
                        except Exception as e:
                            logger.info(f"[FILE WATCHER] Error sending to WebSocket: {e}")
                            disconnected.append(ws)

                    # Remove disconnected websockets
                    for ws in disconnected:
                        active_websockets.remove(ws)
                        logger.info(
                            f"[FILE WATCHER] Removed disconnected WebSocket. Remaining: {len(active_websockets)}"
                        )

        except Exception as e:
            logger.info(f"[FILE WATCHER] Error broadcasting file change: {e}")

    # File watcher setup
    def setup_file_watcher():
        """Set up file system watcher for SyftBox datasites directory."""
        logger.info("[FILE WATCHER] Setting up file watcher...")
        import asyncio
        import threading
        from pathlib import Path

        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer

        class SyftBoxFileHandler(FileSystemEventHandler):
            """Handler for file system events in SyftBox datasites."""

            def _schedule_broadcast(self, action: str, path: str):
                """Schedule broadcast in the event loop."""
                try:
                    loop = get_websocket_loop()
                    future = asyncio.run_coroutine_threadsafe(
                        broadcast_file_change(action, path), loop
                    )
                    # Wait for the broadcast to complete (with timeout)
                    future.result(timeout=2.0)
                except Exception as e:
                    logger.info(f"[FILE WATCHER] Error scheduling broadcast: {e}")

            def on_created(self, event):
                if not event.is_directory:
                    logger.info(f"[FILE WATCHER] File created: {event.src_path}")
                    self._schedule_broadcast("created", event.src_path)
                else:
                    logger.info(f"[FILE WATCHER] Directory created: {event.src_path}")

            def on_deleted(self, event):
                if not event.is_directory:
                    logger.info(f"[FILE WATCHER] File deleted: {event.src_path}")
                    self._schedule_broadcast("deleted", event.src_path)
                else:
                    logger.info(f"[FILE WATCHER] Directory deleted: {event.src_path}")

            def on_modified(self, event):
                if not event.is_directory:
                    logger.info(f"[FILE WATCHER] File modified: {event.src_path}")
                    self._schedule_broadcast("modified", event.src_path)

            def on_moved(self, event):
                if not event.is_directory:
                    logger.info(f"[FILE WATCHER] File moved: {event.src_path} -> {event.dest_path}")
                    # Treat as delete + create
                    self._schedule_broadcast("deleted", event.src_path)
                    self._schedule_broadcast("created", event.dest_path)
                else:
                    logger.info(
                        f"[FILE WATCHER] Directory moved: {event.src_path} -> {event.dest_path}"
                    )

        # Find SyftBox datasites directory
        syftbox_dirs = [
            Path.home() / "SyftBox" / "datasites",
            Path.home() / ".syftbox" / "datasites",
            Path("/tmp/SyftBox/datasites"),
        ]

        watch_dir = None
        for path in syftbox_dirs:
            logger.info(f"[FILE WATCHER] Checking directory: {path}")
            if path.exists():
                watch_dir = path
                logger.info(f"[FILE WATCHER] Found directory: {watch_dir}")
                break

        if watch_dir:
            logger.info(f"[FILE WATCHER] Starting file watcher for: {watch_dir}")

            # Set up observer
            observer = Observer()
            event_handler = SyftBoxFileHandler()
            observer.schedule(event_handler, str(watch_dir), recursive=True)

            # Start observer in a separate thread
            def start_watcher():
                try:
                    observer.start()
                    logger.info("[FILE WATCHER] File watcher started successfully")
                    # Keep the watcher running
                    observer.join()
                except Exception as e:
                    logger.info(f"[FILE WATCHER] Error starting file watcher: {e}")

            watcher_thread = threading.Thread(target=start_watcher, daemon=True)
            watcher_thread.start()

            return observer
        else:
            logger.info(
                "[FILE WATCHER] No SyftBox datasites directory found, file watcher disabled"
            )
            return None

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

    # Store file watcher observer for cleanup
    file_watcher_observer = None

    @app.on_event("startup")
    async def startup_event():
        """Initialize file watcher on startup."""
        logger.info("[STARTUP] Initializing application...")
        global file_watcher_observer
        # Initialize the WebSocket event loop
        logger.info("[STARTUP] Setting up WebSocket event loop...")
        get_websocket_loop()
        logger.info("[STARTUP] Setting up file watcher...")
        file_watcher_observer = setup_file_watcher()
        logger.info("[STARTUP] Startup complete")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Clean up file watcher on shutdown."""
        if file_watcher_observer:
            logger.info("[FILE WATCHER] Stopping file watcher...")
            file_watcher_observer.stop()
            file_watcher_observer.join()

    @app.get("/")  # type: ignore[misc]
    async def root() -> Dict[str, str]:
        """Root endpoint with basic info."""
        return {"message": "SyftPerm Permission Editor", "docs": "/docs"}

    @app.get("/permissions/{path:path}", response_model=PermissionResponse)  # type: ignore[misc]
    async def get_permissions(
        path: str, include_reasons: bool = Query(False)
    ) -> PermissionResponse:
        """Get permissions for a file or folder, optionally with detailed reasons."""
        try:
            # Resolve the path
            file_path = Path(path)
            if not file_path.exists():
                raise HTTPException(status_code=404, detail=f"Path not found: {path}")

            # Open with syft-perm
            syft_obj = syft_open(file_path)

            # Get current permissions
            permissions = syft_obj._get_all_permissions()

            # Add permission reasons if requested
            if include_reasons:
                permissions_with_reasons = {}
                # Collect all unique users from all permission levels
                all_users = set()
                for perm_level, user_list in permissions.items():
                    all_users.update(user_list)

                # For each user, get their permissions and reasons
                for user in all_users:
                    user_permissions = {}
                    # Get which permission levels this user has
                    for perm_level, user_list in permissions.items():
                        user_permissions[perm_level] = user_list if user in user_list else []

                    permissions_with_reasons[user] = {
                        "permissions": user_permissions,
                        "reasons": {},
                    }
                    # Get detailed reasons for each permission level
                    for perm in ["read", "create", "write", "admin"]:
                        try:
                            has_perm, reasons = syft_obj._check_permission_with_reasons(user, perm)
                            permissions_with_reasons[user]["reasons"][perm] = {
                                "granted": has_perm,
                                "reasons": reasons,
                            }
                        except Exception as e:
                            # Fallback if permission checking fails
                            permissions_with_reasons[user]["reasons"][perm] = {
                                "granted": False,
                                "reasons": [f"Error checking permissions: {str(e)}"],
                            }
                permissions = permissions_with_reasons

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
            import traceback

            error_details = (
                f"Error processing permissions for {path}: {str(e)}\n{traceback.format_exc()}"
            )
            logger.error(error_details)
            raise HTTPException(status_code=500, detail=f"Permission processing failed: {str(e)}")

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
                    syft_obj.grant_read_access(update.user, force=True)
                elif update.permission == "create":
                    syft_obj.grant_create_access(update.user, force=True)
                elif update.permission == "write":
                    syft_obj.grant_write_access(update.user, force=True)
                elif update.permission == "admin":
                    syft_obj.grant_admin_access(update.user, force=True)
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
        filetype: Optional[str] = Query(None, description="Filter by file type: 'file' or 'folder'"),
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
                        
                        # Apply filetype filter if provided
                        if filetype:
                            if filetype == "file" and item.is_dir():
                                # Still scan subdirectories to find files within
                                scan_directory(item, base_path)
                                continue
                            elif filetype == "folder" and not item.is_dir():
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
    async def files_widget(
        search: Optional[str] = Query(None, description="Search term for file names"),
        admin: Optional[str] = Query(None, description="Filter by admin email"),
        folders: Optional[str] = Query(None, description="Comma-separated folder paths"),
        page: int = Query(1, ge=1, description="Page number (1-based)"),
        items_per_page: int = Query(50, ge=1, le=1000, description="Items per page"),
        start: Optional[int] = Query(None, ge=0, description="Start index for slicing"),
        end: Optional[int] = Query(None, ge=0, description="End index for slicing"),
        filetype: Optional[str] = Query(None, description="Filter by file type: 'file' or 'folder'"),
    ) -> str:
        """Serve the files widget interface with filtering support."""
        # Get current user email
        current_user_email = get_current_user_email() or ""

        # Parse folders if provided
        folder_list = None
        if folders:
            folder_list = [f.strip() for f in folders.split(",") if f.strip()]

        # Generate the widget HTML with parameters
        return get_files_widget_html(
            search=search,
            admin=admin,
            folders=folder_list,
            page=page,
            items_per_page=items_per_page,
            start=start,
            end=end,
            current_user_email=current_user_email,
            filetype=filetype,
        )

    @app.get("/api/scan-progress")  # type: ignore[misc]
    async def get_scan_progress() -> Dict[str, Any]:
        """Get current scan progress."""
        return scan_progress.copy()

    @app.get("/api/files-data")  # type: ignore[misc]
    async def get_files_data(
        search: Optional[str] = Query(None),
        admin: Optional[str] = Query(None),
        folders: Optional[str] = Query(None),
        start: Optional[int] = Query(None),
        end: Optional[int] = Query(None),
        filetype: Optional[str] = Query(None),
    ) -> Dict[str, Any]:
        """Get files data for the widget with filtering support."""
        import asyncio

        from . import files as sp_files

        # Reset progress
        scan_progress["status"] = "scanning"
        scan_progress["current"] = 0
        scan_progress["total"] = 0
        scan_progress["message"] = "Starting scan..."

        # Define progress callback without rate limiting
        def progress_callback(current: int, total: int, message: str):
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

        # Run scan in a thread to not block async endpoint
        loop = asyncio.get_event_loop()
        all_files = await loop.run_in_executor(
            None, lambda: sp_files._scan_files(progress_callback=progress_callback)
        )

        # Mark as complete
        scan_progress["status"] = "complete"
        scan_progress["message"] = "Scan complete"

        # Apply filters if provided
        filtered_files = all_files

        # Apply search filter
        if search:
            search_terms = sp_files._parse_search_terms(search)
            filtered_files = [
                f for f in filtered_files if sp_files._matches_search_terms(f, search_terms)
            ]

        # Apply admin filter
        if admin:
            filtered_files = [
                f for f in filtered_files if f.get("datasite_owner", "").lower() == admin.lower()
            ]

        # Apply folder filter
        if folders:
            folder_list = [f.strip() for f in folders.split(",") if f.strip()]
            filtered_files = sp_files._apply_folder_filter(filtered_files, folder_list)
        
        # Apply filetype filter
        if filetype:
            if filetype == "file":
                filtered_files = [f for f in filtered_files if not f.get("is_dir", False)]
            elif filetype == "folder":
                filtered_files = [f for f in filtered_files if f.get("is_dir", False)]

        # Sort by modified date (newest first) - always sort to ensure consistent ordering
        filtered_files = sorted(filtered_files, key=lambda x: x.get("modified", 0), reverse=True)

        # Apply slicing if provided
        if start is not None or end is not None:
            # Convert to 0-based indexing if needed
            slice_start = (start - 1) if start is not None and start > 0 else start
            slice_end = (end - 1) if end is not None and end > 0 else end

            filtered_files = filtered_files[slice(slice_start, slice_end)]

        # Return the data as JSON
        return {
            "files": filtered_files,
            "total": len(filtered_files),
            "total_unfiltered": len(all_files),
        }

    @app.post("/api/restart")  # type: ignore[misc]
    async def restart_server() -> Dict[str, str]:
        """Restart the server."""
        import os
        import sys

        # Send response before restarting
        response = {"status": "restarting", "message": "Server is restarting..."}

        # Schedule restart after response is sent
        def do_restart():
            # Give time for response to be sent
            import time

            time.sleep(0.5)

            # Restart the process
            os.execv(sys.executable, [sys.executable] + sys.argv)

        # Start restart in background thread
        import threading

        threading.Thread(target=do_restart, daemon=True).start()

        return response

    @app.websocket("/ws/file-updates")  # type: ignore[misc]
    async def websocket_endpoint(websocket: WebSocket) -> None:
        """WebSocket endpoint for real-time file updates."""
        logger.info(f"[WEBSOCKET] New connection attempt from {websocket.client}")
        await websocket.accept()

        # Add to active connections
        with websocket_lock:
            active_websockets.append(websocket)
            logger.info(
                f"[WEBSOCKET] Client connected. Total connections: {len(active_websockets)}"
            )

        try:
            # Keep connection alive
            while True:
                # Wait for any message from client (like ping/pong)
                data = await websocket.receive_text()
                # Echo back for heartbeat
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            # Remove from active connections
            with websocket_lock:
                active_websockets.remove(websocket)
                logger.info(
                    f"[WEBSOCKET] Client disconnected. Total connections: {len(active_websockets)}"
                )
        except Exception as e:
            logger.info(f"[WEBSOCKET] Error: {e}")
            with websocket_lock:
                if websocket in active_websockets:
                    active_websockets.remove(websocket)

    # File System Editor Endpoints
    from .filesystem_editor import FileSystemManager, generate_editor_html

    # Initialize the filesystem manager
    fs_manager = FileSystemManager()

    @app.get("/api/filesystem/list")  # type: ignore[misc]
    async def list_directory(
        path: str = Query(...), syft_user: Optional[str] = Query(None)
    ) -> Dict[str, Any]:
        """List directory contents."""
        from .filesystem_editor import get_current_user_email

        # Use syft_user if provided (from syft:// URL), otherwise detect current user
        current_user = syft_user or get_current_user_email()
        return fs_manager.list_directory(path, user_email=current_user)

    @app.get("/api/filesystem/read")  # type: ignore[misc]
    async def read_file(
        path: str = Query(...), syft_user: Optional[str] = Query(None)
    ) -> Dict[str, Any]:
        """Read file contents."""
        from .filesystem_editor import get_current_user_email

        # Use syft_user if provided (from syft:// URL), otherwise detect current user
        current_user = syft_user or get_current_user_email()
        return fs_manager.read_file(path, user_email=current_user)

    @app.post("/api/filesystem/write")  # type: ignore[misc]
    async def write_file(request: Dict[str, Any]) -> Dict[str, Any]:
        """Write content to a file."""
        path = request.get("path")
        content = request.get("content", "")
        create_dirs = request.get("create_dirs", False)
        syft_user = request.get("syft_user")

        if not path:
            raise HTTPException(status_code=400, detail="Path is required")

        from .filesystem_editor import get_current_user_email

        # Use syft_user if provided (from syft:// URL), otherwise detect current user
        current_user = syft_user or get_current_user_email()
        return fs_manager.write_file(path, content, create_dirs, user_email=current_user)

    @app.post("/api/filesystem/create-directory")  # type: ignore[misc]
    async def create_directory(request: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new directory."""
        path = request.get("path")
        syft_user = request.get("syft_user")

        if not path:
            raise HTTPException(status_code=400, detail="Path is required")

        from .filesystem_editor import get_current_user_email

        # Use syft_user if provided (from syft:// URL), otherwise detect current user
        current_user = syft_user or get_current_user_email()
        return fs_manager.create_directory(path, user_email=current_user)

    @app.delete("/api/filesystem/delete")  # type: ignore[misc]
    async def delete_item(path: str = Query(...), recursive: bool = Query(False)) -> Dict[str, Any]:
        """Delete a file or directory."""
        return fs_manager.delete_item(path, recursive)

    @app.post("/api/filesystem/rename")  # type: ignore[misc]
    async def rename_item(
        old_path: str = Query(...),
        new_path: str = Query(...),
        syft_user: Optional[str] = Query(None),
    ) -> Dict[str, Any]:
        """Rename a file or directory."""
        current_user = syft_user or get_current_user_email()
        return fs_manager.rename_item(old_path, new_path, user_email=current_user)

    @app.get("/file-editor", response_class=HTMLResponse)  # type: ignore[misc]
    async def file_editor_interface(syft_user: Optional[str] = Query(None)) -> HTMLResponse:
        """Serve the file editor interface."""
        from . import _is_dark

        return HTMLResponse(
            content=generate_editor_html(is_dark_mode=_is_dark(), syft_user=syft_user)
        )

    @app.get("/file-editor/{path:path}", response_class=HTMLResponse)  # type: ignore[misc]
    async def file_editor_with_path(
        path: str, syft_user: Optional[str] = Query(None), new: Optional[str] = Query(None)
    ) -> HTMLResponse:
        """Serve the file editor interface with a specific path."""
        from . import _is_dark

        is_new_file = new == "true"
        return HTMLResponse(
            content=generate_editor_html(
                initial_path=path,
                is_dark_mode=_is_dark(),
                syft_user=syft_user,
                is_new_file=is_new_file,
            )
        )

    @app.get("/share-modal", response_class=HTMLResponse)  # type: ignore[misc]
    async def share_modal(
        path: str = Query(...), syft_user: Optional[str] = Query(None)
    ) -> HTMLResponse:
        """Serve the share modal as a standalone page."""
        from . import _is_dark
        from .filesystem_editor import generate_share_modal_html

        return HTMLResponse(
            content=generate_share_modal_html(
                path=path, is_dark_mode=_is_dark(), syft_user=syft_user
            )
        )


# Server management
_server_thread: Optional[threading.Thread] = None
_server_port = 8765


def start_server(port: int = 8765, host: str = "127.0.0.1") -> str:
    """Start the FastAPI server in a background thread."""
    if not _SERVER_AVAILABLE:
        raise ImportError(
            "Server dependencies not available. Install with: pip install 'syft-perm[server]'"
        )

    global _server_thread, _server_port

    # Check if a server is already running
    if _server_thread and _server_thread.is_alive():
        return f"http://{host}:{_server_port}"

    # Try to use configured port first
    configured_port = _get_configured_port()
    if configured_port:
        # Check if a server is running on the configured port
        import aiohttp

        server_url = f"http://localhost:{configured_port}"
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

            with urllib.request.urlopen(
                f"http://localhost:{configured_port}/", timeout=0.5
            ) as response:
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
            with open(config_path, "r") as f:
                config = json.load(f)
                return config.get("port")
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

            with urllib.request.urlopen(
                f"http://localhost:{configured_port}/", timeout=0.5
            ) as response:
                if response.status == 200:
                    return f"http://localhost:{configured_port}/files-widget"
        except Exception:
            pass

    # Fall back to default behavior
    server_url = get_server_url()
    if not server_url:
        server_url = start_server()

    return f"{server_url}/files-widget"


def get_file_editor_url(path: str = None) -> str:
    """Get the URL for the file editor interface."""
    if not _SERVER_AVAILABLE:
        return "Server not available - install with: pip install 'syft-perm[server]'"

    # First check if there's a configured port
    configured_port = _get_configured_port()
    if configured_port:
        # Verify the server is running on this port
        try:
            import urllib.request

            with urllib.request.urlopen(
                f"http://localhost:{configured_port}/", timeout=0.5
            ) as response:
                if response.status == 200:
                    if path:
                        return f"http://localhost:{configured_port}/file-editor/{path}"
                    return f"http://localhost:{configured_port}/file-editor"
        except Exception:
            pass

    # Fall back to default behavior
    server_url = get_server_url()
    if not server_url:
        server_url = start_server()

    if path:
        return f"{server_url}/file-editor/{path}"
    return f"{server_url}/file-editor"
