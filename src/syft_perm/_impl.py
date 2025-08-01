"""Internal implementation of SyftFile and SyftFolder classes with ACL compatibility."""

import shutil
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Union

import yaml

from ._utils import (
    format_users,
    is_datasite_email,
    read_syftpub_yaml,
    read_syftpub_yaml_full,
    resolve_path,
    update_syftpub_yaml,
)
from .core import (
    PermissionCache,
    PermissionReason,
    PermissionResult,
    _acl_norm_path,
    _calculate_glob_specificity,
    _doublestar_match,
    _glob_match,
    _is_owner,
    _sort_rules_by_specificity,
    clear_permission_cache,
    get_cache_stats,
)
from .core.permissions import _permission_cache
from .core.visualization import PermissionExplanation, ShareWidget

FILE_LIMIT = "Blocked by {limit_type} limit"


def _confirm_action(message: str, force: bool = False) -> bool:
    """
    Confirm a sensitive action with the user.

    Args:
        message: The confirmation message to display
        force: Whether to skip confirmation

    Returns:
        bool: True if confirmed or forced, False otherwise
    """
    if force:
        return True

    response = input(f"{message} [y/N] ").lower().strip()
    return response in ["y", "yes"]


class SyftFile:
    """A file wrapper that manages SyftBox permissions."""

    def __init__(self, path: Union[str, Path]):
        # Store original path (might be syft:// URL)
        self._original_path = str(path)

        # Extract user from syft:// URL if present
        self._syft_user = None
        if isinstance(path, str) and path.startswith("syft://"):
            # Extract user from syft://user@domain/path format
            try:
                url_parts = path[7:].split("/", 1)  # Remove "syft://" prefix
                if "@" in url_parts[0]:
                    self._syft_user = url_parts[0]
            except Exception:
                pass

        resolved_path = resolve_path(str(path))
        if resolved_path is None:
            raise ValueError("Could not resolve path")
        self._path: Path = resolved_path

        # Ensure parent directory exists
        self._path.parent.mkdir(parents=True, exist_ok=True)

        # File metadata for limit checks
        self._is_symlink = self._path.is_symlink() if self._path.exists() else False
        self._size = (
            self._path.stat().st_size if self._path.exists() and not self._is_symlink else 0
        )

    @property
    def _name(self) -> str:
        """Get the file name"""
        return self._path.name

    @property
    def _permissions_dict(self) -> Dict[str, List[str]]:
        """Get all permissions for this file as a dictionary."""
        return self._get_all_permissions()

    @property
    def _has_yaml(self) -> bool:
        """Check if this file has any associated yaml permission files."""
        # Check if any yaml files were found during permission resolution
        # This is simpler: if we have ANY permissions (including "*"),
        # then yaml files exist
        perms = self._get_all_permissions()

        # Check each permission type
        for permission_type, users in perms.items():
            if users:  # If there are any users (including "*")
                return True

        # No permissions found means no yaml files processed this file
        return False

    def _get_all_permissions(self) -> Dict[str, List[str]]:
        """Get all permissions for this file using old syftbox nearest-node algorithm."""
        # Check cache first
        cache_key = str(self._path)
        cached = _permission_cache.get(cache_key)
        if cached is not None:
            return cached

        # Initialize default permissions
        nearest_permissions: Dict[str, List[str]] = {
            "read": [],
            "create": [],
            "write": [],
            "admin": [],
        }

        # First pass: collect all yaml files and check for terminal nodes
        yaml_files = []
        current_path = self._path
        terminal_found_at = None

        while current_path.parent != current_path:  # Stop at root
            parent_dir = current_path.parent
            syftpub_path = parent_dir / "syft.pub.yaml"

            if syftpub_path.exists():
                try:
                    with open(syftpub_path, "r") as f:
                        content = yaml.safe_load(f) or {"rules": []}

                    yaml_files.append((parent_dir, content))

                    # If this is a terminal node, remember it and stop collecting
                    if content.get("terminal", False) and terminal_found_at is None:
                        terminal_found_at = parent_dir
                        break

                except Exception:
                    pass

            current_path = parent_dir

        # Second pass: process yaml files from the terminal node (or root) down
        # If we found a terminal node, only process that node's rules
        if terminal_found_at is not None:
            # Only process the terminal node's rules
            for parent_dir, content in yaml_files:
                if parent_dir == terminal_found_at:
                    rules = content.get("rules", [])
                    sorted_rules = _sort_rules_by_specificity(rules)
                    for rule in sorted_rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our file path relative to this directory
                        rel_path = str(self._path.relative_to(parent_dir))
                        if _glob_match(pattern, rel_path):
                            access = rule.get("access", {})
                            # Check file limits if present
                            limits = rule.get("limits", {})
                            if limits:
                                # Check if directories are allowed
                                if (
                                    not limits.get("allow_dirs", True)
                                    and self._path is not None
                                    and self._path.is_dir()
                                ):
                                    continue  # Skip this rule for directories

                                # Check if symlinks are allowed
                                if not limits.get("allow_symlinks", True) and self._is_symlink:
                                    continue  # Skip this rule for symlinks

                                # Check file size limits
                                max_file_size = limits.get("max_file_size")
                                if max_file_size is not None:
                                    if self._size > max_file_size:
                                        continue  # Skip this rule if file exceeds size limit

                            # Terminal rules: use first matching rule
                            nearest_permissions = {
                                perm: format_users(access.get(perm, []))
                                for perm in ["read", "create", "write", "admin"]
                            }
                            break
                    break
        else:
            # No terminal node found, use nearest-node algorithm
            # Process from the file up, and use the FIRST matching rule found
            for parent_dir, content in yaml_files:  # yaml_files is already in order from file up
                rules = content.get("rules", [])
                sorted_rules = _sort_rules_by_specificity(rules)
                found_match = False

                for rule in sorted_rules:
                    pattern = rule.get("pattern", "")
                    # Check if pattern matches our file path relative to this directory
                    rel_path = (
                        str(self._path.relative_to(parent_dir)) if self._path is not None else ""
                    )
                    if _glob_match(pattern, rel_path):
                        access = rule.get("access", {})
                        # Check file limits if present
                        limits = rule.get("limits", {})
                        if limits:
                            # Check if directories are allowed
                            if not limits.get("allow_dirs", True) and self._path.is_dir():
                                continue  # Skip this rule for directories

                            # Check if symlinks are allowed
                            if not limits.get("allow_symlinks", True) and self._is_symlink:
                                continue  # Skip this rule for symlinks

                            # Check file size limits
                            max_file_size = limits.get("max_file_size")
                            if max_file_size is not None:
                                if self._size > max_file_size:
                                    continue  # Skip this rule if file exceeds size limit

                        # Found the nearest matching rule
                        nearest_permissions = {
                            perm: format_users(access.get(perm, []))
                            for perm in ["read", "create", "write", "admin"]
                        }
                        found_match = True
                        break

                # If we found a match in this yaml file, stop searching
                if found_match:
                    break

        # Add owner permissions: datasite owner gets full admin access
        path_str = str(self._path)
        if "datasites" in path_str:
            # Extract datasite owner from path like: /path/to/SyftBox/datasites/user@domain.com/...
            parts = path_str.split("datasites")
            if len(parts) > 1:
                datasites_relative = parts[-1].lstrip("/\\")
                path_segments = datasites_relative.split("/")
                if path_segments and "@" in path_segments[0]:
                    datasite_owner = path_segments[0]
                    # Grant full permissions to datasite owner
                    for perm_type in ["read", "create", "write", "admin"]:
                        if datasite_owner not in nearest_permissions[perm_type]:
                            nearest_permissions[perm_type].append(datasite_owner)

        # Cache and return the effective permissions
        _permission_cache.set(cache_key, nearest_permissions)
        return nearest_permissions

    def _get_permission_table(self) -> List[List[str]]:
        """Get permissions formatted as a table showing effective permissions.

        Shows hierarchy and reasons.
        """
        perms = self._get_all_permissions()

        # Get all unique users
        all_users = set()
        for users in perms.values():
            all_users.update(users)

        # Create table rows
        rows = []

        # First add public if it exists
        if "*" in all_users:
            # Collect all reasons for public

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons("*", "read")
            create_has, create_reasons = self._check_permission_with_reasons("*", "create")
            write_has, write_reasons = self._check_permission_with_reasons("*", "write")
            admin_has, admin_reasons = self._check_permission_with_reasons("*", "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            rows.append(
                [
                    "public",
                    "✓" if read_has else "",
                    "✓" if create_has else "",
                    "✓" if write_has else "",
                    "✓" if admin_has else "",
                    reason_text,
                ]
            )
            all_users.remove("*")  # Remove so we don't process it again

        # Then add all other users
        for user in sorted(all_users):
            # Collect all reasons for this user

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons(user, "read")
            create_has, create_reasons = self._check_permission_with_reasons(user, "create")
            write_has, write_reasons = self._check_permission_with_reasons(user, "write")
            admin_has, admin_reasons = self._check_permission_with_reasons(user, "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            row = [
                user,
                "✓" if read_has else "",
                "✓" if create_has else "",
                "✓" if write_has else "",
                "✓" if admin_has else "",
                reason_text,
            ]
            rows.append(row)

        return rows

    def __repr__(self) -> str:
        """Return string representation showing permissions table."""
        rows = self._get_permission_table()
        if not rows:
            return f"SyftFile('{self._path}') - No permissions set"

        try:
            from tabulate import tabulate

            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="simple",
            )
            return f"SyftFile('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFile('{self._path}')\n"]
            result.append("User               Read  Create  Write  Admin  Reason")
            result.append("-" * 70)
            for row in rows:
                result.append(
                    f"{row[0]:<20} {row[1]:<5} {row[2]:<7} {row[3]:<6} "
                    f"{row[4]:<5} {row[5] if len(row) > 5 else ''}"
                )
            return "\n".join(result)

    def _ensure_server_and_get_editor_url(self) -> str:
        """Ensure the permission editor server is running and return the editor URL."""
        try:
            from ._auto_recovery import ensure_server_running
            from .server import get_editor_url, get_server_url, start_server

            # Check if server is already running
            server_url = get_server_url()
            if server_url:
                # Verify it's actually responding
                success, error = ensure_server_running(server_url)
                if not success:
                    print(f"Server health check failed: {error}")
                    server_url = None

            if not server_url:
                # Start the server
                server_url = start_server()
                print(f"🚀 SyftPerm permission editor started at: {server_url}")

            # Return the editor URL for this file
            return get_editor_url(str(self._path))

        except ImportError:
            # FastAPI not available
            return "Install 'syft-perm[server]' for permission editor"
        except Exception as e:
            # Server failed to start
            return f"Permission editor unavailable: {e}"

    def _get_loading_html(self) -> str:
        """Get static HTML to show while server is starting."""
        import threading
        import uuid

        # Generate unique ID for this instance
        instance_id = str(uuid.uuid4())

        # Start server recovery in background
        def start_server_background():
            try:
                self._ensure_server_and_get_editor_url()
            except Exception:
                pass  # Silently fail in background

        thread = threading.Thread(target=start_server_background, daemon=True)
        thread.start()

        # Return static HTML with auto-refresh
        return f"""
        <div id="syft-perm-{instance_id}" style="padding: 20px; background: #f5f5f5; border-radius: 8px; font-family: sans-serif;">  # noqa: E501
            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>
            <div style="background: white; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <p style="margin: 0;"><strong>File:</strong> {self._path}</p>
            </div>
            <div style="background: #e3f2fd; padding: 15px; border-radius: 4px; text-align: center;">  # noqa: E501
                <div style="display: inline-block;">
                    <div style="border: 3px solid #1976d2; border-radius: 50%; border-top-color: transparent;  # noqa: E501
                                width: 30px; height: 30px; animation: spin-{instance_id} 1s linear infinite;  # noqa: E501
                                margin: 0 auto 10px;"></div>
                    <p style="color: #1976d2; margin: 0;">Starting permission editor server...</p>
                    <p style="color: #666; font-size: 0.9em; margin-top: 5px;">This may take a moment if auto-recovery is needed</p>  # noqa: E501
                </div>
            </div>
            <style>
                @keyframes spin-{instance_id} {{
                    to {{ transform: rotate(360deg); }}
                }}
            </style>
            <script>
                (function() {{
                    let attempts = 0;
                    const maxAttempts = 30;
                    const checkInterval = 2000;

                    function checkServerAndReload() {{
                        attempts++;

                        // Try to fetch from the expected server
                        fetch('http://127.0.0.1:8765/')
                            .then(response => {{
                                if (response.ok) {{
                                    // Server is ready, reload the cell output
                                    if (window.Jupyter && window.Jupyter.notebook) {{
                                        // Find and re-execute this cell
                                        const cells = window.Jupyter.notebook.get_cells();
                                        for (let cell of cells) {{
                                            if (cell.output_area && cell.output_area.element) {{
                                                const output = cell.output_area.element[0];
                                                if (output && output.innerHTML.includes('syft-perm-{instance_id}')) {{  # noqa: E501
                                                    cell.execute();
                                                    return;
                                                }}
                                            }}
                                        }}
                                    }}
                                }}
                            }})
                            .catch(() => {{
                                // Server not ready yet
                                if (attempts < maxAttempts) {{
                                    setTimeout(checkServerAndReload, checkInterval);
                                }} else {{
                                    // Update the UI to show failure
                                    const elem = document.getElementById('syft-perm-{instance_id}');
                                    if (elem) {{
                                        elem.innerHTML = `
                                            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>  # noqa: E501
                                            <div style="background: #ffebee; padding: 15px; border-radius: 4px; color: #c62828;">  # noqa: E501
                                                <p style="margin: 0;"><strong>Error:</strong> Failed to start permission editor server</p>  # noqa: E501
                                                <p style="margin: 5px 0 0 0; font-size: 0.9em;">Please check your installation and try again</p>  # noqa: E501
                                            </div>
                                        `;
                                    }}
                                }}
                            }});
                    }}

                    // Start checking after a short delay
                    setTimeout(checkServerAndReload, 1000);
                }})();
            </script>
        </div>
        """

    def _repr_html_(self) -> str:
        """Return an interactive iframe when the server is available or a static, read-only widget otherwise."""
        from . import _get_file_editor_url as get_file_editor_url
        from . import _is_dark as is_dark

        # Helper to quickly decide if a returned URL is actually usable
        def _looks_like_valid_url(url: str) -> bool:
            return url.startswith("http://") or url.startswith("https://")

        try:
            editor_url = get_file_editor_url(str(self._path))
            if not _looks_like_valid_url(editor_url):
                raise RuntimeError("permission-editor server unavailable")

            # Preserve syft_user context if present
            if self._syft_user:
                import urllib.parse as _urllib_parse

                sep = "&" if "?" in editor_url else "?"
                editor_url = f"{editor_url}{sep}syft_user={_urllib_parse.quote(self._syft_user)}"

            border_colour = "#3e3e42" if is_dark() else "#ddd"
            bg_colour = "#1e1e1e" if is_dark() else "#ffffff"
            return (
                f'<div style="width:100%;height:600px;border:1px solid {border_colour};'
                f'border-radius:8px;overflow:hidden;background:{bg_colour};">'
                f'<iframe src="{editor_url}" style="width:100%;height:100%;border:none;'
                f'background:transparent;" frameborder="0" allow="clipboard-read; clipboard-write"></iframe></div>'
            )
        except Exception:
            # -----------------------------
            # Offline fallback (read-only)
            # -----------------------------
            import html as _html
            import json as _json
            import uuid as _uuid
            from pathlib import Path as _Path

            from .filesystem_editor import generate_editor_html as _gen_html

            is_dark_mode = is_dark()
            # (no external import needed)

            # Build static data for the in-browser stubbed API
            root_dir = _Path(self._path).parent

            def _build_local_data(start_path: _Path):
                directories: dict = {}
                files: dict = {}

                def _recurse(dir_path: _Path):
                    try:
                        items = []
                        for child in sorted(
                            dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
                        ):
                            try:
                                stat = child.stat()
                                # Format modified date as ISO string like the server-backed API
                                modified_iso = datetime.fromtimestamp(stat.st_mtime).isoformat()
                                item_info = {
                                    "name": child.name,
                                    "path": str(child),
                                    "is_directory": child.is_dir(),
                                    "size": None if child.is_dir() else stat.st_size,
                                    "modified": modified_iso,
                                    "is_editable": False,  # read-only fallback
                                    "extension": (
                                        child.suffix.lower() if not child.is_dir() else None
                                    ),
                                }
                            except Exception:
                                continue
                            items.append(item_info)

                            if child.is_dir():
                                _recurse(child)
                            else:
                                try:
                                    with open(child, "r", encoding="utf-8", errors="replace") as f:
                                        content = f.read()
                                except Exception:
                                    content = ""
                                if len(content) > 20000:
                                    content = content[:20000] + "\n\n… (truncated)"
                                files[str(child)] = {
                                    "path": str(child),
                                    "content": content,
                                    "size": stat.st_size,
                                    "modified": modified_iso,
                                    "extension": child.suffix.lower(),
                                    "encoding": "utf-8",
                                    "can_write": False,
                                    "can_admin": False,
                                    "write_users": [],
                                }
                        directories[str(dir_path)] = {
                            "path": str(dir_path),
                            "parent": str(dir_path.parent) if dir_path.parent != dir_path else None,
                            "items": items,
                            "total_items": len(items),
                            "can_admin": False,
                        }
                    except Exception:
                        pass

                _recurse(start_path)
                return {"directories": directories, "files": files}

            local_data = _build_local_data(root_dir)
            data_json = _json.dumps(local_data)

            # Base HTML from the editor (we'll stub out its network calls)
            base_html = _gen_html(
                initial_path=str(self._path),
                is_dark_mode=is_dark_mode,
                syft_user=getattr(self, "_syft_user", None),
            )

            # JavaScript stub to override fetch with local data
            stub_script = f"""
<script>
(function() {{
  const LOCAL_DATA = {data_json};
  function makeResp(obj) {{
    return Promise.resolve(new Response(JSON.stringify(obj), {{status: 200, headers: {{'Content-Type': 'application/json'}}}}));
  }}
  window.fetch = function(url, opts) {{
    try {{
      const u = new URL(url, window.location.origin);
      if (u.pathname.startsWith('/api/filesystem/list')) {{
        const p = decodeURIComponent(u.searchParams.get('path') || '');
        if (LOCAL_DATA.directories[p]) return makeResp(LOCAL_DATA.directories[p]);
      }}
      if (u.pathname.startsWith('/api/filesystem/read')) {{
        const p = decodeURIComponent(u.searchParams.get('path') || '');
        if (LOCAL_DATA.files[p]) return makeResp(LOCAL_DATA.files[p]);
      }}
    }} catch (e) {{}}
    return Promise.reject(new Error('Offline read-only viewer'));
  }};
}})();
</script>
"""

            insert_at = base_html.find("<script")
            if insert_at == -1:
                final_html = stub_script + base_html
            else:
                final_html = base_html[:insert_at] + stub_script + base_html[insert_at:]

            return final_html

    def grant_read_access(self, user: str, *, force: bool = False) -> None:
        """Grant read permission to a user."""
        self._grant_access(user, "read", force=force)

    def grant_create_access(self, user: str, *, force: bool = False) -> None:
        """Grant create permission to a user."""
        self._grant_access(user, "create", force=force)

    def grant_write_access(self, user: str, *, force: bool = False) -> None:
        """Grant write permission to a user."""
        if user in ["*", "public"] and not _confirm_action(
            f"⚠️  Warning: Granting public write access to '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "write", force=force)

    def grant_admin_access(self, user: str, *, force: bool = False) -> None:
        """Grant admin permission to a user."""
        if not _confirm_action(
            f"⚠️  Warning: Granting admin access to '{user}' for '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "admin", force=force)

    def revoke_read_access(self, user: str) -> None:
        """Revoke read permission from a user."""
        self._revoke_access(user, "read")

    def revoke_create_access(self, user: str) -> None:
        """Revoke create permission from a user."""
        self._revoke_access(user, "create")

    def revoke_write_access(self, user: str) -> None:
        """Revoke write permission from a user."""
        self._revoke_access(user, "write")

    def revoke_admin_access(self, user: str) -> None:
        """Revoke admin permission from a user."""
        self._revoke_access(user, "admin")

    def has_read_access(self, user: str) -> bool:
        """Check if a user has read permission."""
        return self._check_permission(user, "read")

    def has_create_access(self, user: str) -> bool:
        """Check if a user has create permission."""
        return self._check_permission(user, "create")

    def has_write_access(self, user: str) -> bool:
        """Check if a user has write permission."""
        return self._check_permission(user, "write")

    def has_admin_access(self, user: str) -> bool:
        """Check if a user has admin permission."""
        return self._check_permission(user, "admin")

    def _grant_access(
        self,
        user: str,
        permission: Literal["read", "create", "write", "admin"],
        *,
        force: bool = False,
    ) -> None:
        """Internal method to grant permission to a user."""
        # Validate that the email belongs to a datasite
        if not is_datasite_email(user) and not force:
            raise ValueError(
                f"'{user}' is not a valid datasite email. "
                f"Use force=True to override this check."
            )

        # Read all existing permissions for this file
        access_dict = read_syftpub_yaml(self._path.parent, self._name) or {}

        # Update the specific permission
        users = set(access_dict.get(permission, []))
        users.add(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present (even if empty)
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path.parent, self._name, access_dict)

        # Invalidate cache for this path and its parents
        _permission_cache.invalidate(str(self._path))

    def _revoke_access(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> None:
        """Internal method to revoke permission from a user."""
        access_dict = read_syftpub_yaml(self._path.parent, self._name) or {}
        users = set(access_dict.get(permission, []))
        # Handle revoking from public access
        if user in ["*", "public"]:
            users = set()  # Clear all if revoking public
        else:
            users.discard(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path.parent, self._name, access_dict)

        # Invalidate cache for this path and its parents
        _permission_cache.invalidate(str(self._path))

    def _check_permission(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            return True

        # Implement permission hierarchy following old syftbox logic: Admin > Write > Create > Read
        # Get all permission sets
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check public access for each level
        everyone_admin = "*" in admin_users
        everyone_write = "*" in write_users
        everyone_create = "*" in create_users
        everyone_read = "*" in read_users

        # Check user-specific access following old syftbox hierarchy logic
        is_admin = everyone_admin or user in admin_users
        is_writer = is_admin or everyone_write or user in write_users
        is_creator = is_writer or everyone_create or user in create_users
        is_reader = is_creator or everyone_read or user in read_users

        # Return based on requested permission level
        if permission == "admin":
            return is_admin
        elif permission == "write":
            return is_writer
        elif permission == "create":
            return is_creator
        elif permission == "read":
            return is_reader

    def _get_all_permissions_with_sources(self) -> Dict[str, Any]:
        """Get all permissions using old syftbox nearest-node algorithm with source tracking."""
        # Start with empty permissions and sources
        effective_perms: Dict[str, List[str]] = {"read": [], "create": [], "write": [], "admin": []}
        source_info: Dict[str, List[Dict[str, Any]]] = {
            "read": [],
            "create": [],
            "write": [],
            "admin": [],
        }
        terminal_path = None
        terminal_pattern = None  # Track the pattern that was matched in terminal
        matched_pattern = None  # Track any pattern that was matched (terminal or non-terminal)

        # Walk up the directory tree to find the nearest node with matching rules
        current_path = self._path
        while current_path.parent != current_path:  # Stop at root
            parent_dir = current_path.parent
            syftpub_path = parent_dir / "syft.pub.yaml"

            if syftpub_path.exists():
                try:
                    with open(syftpub_path, "r") as f:
                        content = yaml.safe_load(f) or {"rules": []}

                    # Check if this is a terminal node
                    if content.get("terminal", False):
                        terminal_path = syftpub_path
                        # Terminal nodes stop inheritance and their rules take precedence
                        rules = content.get("rules", [])
                        sorted_rules = _sort_rules_by_specificity(rules)
                        for rule in sorted_rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our file path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path):
                                matched_pattern = pattern  # Also track in general matched pattern
                                access = rule.get("access", {})

                                # Check file limits if present
                                limits = rule.get("limits", {})
                                if limits:
                                    # Check if directories are allowed
                                    if (
                                        not limits.get("allow_dirs", True)
                                        and self._path is not None
                                        and self._path.is_dir()
                                    ):
                                        continue  # Skip this rule for directories

                                    # Check if symlinks are allowed
                                    if not limits.get("allow_symlinks", True) and self._is_symlink:
                                        continue  # Skip this rule for symlinks

                                    # Check file size limits
                                    max_file_size = limits.get("max_file_size")
                                    if max_file_size is not None:
                                        if self._size > max_file_size:
                                            continue  # Skip this rule if file exceeds size limit

                                # Terminal rules override everything - return immediately
                                for perm in ["read", "create", "write", "admin"]:
                                    users = format_users(access.get(perm, []))
                                    effective_perms[perm] = users
                                    if users:
                                        source_info[perm] = [
                                            {
                                                "path": syftpub_path,
                                                "pattern": pattern,
                                                "terminal": True,
                                                "inherited": False,
                                            }
                                        ]
                                return {
                                    "permissions": effective_perms,
                                    "sources": source_info,
                                    "terminal": terminal_path,
                                    "terminal_pattern": terminal_pattern,
                                    "matched_pattern": matched_pattern,
                                }
                        # If no match in terminal, stop inheritance with empty permissions
                        return {
                            "permissions": effective_perms,
                            "sources": source_info,
                            "terminal": terminal_path,
                            "terminal_pattern": terminal_pattern,
                            "matched_pattern": matched_pattern,
                        }

                    # Process rules for non-terminal nodes (sort by specificity first)
                    rules = content.get("rules", [])
                    sorted_rules = _sort_rules_by_specificity(rules)
                    found_matching_rule = False
                    for rule in sorted_rules:
                        pattern = rule.get("pattern", "")
                        # Check if pattern matches our file path relative to this directory
                        rel_path = (
                            str(self._path.relative_to(parent_dir))
                            if self._path is not None
                            else ""
                        )
                        if _glob_match(pattern, rel_path):
                            access = rule.get("access", {})

                            # Check file limits if present
                            limits = rule.get("limits", {})
                            if limits:
                                # Check if directories are allowed
                                if not limits.get("allow_dirs", True) and self._path.is_dir():
                                    continue  # Skip this rule for directories

                                # Check if symlinks are allowed
                                if not limits.get("allow_symlinks", True) and self._is_symlink:
                                    continue  # Skip this rule for symlinks

                                # Check file size limits
                                max_file_size = limits.get("max_file_size")
                                if max_file_size is not None:
                                    if self._size > max_file_size:
                                        continue  # Skip this rule if file exceeds size limit

                            # Found a matching rule - this becomes our nearest node
                            matched_pattern = pattern  # Track the matched pattern
                            # Use this node's permissions (not accumulate)
                            for perm in ["read", "create", "write", "admin"]:
                                users = format_users(access.get(perm, []))
                                effective_perms[perm] = users
                                if users:
                                    source_info[perm] = [
                                        {
                                            "path": syftpub_path,
                                            "pattern": pattern,
                                            "terminal": False,
                                            "inherited": parent_dir != self._path.parent,
                                        }
                                    ]
                            found_matching_rule = True
                            # Stop at first matching rule
                            # (rules should be sorted by specificity)
                            break

                    # If we found a matching rule, this is our nearest node - stop searching
                    if found_matching_rule:
                        break

                except Exception:
                    pass

            current_path = parent_dir

        return {
            "permissions": effective_perms,
            "sources": source_info,
            "terminal": terminal_path,
            "terminal_pattern": terminal_pattern,
            "matched_pattern": matched_pattern,
        }

    def _check_permission_with_reasons(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> tuple[bool, List[str]]:
        """Check if a user has a specific permission and return reasons why."""
        reasons = []

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            reasons.append("Owner of path")
            return True, reasons

        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        matched_pattern = perm_data.get("matched_pattern")

        # If blocked by terminal
        if terminal and not any(all_perms.values()):
            reasons.append(f"Blocked by terminal at {terminal.parent}")
            return False, reasons

        # Check hierarchy and build reasons
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check if user has the permission through hierarchy
        has_permission = False

        if permission == "admin":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Explicitly granted admin in {src['path'].parent}")
        elif permission == "write":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Explicitly granted write in {src['path'].parent}")
        elif permission == "create":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Explicitly granted create in {src['path'].parent}")
        elif permission == "read":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Included via create permission in {src['path'].parent}")
            elif "*" in read_users or user in read_users:
                has_permission = True
                if sources.get("read"):
                    src = sources["read"][0]
                    reasons.append(f"Explicitly granted read in {src['path'].parent}")

        # Add pattern info only for the specific permission being checked
        # (not for inherited permissions - that would be confusing)
        if sources.get(permission):
            for src in sources[permission]:
                if src["pattern"]:
                    # Show the pattern that was matched for this specific permission
                    if f"Pattern '{src['pattern']}' matched" not in reasons:
                        reasons.append(f"Pattern '{src['pattern']}' matched")
                    break

        # If we don't have permission but a pattern was matched (terminal or non-terminal),
        # it means the rule was evaluated but didn't grant this permission
        elif matched_pattern and not has_permission:
            if f"Pattern '{matched_pattern}' matched" not in reasons:
                reasons.append(f"Pattern '{matched_pattern}' matched")

        # Check for public access
        if "*" in all_perms.get(permission, []) or (
            has_permission and "*" in [admin_users, write_users, create_users, read_users]
        ):
            if "Public access (*)" not in reasons:
                reasons.append("Public access (*)")

        if not has_permission and not reasons:
            reasons.append("No permission found")

        return has_permission, reasons

    def explain_permissions(self, user: Union[str, None] = None) -> PermissionExplanation:
        """Provide detailed explanation of why user has/lacks permissions.

        Args:
            user: Email of user to analyze. If None, shows permissions for all users.

        Returns:
            PermissionExplanation object that displays nicely in both console and Jupyter
        """
        result = PermissionExplanation(str(self._path), user)

        if user is not None:
            # Single user analysis
            permissions_data = {}
            for perm in ["admin", "write", "create", "read"]:
                has_perm, reasons = self._check_permission_with_reasons(user, perm)  # type: ignore
                permissions_data[perm] = {"granted": has_perm, "reasons": reasons}

            result.add_user_explanation(user, permissions_data)
        else:
            # All users analysis
            # Get all permissions and collect unique users
            all_perms = self._get_all_permissions()
            all_users = set()
            for perm_level in all_perms.values():
                all_users.update(perm_level)

            # Sort users for consistent output
            sorted_users = sorted(all_users)

            for current_user in sorted_users:
                permissions_data = {}
                for perm in ["admin", "write", "create", "read"]:
                    has_perm, reasons = self._check_permission_with_reasons(current_user, perm)  # type: ignore
                    permissions_data[perm] = {"granted": has_perm, "reasons": reasons}

                result.add_user_explanation(current_user, permissions_data)

        return result

    def move_file_and_its_permissions(self, new_path: Union[str, Path]) -> "SyftFile":
        """
        Move the file to a new location while preserving its permissions.

        Args:
            new_path: The destination path for the file

        Returns:
            SyftFile: A new SyftFile instance pointing to the moved file

        Raises:
            FileNotFoundError: If source file doesn't exist
            FileExistsError: If destination file already exists
            ValueError: If new_path is invalid
        """
        # Resolve and validate paths
        resolved_new_path = resolve_path(str(new_path))
        if resolved_new_path is None:
            raise ValueError("Could not resolve new path")
        new_path = resolved_new_path

        if not self._path.exists():
            raise FileNotFoundError(f"Source file not found: {self._path}")

        if new_path.exists():
            raise FileExistsError(f"Destination file already exists: {new_path}")

        # Get current permissions
        perms = self._get_all_permissions()

        # Create parent directory if needed
        new_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the file
        shutil.move(str(self._path), str(new_path))

        # Create new SyftFile instance
        new_file = SyftFile(new_path)

        # Apply permissions to new location
        for permission, users in perms.items():
            for user in users:
                if permission in ["read", "create", "write", "admin"]:
                    new_file._grant_access(user, permission)  # type: ignore[arg-type]

        return new_file

    @property
    def share(self):
        """Get the share widget for this file."""
        return ShareWidget(self)


class SyftFolder:
    """A folder wrapper that manages SyftBox permissions."""

    def __init__(self, path: Union[str, Path]):
        # Store original path (might be syft:// URL)
        self._original_path = str(path)

        # Extract user from syft:// URL if present
        self._syft_user = None
        if isinstance(path, str) and path.startswith("syft://"):
            # Extract user from syft://user@domain/path format
            try:
                url_parts = path[7:].split("/", 1)  # Remove "syft://" prefix
                if "@" in url_parts[0]:
                    self._syft_user = url_parts[0]
            except Exception:
                pass

        resolved_path = resolve_path(str(path))
        if resolved_path is None:
            raise ValueError("Could not resolve path")
        self._path: Path = resolved_path

        # Ensure folder exists
        self._path.mkdir(parents=True, exist_ok=True)

    @property
    def _name(self) -> str:
        """Get the folder name"""
        return self._path.name

    @property
    def _permissions_dict(self) -> Dict[str, List[str]]:
        """Get all permissions for this folder as a dictionary."""
        return self._get_all_permissions()

    def get_terminal(self) -> bool:
        """Check if this folder is a terminal node (blocks inheritance)."""
        syftpub_path = self._path / "syft.pub.yaml"
        if not syftpub_path.exists():
            return False

        try:
            with open(syftpub_path, "r") as f:
                content = yaml.safe_load(f) or {}
            return content.get("terminal", False)
        except Exception:
            return False

    def set_terminal(self, value: bool) -> None:
        """Set terminal status for this folder."""
        syftpub_path = self._path / "syft.pub.yaml"

        # Read existing content or create new
        content = {"rules": []}
        if syftpub_path.exists():
            try:
                with open(syftpub_path, "r") as f:
                    content = yaml.safe_load(f) or {"rules": []}
            except Exception:
                content = {"rules": []}

        # Set terminal value
        content["terminal"] = value

        # Ensure directory exists
        syftpub_path.parent.mkdir(parents=True, exist_ok=True)

        # Write back to file
        with open(syftpub_path, "w") as f:
            yaml.dump(content, f, default_flow_style=False, sort_keys=False)

        # Clear cache since we modified the file
        _permission_cache.invalidate(str(self._path))

    def _get_all_permissions(self) -> Dict[str, List[str]]:
        """Get all permissions for this folder from its own syft.pub.yaml file."""
        # Check cache first
        cache_key = str(self._path)
        cached = _permission_cache.get(cache_key)
        if cached is not None:
            return cached

        # Initialize permissions
        folder_permissions: Dict[str, List[str]] = {
            "read": [],
            "create": [],
            "write": [],
            "admin": [],
        }

        # First check if this folder has its own syft.pub.yaml file
        syftpub_path = self._path / "syft.pub.yaml"
        if syftpub_path.exists():
            try:
                with open(syftpub_path, "r") as f:
                    content = yaml.safe_load(f) or {"rules": []}

                # Process rules from the folder's own yaml file
                rules = content.get("rules", [])
                sorted_rules = _sort_rules_by_specificity(rules)
                for rule in sorted_rules:
                    pattern = rule.get("pattern", "")
                    # For the folder's own permissions, we look for "**" pattern
                    # which means permissions for the folder itself
                    if pattern == "**":
                        access = rule.get("access", {})
                        # Check file limits if present
                        limits = rule.get("limits", {})
                        if limits:
                            # Check if directories are allowed
                            if not limits.get("allow_dirs", True):
                                continue  # Skip this rule for directories

                        # Use this rule's permissions
                        folder_permissions = {
                            perm: format_users(access.get(perm, []))
                            for perm in ["read", "create", "write", "admin"]
                        }
                        # Stop at first matching rule (sorted by specificity)
                        break

            except Exception:
                pass

        # If no own permissions found, fall back to hierarchical search
        if not any(folder_permissions.values()):
            # Walk up the directory tree to find the nearest node with matching rules
            current_path = self._path
            while current_path.parent != current_path:  # Stop at root
                parent_dir = current_path.parent
                syftpub_path = parent_dir / "syft.pub.yaml"

                if syftpub_path.exists():
                    try:
                        with open(syftpub_path, "r") as f:
                            content = yaml.safe_load(f) or {"rules": []}

                        # Check if this is a terminal node
                        if content.get("terminal", False):
                            # Terminal nodes stop inheritance and their rules take precedence
                            rules = content.get("rules", [])
                            sorted_rules = _sort_rules_by_specificity(rules)
                            for rule in sorted_rules:
                                pattern = rule.get("pattern", "")
                                # Check if pattern matches our folder path
                                # relative to this directory
                                rel_path = str(self._path.relative_to(parent_dir))
                                if _glob_match(pattern, rel_path) or _glob_match(
                                    pattern, rel_path + "/"
                                ):
                                    access = rule.get("access", {})
                                    # Check file limits if present
                                    limits = rule.get("limits", {})
                                    if limits:
                                        # Check if directories are allowed
                                        if not limits.get("allow_dirs", True):
                                            continue  # Skip this rule for directories

                                    # Terminal rules override everything - return immediately
                                    result = {
                                        perm: format_users(access.get(perm, []))
                                        for perm in ["read", "create", "write", "admin"]
                                    }
                                    _permission_cache.set(cache_key, result)
                                    return result
                            # If no match in terminal, stop inheritance with empty permissions
                            _permission_cache.set(cache_key, folder_permissions)
                            return folder_permissions

                        # Process rules for non-terminal nodes (sort by specificity first)
                        rules = content.get("rules", [])
                        sorted_rules = _sort_rules_by_specificity(rules)
                        found_matching_rule = False
                        for rule in sorted_rules:
                            pattern = rule.get("pattern", "")
                            # Check if pattern matches our folder path relative to this directory
                            rel_path = str(self._path.relative_to(parent_dir))
                            if _glob_match(pattern, rel_path) or _glob_match(
                                pattern, rel_path + "/"
                            ):
                                access = rule.get("access", {})
                                # Check file limits if present
                                limits = rule.get("limits", {})
                                if limits:
                                    # Check if directories are allowed
                                    if not limits.get("allow_dirs", True):
                                        continue  # Skip this rule for directories

                                # Found a matching rule - this becomes our nearest node
                                # Use this node's permissions (not accumulate)
                                folder_permissions = {
                                    perm: format_users(access.get(perm, []))
                                    for perm in ["read", "create", "write", "admin"]
                                }
                                found_matching_rule = True
                                # Stop at first matching rule
                                # (rules should be sorted by specificity)
                                break

                        # If we found a matching rule, this is our nearest node - stop searching
                        if found_matching_rule:
                            break

                    except Exception:
                        pass

                current_path = parent_dir

        # Add owner permissions: datasite owner gets full admin access
        path_str = str(self._path)
        if "datasites" in path_str:
            # Extract datasite owner from path like: /path/to/SyftBox/datasites/user@domain.com/...
            parts = path_str.split("datasites")
            if len(parts) > 1:
                datasites_relative = parts[-1].lstrip("/\\")
                path_segments = datasites_relative.split("/")
                if path_segments and "@" in path_segments[0]:
                    datasite_owner = path_segments[0]
                    # Grant full permissions to datasite owner
                    for perm_type in ["read", "create", "write", "admin"]:
                        if datasite_owner not in folder_permissions[perm_type]:
                            folder_permissions[perm_type].append(datasite_owner)

        # Cache and return the effective permissions
        _permission_cache.set(cache_key, folder_permissions)
        return folder_permissions

    def _get_permission_table(self) -> List[List[str]]:
        """Get permissions formatted as a table showing effective permissions.

        Shows hierarchy and reasons.
        """
        perms = self._get_all_permissions()

        # Get all unique users
        all_users = set()
        for users in perms.values():
            all_users.update(users)

        # Create table rows
        rows = []

        # First add public if it exists
        if "*" in all_users:
            # Collect all reasons for public

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons("*", "read")
            create_has, create_reasons = self._check_permission_with_reasons("*", "create")
            write_has, write_reasons = self._check_permission_with_reasons("*", "write")
            admin_has, admin_reasons = self._check_permission_with_reasons("*", "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            rows.append(
                [
                    "public",
                    "✓" if read_has else "",
                    "✓" if create_has else "",
                    "✓" if write_has else "",
                    "✓" if admin_has else "",
                    reason_text,
                ]
            )
            all_users.remove("*")  # Remove so we don't process it again

        # Then add all other users
        for user in sorted(all_users):
            # Collect all reasons for this user

            # Check each permission level and collect reasons
            read_has, read_reasons = self._check_permission_with_reasons(user, "read")
            create_has, create_reasons = self._check_permission_with_reasons(user, "create")
            write_has, write_reasons = self._check_permission_with_reasons(user, "write")
            admin_has, admin_reasons = self._check_permission_with_reasons(user, "admin")

            # Collect reasons with permission level prefixes
            permission_reasons = []

            # Collect all reasons with their permission levels
            if admin_has:
                for reason in admin_reasons:
                    permission_reasons.append(f"[Admin] {reason}")

            if write_has:
                for reason in write_reasons:
                    # Skip if this is just hierarchy from admin
                    if "Included via admin permission" not in reason:
                        permission_reasons.append(f"[Write] {reason}")

            if create_has:
                for reason in create_reasons:
                    # Skip if this is just hierarchy from write/admin
                    if (
                        "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Create] {reason}")

            if read_has:
                for reason in read_reasons:
                    # Skip if this is just hierarchy from create/write/admin
                    if (
                        "Included via create permission" not in reason
                        and "Included via write permission" not in reason
                        and "Included via admin permission" not in reason
                    ):
                        permission_reasons.append(f"[Read] {reason}")

            # Format reasons for display
            if not permission_reasons and not any([read_has, create_has, write_has, admin_has]):
                reason_text = "No permissions found"
            else:
                # Smart deduplication: consolidate pattern matches across permission levels
                unique_reasons = []
                seen_patterns = set()
                seen_other = set()

                for reason in permission_reasons:
                    # Extract pattern from reason if it contains "Pattern"
                    if "Pattern '" in reason and "matched" in reason:
                        # Extract just the pattern part
                        pattern_start = reason.find("Pattern '") + 9
                        pattern_end = reason.find("' matched", pattern_start)
                        if pattern_end > pattern_start:
                            pattern = reason[pattern_start:pattern_end]
                            if pattern not in seen_patterns:
                                seen_patterns.add(pattern)
                                # Add pattern match without permission level prefix
                                unique_reasons.append(f"Pattern '{pattern}' matched")
                    else:
                        # For non-pattern reasons, keep the permission-level prefix
                        if reason not in seen_other:
                            seen_other.add(reason)
                            unique_reasons.append(reason)

                reason_text = "; ".join(unique_reasons)

            row = [
                user,
                "✓" if read_has else "",
                "✓" if create_has else "",
                "✓" if write_has else "",
                "✓" if admin_has else "",
                reason_text,
            ]
            rows.append(row)

        return rows

    def __repr__(self) -> str:
        """Return string representation showing permissions table."""
        rows = self._get_permission_table()
        if not rows:
            return f"SyftFolder('{self._path}') - No permissions set"

        try:
            from tabulate import tabulate

            table = tabulate(
                rows,
                headers=["User", "Read", "Create", "Write", "Admin", "Reason"],
                tablefmt="simple",
            )
            return f"SyftFolder('{self._path}')\n\n{table}"
        except ImportError:
            # Fallback to simple table format if tabulate not available
            result = [f"SyftFolder('{self._path}')\n"]
            result.append("User               Read  Create  Write  Admin  Reason")
            result.append("-" * 70)
            for row in rows:
                result.append(
                    f"{row[0]:<20} {row[1]:<5} {row[2]:<7} {row[3]:<6} "
                    f"{row[4]:<5} {row[5] if len(row) > 5 else ''}"
                )
            return "\n".join(result)

    def _ensure_server_and_get_editor_url(self) -> str:
        """Ensure the permission editor server is running and return the editor URL."""
        try:
            from ._auto_recovery import ensure_server_running
            from .server import get_editor_url, get_server_url, start_server

            # Check if server is already running
            server_url = get_server_url()
            if server_url:
                # Verify it's actually responding
                success, error = ensure_server_running(server_url)
                if not success:
                    print(f"Server health check failed: {error}")
                    server_url = None

            if not server_url:
                # Start the server
                server_url = start_server()
                print(f"🚀 SyftPerm permission editor started at: {server_url}")

            # Return the editor URL for this folder
            return get_editor_url(str(self._path))

        except ImportError:
            # FastAPI not available
            return "Install 'syft-perm[server]' for permission editor"
        except Exception as e:
            # Server failed to start
            return f"Permission editor unavailable: {e}"

    def _get_loading_html(self) -> str:
        """Get static HTML to show while server is starting."""
        import threading
        import uuid

        # Generate unique ID for this instance
        instance_id = str(uuid.uuid4())

        # Start server recovery in background
        def start_server_background():
            try:
                self._ensure_server_and_get_editor_url()
            except Exception:
                pass  # Silently fail in background

        thread = threading.Thread(target=start_server_background, daemon=True)
        thread.start()

        # Return static HTML with auto-refresh
        return f"""
        <div id="syft-perm-{instance_id}" style="padding: 20px; background: #f5f5f5; border-radius: 8px; font-family: sans-serif;">  # noqa: E501
            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>
            <div style="background: white; padding: 15px; border-radius: 4px; margin-bottom: 15px;">
                <p style="margin: 0;"><strong>File:</strong> {self._path}</p>
            </div>
            <div style="background: #e3f2fd; padding: 15px; border-radius: 4px; text-align: center;">  # noqa: E501
                <div style="display: inline-block;">
                    <div style="border: 3px solid #1976d2; border-radius: 50%; border-top-color: transparent;  # noqa: E501
                                width: 30px; height: 30px; animation: spin-{instance_id} 1s linear infinite;  # noqa: E501
                                margin: 0 auto 10px;"></div>
                    <p style="color: #1976d2; margin: 0;">Starting permission editor server...</p>
                    <p style="color: #666; font-size: 0.9em; margin-top: 5px;">This may take a moment if auto-recovery is needed</p>  # noqa: E501
                </div>
            </div>
            <style>
                @keyframes spin-{instance_id} {{
                    to {{ transform: rotate(360deg); }}
                }}
            </style>
            <script>
                (function() {{
                    let attempts = 0;
                    const maxAttempts = 30;
                    const checkInterval = 2000;

                    function checkServerAndReload() {{
                        attempts++;

                        // Try to fetch from the expected server
                        fetch('http://127.0.0.1:8765/')
                            .then(response => {{
                                if (response.ok) {{
                                    // Server is ready, reload the cell output
                                    if (window.Jupyter && window.Jupyter.notebook) {{
                                        // Find and re-execute this cell
                                        const cells = window.Jupyter.notebook.get_cells();
                                        for (let cell of cells) {{
                                            if (cell.output_area && cell.output_area.element) {{
                                                const output = cell.output_area.element[0];
                                                if (output && output.innerHTML.includes('syft-perm-{instance_id}')) {{  # noqa: E501
                                                    cell.execute();
                                                    return;
                                                }}
                                            }}
                                        }}
                                    }}
                                }}
                            }})
                            .catch(() => {{
                                // Server not ready yet
                                if (attempts < maxAttempts) {{
                                    setTimeout(checkServerAndReload, checkInterval);
                                }} else {{
                                    // Update the UI to show failure
                                    const elem = document.getElementById('syft-perm-{instance_id}');
                                    if (elem) {{
                                        elem.innerHTML = `
                                            <h3 style="margin-top: 0;">🔐 SyftPerm Permission Manager</h3>  # noqa: E501
                                            <div style="background: #ffebee; padding: 15px; border-radius: 4px; color: #c62828;">  # noqa: E501
                                                <p style="margin: 0;"><strong>Error:</strong> Failed to start permission editor server</p>  # noqa: E501
                                                <p style="margin: 5px 0 0 0; font-size: 0.9em;">Please check your installation and try again</p>  # noqa: E501
                                            </div>
                                        `;
                                    }}
                                }}
                            }});
                    }}

                    // Start checking after a short delay
                    setTimeout(checkServerAndReload, 1000);
                }})();
            </script>
        </div>
        """

    def _repr_html_(self) -> str:
        """Return an interactive iframe when the server is available or a static, read-only widget otherwise."""
        from . import _get_file_editor_url as get_file_editor_url
        from . import _is_dark as is_dark

        # Helper to quickly decide if a returned URL is actually usable
        def _looks_like_valid_url(url: str) -> bool:
            return url.startswith("http://") or url.startswith("https://")

        try:
            editor_url = get_file_editor_url(str(self._path))
            if not _looks_like_valid_url(editor_url):
                raise RuntimeError("permission-editor server unavailable")

            # Preserve syft_user context if present
            if self._syft_user:
                import urllib.parse as _urllib_parse

                sep = "&" if "?" in editor_url else "?"
                editor_url = f"{editor_url}{sep}syft_user={_urllib_parse.quote(self._syft_user)}"

            border_colour = "#3e3e42" if is_dark() else "#ddd"
            bg_colour = "#1e1e1e" if is_dark() else "#ffffff"
            return (
                f'<div style="width:100%;height:600px;border:1px solid {border_colour};'
                f'border-radius:8px;overflow:hidden;background:{bg_colour};">'
                f'<iframe src="{editor_url}" style="width:100%;height:100%;border:none;'
                f'background:transparent;" frameborder="0" allow="clipboard-read; clipboard-write"></iframe></div>'
            )
        except Exception:
            # -----------------------------
            # Offline fallback (read-only)
            # -----------------------------
            import html as _html
            import json as _json
            import uuid as _uuid
            from pathlib import Path as _Path

            from .filesystem_editor import generate_editor_html as _gen_html

            is_dark_mode = is_dark()
            # (no external import needed)

            # Build static data for the in-browser stubbed API
            root_dir = _Path(self._path).parent

            def _build_local_data(start_path: _Path):
                directories: dict = {}
                files: dict = {}

                def _recurse(dir_path: _Path):
                    try:
                        items = []
                        for child in sorted(
                            dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())
                        ):
                            try:
                                stat = child.stat()
                                # Format modified date as ISO string like the server-backed API
                                modified_iso = datetime.fromtimestamp(stat.st_mtime).isoformat()
                                item_info = {
                                    "name": child.name,
                                    "path": str(child),
                                    "is_directory": child.is_dir(),
                                    "size": None if child.is_dir() else stat.st_size,
                                    "modified": modified_iso,
                                    "is_editable": False,  # read-only fallback
                                    "extension": (
                                        child.suffix.lower() if not child.is_dir() else None
                                    ),
                                }
                            except Exception:
                                continue
                            items.append(item_info)

                            if child.is_dir():
                                _recurse(child)
                            else:
                                try:
                                    with open(child, "r", encoding="utf-8", errors="replace") as f:
                                        content = f.read()
                                except Exception:
                                    content = ""
                                if len(content) > 20000:
                                    content = content[:20000] + "\n\n… (truncated)"
                                files[str(child)] = {
                                    "path": str(child),
                                    "content": content,
                                    "size": stat.st_size,
                                    "modified": modified_iso,
                                    "extension": child.suffix.lower(),
                                    "encoding": "utf-8",
                                    "can_write": False,
                                    "can_admin": False,
                                    "write_users": [],
                                }
                        directories[str(dir_path)] = {
                            "path": str(dir_path),
                            "parent": str(dir_path.parent) if dir_path.parent != dir_path else None,
                            "items": items,
                            "total_items": len(items),
                            "can_admin": False,
                        }
                    except Exception:
                        pass

                _recurse(start_path)
                return {"directories": directories, "files": files}

            local_data = _build_local_data(root_dir)
            data_json = _json.dumps(local_data)

            # Base HTML from the editor (we'll stub out its network calls)
            base_html = _gen_html(
                initial_path=str(self._path),
                is_dark_mode=is_dark_mode,
                syft_user=getattr(self, "_syft_user", None),
            )

            # JavaScript stub to override fetch with local data
            stub_script = f"""
<script>
(function() {{
  const LOCAL_DATA = {data_json};
  function makeResp(obj) {{
    return Promise.resolve(new Response(JSON.stringify(obj), {{status: 200, headers: {{'Content-Type': 'application/json'}}}}));
  }}
  window.fetch = function(url, opts) {{
    try {{
      const u = new URL(url, window.location.origin);
      if (u.pathname.startsWith('/api/filesystem/list')) {{
        const p = decodeURIComponent(u.searchParams.get('path') || '');
        if (LOCAL_DATA.directories[p]) return makeResp(LOCAL_DATA.directories[p]);
      }}
      if (u.pathname.startsWith('/api/filesystem/read')) {{
        const p = decodeURIComponent(u.searchParams.get('path') || '');
        if (LOCAL_DATA.files[p]) return makeResp(LOCAL_DATA.files[p]);
      }}
    }} catch (e) {{}}
    return Promise.reject(new Error('Offline read-only viewer'));
  }};
}})();
</script>
"""

            insert_at = base_html.find("<script")
            if insert_at == -1:
                final_html = stub_script + base_html
            else:
                final_html = base_html[:insert_at] + stub_script + base_html[insert_at:]

            return final_html

    def grant_read_access(self, user: str, *, force: bool = False) -> None:
        """Grant read permission to a user."""
        self._grant_access(user, "read", force=force)

    def grant_create_access(self, user: str, *, force: bool = False) -> None:
        """Grant create permission to a user."""
        self._grant_access(user, "create", force=force)

    def grant_write_access(self, user: str, *, force: bool = False) -> None:
        """Grant write permission to a user."""
        if user in ["*", "public"] and not _confirm_action(
            f"⚠️  Warning: Granting public write access to '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "write", force=force)

    def grant_admin_access(self, user: str, *, force: bool = False) -> None:
        """Grant admin permission to a user."""
        if not _confirm_action(
            f"⚠️  Warning: Granting admin access to '{user}' for '{self._path}'. Are you sure?",
            force=force,
        ):
            print("Operation cancelled.")
            return
        self._grant_access(user, "admin", force=force)

    def revoke_read_access(self, user: str) -> None:
        """Revoke read permission from a user."""
        self._revoke_access(user, "read")

    def revoke_create_access(self, user: str) -> None:
        """Revoke create permission from a user."""
        self._revoke_access(user, "create")

    def revoke_write_access(self, user: str) -> None:
        """Revoke write permission from a user."""
        self._revoke_access(user, "write")

    def revoke_admin_access(self, user: str) -> None:
        """Revoke admin permission from a user."""
        self._revoke_access(user, "admin")

    def has_read_access(self, user: str) -> bool:
        """Check if a user has read permission."""
        return self._check_permission(user, "read")

    def has_create_access(self, user: str) -> bool:
        """Check if a user has create permission."""
        return self._check_permission(user, "create")

    def has_write_access(self, user: str) -> bool:
        """Check if a user has write permission."""
        return self._check_permission(user, "write")

    def has_admin_access(self, user: str) -> bool:
        """Check if a user has admin permission."""
        return self._check_permission(user, "admin")

    def _grant_access(
        self,
        user: str,
        permission: Literal["read", "create", "write", "admin"],
        *,
        force: bool = False,
    ) -> None:
        """Internal method to grant permission to a user."""
        # Validate that the email belongs to a datasite
        if not is_datasite_email(user) and not force:
            raise ValueError(
                f"'{user}' is not a valid datasite email. "
                f"Use force=True to override this check."
            )

        # Read all existing permissions for this folder
        access_dict = read_syftpub_yaml(self._path, "**") or {}

        # Update the specific permission
        users = set(access_dict.get(permission, []))
        users.add(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present (even if empty)
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path, "**", access_dict)

        # Invalidate cache for this path and its children
        _permission_cache.invalidate(str(self._path))

    def _revoke_access(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> None:
        """Internal method to revoke permission from a user."""
        access_dict = read_syftpub_yaml(self._path, "**") or {}
        users = set(access_dict.get(permission, []))
        # Handle revoking from public access
        if user in ["*", "public"]:
            users = set()  # Clear all if revoking public
        else:
            users.discard(user)
        access_dict[permission] = format_users(list(users))

        # Make sure all permission types are present
        for perm in ["read", "create", "write", "admin"]:
            if perm not in access_dict:
                access_dict[perm] = []

        update_syftpub_yaml(self._path, "**", access_dict)

        # Invalidate cache for this path and its children
        _permission_cache.invalidate(str(self._path))

    def _check_permission(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> bool:
        """Internal method to check if a user has a specific permission, including inherited."""
        # Get all permissions including inherited ones
        all_perms = self._get_all_permissions()

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            return True

        # Implement permission hierarchy following old syftbox logic: Admin > Write > Create > Read
        # Get all permission sets
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check public access for each level
        everyone_admin = "*" in admin_users
        everyone_write = "*" in write_users
        everyone_create = "*" in create_users
        everyone_read = "*" in read_users

        # Check user-specific access following old syftbox hierarchy logic
        is_admin = everyone_admin or user in admin_users
        is_writer = is_admin or everyone_write or user in write_users
        is_creator = is_writer or everyone_create or user in create_users
        is_reader = is_creator or everyone_read or user in read_users

        # Return based on requested permission level
        if permission == "admin":
            return is_admin
        elif permission == "write":
            return is_writer
        elif permission == "create":
            return is_creator
        elif permission == "read":
            return is_reader

    def _check_permission_with_reasons(
        self, user: str, permission: Literal["read", "create", "write", "admin"]
    ) -> tuple[bool, List[str]]:
        """Check if a user has a specific permission and return reasons why."""
        reasons = []

        # Check if user is the owner using old syftbox logic
        if _is_owner(str(self._path), user):
            reasons.append("Owner of path")
            return True, reasons

        # Get all permissions with source tracking
        perm_data = self._get_all_permissions_with_sources()
        all_perms = perm_data["permissions"]
        sources = perm_data["sources"]
        terminal = perm_data.get("terminal")
        matched_pattern = perm_data.get("matched_pattern")

        # If blocked by terminal
        if terminal and not any(all_perms.values()):
            reasons.append(f"Blocked by terminal at {terminal.parent}")
            return False, reasons

        # Check hierarchy and build reasons
        admin_users = all_perms.get("admin", [])
        write_users = all_perms.get("write", [])
        create_users = all_perms.get("create", [])
        read_users = all_perms.get("read", [])

        # Check if user has the permission through hierarchy
        has_permission = False

        if permission == "admin":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Explicitly granted admin in {src['path'].parent}")
        elif permission == "write":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Explicitly granted write in {src['path'].parent}")
        elif permission == "create":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Explicitly granted create in {src['path'].parent}")
        elif permission == "read":
            if "*" in admin_users or user in admin_users:
                has_permission = True
                if sources.get("admin"):
                    src = sources["admin"][0]
                    reasons.append(f"Included via admin permission in {src['path'].parent}")
            elif "*" in write_users or user in write_users:
                has_permission = True
                if sources.get("write"):
                    src = sources["write"][0]
                    reasons.append(f"Included via write permission in {src['path'].parent}")
            elif "*" in create_users or user in create_users:
                has_permission = True
                if sources.get("create"):
                    src = sources["create"][0]
                    reasons.append(f"Included via create permission in {src['path'].parent}")
            elif "*" in read_users or user in read_users:
                has_permission = True
                if sources.get("read"):
                    src = sources["read"][0]
                    reasons.append(f"Explicitly granted read in {src['path'].parent}")

        # Add pattern info only for the specific permission being checked
        # (not for inherited permissions - that would be confusing)
        if sources.get(permission):
            for src in sources[permission]:
                if src["pattern"]:
                    # Show the pattern that was matched for this specific permission
                    if f"Pattern '{src['pattern']}' matched" not in reasons:
                        reasons.append(f"Pattern '{src['pattern']}' matched")
                    break

        # If we don't have permission but a pattern was matched (terminal or non-terminal),
        # it means the rule was evaluated but didn't grant this permission
        elif matched_pattern and not has_permission:
            if f"Pattern '{matched_pattern}' matched" not in reasons:
                reasons.append(f"Pattern '{matched_pattern}' matched")

        # Check for public access
        if "*" in all_perms.get(permission, []) or (
            has_permission and "*" in [admin_users, write_users, create_users, read_users]
        ):
            if "Public access (*)" not in reasons:
                reasons.append("Public access (*)")

        if not has_permission and not reasons:
            reasons.append("No permission found")

        return has_permission, reasons

    def explain_permissions(self, user: Union[str, None] = None) -> PermissionExplanation:
        """Provide detailed explanation of why user has/lacks permissions.

        Args:
            user: Email of user to analyze. If None, shows permissions for all users.

        Returns:
            PermissionExplanation object that displays nicely in both console and Jupyter
        """
        result = PermissionExplanation(str(self._path), user)

        if user is not None:
            # Single user analysis
            permissions_data = {}
            for perm in ["admin", "write", "create", "read"]:
                has_perm, reasons = self._check_permission_with_reasons(user, perm)  # type: ignore
                permissions_data[perm] = {"granted": has_perm, "reasons": reasons}

            result.add_user_explanation(user, permissions_data)
        else:
            # All users analysis
            # Get all permissions and collect unique users
            all_perms = self._get_all_permissions()
            all_users = set()
            for perm_level in all_perms.values():
                all_users.update(perm_level)

            # Sort users for consistent output
            sorted_users = sorted(all_users)

            for current_user in sorted_users:
                permissions_data = {}
                for perm in ["admin", "write", "create", "read"]:
                    has_perm, reasons = self._check_permission_with_reasons(current_user, perm)  # type: ignore
                    permissions_data[perm] = {"granted": has_perm, "reasons": reasons}

                result.add_user_explanation(current_user, permissions_data)

        return result

    def move_folder_and_permissions(
        self, new_path: Union[str, Path], *, force: bool = False
    ) -> "SyftFolder":
        """
        Move the folder to a new location while preserving all permissions recursively.

        Args:
            new_path: The destination path for the folder
            force: Skip confirmation for moving large folders

        Returns:
            SyftFolder: A new SyftFolder instance pointing to the moved folder

        Raises:
            FileNotFoundError: If source folder doesn't exist
            FileExistsError: If destination folder already exists
            ValueError: If new_path is invalid
        """
        # Resolve and validate paths
        resolved_new_path = resolve_path(str(new_path))
        if resolved_new_path is None:
            raise ValueError("Could not resolve new path")
        new_path = resolved_new_path

        if not self._path.exists():
            raise FileNotFoundError(f"Source folder not found: {self._path}")

        if new_path.exists():
            raise FileExistsError(f"Destination folder already exists: {new_path}")

        # Count files for large folder warning
        file_count = sum(1 for _ in self._path.rglob("*"))
        if file_count > 100 and not _confirm_action(
            f"⚠️  Warning: Moving large folder with {file_count} files. "
            f"This may take a while. Continue?",
            force=force,
        ):
            print("Operation cancelled.")
            return self

        # Get permissions for all files and folders
        permission_map = {}
        for item in self._path.rglob("*"):
            if item.is_file():
                file_obj = SyftFile(item)
                permission_map[item] = file_obj._get_all_permissions()
            elif item.is_dir():
                folder_obj = SyftFolder(item)
                permission_map[item] = folder_obj._get_all_permissions()

        # Also store root folder permissions
        permission_map[self._path] = self._get_all_permissions()

        # Create parent directory if needed
        new_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the folder
        shutil.move(str(self._path), str(new_path))

        # Create new SyftFolder instance
        new_folder = SyftFolder(new_path)

        # Reapply all permissions
        for old_path, perms in permission_map.items():
            # Calculate new path
            rel_path = old_path.relative_to(self._path)
            new_item_path = new_path / rel_path

            # Apply permissions
            if new_item_path.is_file():
                file_obj = SyftFile(new_item_path)
                for permission, users in perms.items():
                    for user in users:
                        if permission in ["read", "create", "write", "admin"]:
                            file_obj._grant_access(user, permission)  # type: ignore[arg-type]
            elif new_item_path.is_dir():
                folder_obj = SyftFolder(new_item_path)
                for permission, users in perms.items():
                    for user in users:
                        if permission in ["read", "create", "write", "admin"]:
                            folder_obj._grant_access(user, permission)  # type: ignore[arg-type]

        return new_folder

    def _get_all_permissions_with_sources(self) -> Dict[str, Any]:
        """Get all permissions for this folder with source information."""
        # Initialize result structure
        result = {
            "permissions": {"read": [], "create": [], "write": [], "admin": []},
            "sources": {"read": [], "create": [], "write": [], "admin": []},
            "terminal": None,
            "terminal_pattern": None,
            "matched_pattern": None,
        }

        # Check if this folder has its own syft.pub.yaml file
        syftpub_path = self._path / "syft.pub.yaml"
        if syftpub_path.exists():
            try:
                with open(syftpub_path, "r") as f:
                    content = yaml.safe_load(f) or {"rules": []}

                # Process rules from the folder's own yaml file
                rules = content.get("rules", [])
                sorted_rules = _sort_rules_by_specificity(rules)
                for rule in sorted_rules:
                    pattern = rule.get("pattern", "")
                    # For the folder's own permissions, we look for "**" pattern
                    if pattern == "**":
                        access = rule.get("access", {})
                        # Check file limits if present
                        limits = rule.get("limits", {})
                        if limits and not limits.get("allow_dirs", True):
                            continue  # Skip this rule for directories

                        # Use this rule's permissions
                        for perm in ["read", "create", "write", "admin"]:
                            users = format_users(access.get(perm, []))
                            result["permissions"][perm] = users
                            if users:
                                result["sources"][perm] = [
                                    {
                                        "path": syftpub_path,
                                        "pattern": pattern,
                                        "terminal": False,
                                        "inherited": False,
                                    }
                                ]

                        result["matched_pattern"] = pattern
                        return result

            except Exception:
                pass

        # If no own permissions found, fall back to SyftFile logic for hierarchical search
        from ._impl import SyftFile

        file_obj = SyftFile(self._path)
        return file_obj._get_all_permissions_with_sources()

    @property
    def share(self):
        """Get the share widget for this file."""
        return ShareWidget(self)
