"""Visualization components for SyftPerm - permission explanations and share widgets."""

from typing import Any, Dict, List, Union


class PermissionExplanation:
    """
    A permission explanation that renders nicely in both console and Jupyter.
    """

    def __init__(self, path: str, user: Union[str, None] = None):
        self.path = path
        self.user = user
        self.explanations = {}  # Will be populated by the calling method

    def add_user_explanation(self, user: str, permissions_data: Dict[str, Any]):
        """Add explanation data for a user."""
        self.explanations[user] = permissions_data

    def __repr__(self) -> str:
        """Console string representation."""
        if self.user is not None:
            # Single user analysis
            output = f"Permission analysis for {self.user} on {self.path}:\n\n"

            if self.user in self.explanations:
                perms = self.explanations[self.user]
                for perm in ["admin", "write", "create", "read"]:
                    if perm in perms:
                        status = "✓ GRANTED" if perms[perm]["granted"] else "✗ DENIED"
                        output += f"{perm.upper()}: {status}\n"
                        for reason in perms[perm]["reasons"]:
                            output += f"  • {reason}\n"
                        output += "\n"
        else:
            # All users analysis
            output = f"Permission analysis for ALL USERS on {self.path}:\n\n"

            if not self.explanations:
                output += "No users have any permissions on this file/folder.\n"
            else:
                # Sort users for consistent output
                sorted_users = sorted(self.explanations.keys())

                for current_user in sorted_users:
                    output += f"👤 {current_user}:\n"
                    perms = self.explanations[current_user]

                    for perm in ["admin", "write", "create", "read"]:
                        if perm in perms:
                            status = "✓ GRANTED" if perms[perm]["granted"] else "✗ DENIED"
                            output += f"  {perm.upper()}: {status}\n"
                            for reason in perms[perm]["reasons"]:
                                output += f"    • {reason}\n"

                    output += "\n"

        return output

    def _repr_html_(self) -> str:
        """HTML representation for Jupyter notebooks focusing on permission reasons."""
        from .. import _is_dark as is_dark

        # Use the proper dark mode detection
        is_dark_mode = is_dark()

        # Color scheme based on proper theme detection
        if is_dark_mode:
            bg_color = "#1e1e1e"
            text_color = "#d4d4d4"
            border_color = "#3e3e42"
            header_bg = "#252526"
            granted_color = "#4ade80"
            denied_color = "#f87171"
            card_bg = "#2d2d30"
            reason_bg = "#1f1f1f"
        else:
            bg_color = "#ffffff"
            text_color = "#1f2937"
            border_color = "#e5e7eb"
            header_bg = "#f9fafb"
            granted_color = "#10b981"
            denied_color = "#ef4444"
            card_bg = "#f8fafc"
            reason_bg = "#f1f5f9"

        container_id = f"perm_explanation_{hash(str(self.path) + str(self.user or '')) % 10000}"

        if self.user is not None:
            # Single user HTML view - focus on REASONS
            title = f"Permission Reasons: {self.user}"

            html = f"""
            <div id="{container_id}" style="
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 8px;
                margin: 8px 0;
                overflow: hidden;
            ">
                <div style="
                    background: {header_bg};
                    padding: 12px 16px;
                    border-bottom: 1px solid {border_color};
                ">
                    <h3 style="margin: 0; font-size: 16px; font-weight: 600;">{title}</h3>
                    <p style="margin: 4px 0 0 0; font-size: 12px; opacity: 0.7;">{self.path}</p>
                </div>
                <div style="padding: 16px;">
            """

            if self.user in self.explanations:
                perms = self.explanations[self.user]
                for perm in ["admin", "write", "create", "read"]:
                    if perm in perms:
                        granted = perms[perm]["granted"]
                        status_color = granted_color if granted else denied_color
                        status_icon = "✓" if granted else "✗"
                        status_text = "GRANTED" if granted else "DENIED"
                        reasons = perms[perm]["reasons"]

                        html += f"""
                        <div style="
                            margin-bottom: 16px;
                            padding: 16px;
                            background: {card_bg};
                            border-radius: 8px;
                            border-left: 4px solid {status_color};
                        ">
                            <div style="
                                font-weight: 600;
                                margin-bottom: 12px;
                                color: {status_color};
                                display: flex;
                                align-items: center;
                                gap: 8px;
                                font-size: 14px;
                            ">
                                <span>{status_icon}</span>
                                <span>{perm.upper()}: {status_text}</span>
                            </div>
                        """

                        if reasons:
                            html += f"""
                            <div style="
                                background: {reason_bg};
                                border-radius: 6px;
                                padding: 12px;
                                margin-top: 8px;
                            ">
                                <div style="
                                    font-weight: 600;
                                    margin-bottom: 8px;
                                    font-size: 12px;
                                    text-transform: uppercase;
                                    letter-spacing: 0.5px;
                                    opacity: 0.8;
                                ">
                                    Reasons:
                                </div>
                                <ul style="
                                    margin: 0;
                                    padding-left: 20px;
                                    font-size: 13px;
                                    line-height: 1.5;
                                ">
                            """
                            for reason in reasons:
                                html += f"<li style='margin-bottom: 6px;'>{reason}</li>"
                            html += "</ul></div>"
                        else:
                            html += f"""
                            <div style="
                                background: {reason_bg};
                                border-radius: 6px;
                                padding: 12px;
                                margin-top: 8px;
                                font-style: italic;
                                opacity: 0.7;
                                font-size: 13px;
                            ">
                                No specific reasons available
                            </div>
                            """

                        html += "</div>"

            html += "</div></div>"

        else:
            # All users HTML view - focus on REASONS for each user
            title = "Permission Reasons: All Users"

            html = f"""
            <div id="{container_id}" style="
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: {bg_color};
                color: {text_color};
                border: 1px solid {border_color};
                border-radius: 8px;
                margin: 8px 0;
                overflow: hidden;
            ">
                <div style="
                    background: {header_bg};
                    padding: 12px 16px;
                    border-bottom: 1px solid {border_color};
                ">
                    <h3 style="margin: 0; font-size: 16px; font-weight: 600;">{title}</h3>
                    <p style="margin: 4px 0 0 0; font-size: 12px; opacity: 0.7;">{self.path}</p>
                </div>
                <div style="padding: 16px;">
            """

            if not self.explanations:
                html += f"""
                <div style="
                    text-align: center;
                    padding: 24px;
                    opacity: 0.6;
                    font-style: italic;
                ">
                    No users have any permissions on this file/folder.
                </div>
                """
            else:
                sorted_users = sorted(self.explanations.keys())

                for i, current_user in enumerate(sorted_users):
                    if i > 0:
                        html += f"<hr style='margin: 24px 0; border: none; height: 1px; background: {border_color};'>"

                    html += f"""
                    <div style="margin-bottom: 20px;">
                        <h4 style="
                            margin: 0 0 16px 0;
                            font-size: 15px;
                            font-weight: 600;
                            display: flex;
                            align-items: center;
                            gap: 8px;
                            color: {text_color};
                        ">
                            <span>👤</span>
                            <span>{current_user}</span>
                        </h4>
                    """

                    perms = self.explanations[current_user]

                    # Show each permission with its reasons
                    for perm in ["admin", "write", "create", "read"]:
                        if perm in perms:
                            granted = perms[perm]["granted"]
                            status_color = granted_color if granted else denied_color
                            status_icon = "✓" if granted else "✗"
                            status_text = "GRANTED" if granted else "DENIED"
                            reasons = perms[perm]["reasons"]

                            html += f"""
                            <div style="
                                margin-bottom: 12px;
                                padding: 12px;
                                background: {card_bg};
                                border-radius: 6px;
                                border-left: 3px solid {status_color};
                            ">
                                <div style="
                                    font-weight: 600;
                                    margin-bottom: 8px;
                                    color: {status_color};
                                    display: flex;
                                    align-items: center;
                                    gap: 6px;
                                    font-size: 13px;
                                ">
                                    <span>{status_icon}</span>
                                    <span>{perm.upper()}: {status_text}</span>
                                </div>
                            """

                            if reasons:
                                html += f"""
                                <div style="
                                    background: {reason_bg};
                                    border-radius: 4px;
                                    padding: 8px;
                                    margin-top: 6px;
                                ">
                                    <ul style="
                                        margin: 0;
                                        padding-left: 16px;
                                        font-size: 12px;
                                        line-height: 1.4;
                                    ">
                                """
                                for reason in reasons:
                                    html += f"<li style='margin-bottom: 4px;'>{reason}</li>"
                                html += "</ul></div>"

                            html += "</div>"

                    html += "</div>"

            html += "</div></div>"

        return html


class ShareWidget:
    """Widget to display share permissions in an iframe."""

    def __init__(self, syft_object):
        self._object = syft_object
        self._path = str(syft_object._path)

        # Extract user context if available
        self._syft_user = getattr(syft_object, "_syft_user", None)

    def _repr_html_(self) -> str:
        """Return HTML representation for Jupyter display."""
        import urllib.parse as _url

        from .. import _is_dark as is_dark

        # Try to ensure/locate a running server first (same logic we added elsewhere)
        try:
            from ..server import _SERVER_AVAILABLE
            from ..server import get_server_url as _get_url
            from ..server import start_server as _start_server

            if _SERVER_AVAILABLE:
                server_url = _get_url()
                if _SERVER_AVAILABLE and not server_url:
                    # Start background server and grab its url
                    server_url = _start_server()
        except Exception:
            server_url = None  # Any import/start failure -> fallback

        if server_url:
            share_url = f"{server_url}/share-modal?path={_url.quote(self._path)}"
            if self._syft_user:
                share_url += f"&syft_user={_url.quote(self._syft_user)}"
            border = "#3e3e42" if is_dark() else "#ddd"
            return (
                f'<div style="width:100%;height:600px;border:1px solid {border};border-radius:12px;overflow:hidden;">'
                f'<iframe src="{share_url}" style="width:100%;height:100%;border:none;border-radius:12px;"></iframe></div>'
            )

        # ---------------- Offline fallback ----------------
        # Display a simple, read-only permission table similar to __repr__ output
        rows = (
            self._object._get_permission_table()
            if hasattr(self._object, "_get_permission_table")
            else []
        )
        if not rows:
            return f"<pre>Permissions unknown for {self._path}</pre>"

        # Build HTML table manually
        header = "<tr><th>User</th><th>Read</th><th>Create</th><th>Write</th><th>Admin</th></tr>"
        body_rows = []
        for user, r, c, w, a, *_ in rows:
            body_rows.append(
                f"<tr><td>{_url.unquote(user)}</td><td>{r}</td><td>{c}</td><td>{w}</td><td>{a}</td></tr>"
            )
        table_html = (
            "<table style='border-collapse:collapse;'>" + header + "".join(body_rows) + "</table>"
        )

        return (
            f"<div style='font-family: sans-serif; border:1px solid #ccc; padding:15px; border-radius:8px;'>"
            f"<h3 style='margin-top:0;'>Share Permissions (read-only)</h3>"
            f"<p style='margin:4px 0;'><strong>Path:</strong> {self._path}</p>"
            f"{table_html}"  # noqa: E501
            f"<p style='margin-top:10px;color:#888;font-size:0.9em;'>Permission editor unavailable (server dependencies not installed).</p>"
            f"</div>"
        )

    def __repr__(self) -> str:
        """String representation."""
        return f"ShareWidget('{self._path}')"


def get_permission_table_html(rows: List[List[str]], path: str) -> str:
    """
    Generate HTML table representation for permissions.

    Args:
        rows: List of permission rows from _get_permission_table
        path: Path to the file/folder

    Returns:
        HTML string for the permission table
    """
    import urllib.parse as _url

    if not rows:
        return f"<pre>Permissions unknown for {path}</pre>"

    # Build HTML table
    header = "<tr><th>User</th><th>Read</th><th>Create</th><th>Write</th><th>Admin</th></tr>"
    body_rows = []
    for user, r, c, w, a, *_ in rows:
        body_rows.append(
            f"<tr><td>{_url.unquote(user)}</td><td>{r}</td><td>{c}</td><td>{w}</td><td>{a}</td></tr>"
        )
    table_html = (
        "<table style='border-collapse:collapse;'>" + header + "".join(body_rows) + "</table>"
    )

    return (
        f"<div style='font-family: sans-serif; border:1px solid #ccc; padding:15px; border-radius:8px;'>"
        f"<h3 style='margin-top:0;'>Share Permissions</h3>"
        f"<p style='margin:4px 0;'><strong>Path:</strong> {path}</p>"
        f"{table_html}"
        f"</div>"
    )
