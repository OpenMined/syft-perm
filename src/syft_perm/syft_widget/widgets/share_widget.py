"""Share widget using unified infrastructure."""

import urllib.parse
from typing import Any, List, Optional

from ..base import UnifiedWidget
from ..html_generator import HTMLGenerator


class ShareWidgetUnified(UnifiedWidget):
    """Share widget with unified server handling."""

    def __init__(self, syft_object: Any):
        """Initialize the share widget."""
        super().__init__("share")
        self._object = syft_object
        self._path = str(syft_object._path)
        self._syft_user = getattr(syft_object, "_syft_user", None)

        # Check for dark mode
        try:
            from ... import is_dark

            dark_mode = is_dark()
        except Exception:
            dark_mode = False

        self.html_generator = HTMLGenerator(dark_mode=dark_mode)

        # Get permission data for static display
        self._permission_rows = self._get_permission_data()

    def get_static_html(self, **kwargs) -> str:
        """Generate static HTML for share display."""
        # Create header
        header = f"""
        <div style="
            background: {self.html_generator.theme['header_bg']};
            padding: 16px;
            border-bottom: 1px solid {self.html_generator.theme['border']};
        ">
            <h3 style="margin: 0; font-size: 18px; font-weight: 600;">
                🔐 Share Permissions
            </h3>
            <div style="margin-top: 8px; font-size: 14px; color: {self.html_generator.theme['muted']};">
                <strong>Path:</strong> {self._path}
            </div>
        </div>
        """

        # Create permissions table
        if self._permission_rows:
            # Build table rows
            headers = ["User", "Read", "Create", "Write", "Admin", "Actions"]
            rows = []

            for user, read, create, write, admin, *_ in self._permission_rows:
                # Create action buttons (disabled in static mode)
                actions = {
                    "content": f"""
                    <div style="display: flex; gap: 4px;">
                        {self.html_generator.render_button(
                            "Edit",
                            variant="secondary",
                            interactive_only=True,
                            icon="✏️"
                        )}
                        {self.html_generator.render_button(
                            "Remove",
                            variant="danger",
                            interactive_only=True,
                            icon="🗑️"
                        )}
                    </div>
                    """,
                    "interactive": True,
                }

                # Format permission indicators
                read_icon = "✅" if read == "Yes" else "❌"
                create_icon = "✅" if create == "Yes" else "❌"
                write_icon = "✅" if write == "Yes" else "❌"
                admin_icon = "✅" if admin == "Yes" else "❌"

                rows.append(
                    [
                        urllib.parse.unquote(user),
                        read_icon,
                        create_icon,
                        write_icon,
                        admin_icon,
                        actions,
                    ]
                )

            table_html = self.html_generator.render_table(
                headers=headers, rows=rows, interactive_columns=[5]  # Actions column
            )
        else:
            table_html = self.html_generator.render_notification(
                "No permissions configured for this file/folder.", type="info"
            )

        # Add user management section
        add_user_section = f"""
        <div style="
            margin-top: 24px;
            padding: 16px;
            background: {self.html_generator.theme['card_bg']};
            border-radius: 8px;
            border: 1px solid {self.html_generator.theme['border']};
        ">
            <h4 style="margin: 0 0 12px 0; font-size: 16px;">Add User</h4>
            <div style="display: flex; gap: 8px; align-items: flex-end;">
                <div style="flex: 1;">
                    <label style="display: block; margin-bottom: 4px; font-size: 14px;">
                        Email Address
                    </label>
                    {self.html_generator.render_input(
                        type="email",
                        name="new_user_email",
                        placeholder="user@example.com",
                        interactive_only=True
                    )}
                </div>
                {self.html_generator.render_button(
                    "Add User",
                    variant="primary",
                    interactive_only=True,
                    icon="➕"
                )}
            </div>
        </div>
        """

        # Add quick actions
        quick_actions = f"""
        <div style="margin-top: 16px; display: flex; gap: 8px;">
            {self.html_generator.render_button(
                "Make Public",
                variant="secondary",
                interactive_only=True,
                icon="🌍"
            )}
            {self.html_generator.render_button(
                "Copy Share Link",
                variant="secondary",
                interactive_only=True,
                icon="🔗"
            )}
            {self.html_generator.render_button(
                "Export Permissions",
                variant="secondary",
                interactive_only=True,
                icon="📥"
            )}
        </div>
        """

        # Add info message
        info_message = self.html_generator.render_notification(
            "Permission editing requires server connection. Changes are saved automatically.",
            type="info",
            dismissible=True,
        )

        # Combine all elements
        return f"""
        <div class="syft-widget syft-share-widget" style="
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: {self.html_generator.theme['bg']};
            color: {self.html_generator.theme['fg']};
            border: 1px solid {self.html_generator.theme['border']};
            border-radius: 12px;
            overflow: hidden;
        ">
            {header}
            <div style="padding: 16px;">
                {info_message}
                {table_html}
                {add_user_section}
                {quick_actions}
            </div>
        </div>
        """

    def get_interactive_html(self, server_url: str, **kwargs) -> str:
        """Generate interactive HTML that connects to server."""
        # Build URL with parameters
        share_url = f"{server_url}/share-modal?path={urllib.parse.quote(self._path)}"
        if self._syft_user:
            share_url += f"&syft_user={urllib.parse.quote(self._syft_user)}"

        # Return iframe with share modal
        border_color = self.html_generator.theme["border"]
        return f"""
        <div style="width: 100%; height: 600px; border: 1px solid {border_color}; border-radius: 12px; overflow: hidden;">
            <iframe src="{share_url}" style="width: 100%; height: 100%; border: none;"></iframe>
        </div>
        """

    def get_server_endpoint(self) -> str:
        """Get the server endpoint for this widget."""
        return "/share-modal"

    def _get_permission_data(self) -> List[List[str]]:
        """Get permission data from the syft object."""
        try:
            if hasattr(self._object, "_get_permission_table"):
                return self._object._get_permission_table()
            elif hasattr(self._object, "permissions"):
                # Convert permissions to table format
                perms = self._object.permissions
                if perms and hasattr(perms, "to_dict"):
                    perm_dict = perms.to_dict()
                    rows = []

                    # Get all unique users
                    all_users = set()
                    for perm_type in ["read", "create", "write", "admin"]:
                        all_users.update(perm_dict.get(perm_type, []))

                    # Build rows for each user
                    for user in sorted(all_users):
                        row = [
                            user,
                            "Yes" if user in perm_dict.get("read", []) else "No",
                            "Yes" if user in perm_dict.get("create", []) else "No",
                            "Yes" if user in perm_dict.get("write", []) else "No",
                            "Yes" if user in perm_dict.get("admin", []) else "No",
                        ]
                        rows.append(row)

                    return rows
        except Exception:
            pass

        return []
