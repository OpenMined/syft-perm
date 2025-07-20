"""Shared HTML generation utilities for consistent rendering."""

from typing import Dict, List, Optional, Union


class HTMLGenerator:
    """
    Generates HTML components that work in both static and interactive modes.

    Features:
    - Mode-aware rendering (static vs interactive)
    - Consistent styling across widgets
    - Automatic disabling of interactive elements in static mode
    - Dark mode support
    """

    def __init__(self, dark_mode: bool = False):
        """
        Initialize the HTML generator.

        Args:
            dark_mode: Whether to use dark mode styling
        """
        self.dark_mode = dark_mode
        self.theme = self._get_theme()

    def _get_theme(self) -> Dict[str, str]:
        """Get theme colors based on mode."""
        if self.dark_mode:
            return {
                "bg": "#1e1e1e",
                "fg": "#d4d4d4",
                "border": "#3e3e42",
                "header_bg": "#252526",
                "card_bg": "#2d2d30",
                "button_bg": "#0e639c",
                "button_hover": "#1177bb",
                "success": "#4ade80",
                "error": "#f87171",
                "warning": "#fbbf24",
                "muted": "#9ca3af",
            }
        else:
            return {
                "bg": "#ffffff",
                "fg": "#1f2937",
                "border": "#e5e7eb",
                "header_bg": "#f9fafb",
                "card_bg": "#f8fafc",
                "button_bg": "#3b82f6",
                "button_hover": "#2563eb",
                "success": "#10b981",
                "error": "#ef4444",
                "warning": "#f59e0b",
                "muted": "#6b7280",
            }

    def render_button(
        self,
        text: str,
        onclick: Optional[str] = None,
        variant: str = "primary",
        disabled: bool = False,
        interactive_only: bool = False,
        icon: Optional[str] = None,
    ) -> str:
        """
        Render a button that works in both modes.

        Args:
            text: Button text
            onclick: JavaScript onclick handler (interactive mode)
            variant: Button variant ('primary', 'secondary', 'danger')
            disabled: Whether button is disabled
            interactive_only: Whether button only works in interactive mode
            icon: Optional icon HTML

        Returns:
            HTML string for button
        """
        # Determine button colors
        if variant == "primary":
            bg_color = self.theme["button_bg"]
            hover_color = self.theme["button_hover"]
            text_color = "#ffffff"
        elif variant == "danger":
            bg_color = self.theme["error"]
            hover_color = "#dc2626"
            text_color = "#ffffff"
        else:  # secondary
            bg_color = self.theme["card_bg"]
            hover_color = self.theme["header_bg"]
            text_color = self.theme["fg"]

        # Build attributes
        attrs = []
        if onclick and not interactive_only:
            attrs.append(f'onclick="{onclick}"')
        if disabled:
            attrs.append("disabled")
        if interactive_only:
            attrs.append('data-interactive-only="true"')

        attrs_str = " ".join(attrs)

        # Build button HTML
        icon_html = f'<span style="margin-right: 6px;">{icon}</span>' if icon else ""

        button_html = f"""
        <button {attrs_str} style="
            background: {bg_color};
            color: {text_color};
            border: none;
            padding: 8px 16px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        " onmouseover="this.style.background='{hover_color}'" onmouseout="this.style.background='{bg_color}'">
            {icon_html}{text}
        </button>
        """

        return button_html

    def render_input(
        self,
        type: str = "text",
        name: Optional[str] = None,
        value: Optional[str] = None,
        placeholder: Optional[str] = None,
        disabled: bool = False,
        interactive_only: bool = False,
    ) -> str:
        """
        Render an input field that works in both modes.

        Args:
            type: Input type
            name: Input name attribute
            value: Initial value
            placeholder: Placeholder text
            disabled: Whether input is disabled
            interactive_only: Whether input only works in interactive mode

        Returns:
            HTML string for input
        """
        attrs = []
        if name:
            attrs.append(f'name="{name}"')
        if value:
            attrs.append(f'value="{value}"')
        if placeholder:
            attrs.append(f'placeholder="{placeholder}"')
        if disabled:
            attrs.append("disabled")
        if interactive_only:
            attrs.append('data-interactive-only="true"')

        attrs_str = " ".join(attrs)

        input_html = f"""
        <input type="{type}" {attrs_str} style="
            background: {self.theme["bg"]};
            color: {self.theme["fg"]};
            border: 1px solid {self.theme["border"]};
            padding: 8px 12px;
            border-radius: 6px;
            font-size: 14px;
            width: 100%;
            transition: border-color 0.2s;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        " onfocus="this.style.borderColor='{self.theme["button_bg"]}'" onblur="this.style.borderColor='{self.theme["border"]}'">
        """

        return input_html

    def render_table(
        self,
        headers: List[str],
        rows: List[List[Union[str, Dict]]],
        interactive_columns: Optional[List[int]] = None,
        sortable: bool = False,
    ) -> str:
        """
        Render a table that works in both modes.

        Args:
            headers: List of header strings
            rows: List of row data (strings or dicts with 'content' and 'interactive')
            interactive_columns: Column indices that are interactive-only
            sortable: Whether table is sortable (interactive mode)

        Returns:
            HTML string for table
        """
        interactive_columns = interactive_columns or []

        # Build header
        header_cells = []
        for i, header in enumerate(headers):
            sortable_attr = (
                'data-sortable="true"' if sortable and i not in interactive_columns else ""
            )
            header_cells.append(
                f'<th {sortable_attr} style="padding: 12px; text-align: left; font-weight: 600; border-bottom: 2px solid {self.theme["border"]};">{header}</th>'
            )

        header_html = (
            f'<tr style="background: {self.theme["header_bg"]};">{"".join(header_cells)}</tr>'
        )

        # Build rows
        row_htmls = []
        for row in rows:
            cells = []
            for i, cell in enumerate(row):
                if isinstance(cell, dict):
                    content = cell.get("content", "")
                    interactive = cell.get("interactive", False)
                else:
                    content = str(cell)
                    interactive = i in interactive_columns

                cell_attrs = 'data-interactive-only="true"' if interactive else ""
                cells.append(
                    f'<td {cell_attrs} style="padding: 12px; border-bottom: 1px solid {self.theme["border"]};">{content}</td>'
                )

            row_htmls.append(f'<tr style="background: {self.theme["bg"]};">{"".join(cells)}</tr>')

        # Build table
        table_html = f"""
        <table style="
            width: 100%;
            border-collapse: collapse;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            color: {self.theme["fg"]};
        ">
            <thead>{header_html}</thead>
            <tbody>{"".join(row_htmls)}</tbody>
        </table>
        """

        return table_html

    def render_card(
        self,
        title: str,
        content: str,
        actions: Optional[List[str]] = None,
        expandable: bool = False,
    ) -> str:
        """
        Render a card component.

        Args:
            title: Card title
            content: Card content HTML
            actions: List of action button HTML strings
            expandable: Whether card is expandable (interactive mode)

        Returns:
            HTML string for card
        """
        expand_button = ""
        if expandable:
            expand_button = f"""
            <button data-interactive-only="true" style="
                background: none;
                border: none;
                color: {self.theme["muted"]};
                cursor: pointer;
                padding: 4px;
            ">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="currentColor">
                    <path fill-rule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clip-rule="evenodd" />
                </svg>
            </button>
            """

        actions_html = ""
        if actions:
            actions_html = f"""
            <div style="display: flex; gap: 8px; margin-top: 16px;">
                {"".join(actions)}
            </div>
            """

        card_html = f"""
        <div style="
            background: {self.theme["card_bg"]};
            border: 1px solid {self.theme["border"]};
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        ">
            <div style="
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 12px;
            ">
                <h3 style="
                    margin: 0;
                    font-size: 16px;
                    font-weight: 600;
                    color: {self.theme["fg"]};
                ">{title}</h3>
                {expand_button}
            </div>
            <div style="color: {self.theme["fg"]};">
                {content}
            </div>
            {actions_html}
        </div>
        """

        return card_html

    def render_notification(
        self, message: str, type: str = "info", dismissible: bool = True
    ) -> str:
        """
        Render a notification component.

        Args:
            message: Notification message
            type: Notification type ('info', 'success', 'warning', 'error')
            dismissible: Whether notification can be dismissed

        Returns:
            HTML string for notification
        """
        # Determine colors based on type
        if type == "success":
            bg_color = "#10b98133"
            border_color = self.theme["success"]
            text_color = "#047857"
        elif type == "warning":
            bg_color = "#f59e0b33"
            border_color = self.theme["warning"]
            text_color = "#92400e"
        elif type == "error":
            bg_color = "#ef444433"
            border_color = self.theme["error"]
            text_color = "#991b1b"
        else:  # info
            bg_color = "#3b82f633"
            border_color = self.theme["button_bg"]
            text_color = "#1e40af"

        dismiss_button = ""
        if dismissible:
            dismiss_button = f"""
            <button onclick="this.parentElement.remove()" style="
                background: none;
                border: none;
                color: {text_color};
                cursor: pointer;
                padding: 0;
                margin-left: 12px;
            ">
                <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor">
                    <path fill-rule="evenodd" d="M4.646 4.646a.5.5 0 01.708 0L8 7.293l2.646-2.647a.5.5 0 01.708.708L8.707 8l2.647 2.646a.5.5 0 01-.708.708L8 8.707l-2.646 2.647a.5.5 0 01-.708-.708L7.293 8 4.646 5.354a.5.5 0 010-.708z" clip-rule="evenodd"/>
                </svg>
            </button>
            """

        notification_html = f"""
        <div style="
            background: {bg_color};
            border: 1px solid {border_color};
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 14px;
            color: {text_color};
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        ">
            <span>{message}</span>
            {dismiss_button}
        </div>
        """

        return notification_html
