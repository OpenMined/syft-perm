"""Theme definitions for filesystem editor."""

from typing import Dict


def get_theme_colors(is_dark_mode: bool) -> Dict[str, str]:
    """Get theme colors based on dark/light mode."""

    if is_dark_mode:
        # Dark mode colors
        return {
            "bg_color": "#1e1e1e",
            "text_color": "#d4d4d4",
            "border_color": "#3e3e42",
            "panel_bg": "#252526",
            "panel_header_bg": "#2d2d30",
            "accent_bg": "#2d2d30",
            "muted_color": "#9ca3af",
            "btn_primary_bg": "rgba(59, 130, 246, 0.2)",
            "btn_primary_border": "rgba(59, 130, 246, 0.4)",
            "btn_secondary_bg": "#2d2d30",
            "btn_secondary_hover": "#3e3e42",
            "editor_bg": "#1e1e1e",
            "status_bar_bg": "#252526",
            "status_bar_border": "#3e3e42",
            "breadcrumb_bg": "#252526",
            "file_item_hover": "#2d2d30",
            "empty_state_color": "#9ca3af",
            "error_bg": "rgba(239, 68, 68, 0.1)",
            "error_color": "#ef4444",
            "success_bg": "#065f46",
            "success_border": "#10b981",
        }
    else:
        # Light mode colors
        return {
            "bg_color": "#ffffff",
            "text_color": "#374151",
            "border_color": "#e5e7eb",
            "panel_bg": "#ffffff",
            "panel_header_bg": "#f8f9fa",
            "accent_bg": "#f3f4f6",
            "muted_color": "#6b7280",
            "btn_primary_bg": "rgba(147, 197, 253, 0.25)",
            "btn_primary_border": "rgba(147, 197, 253, 0.4)",
            "btn_secondary_bg": "#f3f4f6",
            "btn_secondary_hover": "#e5e7eb",
            "editor_bg": "#ffffff",
            "status_bar_bg": "#ffffff",
            "status_bar_border": "#e5e7eb",
            "breadcrumb_bg": "#ffffff",
            "file_item_hover": "#f3f4f6",
            "empty_state_color": "#6b7280",
            "error_bg": "rgba(254, 226, 226, 0.5)",
            "error_color": "#dc2626",
            "success_bg": "#dcfce7",
            "success_border": "#bbf7d0",
        }
