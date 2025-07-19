"""Editor HTML generation for filesystem editor."""

import os
from pathlib import Path
from typing import Optional

from ..styles import get_editor_styles
from ..themes import get_theme_colors
from .html_structure import get_editor_html_structure
from .javascript import get_editor_javascript


def generate_editor_html(
    initial_path: str = None,
    is_dark_mode: bool = False,
    syft_user: Optional[str] = None,
    is_new_file: bool = False,
) -> str:
    """Generate the HTML for the filesystem code editor."""

    initial_path = initial_path or str(Path.home())

    # Check if initial_path is a file or directory
    is_initial_file = False

    if is_new_file:
        # For new files, treat as a file and set parent directory
        is_initial_file = True
        try:
            path_obj = Path(initial_path)
            initial_dir = str(path_obj.parent)
        except Exception:
            # If path parsing fails, use home directory as fallback
            initial_dir = str(Path.home())
    else:
        try:
            path_obj = Path(initial_path)
            if path_obj.exists() and path_obj.is_file():
                is_initial_file = True
                # For files, we'll pass the parent directory as the current path
                initial_dir = str(path_obj.parent)
            else:
                initial_dir = initial_path
        except Exception:
            initial_dir = initial_path

    # Get theme colors
    theme_colors = get_theme_colors(is_dark_mode)

    # Get CSS styles
    styles = get_editor_styles(theme_colors, is_dark_mode)

    # Get HTML structure
    html_body = get_editor_html_structure(theme_colors)

    # Get JavaScript code
    javascript = get_editor_javascript(
        initial_dir=initial_dir,
        initial_path=initial_path,
        is_initial_file=is_initial_file,
        is_dark_mode=is_dark_mode,
        theme_colors=theme_colors,
        syft_user=syft_user,
        is_new_file=is_new_file,
    )

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SyftBox File Editor</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/{('prism-tomorrow' if is_dark_mode else 'prism')}.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-core.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/plugins/autoloader/prism-autoloader.min.js"></script>
    <style>
    {styles}
    </style>
</head>
<body>
    {html_body}
    <script>
    {javascript}
    </script>
</body>
</html>
"""

    return html_content
