#!/usr/bin/env python3
"""Test script for the file editor with syntax highlighting."""

import tempfile
import webbrowser
from pathlib import Path
from src.syft_perm.filesystem_editor import generate_editor_html

def test_editor():
    # Create a temporary HTML file
    html_content = generate_editor_html(is_dark_mode=False)
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
        f.write(html_content)
        temp_file = f.name
    
    print(f"Generated test HTML file: {temp_file}")
    print("Opening in browser...")
    
    # Open in browser
    webbrowser.open(f"file://{temp_file}")
    
    return temp_file

if __name__ == "__main__":
    test_file = test_editor()
    print(f"Test file created at: {test_file}")
    print("You can manually delete this file when done testing.")