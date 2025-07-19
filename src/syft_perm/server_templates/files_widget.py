"""Files widget HTML template for the syft-perm server."""

from typing import List, Optional


def get_files_widget_html(
    search: Optional[str] = None,
    admin: Optional[str] = None,
    folders: Optional[List[str]] = None,
    page: int = 1,
    items_per_page: int = 50,
    start: Optional[int] = None,
    end: Optional[int] = None,
    current_user_email: str = "",
) -> str:
    """Generate the files widget HTML for web serving."""
    import json
    import random
    import uuid

    # Import needed functions
    from .. import _is_dark as is_dark

    container_id = f"syft_files_{uuid.uuid4().hex[:8]}"

    # Check if Jupyter is in dark mode
    is_dark_mode = is_dark()

    # Non-obvious tips for users
    tips = [
        'Use quotation marks to search for exact phrases like "machine learning"',
        "Multiple words without quotes searches for files containing ALL words",
        "Press Tab in search boxes for auto-completion suggestions",
        "Tab completion in Admin filter shows all available datasite emails",
        "Use sp.files.page(5) to jump directly to page 5",
        "Click any row to copy its syft:// path to clipboard",
        'Try sp.files.search("keyword") for programmatic filtering',
        'Use sp.files.filter(extension=".csv") to find specific file types',
        'Chain filters: sp.files.filter(extension=".py").search("test")',
        "Escape special characters with backslash when searching",
        "ASCII loading bar only appears with logger.info(sp.files), not in Jupyter",
        "Loading progress: first 10% is setup, 10-100% is file scanning",
        "Press Escape to close the tab-completion dropdown",
        'Use sp.open("syft://path") to access files programmatically',
        "Search for dates in various formats: 2024-01-15, Jan-15, etc",
        'Admin filter supports partial matching - type "gmail" for all Gmail users',
        "File sizes show as B, KB, MB, or GB automatically",
        "The # column shows files in chronological order by modified date",
        "Empty search returns all files - useful for resetting filters",
        "Search works across file names, paths, and extensions at once",
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
        border: none;
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

    /* Dynamic rainbow class will be created in JavaScript */

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
        padding: 0.09375rem 0.1875rem;
        border-radius: 0.25rem;
        font-size: 0.6875rem;
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

    #{container_id} .btn-green {{
        background: {'#14532d' if is_dark_mode else '#d1fae5'};
        color: {'#4ade80' if is_dark_mode else '#16a34a'};
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

    #{container_id} .btn-blue {{
        background: {'#1e3a8a' if is_dark_mode else '#dbeafe'};
        color: {'#60a5fa' if is_dark_mode else '#3b82f6'};
    }}

    #{container_id} .btn-gray {{
        background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
        color: {'#9ca3af' if is_dark_mode else '#6b7280'};
    }}

    #{container_id} .btn-clickable {{
        cursor: pointer !important;
        opacity: 1 !important;
    }}

    #{container_id} .btn-clickable:hover {{
        opacity: 0.85 !important;
        transform: translateY(-1px);
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
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

    .modal {{
        display: none;
        position: fixed;
        z-index: 1000;
        left: 0;
        top: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.5);
        backdrop-filter: blur(4px);
    }}

    .modal-content {{
        position: relative;
        background-color: {bg_color};
        margin: 10% auto;
        padding: 20px;
        border: 1px solid {border_color};
        border-radius: 8px;
        width: 500px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }}

    .modal-editor {{
        width: 90%;
        height: 80vh;
        max-width: 1200px;
    }}

    .modal-header {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 20px;
        padding-bottom: 10px;
        border-bottom: 1px solid {border_color};
    }}

    .modal-title {{
        font-size: 1.2rem;
        font-weight: 600;
        color: {text_color};
    }}

    .modal-close {{
        cursor: pointer;
        font-size: 1.5rem;
        color: {text_color};
        opacity: 0.6;
        transition: opacity 0.2s;
    }}

    .modal-close:hover {{
        opacity: 1;
    }}

    .modal-body {{
        margin-bottom: 20px;
    }}

    .modal-footer {{
        display: flex;
        justify-content: flex-end;
        gap: 10px;
        padding-top: 10px;
        border-top: 1px solid {border_color};
    }}

    .form-group {{
        margin-bottom: 15px;
    }}

    .form-label {{
        display: block;
        margin-bottom: 5px;
        font-weight: 500;
        color: {text_color};
    }}

    .form-input {{
        width: 100%;
        padding: 8px 24px 8px 12px;
        border: 1px solid {input_border};
        border-radius: 4px;
        background: {input_bg};
        color: {text_color};
        font-size: 0.875rem;
    }}

    .form-hint {{
        margin-top: 5px;
        font-size: 0.75rem;
        color: {page_info_color};
    }}

    .btn-primary {{
        padding: 8px 16px;
        background: {'#3b82f6' if is_dark_mode else '#3b82f6'};
        color: white;
        border: none;
        border-radius: 4px;
        font-size: 0.875rem;
        cursor: pointer;
        transition: background 0.2s;
    }}

    .btn-primary:hover {{
        background: {'#2563eb' if is_dark_mode else '#2563eb'};
    }}

    .btn-secondary {{
        padding: 8px 16px;
        background: {'#4b5563' if is_dark_mode else '#e5e7eb'};
        color: {text_color};
        border: none;
        border-radius: 4px;
        font-size: 0.875rem;
        cursor: pointer;
        transition: background 0.2s;
    }}

    .btn-secondary:hover {{
        background: {'#374151' if is_dark_mode else '#d1d5db'};
    }}

    .autocomplete-option:focus {{
        background: {'#2d2d30' if is_dark_mode else '#f3f4f6'};
        outline: none;
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
                <linearGradient id="paint2_linear_7523_4240" x1="-0.378906" y1="89.7878" 
                               x2="155.761" y2="360.282" gradientUnits="userSpaceOnUse">
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

        <div style="font-size: 20px; font-weight: 600; color: {text_color}; 
                    margin-top: 2rem; text-align: center;">
            loading <br />the private internet
        </div>

        <div style="width: 340px; height: 6px; 
                    background-color: {'#2d2d30' if is_dark_mode else '#e5e5e5'}; 
                    border-radius: 3px; margin: 1.5rem auto; overflow: hidden;">
            <div id="loading-bar-{container_id}" class="progress-bar-gradient" 
                 style="width: 0%; height: 100%;"></div>
        </div>

        <div id="loading-status-{container_id}" 
             style="color: {status_color}; font-size: 0.875rem; margin-top: 0.5rem;">
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
            <input id="{container_id}-admin-filter" placeholder="Filter by Admin..." 
                   style="flex: 1;">
            <select id="rainbowDuration" onchange="updateRainbowDuration_{container_id}()" 
                    style="padding: 0.5rem; border: 1px solid {input_border}; 
                           border-radius: 0.25rem; background: {input_bg}; 
                           color: {text_color}; font-size: 0.875rem;">
                <option value="0">No Rainbow</option>
                <option value="5" selected>5 seconds</option>
                <option value="10">10 seconds</option>
                <option value="30">30 seconds</option>
                <option value="60">1 minute</option>
                <option value="300">5 minutes</option>
                <option value="600">10 minutes</option>
            </select>
            <button class="btn btn-green btn-clickable" onclick="openNewFileModal()">New</button>
            <button class="btn btn-gray btn-clickable" onclick="restartServer()">Refresh</button>
            <button id="{container_id}-delete-selected" class="btn btn-red btn-clickable" 
                    onclick="deleteSelected_{container_id}()" style="display: none;">Delete Selected</button>
            <button id="{container_id}-python-selected" class="btn btn-blue btn-clickable" 
                    onclick="generatePythonCode_{container_id}()" style="display: none;">Python</button>
            <button class="btn btn-purple btn-clickable" 
                    onclick="window.open(window.location.href, '_blank')">Open in Window</button>
        </div>

        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th style="width: 2rem; padding-left: 0.5rem;">
                            <input type="checkbox" id="{container_id}-select-all" 
                                   onclick="toggleSelectAll_{container_id}()"></th>
                        <th style="width: 2.5rem; cursor: pointer;" 
                            onclick="sortTable_{container_id}('index')"># ↕</th>
                        <th style="width: 25rem; cursor: pointer;" 
                            onclick="sortTable_{container_id}('name')">URL ↕</th>
                        <th style="width: 8rem; cursor: pointer;" 
                            onclick="sortTable_{container_id}('modified')">Modified ↕</th>
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
            <div>
                <a href="https://github.com/OpenMined/syft-perm/issues" target="_blank" style="color: {page_info_color}; text-decoration: none; font-size: 0.75rem;">
                    Report a Bug
                </a>
            </div>
            <span class="status" id="{container_id}-status">Loading...</span>
            <div class="pagination-controls">
                <button onclick="changePage_{container_id}(-1)" id="{container_id}-prev-btn" disabled>Previous</button>
                <span class="page-info" id="{container_id}-page-info">Page 1 of 1</span>
                <button onclick="changePage_{container_id}(1)" id="{container_id}-next-btn">Next</button>
            </div>
        </div>
    </div>

    <!-- New File Modal -->
    <div id="newFileModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Create New File</h3>
                <span class="modal-close" onclick="closeNewFileModal()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">File Path</label>
                    <div style="position: relative;">
                        <input type="text" id="newFilePath" class="form-input" placeholder="syft://user@example.com/path/to/file.txt" autocomplete="off">
                        <div id="newFileAutocomplete" class="autocomplete-dropdown"></div>
                    </div>
                    <div class="form-hint">Enter a syft:// path for the new file. Press Tab to autocomplete.</div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeNewFileModal()">Cancel</button>
                <button class="btn btn-primary" onclick="createNewFile()">Create & Edit</button>
            </div>
        </div>
    </div>

    <!-- File Editor Modal -->
    <div id="fileEditorModal" class="modal">
        <div class="modal-content modal-editor">
            <div style="height: 100%; border: 1px solid {border_color}; border-radius: 8px; overflow: hidden;">
                <iframe id="fileEditorFrame" width="100%" height="100%" frameborder="0" style="border: none;"></iframe>
            </div>
        </div>
    </div>

    <script>
    (function() {{
        // Configuration
        var CONFIG = {{
            // Rainbow animation duration in seconds when a file is created/edited
            // Adjust this value to control how long the rainbow effect lasts
            // Examples: 3 = 3 seconds, 10 = 10 seconds, 0.5 = half a second
            rainbowDurationSeconds: 5,

            // Rainbow animation speed (duration of one color cycle in seconds)
            // Lower values = faster rainbow, higher values = slower rainbow
            // Default: 0.8 seconds per color cycle
            rainbowCycleSpeed: 0.8,

            // Current user email
            currentUserEmail: '{current_user_email}'
        }};

        // Calculate iteration count based on config
        var rainbowIterations = CONFIG.rainbowDurationSeconds / CONFIG.rainbowCycleSpeed;

        // Create dynamic CSS for rainbow animation
        var rainbowStyleElement = document.createElement('style');
        rainbowStyleElement.id = 'rainbow-style-{container_id}';
        document.head.appendChild(rainbowStyleElement);

        // Function to update rainbow CSS
        function updateRainbowCSS() {{
            if (CONFIG.rainbowDurationSeconds === 0) {{
                rainbowStyleElement.textContent = '';
                return;
            }}

            var rainbowIterations = CONFIG.rainbowDurationSeconds / CONFIG.rainbowCycleSpeed;
            rainbowStyleElement.textContent = `
                #{container_id} .rainbow-flash-dynamic {{
                    animation: {'rainbow-dark' if is_dark_mode else 'rainbow'} ${{CONFIG.rainbowCycleSpeed}}s ease-in-out;
                    animation-iteration-count: ${{rainbowIterations}};
                    animation-duration: ${{CONFIG.rainbowCycleSpeed}}s;
                }}
            `;
        }}

        // Initial CSS update
        updateRainbowCSS();

        // Initialize variables
        var allFiles = [];
        var filteredFiles = [];
        var currentPage = {page};
        var itemsPerPage = {items_per_page};
        var sortColumn = 'modified';  // Default sort by modified date
        var sortDirection = 'desc';    // Default descending (newest first)
        var chronologicalIds = {{}};
        var currentUserEmail = {json.dumps(current_user_email, ensure_ascii=True, separators=(',', ':'))};

        // WebSocket for real-time file updates
        var ws = null;
        var wsReconnectInterval = null;
        var wsUrl = window.location.protocol.replace('http', 'ws') + '//' + window.location.host + '/ws/file-updates';

        function connectWebSocket() {{
            if (ws && ws.readyState === WebSocket.OPEN) {{
                return;
            }}

            try {{
                ws = new WebSocket(wsUrl);

                ws.onopen = function() {{
                    console.log('[WebSocket] Connected for file updates');
                    if (wsReconnectInterval) {{
                        clearInterval(wsReconnectInterval);
                        wsReconnectInterval = null;
                    }}
                    // Send periodic ping to keep connection alive
                    setInterval(function() {{
                        if (ws && ws.readyState === WebSocket.OPEN) {{
                            ws.send('ping');
                        }}
                    }}, 30000); // Every 30 seconds
                }};

                ws.onmessage = function(event) {{
                    if (event.data === 'pong') {{
                        return; // Ignore pong responses
                    }}

                    try {{
                        var data = JSON.parse(event.data);
                        handleFileUpdate(data);
                    }} catch (e) {{
                        console.error('[WebSocket] Error parsing message:', e);
                    }}
                }};

                ws.onclose = function() {{
                    console.log('[WebSocket] Disconnected');
                    // Try to reconnect every 5 seconds
                    if (!wsReconnectInterval) {{
                        wsReconnectInterval = setInterval(connectWebSocket, 5000);
                    }}
                }};

                ws.onerror = function(error) {{
                    console.error('[WebSocket] Error:', error);
                }};
            }} catch (e) {{
                console.error('[WebSocket] Failed to connect:', e);
            }}
        }}

        // Connect WebSocket
        connectWebSocket();

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

                // Get current URL parameters
                const urlParams = new URLSearchParams(window.location.search);
                const apiParams = new URLSearchParams();

                // Pass through relevant parameters
                if (urlParams.has('search')) apiParams.set('search', urlParams.get('search'));
                if (urlParams.has('admin')) apiParams.set('admin', urlParams.get('admin'));
                if (urlParams.has('folders')) apiParams.set('folders', urlParams.get('folders'));
                if (urlParams.has('start')) apiParams.set('start', urlParams.get('start'));
                if (urlParams.has('end')) apiParams.set('end', urlParams.get('end'));

                // Start fetching files data (this will trigger the scan)
                const filesPromise = fetch('/api/files-data' + (apiParams.toString() ? '?' + apiParams.toString() : ''));

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

                // Create chronological IDs (oldest = 0, incrementing)
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
                document.getElementById('loading-container-{container_id}').style.display = 'none';
                document.getElementById('{container_id}').style.display = 'flex';

                // Initial render
                renderTable();
                updateStatus();

            }} catch (error) {{
                console.error('Error loading files:', error);
                updateProgress(0, 'Error loading files. Please refresh the page.');
            }}
        }}

        var showFooterTip = {'true' if show_footer_tip else 'false'};
        var footerTip = {json.dumps(footer_tip, ensure_ascii=True, separators=(',', ':'))};

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

        // Parse search terms (helper function)
        function parseSearchTerms(search) {{
            var terms = [];
            var currentTerm = '';
            var inQuotes = false;

            for (var i = 0; i < search.length; i++) {{
                var char = search[i];
                if (char === '"') {{
                    inQuotes = !inQuotes;
                }} else if (char === ' ' && !inQuotes) {{
                    if (currentTerm) {{
                        terms.push(currentTerm.toLowerCase());
                        currentTerm = '';
                    }}
                }} else {{
                    currentTerm += char;
                }}
            }}

            if (currentTerm) {{
                terms.push(currentTerm.toLowerCase());
            }}

            return terms;
        }}

        function showStatus(message) {{
            var statusEl = document.getElementById('{container_id}-status');
            if (statusEl) statusEl.textContent = message;
        }}

        // Restart server function - expose globally
        window.restartServer = async function() {{
            try {{
                showStatus('Restarting server...');

                const response = await fetch('/api/restart', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json'
                    }}
                }});

                if (response.ok) {{
                    showStatus('Server is restarting. Page will reload...');

                    // Wait a bit then reload the page
                    setTimeout(() => {{
                        window.location.reload();
                    }}, 2000);
                }} else {{
                    showStatus('Failed to restart server');
                }}
            }} catch (error) {{
                console.error('Error restarting server:', error);
                showStatus('Error restarting server');
            }}
        }};

        // Modal functions - expose globally
        window.openNewFileModal = function(prefilledPath) {{
            document.getElementById('newFileModal').style.display = 'block';
            var pathInput = document.getElementById('newFilePath');

            // If a path is provided, use it (from row "New" button)
            if (prefilledPath) {{
                pathInput.value = 'syft://' + prefilledPath + '/';
            }} else {{
                // Try to auto-populate with current user's datasite
                if (typeof currentUserEmail !== 'undefined' && currentUserEmail) {{
                    pathInput.value = 'syft://' + currentUserEmail + '/';
                }} else {{
                    // Try to detect from existing files
                    var userEmails = new Set();
                    allFiles.forEach(function(file) {{
                        if (file.datasite_owner) {{
                            userEmails.add(file.datasite_owner);
                        }}
                    }});

                    // If only one user, use that
                    if (userEmails.size === 1) {{
                        var email = Array.from(userEmails)[0];
                        pathInput.value = 'syft://' + email + '/';
                    }}
                }}
            }}

            pathInput.focus();
            // Move cursor to end
            pathInput.setSelectionRange(pathInput.value.length, pathInput.value.length);

            // Trigger autocomplete to show suggestions
            if (pathInput.value) {{
                // Use setTimeout to ensure the focus and DOM updates are complete
                setTimeout(function() {{
                    var event = new Event('input', {{ bubbles: true }});
                    pathInput.dispatchEvent(event);
                }}, 10);
            }}
        }};

        window.closeNewFileModal = function() {{
            document.getElementById('newFileModal').style.display = 'none';
            document.getElementById('newFilePath').value = '';
            var dropdown = document.getElementById('newFileAutocomplete');
            dropdown.innerHTML = '';
            dropdown.classList.remove('show');
            // Note: restoreArrowKeys is scoped to setupNewFileAutocomplete
        }};

        window.createNewFile = function() {{
            var filePath = document.getElementById('newFilePath').value.trim();

            if (!filePath) {{
                alert('Please enter a file path');
                return;
            }}

            // Validate syft:// format
            if (!filePath.startsWith('syft://')) {{
                alert('File path must start with syft://');
                return;
            }}

            // Close the first modal
            closeNewFileModal();

            // Open the editor modal with the new file
            var editorUrl = '/file-editor?path=' + encodeURIComponent(filePath) + '&new=true&embedded=true';
            document.getElementById('fileEditorFrame').src = editorUrl;
            document.getElementById('fileEditorModal').style.display = 'block';
        }};

        // Close modal when clicking outside
        window.onclick = function(event) {{
            var newFileModal = document.getElementById('newFileModal');
            var editorModal = document.getElementById('fileEditorModal');

            if (event.target === newFileModal) {{
                closeNewFileModal();
            }} else if (event.target === editorModal) {{
                document.getElementById('fileEditorModal').style.display = 'none';
                document.getElementById('fileEditorFrame').src = '';
            }}
        }}

        // Autocomplete for new file path
        var autocompleteIndex = -1;
        var autocompleteSuggestions = [];

        function setupNewFileAutocomplete() {{
            var input = document.getElementById('newFilePath');
            var dropdown = document.getElementById('newFileAutocomplete');

            function showAutocompleteSuggestions() {{
                var value = input.value;
                autocompleteIndex = -1;
                autocompleteSuggestions = [];

                if (!value || !value.includes('://')) {{
                    dropdown.innerHTML = '';
                    dropdown.classList.remove('show');
                    return;
                }}

                // Parse the current input
                var parts = value.split('://');
                if (parts.length !== 2 || parts[0] !== 'syft') {{
                    dropdown.innerHTML = '';
                    dropdown.classList.remove('show');
                    return;
                }}

                var pathPart = parts[1];
                var pathSegments = pathPart.split('/');
                var userPart = pathSegments[0];
                var currentPath = pathSegments.slice(1).join('/');

                // Get unique datasites
                var datasites = new Set();
                allFiles.forEach(function(file) {{
                    if (file.datasite_owner) {{
                        datasites.add(file.datasite_owner);
                    }}
                }});

                autocompleteSuggestions = [];

                // If still typing the user part
                if (!userPart.includes('@') || pathSegments.length === 1) {{
                    // Suggest datasites
                    Array.from(datasites).forEach(function(datasite) {{
                        if (datasite.toLowerCase().includes(userPart.toLowerCase())) {{
                            autocompleteSuggestions.push('syft://' + datasite + '/');
                        }}
                    }});
                }} else {{
                    // Suggest paths within the datasite (only folders with create permissions)
                    var uniquePaths = new Set();
                    allFiles.forEach(function(file) {{
                        if (file.datasite_owner === userPart && file.name.startsWith(userPart + '/') && file.is_dir) {{
                            // Check if user has create permissions for this folder
                            var canCreate = false;
                            if (file.permissions && currentUserEmail) {{
                                if (file.permissions.admin && file.permissions.admin.includes(currentUserEmail)) {{
                                    canCreate = true;
                                }} else if (file.permissions.write && file.permissions.write.includes(currentUserEmail)) {{
                                    canCreate = true;
                                }} else if (file.permissions.create && file.permissions.create.includes(currentUserEmail)) {{
                                    canCreate = true;
                                }}
                            }}

                            // Also check permissions_summary
                            if (!canCreate && file.permissions_summary && currentUserEmail) {{
                                for (var k = 0; k < file.permissions_summary.length; k++) {{
                                    var summary = file.permissions_summary[k];
                                    if (summary.includes(currentUserEmail)) {{
                                        if (summary.startsWith('admin: ') || summary.startsWith('write: ') || summary.startsWith('create: ')) {{
                                            canCreate = true;
                                            break;
                                        }}
                                    }}
                                }}
                            }}

                            // Only suggest if user has create permissions
                            if (canCreate) {{
                                var filePath = file.name.substring(userPart.length + 1);
                                var segments = filePath.split('/');

                                // Build partial paths for autocomplete
                                var partialPath = '';
                                for (var i = 0; i < segments.length; i++) {{
                                    if (i > 0) partialPath += '/';
                                    partialPath += segments[i];

                                    // Only suggest if it matches current input
                                    if (partialPath.toLowerCase().startsWith(currentPath.toLowerCase()) &&
                                        partialPath.length > currentPath.length) {{
                                        uniquePaths.add('syft://' + userPart + '/' + partialPath);
                                    }}
                                }}
                            }}
                        }}
                    }});
                    autocompleteSuggestions = Array.from(uniquePaths).sort();
                }}

                // Show suggestions
                if (autocompleteSuggestions.length > 0) {{
                    dropdown.innerHTML = '';
                    autocompleteSuggestions.slice(0, 10).forEach(function(suggestion, index) {{
                        var option = document.createElement('div');
                        option.className = 'autocomplete-option';
                        option.textContent = suggestion;
                        option.tabIndex = -1; // Make focusable but not in tab order
                        option.onclick = function() {{
                            input.value = suggestion;
                            dropdown.innerHTML = '';
                            dropdown.classList.remove('show');
                            autocompleteIndex = -1;
                            autocompleteSuggestions = [];
                            input.focus();
                        }};
                        // Handle keyboard events on the option itself
                        option.addEventListener('keydown', function(e) {{
                            if (e.key === 'Enter') {{
                                e.preventDefault();
                                input.value = suggestion;
                                dropdown.innerHTML = '';
                                dropdown.classList.remove('show');
                                input.focus();
                            }} else if (e.key === 'Escape') {{
                                dropdown.innerHTML = '';
                                dropdown.classList.remove('show');
                                input.focus();
                            }} else if (e.key === 'ArrowDown') {{
                                e.preventDefault();
                                var nextOption = option.nextElementSibling;
                                if (nextOption) {{
                                    nextOption.focus();
                                }}
                            }} else if (e.key === 'ArrowUp') {{
                                e.preventDefault();
                                var prevOption = option.previousElementSibling;
                                if (prevOption) {{
                                    prevOption.focus();
                                }} else {{
                                    input.focus();
                                }}
                            }}
                        }});
                        dropdown.appendChild(option);
                    }});
                    dropdown.classList.add('show');
                    overrideArrowKeys(); // Override arrow keys when showing dropdown
                }} else {{
                    dropdown.innerHTML = '';
                    dropdown.classList.remove('show');
                    restoreArrowKeys(); // Restore arrow keys when hiding dropdown
                }}
            }}

            input.addEventListener('input', showAutocompleteSuggestions);
            input.addEventListener('focus', showAutocompleteSuggestions);

            // Override the input's default arrow key behavior
            var originalKeyDown = null;

            // When dropdown is shown, override arrow key behavior
            function overrideArrowKeys() {{
                if (!originalKeyDown) {{
                    originalKeyDown = input.onkeydown;
                    input.onkeydown = function(e) {{
                        if ((e.key === 'ArrowDown' || e.key === 'ArrowUp') && dropdown.classList.contains('show')) {{
                            return false;
                        }}
                        if (originalKeyDown) return originalKeyDown.call(this, e);
                    }};
                }}
            }}

            // Restore original behavior when dropdown is hidden
            function restoreArrowKeys() {{
                if (originalKeyDown !== null) {{
                    input.onkeydown = originalKeyDown;
                    originalKeyDown = null;
                }}
            }}

            // Handle keyboard navigation with capture phase to ensure it runs first
            input.addEventListener('keydown', function(e) {{
                // Use the outer dropdown variable, don't redeclare
                var options = dropdown.querySelectorAll('.autocomplete-option');

                if (e.key === 'Tab') {{
                    e.preventDefault();
                    if (autocompleteSuggestions.length > 0) {{
                        if (autocompleteIndex === -1) {{
                            // Use first suggestion
                            input.value = autocompleteSuggestions[0];
                        }} else {{
                            // Use selected suggestion
                            input.value = autocompleteSuggestions[autocompleteIndex];
                        }}
                        dropdown.innerHTML = '';
                        dropdown.classList.remove('show');
                        restoreArrowKeys();
                    }}
                }} else if (e.key === 'ArrowDown') {{
                    if (dropdown.classList.contains('show') && autocompleteSuggestions.length > 0) {{
                        e.preventDefault();
                        var firstOption = dropdown.querySelector('.autocomplete-option');
                        if (firstOption) {{
                            firstOption.focus();
                        }}
                        return false;
                    }}
                }} else if (e.key === 'ArrowUp') {{
                    if (dropdown.classList.contains('show') && autocompleteSuggestions.length > 0) {{
                        e.preventDefault();
                        var lastOption = dropdown.querySelector('.autocomplete-option:last-child');
                        if (lastOption) {{
                            lastOption.focus();
                        }}
                        return false;
                    }}
                }} else if (e.key === 'Enter') {{
                    if (autocompleteIndex >= 0 && autocompleteIndex < autocompleteSuggestions.length) {{
                        e.preventDefault();
                        input.value = autocompleteSuggestions[autocompleteIndex];
                        dropdown.innerHTML = '';
                        dropdown.classList.remove('show');
                    }}
                }} else if (e.key === 'Escape') {{
                    dropdown.innerHTML = '';
                    dropdown.classList.remove('show');
                    autocompleteIndex = -1;
                    restoreArrowKeys();
                }}
            }}, true); // Use capture phase

            // Hide dropdown when clicking outside
            document.addEventListener('click', function(e) {{
                if (!input.contains(e.target) && !dropdown.contains(e.target)) {{
                    dropdown.innerHTML = '';
                    dropdown.classList.remove('show');
                    restoreArrowKeys();
                }}
            }});
        }}

        function updateAutocompleteSelection(options) {{
            options.forEach(function(option, index) {{
                if (index === autocompleteIndex) {{
                    option.classList.add('selected');
                }} else {{
                    option.classList.remove('selected');
                }}
            }});
        }}

        // Update rainbow duration from dropdown
        window.updateRainbowDuration_{container_id} = function() {{
            var dropdown = document.getElementById('rainbowDuration');
            var newDuration = parseInt(dropdown.value);
            CONFIG.rainbowDurationSeconds = newDuration;

            // Update the CSS
            updateRainbowCSS();

            // Re-render the table to apply new animation to eligible files
            renderTable();

            // Show status message
            if (newDuration === 0) {{
                showStatus('Rainbow animation disabled');
            }} else if (newDuration >= 60) {{
                var minutes = newDuration / 60;
                showStatus('Rainbow animation set to ' + minutes + ' minute' + (minutes > 1 ? 's' : ''));
            }} else {{
                showStatus('Rainbow animation set to ' + newDuration + ' seconds');
            }}
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

        // Handle file updates from WebSocket
        function handleFileUpdate(data) {{
            var action = data.action;
            var file = data.file;

            console.log('[WebSocket] File', action + ':', file.path);

            // Find existing file index
            var existingIndex = -1;
            for (var i = 0; i < allFiles.length; i++) {{
                if (allFiles[i].path === file.path) {{
                    existingIndex = i;
                    break;
                }}
            }}

            if (action === 'created') {{
                // Assign next chronological ID to the new file (count existing files first)
                var newId = allFiles.length; // This is the next ID
                var fileKey = file.name + '|' + file.path;
                chronologicalIds[fileKey] = newId;
                file.chronoId = newId; // Also set it on the file object itself
                console.log('[WebSocket] Assigned chronological ID', newId, 'to', file.name, '(total files before adding:', allFiles.length, ')');

                // Add new file to beginning (newest first)
                allFiles.unshift(file);

                // Apply current filters by calling searchFiles
                // This will automatically filter, sort, render table, and update status
                searchFiles_{container_id}();
            }} else if (action === 'modified') {{
                if (existingIndex !== -1) {{
                    // Preserve the existing chronological ID
                    var oldFile = allFiles[existingIndex];
                    var fileKey = file.name + '|' + file.path;
                    var existingChronoId = oldFile.chronoId !== undefined ? oldFile.chronoId : chronologicalIds[fileKey];

                    // Update file data
                    allFiles[existingIndex] = file;

                    // Restore the chronological ID (don't change it for modified files)
                    file.chronoId = existingChronoId;
                    if (existingChronoId !== undefined) {{
                        chronologicalIds[fileKey] = existingChronoId;
                    }}

                    console.log('[WebSocket] Modified file', file.name, 'keeping chronological ID', existingChronoId);

                    // Re-apply filters by calling searchFiles
                    // This will automatically filter, sort, render table, and update status
                    searchFiles_{container_id}();
                }}
            }} else if (action === 'deleted') {{
                if (existingIndex !== -1) {{
                    // Remove from allFiles
                    allFiles.splice(existingIndex, 1);

                    // Remove chronological ID for deleted file
                    var fileKey = file.name + '|' + file.path;
                    delete chronologicalIds[fileKey];

                    // Re-apply filters by calling searchFiles
                    // This will automatically filter, sort, render table, and update status
                    searchFiles_{container_id}();
                }}
            }}
        }}

        // Check if file matches current filters
        function matchesCurrentFilters(file) {{
            var searchValue = document.getElementById('{container_id}-search').value;
            var adminFilter = document.getElementById('{container_id}-admin-filter').value;

            // Apply admin filter
            if (adminFilter && (file.datasite_owner || '').toLowerCase().indexOf(adminFilter.toLowerCase()) === -1) {{
                return false;
            }}

            // Apply search filter
            if (searchValue) {{
                var searchTerms = parseSearchTerms(searchValue);

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
            }}

            return true;
        }}

        // Update chronological IDs after file changes
        function updateChronologicalIds() {{
            var sortedByDate = allFiles.slice().sort(function(a, b) {{
                return (a.modified || 0) - (b.modified || 0);  // Sort oldest first
            }});

            chronologicalIds = {{}};
            for (var i = 0; i < sortedByDate.length; i++) {{
                var file = sortedByDate[i];
                var fileKey = file.name + '|' + file.path;
                chronologicalIds[fileKey] = i;  // Start from 0
            }}
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

                var fileKey = file.name + '|' + file.path;
                var chronoId = file.chronoId !== undefined ? file.chronoId : (chronologicalIds[fileKey] !== undefined ? chronologicalIds[fileKey] : i);

                // Prepare escaped path for onclick handlers
                var escapedPath = (file.path || filePath || '').replace(/\\\\/g, '\\\\\\\\').replace(/'/g, "\\\\'");

                // Check if this file was modified within the threshold (rainbow duration + buffer)
                var wsActionClass = '';
                var now = Date.now() / 1000; // Convert to seconds
                var fileModified = file.modified || 0;
                var secondsSinceModified = now - fileModified;

                // Show rainbow if enabled and modified within the animation duration
                if (CONFIG.rainbowDurationSeconds > 0 && secondsSinceModified <= CONFIG.rainbowDurationSeconds) {{
                    wsActionClass = ' class="file-row rainbow-flash-dynamic"';
                }} else {{
                    wsActionClass = ' class="file-row"';
                }}

                html += '<tr' + wsActionClass + ' onclick="copyPath_{container_id}(\\'syft://' + filePath + '\\', this)">' +
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

                // Check if current user is admin for this file
                var isAdmin = false;
                var canCreate = false;

                // Check permissions object first
                if (file.permissions && CONFIG.currentUserEmail) {{
                    if (file.permissions.admin && file.permissions.admin.includes(CONFIG.currentUserEmail)) {{
                        isAdmin = true;
                        canCreate = true; // Admin implies all permissions
                    }} else if (file.permissions.write && file.permissions.write.includes(CONFIG.currentUserEmail)) {{
                        canCreate = true; // Write implies create
                    }} else if (file.permissions.create && file.permissions.create.includes(CONFIG.currentUserEmail)) {{
                        canCreate = true;
                    }}
                }}

                // If not found in permissions object, check permissions_summary
                if (!isAdmin && !canCreate && file.permissions_summary && CONFIG.currentUserEmail) {{
                    for (var j = 0; j < file.permissions_summary.length; j++) {{
                        var summary = file.permissions_summary[j];
                        if (summary.includes(CONFIG.currentUserEmail)) {{
                            if (summary.startsWith('admin: ')) {{
                                isAdmin = true;
                                canCreate = true;
                                break;
                            }} else if (summary.startsWith('write: ')) {{
                                canCreate = true;
                            }} else if (summary.startsWith('create: ')) {{
                                canCreate = true;
                            }}
                        }}
                    }}
                }}

                html += '</div>' +
                    '</td>' +
                    '<td>' +
                        '<div style="display: flex; gap: 0.03125rem;">';

                // Add "New" button based on folder status and permissions
                if (file.is_dir && canCreate) {{
                    html += '<button class="btn btn-green btn-clickable" onclick="event.stopPropagation(); openNewModal_' + '{container_id}' + '(\\'' + escapedPath + '\\')" title="Create new file or folder">' +
                                '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                                    '<line x1="12" y1="5" x2="12" y2="19"></line>' +
                                    '<line x1="5" y1="12" x2="19" y2="12"></line>' +
                                '</svg></button>';
                }} else {{
                    var disabledReason = !file.is_dir ? "New files can only be created in folders" : "You need create, write, or admin permissions to create files";
                    html += '<button class="btn btn-gray" style="opacity: 0.3; cursor: not-allowed;" title="' + disabledReason + '" disabled>' +
                                '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                                    '<line x1="12" y1="5" x2="12" y2="19"></line>' +
                                    '<line x1="5" y1="12" x2="19" y2="12"></line>' +
                                '</svg></button>';
                }}

                html += '<button class="btn btn-gray btn-clickable" onclick="event.stopPropagation(); openFileEditor_' + '{container_id}' + '(\\'' + escapedPath + '\\')" title="Open in editor">Open</button>';

                if (isAdmin) {{
                    html += '<button class="btn btn-blue btn-clickable" onclick="event.stopPropagation(); openShareModal_' + '{container_id}' + '(\\'' + escapedPath + '\\')" title="Share permissions">' +
                                '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
                                    '<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/>' +
                                    '<polyline points="16 6 12 2 8 6"/>' +
                                    '<line x1="12" y1="2" x2="12" y2="15"/>' +
                                '</svg> Share</button>';
                }} else {{
                    html += '<button class="btn btn-gray" disabled title="Only admins can share">' +
                                '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="opacity: 0.5;">' +
                                    '<path d="M4 12v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-8"/>' +
                                    '<polyline points="16 6 12 2 8 6"/>' +
                                    '<line x1="12" y1="2" x2="12" y2="15"/>' +
                                '</svg> Share</button>';
                }}

                html += '<button class="btn btn-purple btn-clickable" onclick="event.stopPropagation(); copyPath_' + '{container_id}' + '(\\'' + escapedPath + '\\')" title="Copy path">Copy</button>';

                // Add delete button with permission check
                var canDelete = isAdmin || canCreate; // Users with write or admin permissions can delete
                if (canDelete) {{
                    html += '<button class="btn btn-red btn-clickable" ' +
                            'onclick="event.stopPropagation(); confirmDelete_' + '{container_id}' + 
                            '(\\'' + escapedPath + '\\')" ' +
                            'title="Delete ' + (isDir ? 'folder' : 'file') + '">' +
                                '<svg class="icon" viewBox="0 0 24 24" ' +
                                'fill="none" stroke="currentColor" stroke-width="2">' +
                                    '<path d="M3 6h18"></path>' +
                                    '<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>' +
                                    '<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>' +
                                    '<line x1="10" x2="10" y1="11" y2="17"></line>' +
                                    '<line x1="14" x2="14" y1="11" y2="17"></line>' +
                                '</svg>' +
                            '</button>';
                }} else {{
                    html += '<button class="btn btn-gray" disabled ' +
                            'title="You need write or admin permissions to delete" ' +
                            'style="opacity: 0.3; cursor: not-allowed;">' +
                                '<svg class="icon" viewBox="0 0 24 24" ' +
                                'fill="none" stroke="currentColor" stroke-width="2" ' +
                                'style="opacity: 0.5;">' +
                                    '<path d="M3 6h18"></path>' +
                                    '<path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"></path>' +
                                    '<path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"></path>' +
                                    '<line x1="10" x2="10" y1="11" y2="17"></line>' +
                                    '<line x1="14" x2="14" y1="11" y2="17"></line>' +
                                '</svg>' +
                            '</button>';
                }}

                html += '</div>' +
                    '</td>' +
                '</tr>';
            }}

            tbody.innerHTML = html;
        }}

        // Search files
        window.searchFiles_{container_id} = function() {{
            var searchTerm = document.getElementById('{container_id}-search').value.toLowerCase();
            var adminFilter = document.getElementById('{container_id}-admin-filter')
                .value.toLowerCase();

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
                var adminMatch = adminFilter === '' || 
                    (file.datasite_owner || '').toLowerCase().includes(adminFilter);
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

            // Sort the filtered files according to current sort settings
            // Use a copy of the sort logic without toggling direction
            filteredFiles.sort(function(a, b) {{
                var aVal, bVal;

                switch(sortColumn) {{
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

            // Calculate total pages after filtering
            var totalPages = Math.max(1, Math.ceil(filteredFiles.length / itemsPerPage));

            // Preserve current page if it's still valid, otherwise go to last valid page
            if (currentPage > totalPages) {{
                currentPage = totalPages;
            }}

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

        // Copy path - for button click
        window.copyPath_{container_id} = function(path, rowElement) {{
            // When called from button, just copy the path
            if (typeof rowElement === 'string' || !rowElement) {{
                navigator.clipboard.writeText(path).then(function() {{
                    showStatus('Path copied to clipboard!');
                    setTimeout(function() {{
                        updateStatus();
                    }}, 2000);
                }}).catch(function() {{
                    showStatus('Failed to copy to clipboard');
                }});
                return;
            }}

            // When called from row click, copy the sp.open command
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

        // Confirm delete dialog
        window.confirmDelete_{container_id} = function(path) {{
            var isDir = false;
            // Check if it's a directory based on the files array
            for (var i = 0; i < filteredFiles.length; i++) {{
                if (filteredFiles[i].path === path) {{
                    isDir = filteredFiles[i].is_dir;
                    break;
                }}
            }}

            var itemType = isDir ? 'folder' : 'file';
            var filename = path.split('/').pop() || path;
            var message = 'Are you sure you want to delete this ' + itemType + '?\\n\\n' + filename;

            if (isDir) {{
                message += '\\n\\nWarning: This will delete the folder and ' +
                    'all its contents permanently.';
            }}

            if (confirm(message)) {{
                deleteItem_{container_id}(path, isDir);
            }}
        }};

        // Delete item function
        window.deleteItem_{container_id} = function(path, isDir) {{
            showStatus('Deleting ' + (isDir ? 'folder' : 'file') + '...');

            fetch('/api/filesystem/delete?path=' + encodeURIComponent(path) + 
                  '&recursive=' + isDir, {{
                method: 'DELETE',
                headers: {{
                    'Content-Type': 'application/json'
                }}
            }})
            .then(function(response) {{
                if (response.ok) {{
                    showStatus((isDir ? 'Folder' : 'File') + ' deleted successfully!');
                    // Refresh the file list
                    loadFiles_{container_id}();
                    setTimeout(function() {{
                        updateStatus();
                    }}, 2000);
                }} else {{
                    return response.text().then(function(text) {{
                        throw new Error(text || 'Failed to delete ' + (isDir ? 'folder' : 'file'));
                    }});
                }}
            }})
            .catch(function(error) {{
                console.error('Delete error:', error);
                showStatus('Error: ' + error.message);
                setTimeout(function() {{
                    updateStatus();
                }}, 3000);
            }});
        }};

        // Toggle select all
        window.toggleSelectAll_{container_id} = function() {{
            var selectAllCheckbox = document.getElementById('{container_id}-select-all');
            var checkboxes = document.querySelectorAll(
                '#{container_id} tbody input[type="checkbox"]');
            checkboxes.forEach(function(cb) {{
                cb.checked = selectAllCheckbox.checked;
            }});
            showStatus(selectAllCheckbox.checked ? 
                'All visible files selected' : 'Selection cleared');
            updateSelectAllState_{container_id}();
        }};

        // Update select all state
        window.updateSelectAllState_{container_id} = function() {{
            var checkboxes = document.querySelectorAll(
                '#{container_id} tbody input[type="checkbox"]');
            var selectAllCheckbox = document.getElementById('{container_id}-select-all');
            var allChecked = true;
            var someChecked = false;

            checkboxes.forEach(function(cb) {{
                if (!cb.checked) allChecked = false;
                if (cb.checked) someChecked = true;
            }});

            selectAllCheckbox.checked = allChecked;
            selectAllCheckbox.indeterminate = !allChecked && someChecked;
            
            // Show/hide selection buttons based on whether files are selected
            var deleteBtn = document.getElementById('{container_id}-delete-selected');
            var pythonBtn = document.getElementById('{container_id}-python-selected');
            if (someChecked) {{
                deleteBtn.style.display = 'inline-block';
                pythonBtn.style.display = 'inline-block';
            }} else {{
                deleteBtn.style.display = 'none';
                pythonBtn.style.display = 'none';
            }}
        }};

        // Open share modal
        window.openShareModal_{container_id} = function(filePath) {{
            // Create modal overlay
            var overlay = document.createElement('div');
            overlay.className = 'modal';
            overlay.style.display = 'block';

            // Create modal content with iframe
            var modalContent = document.createElement('div');
            modalContent.className = 'modal-content';
            modalContent.style.width = '90%';
            modalContent.style.maxWidth = '640px';
            modalContent.style.height = '600px';
            modalContent.style.padding = '0';

            // Create iframe
            var iframe = document.createElement('iframe');
            iframe.src = '/share-modal?path=' + encodeURIComponent(filePath);
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.style.border = 'none';
            iframe.style.borderRadius = '8px';

            modalContent.appendChild(iframe);
            overlay.appendChild(modalContent);
            document.body.appendChild(overlay);

            // Handle close on click outside
            overlay.addEventListener('click', function(e) {{
                if (e.target === overlay) {{
                    document.body.removeChild(overlay);
                }}
            }});

            // Handle close message from iframe
            var messageHandler = function(e) {{
                if (e.data && e.data.action === 'closeShareModal') {{
                    document.body.removeChild(overlay);
                    window.removeEventListener('message', messageHandler);
                }}
            }};
            window.addEventListener('message', messageHandler);
        }};

        // Open file editor modal
        window.openFileEditor_{container_id} = function(filePath, isNewFile) {{
            // Create modal overlay
            var overlay = document.createElement('div');
            overlay.className = 'modal';
            overlay.style.display = 'block';

            // Create modal content with iframe
            var modalContent = document.createElement('div');
            modalContent.className = 'modal-content';
            modalContent.style.width = 'calc(100vw - 40px)';
            modalContent.style.maxWidth = 'calc(100vw - 40px)';
            modalContent.style.height = 'calc(100vh - 40px)';
            modalContent.style.padding = '0';
            modalContent.style.margin = '20px auto';

            // Create iframe
            var iframe = document.createElement('iframe');
            var url = '/file-editor/' + encodeURIComponent(filePath) + '?syft_user=' + encodeURIComponent(CONFIG.currentUserEmail);
            if (isNewFile) {{
                url += '&new=true';
            }}
            iframe.src = url;
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.style.border = 'none';
            iframe.style.borderRadius = '8px';

            modalContent.appendChild(iframe);
            overlay.appendChild(modalContent);
            document.body.appendChild(overlay);

            // Handle close on click outside
            overlay.addEventListener('click', function(e) {{
                if (e.target === overlay) {{
                    document.body.removeChild(overlay);
                }}
            }});

            // Handle close message from iframe
            var messageHandler = function(e) {{
                if (e.data && (e.data === 'closeFileEditor' || e.data.action === 'closeFileEditor')) {{
                    document.body.removeChild(overlay);
                    window.removeEventListener('message', messageHandler);

                    // If it was a new file that was saved, refresh the file list
                    if (isNewFile && e.data && e.data.saved) {{
                        loadFiles();
                    }}
                }}
            }};
            window.addEventListener('message', messageHandler);
        }};

        // Open new file/folder modal
        window.openNewModal_{container_id} = function(folderPath) {{
            // Use the main new file modal but with pre-populated path
            openNewFileModal(folderPath);
        }};

        window.createNewItem_{container_id} = function(folderPath, modalElement) {{
                '<div style="margin: 20px 0;">' +
                    '<label style="display: block; margin-bottom: 10px;">' +
                        '<input type="radio" name="newType" value="file" checked style="margin-right: 8px;">File' +
                    '</label>' +
                    '<label style="display: block; margin-bottom: 10px;">' +
                        '<input type="radio" name="newType" value="folder" style="margin-right: 8px;">Folder' +
                    '</label>' +
                '</div>' +
                '<div style="margin: 20px 0;">' +
                    '<label style="display: block; margin-bottom: 5px;">Name:</label>' +
                    '<input type="text" id="newItemName" style="width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px;" placeholder="Enter name...">' +
                '</div>' +
                '<div style="text-align: right; margin-top: 20px;">' +
                    '<button class="btn btn-gray" style="margin-right: 10px;" id="cancelNewBtn">Cancel</button>' +
                    '<button class="btn btn-green" id="createNewBtn">Create</button>' +
                '</div>';

            // Store folderPath in closure
            var createBtn = modalContent.querySelector('#createNewBtn');
            var cancelBtn = modalContent.querySelector('#cancelNewBtn');

            createBtn.addEventListener('click', function() {{
                createNewItem_{container_id}(folderPath, overlay);
            }});

            cancelBtn.addEventListener('click', function() {{
                document.body.removeChild(overlay);
            }});

            overlay.appendChild(modalContent);
            document.body.appendChild(overlay);

            // Focus the input
            setTimeout(function() {{
                document.getElementById('newItemName').focus();
            }}, 100);

            // Handle close on click outside
            overlay.addEventListener('click', function(e) {{
                if (e.target === overlay) {{
                    document.body.removeChild(overlay);
                }}
            }});

            // Handle Enter key
            document.getElementById('newItemName').addEventListener('keydown', function(e) {{
                if (e.key === 'Enter') {{
                    createNewItem_{container_id}(folderPath, overlay);
                }}
            }});
        }};

        // Create new file or folder
        window.createNewItem_{container_id} = function(folderPath, modalElement) {{
            var itemName = document.getElementById('newItemName').value.trim();
            if (!itemName) {{
                alert('Please enter a name');
                return;
            }}

            var isFile = document.querySelector('input[name="newType"]:checked').value === 'file';
            var fullPath = folderPath + '/' + itemName;

            if (isFile) {{
                // Open file editor with new file path
                document.body.removeChild(modalElement);
                openFileEditor_{container_id}(fullPath, true);  // true = isNewFile
            }} else {{
                // Create folder via API
                fetch('/api/filesystem/write', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify({{
                        path: fullPath + '/.gitkeep',  // Create a placeholder file to create the folder
                        content: '',
                        create_dirs: true,
                        syft_user: CONFIG.currentUserEmail
                    }})
                }})
                .then(response => {{
                    if (response.ok) {{
                        document.body.removeChild(modalElement);
                        showStatus('Folder created successfully');
                        // Refresh the file list
                        loadFiles();
                    }} else {{
                        response.json().then(data => {{
                            alert('Failed to create folder: ' + (data.detail || 'Unknown error'));
                        }});
                    }}
                }})
                .catch(error => {{
                    alert('Failed to create folder: ' + error.message);
                }});
            }}
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

        // Delete selected files
        window.deleteSelected_{container_id} = function() {{
            var checkboxes = document.querySelectorAll('#{container_id} tbody input[type="checkbox"]:checked');
            var selectedFiles = [];
            var writableFiles = [];
            
            checkboxes.forEach(function(cb) {{
                var row = cb.closest('tr');
                var pathCell = row.cells[2]; // URL column
                var fullPath = pathCell.textContent.trim();
                
                // Extract the actual file path from syft:// URL
                var filePath = fullPath;
                if (fullPath.startsWith('syft://')) {{
                    var parts = fullPath.substring(7).split('/');
                    if (parts.length > 1) {{
                        filePath = '/' + parts.slice(1).join('/');
                    }}
                }}
                
                selectedFiles.push({{path: filePath, syftPath: fullPath}});
                
                // Find the file in filteredFiles to check permissions
                for (var i = 0; i < filteredFiles.length; i++) {{
                    if (filteredFiles[i].path === filePath) {{
                        var file = filteredFiles[i];
                        
                        // Use the same permission checking logic as individual row delete
                        var isAdmin = false;
                        var canCreate = false;

                        // Check permissions object first
                        if (file.permissions && CONFIG.currentUserEmail) {{
                            if (file.permissions.admin && file.permissions.admin.includes(CONFIG.currentUserEmail)) {{
                                isAdmin = true;
                                canCreate = true; // Admin implies all permissions
                            }} else if (file.permissions.write && file.permissions.write.includes(CONFIG.currentUserEmail)) {{
                                canCreate = true; // Write implies create
                            }} else if (file.permissions.create && file.permissions.create.includes(CONFIG.currentUserEmail)) {{
                                canCreate = true;
                            }}
                        }}
                        
                        // Users with write or admin permissions can delete
                        var canDelete = isAdmin || canCreate;
                        
                        if (canDelete) {{
                            writableFiles.push({{path: filePath, syftPath: fullPath, isDir: file.is_dir}});
                        }}
                        break;
                    }}
                }}
            }});
            
            if (selectedFiles.length === 0) {{
                showStatus('No files selected');
                return;
            }}
            
            if (writableFiles.length === 0) {{
                showStatus('You do not have write permissions for any of the selected files');
                return;
            }}
            
            var skippedCount = selectedFiles.length - writableFiles.length;
            var message = 'Delete ' + writableFiles.length + ' selected item(s)?';
            if (skippedCount > 0) {{
                message += '\\n\\n(' + skippedCount + ' item(s) will be skipped due to insufficient permissions)';
            }}
            
            if (confirm(message)) {{
                deleteMultipleFiles_{container_id}(writableFiles);
            }}
        }};
        
        // Generate Python code for selected files
        window.generatePythonCode_{container_id} = function() {{
            var checkboxes = document.querySelectorAll('#{container_id} tbody input[type="checkbox"]:checked');
            var pythonCode = [];
            
            checkboxes.forEach(function(cb) {{
                var row = cb.closest('tr');
                var pathCell = row.cells[2]; // URL column
                var fullPath = pathCell.textContent.trim();
                
                pythonCode.push('sp.open("' + fullPath + '")');
            }});
            
            if (pythonCode.length === 0) {{
                showStatus('No files selected');
                return;
            }}
            
            var code = pythonCode.join('\\n');
            
            // Copy to clipboard
            navigator.clipboard.writeText(code).then(function() {{
                showStatus('Python code copied to clipboard (' + pythonCode.length + ' files)');
            }}).catch(function() {{
                // Fallback for older browsers
                var textArea = document.createElement('textarea');
                textArea.value = code;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                showStatus('Python code copied to clipboard (' + pythonCode.length + ' files)');
            }});
        }};
        
        // Delete multiple files
        window.deleteMultipleFiles_{container_id} = function(files) {{
            var deletePromises = [];
            var successCount = 0;
            var errorCount = 0;
            
            files.forEach(function(file) {{
                var promise = fetch('/api/filesystem/delete?path=' + encodeURIComponent(file.path) + '&recursive=' + file.isDir, {{
                    method: 'DELETE'
                }}).then(function(response) {{
                    if (response.ok) {{
                        successCount++;
                    }} else {{
                        errorCount++;
                    }}
                }}).catch(function() {{
                    errorCount++;
                }});
                deletePromises.push(promise);
            }});
            
            Promise.all(deletePromises).then(function() {{
                if (successCount > 0) {{
                    showStatus(successCount + ' file(s) deleted successfully' + (errorCount > 0 ? ', ' + errorCount + ' failed' : ''));
                    restartServer(); // Refresh the file list
                }} else {{
                    showStatus('Failed to delete files');
                }}
            }});
        }};
        
        // Helper function to get current user from URL
        function getCurrentUserFromURL() {{
            var urlParams = new URLSearchParams(window.location.search);
            return urlParams.get('user') || 'unknown';
        }}

        // Add real-time search
        document.getElementById('{container_id}-search').addEventListener('input', function() {{
            searchFiles_{container_id}();
        }});
        document.getElementById('{container_id}-admin-filter').addEventListener('input', function() {{
            searchFiles_{container_id}();
        }});

        // Start loading files when page loads
        loadFiles();

        // Setup autocomplete for new file modal
        setupNewFileAutocomplete();
    }})();
    </script>
</body>
</html>
"""
