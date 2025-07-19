"""CSS styles for the filesystem editor."""

from typing import Dict


def get_editor_styles(theme_colors: Dict[str, str], is_dark_mode: bool) -> str:
    """
    Generate CSS styles for the filesystem editor.

    Args:
        theme_colors: Dictionary of theme color variables
        is_dark_mode: Whether dark mode is enabled

    Returns:
        Complete CSS styles as a string
    """
    # Extract color variables for easier string formatting
    bg_color = theme_colors["bg_color"]
    text_color = theme_colors["text_color"]
    border_color = theme_colors["border_color"]
    panel_bg = theme_colors["panel_bg"]
    panel_header_bg = theme_colors["panel_header_bg"]
    accent_bg = theme_colors["accent_bg"]
    muted_color = theme_colors["muted_color"]
    btn_primary_bg = theme_colors["btn_primary_bg"]
    btn_primary_border = theme_colors["btn_primary_border"]
    btn_secondary_bg = theme_colors["btn_secondary_bg"]
    btn_secondary_hover = theme_colors["btn_secondary_hover"]
    editor_bg = theme_colors["editor_bg"]
    status_bar_bg = theme_colors["status_bar_bg"]
    status_bar_border = theme_colors["status_bar_border"]
    breadcrumb_bg = theme_colors["breadcrumb_bg"]
    file_item_hover = theme_colors["file_item_hover"]
    empty_state_color = theme_colors["empty_state_color"]
    error_bg = theme_colors["error_bg"]
    error_color = theme_colors["error_color"]
    success_bg = theme_colors["success_bg"]
    success_border = theme_colors["success_border"]

    return f"""
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 0;
            background: {bg_color};
            color: {text_color};
            font-size: 13px;
            line-height: 1.5;
            height: 100vh;
            overflow: hidden;
        }}
        
        .container {{
            width: 100%;
            height: 100vh;
            margin: 0;
            padding: 0;
            display: flex;
            flex-direction: column;
        }}
        
        .main-content {{
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 24px;
            flex: 1;
            overflow: hidden;
        }}
        
        .panel {{
            background: {panel_bg};
            border: none;
            border-radius: 0;
            overflow: hidden;
            box-shadow: none;
            display: flex;
            flex-direction: column;
            min-height: 0;
        }}
        
        .panel-header {{
            background: {panel_header_bg};
            padding: 8px 12px;
            border-bottom: 1px solid {border_color};
            font-weight: 600;
            color: {text_color};
            font-size: 12px;
        }}
        
        .panel-content {{
            flex: 1;
            overflow: auto;
            background: {panel_bg};
        }}
        
        .breadcrumb {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 6px;
            padding: 8px 12px;
            background: {breadcrumb_bg};
            border-bottom: 1px solid {border_color};
            font-size: 11px;
            max-height: 150px;
            overflow-y: auto;
        }}
        
        .breadcrumb-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            max-width: 200px;
        }}
        
        .breadcrumb-link {{
            color: {muted_color};
            text-decoration: none;
            padding: 4px 8px;
            border-radius: 4px;
            transition: all 0.2s;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 150px;
            font-weight: 500;
        }}
        
        .breadcrumb-link:hover {{
            background: {accent_bg};
            color: {text_color};
            max-width: none;
        }}
        
        .breadcrumb-current {{
            color: {text_color};
            font-weight: 500;
            background: {accent_bg};
            padding: 4px 8px;
            border-radius: 4px;
            max-width: 150px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        
        .breadcrumb-separator {{
            color: {muted_color};
            font-size: 0.8rem;
        }}
        
        .file-list {{
            padding: 8px 0;
        }}
        
        .file-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 10px 16px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            border: 1px solid transparent;
            background: transparent;
        }}
        
        .file-item:hover {{
            background: {file_item_hover};
        }}
        
        .file-item.selected {{
            background: {accent_bg};
            border-color: {border_color};
        }}
        
        .file-icon {{
            width: 16px;
            height: 16px;
            font-size: 14px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: {muted_color};
        }}
        
        .file-details {{
            flex: 1;
            min-width: 0;
        }}
        
        .file-name {{
            font-weight: 500;
            color: {text_color};
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            font-size: 12px;
        }}
        
        .file-meta {{
            font-size: 10px;
            color: {muted_color};
            margin-top: 1px;
        }}
        
        .editor-container {{
            flex: 1;
            display: flex;
            flex-direction: column;
            min-height: 0;
        }}
        
        .editor-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 12px 16px;
            background: {panel_bg};
            border-bottom: none;
            flex-shrink: 0;
        }}
        
        .editor-title {{
            font-weight: 500;
            color: {text_color};
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            flex: 1;
            font-size: 0.95rem;
            text-align: left;
        }}
        
        .editor-actions {{
            display: flex;
            gap: 6px;
            flex-shrink: 0;
            margin-left: auto;
        }}
        
        .btn {{
            padding: 5px 12px;
            border: none;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            line-height: 1.4;
        }}
        
        .btn-primary {{
            background: {btn_primary_bg};
            color: #3b82f6;
            border: 1px solid {btn_primary_border};
            backdrop-filter: blur(4px);
        }}
        
        .btn-primary:hover {{
            background: {btn_primary_bg};
            border-color: {btn_primary_border};
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.2);
            opacity: 0.8;
        }}
        
        .btn-primary.saving {{
            animation: buttonRainbow 1s ease-in-out;
        }}
        
        @keyframes buttonRainbow {{
            0% {{ background: rgba(255, 204, 204, 0.5); border-color: rgba(255, 179, 179, 0.7); }}
            14% {{ background: rgba(255, 217, 179, 0.5); border-color: rgba(255, 194, 153, 0.7); }}
            28% {{ background: rgba(255, 255, 204, 0.5); border-color: rgba(255, 255, 179, 0.7); }}
            42% {{ background: rgba(204, 255, 204, 0.5); border-color: rgba(179, 255, 179, 0.7); }}
            57% {{ background: rgba(204, 255, 255, 0.5); border-color: rgba(179, 255, 255, 0.7); }}
            71% {{ background: rgba(204, 204, 255, 0.5); border-color: rgba(179, 179, 255, 0.7); }}
            85% {{ background: rgba(255, 204, 255, 0.5); border-color: rgba(255, 179, 255, 0.7); }}
            100% {{ background: rgba(147, 197, 253, 0.25); border-color: rgba(147, 197, 253, 0.4); }}
        }}
        
        .btn-secondary {{
            background: {btn_secondary_bg};
            color: {text_color};
        }}
        
        .btn-secondary:hover {{
            background: {btn_secondary_hover};
        }}
        
        .btn-purple {{
            background: {'#3b2e4d' if is_dark_mode else '#e9d5ff'};
            color: {'#c084fc' if is_dark_mode else '#a855f7'};
            border: 1px solid {'rgba(192, 132, 252, 0.3)' if is_dark_mode else 'rgba(168, 85, 247, 0.3)'};
        }}
        
        .btn-purple:hover {{
            background: {'#4a3861' if is_dark_mode else '#ddd5ff'};
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(168, 85, 247, 0.2);
        }}
        
        /* Additional button colors with better harmony */
        .btn-mint {{
            background: {btn_secondary_bg};
            color: {text_color};
        }}
        
        .btn-mint:hover {{
            background: {btn_secondary_hover};
        }}
        
        .btn-lavender {{
            background: {btn_secondary_bg};
            color: {text_color};
        }}
        
        .btn-lavender:hover {{
            background: {btn_secondary_hover};
        }}
        
        .btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        
        .editor-textarea {{
            flex: 1;
            resize: none;
            border: none;
            outline: none;
            padding: 16px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
            font-size: 14px;
            line-height: 1.6;
            background: {editor_bg};
            color: {text_color};
            tab-size: 4;
            width: 100%;
            height: 100%;
        }}
        
        .editor-textarea:focus {{
            box-shadow: none;
        }}
        
        #editor-container {{
            flex: 1;
            position: relative;
            overflow: hidden;
            display: none;
        }}
        
        #syntax-highlight {{
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            padding: 16px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
            font-size: 14px;
            line-height: 1.6;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow: auto;
            pointer-events: none;
            background: transparent;
        }}
        
        #editor-input {{
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            padding: 16px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, monospace;
            font-size: 14px;
            line-height: 1.6;
            background: transparent;
            color: transparent;
            caret-color: {text_color};
            resize: none;
            border: none;
            outline: none;
            white-space: pre-wrap;
            word-wrap: break-word;
            overflow: auto;
        }}
        
        .status-bar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 8px 16px;
            background: {status_bar_bg};
            border-top: 1px solid {status_bar_border};
            font-size: 0.85rem;
            color: {muted_color};
            flex-shrink: 0;
        }}
        
        .status-left {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        
        .status-right {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}
        
        .loading {{
            text-align: center;
            padding: 40px;
            color: {muted_color};
        }}
        
        .error {{
            background: {error_bg};
            color: {error_color};
            padding: 12px;
            border-radius: 0;
            margin: 12px;
            border: none;
        }}
        
        .success {{
            background: {success_bg};
            color: {('white' if is_dark_mode else '#065f46')};
            padding: 12px 20px;
            border-radius: 8px;
            margin: 12px;
            border: 1px solid {success_border};
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            font-weight: 500;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
            animation: slideIn 0.3s ease-out, rainbowPastel 3s ease-in-out;
        }}
        
        @keyframes slideIn {{
            from {{
                transform: translateX(400px);
                opacity: 0;
            }}
            to {{
                transform: translateX(0);
                opacity: 1;
            }}
        }}
        
        @keyframes slideOut {{
            to {{
                transform: translateX(400px);
                opacity: 0;
            }}
        }}
        
        @keyframes rainbowPastel {{
            0% {{ background: #ffcccc; border-color: #ffb3b3; }} /* Pastel Pink */
            14% {{ background: #ffd9b3; border-color: #ffc299; }} /* Pastel Orange */
            28% {{ background: #ffffcc; border-color: #ffffb3; }} /* Pastel Yellow */
            42% {{ background: #ccffcc; border-color: #b3ffb3; }} /* Pastel Green */
            57% {{ background: #ccffff; border-color: #b3ffff; }} /* Pastel Cyan */
            71% {{ background: #ccccff; border-color: #b3b3ff; }} /* Pastel Blue */
            85% {{ background: #ffccff; border-color: #ffb3ff; }} /* Pastel Purple */
            100% {{ background: #dcfce7; border-color: #bbf7d0; }} /* Final teal */
        }}
        
        .empty-state {{
            text-align: center;
            padding: 60px 20px;
            color: {empty_state_color};
        }}
        
        .empty-state h3 {{
            font-size: 1.1rem;
            margin-bottom: 8px;
            color: {text_color};
            font-weight: 500;
        }}
        
        .empty-state p {{
            color: {empty_state_color};
            font-size: 0.9rem;
        }}
        
        .logo {{
            width: 48px;
            height: 48px;
            margin: 0 auto 16px;
        }}
        
        @media (max-width: 900px) {{
            .main-content {{
                grid-template-columns: 1fr;
                gap: 16px;
            }}
            
            .editor-header {{
                flex-direction: column;
                gap: 8px;
            }}
            
            .editor-actions {{
                width: 100%;
                justify-content: flex-start;
            }}
            
            .breadcrumb {{
                padding: 8px 12px;
            }}
            
            .breadcrumb-item {{
                max-width: 120px;
            }}
            
            .breadcrumb-link,
            .breadcrumb-current {{
                max-width: 100px;
                font-size: 0.85rem;
            }}
        }}
        
        /* Embedded mode detection */
        .embedded-mode {{
            height: 100vh !important;
        }}
        
        .embedded-mode .container {{
            height: 100% !important;
        }}
        
        .embedded-mode .main-content {{
            height: 100% !important;
        }}
        
        .embedded-mode .panel {{
            height: 100% !important;
        }}
        
        .embedded-mode .editor-container {{
            height: 100% !important;
        }}
        
        @media (max-width: 600px) {{
            .container {{
                padding: 8px;
            }}
            
            .panel-header {{
                padding: 10px 12px;
            }}
            
            .breadcrumb {{
                padding: 8px;
            }}
            
            .file-item {{
                padding: 8px 10px;
            }}
            
            .editor-textarea {{
                padding: 10px;
                font-size: 13px;
            }}
        }}
        
        /* File-only mode styles */
        .file-only-mode .panel:first-child {{
            display: none;
        }}
        
        .file-only-mode .main-content {{
            grid-template-columns: 1fr;
        }}
        
        .file-only-mode .editor-panel {{
            border-radius: 0;
        }}
        
        .toggle-explorer-btn {{
            margin-right: 8px;
        }}
        
        /* Syntax highlighting editor styles */
        #editor-container {{
            position: relative;
            width: 100%;
            height: 100%;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        }}
        
        #syntax-highlight {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            margin: 0;
            padding: 12px;
            border: none;
            background: transparent;
            color: transparent;
            font-family: inherit;
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
            overflow: auto;
            box-sizing: border-box;
            pointer-events: none;
            z-index: 1;
        }}
        
        #editor-input {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            margin: 0;
            padding: 12px;
            border: none;
            background: transparent;
            color: {text_color};
            font-family: inherit;
            font-size: 13px;
            line-height: 1.5;
            white-space: pre-wrap;
            overflow: auto;
            resize: none;
            outline: none;
            box-sizing: border-box;
            z-index: 2;
            caret-color: {text_color};
        }}
        
        #editor-input::selection {{
            background: rgba(59, 130, 246, 0.3);
        }}
        
        /* Modal styles */
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(4px);
            animation: fadeIn 0.2s ease-out;
        }}
        
        .modal-content {{
            background-color: {panel_bg};
            margin: 15% auto;
            padding: 24px;
            border: 1px solid {border_color};
            border-radius: 8px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
            animation: slideIn 0.2s ease-out;
        }}
        
        @keyframes fadeIn {{
            from {{
                opacity: 0;
            }}
            to {{
                opacity: 1;
            }}
        }}
        
        @keyframes slideIn {{
            from {{
                transform: translateY(-20px);
                opacity: 0;
            }}
            to {{
                transform: translateY(0);
                opacity: 1;
            }}
        }}
    """
