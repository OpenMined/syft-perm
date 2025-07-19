"""HTML structure generation for filesystem editor."""

from typing import Dict


def get_editor_html_structure(theme_colors: Dict[str, str]) -> str:
    """Generate the HTML body structure for the editor."""

    return f"""
    <div class="container">
        <div class="main-content">
            <div class="panel">
                <div class="panel-header">
                    File Explorer
                </div>
                <div class="breadcrumb" id="breadcrumb">
                    <div class="loading">Loading...</div>
                </div>
                <div class="panel-content">
                    <div class="file-list" id="fileList">
                        <div class="loading">Loading files...</div>
                    </div>
                </div>
            </div>
            <div class="panel">
                <div class="editor-container">
                    <div class="editor-header">
                        <div class="editor-title" id="editorTitle">No file selected</div>
                        <div class="editor-actions">
                            <button class="btn btn-secondary toggle-explorer-btn" id="toggleExplorerBtn" title="Toggle File Explorer">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/>
                                </svg>
                            </button>
                            <button class="btn btn-lavender" id="newFileBtn">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                                    <polyline points="14 2 14 8 20 8"/>
                                    <line x1="12" y1="18" x2="12" y2="12"/>
                                    <line x1="9" y1="15" x2="15" y2="15"/>
                                </svg>
                                New File
                            </button>
                            <button class="btn btn-mint" id="newFolderBtn">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/>
                                    <line x1="12" y1="11" x2="12" y2="17"/>
                                    <line x1="9" y1="14" x2="15" y2="14"/>
                                </svg>
                                New Folder
                            </button>
                            <button class="btn btn-secondary" id="shareBtn" title="Share file/folder">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M16 3h5v5M21 3l-7 7m1 4v4h-5M14 21l7-7"/>
                                </svg>
                                Share
                            </button>
                            <button class="btn btn-secondary" id="renameBtn" title="Rename file/folder" style="display: none;">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M12 20h9"/>
                                    <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
                                </svg>
                                Rename
                            </button>
                            <button class="btn btn-secondary" id="closeFileBtn" title="Close file" style="display: none;">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="18" y1="6" x2="6" y2="18"/>
                                    <line x1="6" y1="6" x2="18" y2="18"/>
                                </svg>
                                Close
                            </button>
                            <button class="btn btn-purple" id="openInWindowBtn" title="Open in new window">
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                                    <polyline points="15 3 21 3 21 9"/>
                                    <line x1="10" y1="14" x2="21" y2="3"/>
                                </svg>
                                Open in Window
                            </button>
                            <button class="btn btn-primary" id="saveBtn" disabled>
                                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M19 21l-7-5-7 5V5a2 2 0 012-2h10a2 2 0 012 2v16z"/>
                                </svg>
                                Save
                            </button>
                        </div>
                    </div>
                    <div class="panel-content">
                        <div class="empty-state" id="emptyState">
                            <svg class="logo" xmlns="http://www.w3.org/2000/svg" width="311" height="360" viewBox="0 0 311 360" fill="none">
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
                                    <linearGradient id="paint2_linear_7523_4240" x1="-0.378906" y1="89.7878" x2="155.761" y2="360.282" gradientUnits="userSpaceOnUse">
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
                            <h3>Welcome to SyftBox Editor</h3>
                            <p>Select a file from the explorer to start editing</p>
                        </div>
                        <div id="editor-container" style="display: none;">
                            <pre id="syntax-highlight"><code class="language-text"></code></pre>
                            <textarea id="editor-input" spellcheck="false"></textarea>
                        </div>
                        <textarea class="editor-textarea" id="editor" style="display: none;" placeholder="Start typing..."></textarea>
                    </div>
                    <div class="status-bar">
                        <div class="status-left">
                            <span id="fileInfo">Ready</span>
                        </div>
                        <div class="status-right">
                            <span id="readOnlyIndicator" style="color: #dc2626; font-weight: 600; margin-right: 10px; display: none;">READ-ONLY</span>
                            <span id="cursorPosition">Ln 1, Col 1</span>
                            <span id="fileSize">0 bytes</span>
                            <a href="https://github.com/OpenMined/syft-perm/issues" target="_blank" style="margin-left: 20px; color: {theme_colors['muted_color']}; text-decoration: none; font-size: 11px;">
                                Report a Bug
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
"""
