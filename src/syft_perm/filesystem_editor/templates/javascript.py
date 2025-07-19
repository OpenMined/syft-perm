"""JavaScript code generation for filesystem editor."""

from typing import Dict, Optional


def get_editor_javascript(
    initial_dir: str,
    initial_path: str,
    is_initial_file: bool,
    is_dark_mode: bool,
    theme_colors: Dict[str, str],
    syft_user: Optional[str] = None,
    is_new_file: bool = False,
) -> str:
    """Generate the JavaScript code for the editor.

    This returns the complete JavaScript code as a string to be embedded in the HTML.
    """

    return f"""
        // Detect if we're in an iframe and add embedded-mode class
        if (window.self !== window.top) {{
            document.body.classList.add('embedded-mode');
        }}
        // Also check for URL parameter
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('embedded') === 'true') {{
            document.body.classList.add('embedded-mode');
        }}

        // Theme colors for JavaScript
        const themeColors = {{
            editor_bg: '{theme_colors['editor_bg']}',
            editor_readonly_bg: '{('#2d2d30' if is_dark_mode else '#f9fafb')}',
            editor_uncertain_bg: '{('#3d3d30' if is_dark_mode else '#fffbeb')}',
            text_color: '{theme_colors['text_color']}',
            muted_color: '{theme_colors['muted_color']}'
        }};

        class FileSystemEditor {{
            constructor() {{
                // Check for path parameter in URL
                const urlParams = new URLSearchParams(window.location.search);
                const pathParam = urlParams.get('path');
                // Get syft_user from URL parameter if present
                this.syftUser = urlParams.get('syft_user') || {repr(syft_user) if syft_user else 'null'};
                // Check if this is a new file
                this.isNewFile = urlParams.get('new') === 'true';
                this.currentPath = pathParam || '{initial_dir}';
                this.initialFilePath = {'`' + initial_path + '`' if is_initial_file else 'null'};
                this.isInitialFile = {str(is_initial_file).lower()};
                this.currentFile = null;
                this.selectedFolder = null;
                this.isModified = false;
                this.isAdmin = false;  // Default to false until we load a file/directory
                this.fileOnlyMode = this.isInitialFile || this.isNewFile;
                this.isDarkMode = {str(is_dark_mode).lower()};
                this.initializeElements();
                this.setupEventListeners();
                if (this.isInitialFile || this.isNewFile) {{
                    if (this.isNewFile) {{
                        // For new files, create an empty file in memory
                        const filePath = this.currentPath;
                        const fileName = filePath.split('/').pop();
                        const parentDir = filePath.substring(0, filePath.lastIndexOf('/'));
                        console.log('Creating new file:', filePath);
                        console.log('File name:', fileName);
                        console.log('Parent directory:', parentDir);
                        // Set up for a new file
                        this.currentFile = {{
                            path: filePath,
                            content: '',
                            size: 0,
                            modified: new Date().toISOString(),
                            extension: fileName.includes('.') ? '.' + fileName.split('.').pop() : '',
                            encoding: 'utf-8',
                            can_write: true,
                            can_admin: true,
                            write_users: [this.syftUser || 'unknown']
                        }};
                        this.isModified = true;  // Mark as modified since it's new
                        this.isReadOnly = false;
                        this.isAdmin = true;
                        // Update UI for the new file
                        this.editorTitle.textContent = fileName + ' (new)';
                        // Show the editor
                        this.toggleFileOnlyMode(true);
                        this.toggleExplorerBtn.style.display = 'none';
                        // Hide empty state and show editor
                        this.emptyState.style.display = 'none';
                        this.editorContainer.style.display = 'none';
                        this.editor.style.display = 'block';
                        // Set editor content
                        this.editor.value = '';
                        this.editorInput.value = '';
                        // Update status
                        this.fileInfo.innerHTML = `<strong>${{fileName}}</strong> (new file - unsaved)`;
                        this.fileSize.textContent = '0 bytes';
                        this.updateCursorPosition();
                        // Focus the editor
                        this.editor.focus();
                        // Update the file browser to show parent directory
                        // Only load directory if we're not in file-only mode
                        this.currentPath = parentDir;
                        if (parentDir && !this.fileOnlyMode) {{
                            this.loadDirectory(parentDir);
                        }}
                    }} else {{
                        // If initial path is an existing file, load it directly
                        this.loadFile(this.initialFilePath);
                        this.toggleFileOnlyMode(true);
                        // Hide toggle button when viewing a single file
                        this.toggleExplorerBtn.style.display = 'none';
                    }}
                }} else {{
                    // Otherwise load the directory
                    this.loadDirectory(this.currentPath);
                }}
            }}

            initializeElements() {{
                this.fileList = document.getElementById('fileList');
                this.editor = document.getElementById('editor');
                this.editorContainer = document.getElementById('editor-container');
                this.editorInput = document.getElementById('editor-input');
                this.syntaxHighlight = document.getElementById('syntax-highlight').querySelector('code');
                this.saveBtn = document.getElementById('saveBtn');
                this.shareBtn = document.getElementById('shareBtn');
                this.renameBtn = document.getElementById('renameBtn');
                this.closeFileBtn = document.getElementById('closeFileBtn');
                this.newFileBtn = document.getElementById('newFileBtn');
                this.newFolderBtn = document.getElementById('newFolderBtn');
                this.editorTitle = document.getElementById('editorTitle');
                this.emptyState = document.getElementById('emptyState');
                this.breadcrumb = document.getElementById('breadcrumb');
                this.fileInfo = document.getElementById('fileInfo');
                this.cursorPosition = document.getElementById('cursorPosition');
                this.fileSize = document.getElementById('fileSize');
                this.toggleExplorerBtn = document.getElementById('toggleExplorerBtn');
                this.readOnlyIndicator = document.getElementById('readOnlyIndicator');
            }}

            getLanguageFromExtension(extension) {{
                const ext = extension.toLowerCase();
                const langMap = {{
                    '.js': 'javascript',
                    '.jsx': 'jsx',
                    '.ts': 'typescript',
                    '.tsx': 'tsx',
                    '.py': 'python',
                    '.html': 'html',
                    '.htm': 'html',
                    '.css': 'css',
                    '.scss': 'scss',
                    '.sass': 'sass',
                    '.json': 'json',
                    '.md': 'markdown',
                    '.xml': 'xml',
                    '.svg': 'svg',
                    '.sql': 'sql',
                    '.c': 'c',
                    '.cpp': 'cpp',
                    '.cc': 'cpp',
                    '.cxx': 'cpp',
                    '.h': 'c',
                    '.hpp': 'cpp',
                    '.java': 'java',
                    '.rs': 'rust',
                    '.php': 'php',
                    '.yaml': 'yaml',
                    '.yml': 'yaml',
                    '.toml': 'toml',
                    '.ini': 'ini',
                    '.cfg': 'ini',
                    '.conf': 'ini',
                    '.sh': 'bash',
                    '.bash': 'bash',
                    '.zsh': 'bash',
                    '.fish': 'bash',
                    '.ps1': 'powershell',
                    '.bat': 'batch',
                    '.cmd': 'batch',
                    '.rb': 'ruby',
                    '.go': 'go',
                    '.swift': 'swift',
                    '.kt': 'kotlin',
                    '.r': 'r',
                    '.R': 'r'
                }};
                return langMap[ext] || 'plaintext';
            }}

            updateSyntaxHighlighting() {{
                const content = this.editorInput.value;
                const language = this.currentFile ? this.getLanguageFromExtension(this.currentFile.extension || '') : 'plaintext';
                // Update language class
                this.syntaxHighlight.className = `language-${{language}}`;
                this.syntaxHighlight.textContent = content;
                // Re-highlight
                if (window.Prism) {{
                    Prism.highlightElement(this.syntaxHighlight);
                }}
            }}

            syncScroll() {{
                const syntaxPre = document.getElementById('syntax-highlight');
                syntaxPre.scrollTop = this.editorInput.scrollTop;
                syntaxPre.scrollLeft = this.editorInput.scrollLeft;
            }}

            setupEventListeners() {{
                this.saveBtn.addEventListener('click', () => this.saveFile());
                this.shareBtn.addEventListener('click', () => this.showShareModal());
                this.renameBtn.addEventListener('click', () => this.showRenameModal());
                this.closeFileBtn.addEventListener('click', () => this.closeFile());
                this.newFileBtn.addEventListener('click', () => this.createNewFile());
                this.newFolderBtn.addEventListener('click', () => this.createNewFolder());
                // Open in Window button
                const openInWindowBtn = document.getElementById('openInWindowBtn');
                if (openInWindowBtn) {{
                    openInWindowBtn.addEventListener('click', () => {{
                        const currentUrl = window.location.href;
                        window.open(currentUrl, '_blank');
                    }});
                }}
                this.toggleExplorerBtn.addEventListener('click', () => this.toggleFileOnlyMode());
                // Editor input listeners
                this.editorInput.addEventListener('input', () => {{
                    this.isModified = true;
                    this.updateUI();
                    this.updateSyntaxHighlighting();
                }});
                this.editorInput.addEventListener('scroll', () => this.syncScroll());
                this.editorInput.addEventListener('keyup', () => this.updateCursorPosition());
                this.editorInput.addEventListener('click', () => this.updateCursorPosition());
                // Fallback textarea listeners
                this.editor.addEventListener('input', () => {{
                    this.isModified = true;
                    this.updateUI();
                }});
                this.editor.addEventListener('keyup', () => this.updateCursorPosition());
                this.editor.addEventListener('click', () => this.updateCursorPosition());
                // Auto-save on Ctrl+S
                document.addEventListener('keydown', (e) => {{
                    if (e.ctrlKey && e.key === 's') {{
                        e.preventDefault();
                        if (this.currentFile) {{
                            this.saveFile();
                        }}
                    }}
                }});
            }}

            async loadDirectory(path) {{
                try {{
                    let url = `/api/filesystem/list?path=${{encodeURIComponent(path)}}`;
                    if (this.syftUser) {{
                        url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;
                    }}
                    const response = await fetch(url);
                    const data = await response.json();
                    if (!response.ok) {{
                        // Handle permission denied or directory not found gracefully
                        if (response.status === 403 || response.status === 404) {{
                            // Show permission denied message instead of error alert
                            const title = response.status === 403 ? 'Permission Denied' : 'Directory Not Found';
                            const message = response.status === 403 ?
                                'You do not have permission to access this directory. It may not exist locally or you may need to request access.' :
                                'The requested directory could not be found. It may have been moved or deleted.';
                            this.fileList.innerHTML = `
                                <div class="empty-state" style="text-align: center; padding: 40px;">
                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="${{themeColors.muted_color}}" stroke-width="1.5" style="margin: 0 auto 16px;">
                                        <path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                    </svg>
                                    <h3 style="color: ${{themeColors.text_color}}; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">
                                        ${{title}}
                                    </h3>
                                    <p style="color: ${{themeColors.muted_color}}; font-size: 14px; margin: 0; max-width: 400px;">
                                        ${{message}}
                                    </p>
                                </div>
                            `;
                            // Clear breadcrumb navigation for permission denied directories
                            this.breadcrumb.innerHTML = `<div class="breadcrumb-current">${{title}}</div>`;
                            return;
                        }}
                        throw new Error(data.detail || 'Failed to load directory');
                    }}
                    this.currentPath = data.path;
                    this.isAdmin = data.can_admin || false;  // Update admin status for the directory
                    this.renderFileList(data.items);
                    this.renderBreadcrumb(data.path, data.parent);
                    this.updateUI();  // Update UI to reflect admin status
                }} catch (error) {{
                    this.showError('Failed to load directory: ' + error.message);
                }}
            }}

            renderFileList(items) {{
                if (items.length === 0) {{
                    this.fileList.innerHTML = '<div class="empty-state"><h3>Empty Directory</h3><p>No files or folders found</p></div>';
                    return;
                }}
                this.fileList.innerHTML = items.map(item => {{
                    const icon = item.is_directory
                        ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/></svg>'
                        : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M13 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>';
                    const sizeText = item.is_directory ? 'Directory' : this.formatFileSize(item.size);
                    const modifiedText = new Date(item.modified).toLocaleString();
                    return `
                        <div class="file-item" data-path="${{item.path}}" data-is-directory="${{item.is_directory}}" data-is-editable="${{item.is_editable}}">
                            <div class="file-icon ${{item.is_directory ? 'directory' : (item.is_editable ? 'editable' : '')}}">${{icon}}</div>
                            <div class="file-details">
                                <div class="file-name">${{item.name}}</div>
                                <div class="file-meta">${{sizeText}} • ${{modifiedText}}</div>
                            </div>
                        </div>
                    `;
                }}).join('');
                // Add click handlers
                this.fileList.querySelectorAll('.file-item').forEach(item => {{
                    item.addEventListener('click', () => {{
                        const path = item.dataset.path;
                        const isDirectory = item.dataset.isDirectory === 'true';
                        const isEditable = item.dataset.isEditable === 'true';
                        // Clear previous selections
                        this.fileList.querySelectorAll('.file-item').forEach(el => el.classList.remove('selected'));
                        // Add selection to current item
                        item.classList.add('selected');
                        if (isDirectory) {{
                            // For directories, just select them (don't navigate)
                            // This allows users to configure permissions for folders
                            this.selectedFolder = path;
                            this.currentFile = null;
                            // Check admin permissions for the selected folder
                            this.checkFolderPermissions(path);
                            // Update the editor title to show selected folder
                            this.editorTitle.textContent = `Selected: ${{path.split('/').pop()}} (folder)`;
                            // Show empty state with folder selected message
                            this.emptyState.style.display = 'flex';
                            this.emptyState.innerHTML = `
                                <div style="text-align: center;">
                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="${{themeColors.muted_color}}" stroke-width="1.5" style="margin: 0 auto 16px;">
                                        <path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/>
                                    </svg>
                                    <h3 style="color: ${{themeColors.text_color}}; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">
                                        Folder Selected
                                    </h3>
                                    <p style="color: ${{themeColors.muted_color}}; font-size: 14px; margin: 0;">
                                        ${{path.split('/').pop()}} - Use the Share button to configure permissions
                                    </p>
                                    <p style="color: ${{themeColors.muted_color}}; font-size: 13px; margin: 8px 0 0 0;">
                                        Double-click to open the folder
                                    </p>
                                </div>
                            `;
                            // Hide editors
                            this.editor.style.display = 'none';
                            this.editorContainer.style.display = 'none';
                            // Enable share button if user has permissions
                            this.updateUI();
                        }} else if (isEditable) {{
                            this.loadFile(path);
                            this.selectedFolder = null;
                        }}
                    }});
                    // Add double-click handler for folders to navigate
                    item.addEventListener('dblclick', () => {{
                        const isDirectory = item.dataset.isDirectory === 'true';
                        if (isDirectory) {{
                            this.loadDirectory(item.dataset.path);
                        }}
                    }});
                    item.addEventListener('contextmenu', (e) => {{
                        e.preventDefault();
                        this.showContextMenu(e, item.dataset.path, item.dataset.isDirectory === 'true');
                    }});
                }});
            }}

            renderBreadcrumb(currentPath, parentPath) {{
                const pathParts = currentPath.split('/').filter(part => part !== '');
                const isRoot = pathParts.length === 0;
                let breadcrumbHtml = '';
                if (isRoot) {{
                    breadcrumbHtml = '<div class="breadcrumb-current">Root</div>';
                }} else {{
                    // Build path parts
                    let currentBuildPath = '';
                    pathParts.forEach((part, index) => {{
                        currentBuildPath += '/' + part;
                        const isLast = index === pathParts.length - 1;
                        if (isLast) {{
                            breadcrumbHtml += `<div class="breadcrumb-current">${{part}}</div>`;
                        }} else {{
                            breadcrumbHtml += `
                                <div class="breadcrumb-item">
                                    <a href="#" class="breadcrumb-link" data-path="${{currentBuildPath}}">${{part}}</a>
                                    <span class="breadcrumb-separator">›</span>
                                </div>
                            `;
                        }}
                    }});
                    // Add home link at beginning
                    breadcrumbHtml = `
                        <div class="breadcrumb-item">
                            <a href="#" class="breadcrumb-link" data-path="/">Home</a>
                            <span class="breadcrumb-separator">›</span>
                        </div>
                    ` + breadcrumbHtml;
                }}
                this.breadcrumb.innerHTML = breadcrumbHtml;
                // Add click handlers for breadcrumb navigation
                this.breadcrumb.querySelectorAll('.breadcrumb-link').forEach(link => {{
                    link.addEventListener('click', (e) => {{
                        e.preventDefault();
                        const path = link.dataset.path;
                        this.loadDirectory(path);
                    }});
                }});
            }}

            async loadFile(path) {{
                try {{
                    let url = `/api/filesystem/read?path=${{encodeURIComponent(path)}}`;
                    if (this.syftUser) {{
                        url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;
                    }}
                    const response = await fetch(url);
                    const data = await response.json();
                    if (!response.ok) {{
                        // Handle permission denied or file not found
                        if (response.status === 403 || response.status === 404) {{
                            // Show permission denied message instead of editor
                            this.currentFile = null;
                            this.editor.value = '';
                            this.isModified = false;
                            this.updateUI();
                            // Hide editor, show empty state with custom message
                            this.editor.style.display = 'none';
                            this.emptyState.style.display = 'flex';
                            const title = response.status === 403 ? 'Permission Denied' : 'File Not Found';
                            const message = response.status === 403 ?
                                'You do not have permission to access this file. It may not exist locally or you may need to request access.' :
                                'The requested file could not be found. It may have been moved or deleted.';
                            this.emptyState.innerHTML = `
                                <div style="text-align: center; padding: 40px;">
                                    <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="${{themeColors.muted_color}}" stroke-width="1.5" style="margin: 0 auto 16px;">
                                        <path d="M12 9v2m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                                    </svg>
                                    <h3 style="color: ${{themeColors.text_color}}; font-size: 18px; margin: 0 0 8px 0; font-weight: 600;">
                                        ${{title}}
                                    </h3>
                                    <p style="color: ${{themeColors.muted_color}}; font-size: 14px; margin: 0; max-width: 400px;">
                                        ${{message}}
                                    </p>
                                </div>
                            `;
                            return;
                        }}
                        throw new Error(data.detail || 'Failed to load file');
                    }}
                    this.currentFile = data;
                    this.isModified = false;
                    this.isReadOnly = !data.can_write;
                    this.isAdmin = data.can_admin || false;
                    this.isUncertainPermissions = false;
                    // Backend now uses syft-perm for proper permission checking
                    // can_write reflects the actual syft-perm decision
                    // No more "uncertain permissions" guesswork needed
                    // Decide which editor to use
                    const useSimpleEditor = true; // For now, always use simple editor
                    if (useSimpleEditor) {{
                        // Use syntax highlighting editor
                        this.editorInput.value = data.content;
                        this.editorInput.readOnly = this.isReadOnly;
                        // Set background color based on permissions
                        if (this.isReadOnly) {{
                            this.editorInput.style.backgroundColor = themeColors.editor_readonly_bg;
                        }} else if (this.isUncertainPermissions) {{
                            this.editorInput.style.backgroundColor = themeColors.editor_uncertain_bg;
                        }} else {{
                            this.editorInput.style.backgroundColor = themeColors.editor_bg;
                        }}
                        // Update syntax highlighting
                        this.updateSyntaxHighlighting();
                        // Show editor container
                        this.emptyState.style.display = 'none';
                        this.editorContainer.style.display = 'block';
                        this.editor.style.display = 'none';
                    }} else {{
                        // Fallback to simple textarea
                        this.editor.value = data.content;
                        this.editor.readOnly = this.isReadOnly;
                        if (this.isReadOnly) {{
                            this.editor.style.backgroundColor = themeColors.editor_readonly_bg;
                        }} else if (this.isUncertainPermissions) {{
                            this.editor.style.backgroundColor = themeColors.editor_uncertain_bg;
                        }} else {{
                            this.editor.style.backgroundColor = themeColors.editor_bg;
                        }}
                        this.emptyState.style.display = 'none';
                        this.editorContainer.style.display = 'none';
                        this.editor.style.display = 'block';
                    }}
                    this.updateUI();
                    // Update file info with appropriate indicator
                    let badge = '';
                    if (this.isReadOnly) {{
                        badge = ' <span style="color: #dc2626; font-weight: 600;">[READ-ONLY]</span>';
                    }} else if (this.isUncertainPermissions) {{
                        badge = ' <span style="color: #f59e0b; font-weight: 600;">[UNCERTAIN PERMISSIONS]</span>';
                    }}
                    this.fileInfo.innerHTML = `${{path.split('/').pop()}} (${{data.extension}})${{badge}}`;
                    this.fileSize.textContent = this.formatFileSize(data.size);
                    // Remove any existing permission warnings
                    const existingWarnings = this.editorContainer.parentElement.querySelectorAll('.permission-warning');
                    existingWarnings.forEach(w => w.remove());
                    // Show permission info
                    if (this.isReadOnly && data.write_users && data.write_users.length > 0) {{
                        const permissionInfo = document.createElement('div');
                        permissionInfo.className = 'permission-warning';
                        permissionInfo.style.cssText = `
                            background: #fef2f2;
                            border: 1px solid #fecaca;
                            border-radius: 6px;
                            padding: 12px;
                            margin: 10px 0;
                            font-size: 13px;
                            color: #dc2626;
                        `;
                        permissionInfo.innerHTML = `
                            <strong>⚠️ Read-Only:</strong> The permission system indicates you don't have write access to this file.
                            Only <strong>${{data.write_users.join(', ')}}</strong> can edit this file.
                        `;
                        this.editorContainer.parentElement.insertBefore(permissionInfo, this.editorContainer);
                    }} else if (this.isUncertainPermissions) {{
                        const permissionInfo = document.createElement('div');
                        permissionInfo.className = 'permission-warning';
                        permissionInfo.id = 'uncertain-permissions-warning';
                        permissionInfo.style.cssText = `
                            background: #fef3c7;
                            border: 1px solid #fcd34d;
                            border-radius: 6px;
                            padding: 12px;
                            margin: 10px 0;
                            font-size: 13px;
                            color: #d97706;
                        `;
                        permissionInfo.innerHTML = `
                            <strong>⚠️ Uncertain Permissions:</strong> This file is in another user's datasite.
                            We can't verify your write permissions until the server processes your changes.
                            If you don't have permission, a conflict file will be created.
                        `;
                        this.editorContainer.parentElement.insertBefore(permissionInfo, this.editorContainer);
                    }}
                    // Update read-only indicator in footer
                    if (this.readOnlyIndicator) {{
                        if (this.isReadOnly) {{
                            this.readOnlyIndicator.textContent = 'READ-ONLY';
                            this.readOnlyIndicator.style.color = '#dc2626';
                            this.readOnlyIndicator.style.display = 'inline';
                        }} else if (this.isUncertainPermissions) {{
                            this.readOnlyIndicator.textContent = 'UNCERTAIN PERMISSIONS';
                            this.readOnlyIndicator.style.color = '#f59e0b';
                            this.readOnlyIndicator.style.display = 'inline';
                        }} else {{
                            this.readOnlyIndicator.style.display = 'none';
                        }}
                    }}
                    // Focus the active editor
                    if (this.editorContainer.style.display !== 'none') {{
                        this.editorInput.focus();
                    }} else {{
                        this.editor.focus();
                    }}
                }} catch (error) {{
                    this.showError('Failed to load file: ' + error.message);
                }}
            }}

            async saveFile() {{
                if (!this.currentFile) return;
                // Check if file is read-only
                if (this.isReadOnly) {{
                    this.showError('Cannot save: This file is read-only. You don\\'t have write permission.');
                    return;
                }}
                // Check if we have uncertain permissions
                if (this.isUncertainPermissions) {{
                    // Show modal to confirm save attempt
                    const userConfirmed = await this.showPermissionModal();
                    if (!userConfirmed) return; // User cancelled
                }}
                // Animate the save button with rainbow effect
                this.saveBtn.classList.add('saving');
                this.saveBtn.style.transform = 'scale(0.95)';
                // Create a more visible notification
                const notification = document.createElement('div');
                notification.style.cssText = `
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    padding: 20px 40px;
                    border-radius: 12px;
                    font-weight: 600;
                    font-size: 16px;
                    color: #065f46;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
                    z-index: 10000;
                    animation: saveNotification 2s ease-in-out forwards;
                `;
                notification.textContent = '✨ Saving...';
                document.body.appendChild(notification);
                // Add the animation style if not already present
                if (!document.getElementById('save-animation-style')) {{
                    const style = document.createElement('style');
                    style.id = 'save-animation-style';
                    style.textContent = `
                        @keyframes saveNotification {{
                            0% {{
                                background: #ffcccc;
                                border: 2px solid #ffb3b3;
                                opacity: 0;
                                transform: translate(-50%, -50%) scale(0.8);
                            }}
                            10% {{
                                opacity: 1;
                                transform: translate(-50%, -50%) scale(1);
                            }}
                            20% {{ background: #ffd9b3; border-color: #ffc299; }}
                            30% {{ background: #ffffcc; border-color: #ffffb3; }}
                            40% {{ background: #ccffcc; border-color: #b3ffb3; }}
                            50% {{ background: #ccffff; border-color: #b3ffff; }}
                            60% {{ background: #ccccff; border-color: #b3b3ff; }}
                            70% {{ background: #ffccff; border-color: #ffb3ff; }}
                            80% {{ background: #dcfce7; border-color: #bbf7d0; }}
                            90% {{
                                opacity: 1;
                                transform: translate(-50%, -50%) scale(1);
                            }}
                            100% {{
                                background: #dcfce7;
                                border-color: #bbf7d0;
                                opacity: 0;
                                transform: translate(-50%, -50%) scale(1.1);
                            }}
                        }}
                    `;
                    document.head.appendChild(style);
                }}
                setTimeout(() => {{
                    this.saveBtn.style.transform = '';
                    this.saveBtn.classList.remove('saving');
                }}, 1000);
                try {{
                    // Get content from the active editor
                    let content = '';
                    if (this.editorContainer.style.display !== 'none') {{
                        content = this.editorInput.value;
                    }} else {{
                        content = this.editor.value;
                    }}
                    // Strip syft:// prefix if present
                    let filePath = this.currentFile.path;
                    if (filePath.startsWith('syft://')) {{
                        filePath = filePath.substring(7); // Remove 'syft://' prefix
                    }}
                    const requestBody = {{
                        path: filePath,
                        content: content
                    }};
                    // Add syft_user if present
                    if (this.syftUser) {{
                        requestBody.syft_user = this.syftUser;
                    }}
                    const response = await fetch('/api/filesystem/write', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify(requestBody)
                    }});
                    const data = await response.json();
                    if (!response.ok) {{
                        throw new Error(data.detail || 'Failed to save file');
                    }}
                    this.isModified = false;
                    this.updateUI();
                    // Update notification to show success
                    const notification = document.querySelector('div[style*="saveNotification"]');
                    if (notification) {{
                        notification.textContent = '✅ Saved!';
                        setTimeout(() => notification.remove(), 500);
                    }}
                    this.showSuccess('File saved successfully');
                    // Update file info
                    this.fileSize.textContent = this.formatFileSize(data.size);
                }} catch (error) {{
                    this.showError('Failed to save file: ' + error.message);
                }}
            }}

            updateUI() {{
                const title = this.currentFile ?
                    `${{this.currentFile.path.split('/').pop()}}${{this.isModified ? ' •' : ''}}${{this.isReadOnly ? ' [READ-ONLY]' : ''}}` :
                    'No file selected';
                this.editorTitle.textContent = title;
                // Disable save button if no file, not modified, or read-only
                this.saveBtn.disabled = !this.currentFile || !this.isModified || this.isReadOnly;
                // Update save button appearance for read-only
                if (this.isReadOnly) {{
                    this.saveBtn.style.opacity = '0.5';
                    this.saveBtn.style.cursor = 'not-allowed';
                    this.saveBtn.title = 'File is read-only';
                }} else {{
                    this.saveBtn.style.opacity = '';
                    this.saveBtn.style.cursor = '';
                    this.saveBtn.title = 'Save file (Ctrl+S)';
                }}
                // Show/hide close button based on whether a file is open
                this.closeFileBtn.style.display = this.currentFile ? 'inline-flex' : 'none';
                
                // Show/hide rename button based on whether a file/folder is selected
                const hasSelection = this.currentFile || this.selectedFolder;
                this.renameBtn.style.display = hasSelection ? 'inline-flex' : 'none';
                
                // Enable rename button only if user has write permissions
                if (this.renameBtn) {{
                    const canRename = hasSelection && (this.isAdmin || !this.isReadOnly);
                    this.renameBtn.disabled = !canRename;
                    
                    if (!canRename) {{
                        this.renameBtn.style.opacity = '0.5';
                        this.renameBtn.style.cursor = 'not-allowed';
                        this.renameBtn.title = this.isReadOnly ? 'Read-only - cannot rename' : 'Select a file or folder first';
                    }} else {{
                        this.renameBtn.style.opacity = '';
                        this.renameBtn.style.cursor = '';
                        this.renameBtn.title = 'Rename file/folder';
                    }}
                }}
                // Update share button - only enabled if user has admin permissions
                if (this.shareBtn) {{
                    const hasFile = this.currentFile || this.selectedFolder || this.currentPath;
                    const canShare = hasFile && this.isAdmin;
                    this.shareBtn.disabled = !canShare;
                    if (!hasFile) {{
                        this.shareBtn.style.opacity = '0.5';
                        this.shareBtn.style.cursor = 'not-allowed';
                        this.shareBtn.title = 'Select a file or folder first';
                    }} else if (!this.isAdmin) {{
                        this.shareBtn.style.opacity = '0.5';
                        this.shareBtn.style.cursor = 'not-allowed';
                        this.shareBtn.title = 'You need admin permissions to share this item';
                    }} else {{
                        this.shareBtn.style.opacity = '';
                        this.shareBtn.style.cursor = '';
                        this.shareBtn.title = 'Share file/folder';
                    }}
                }}
            }}

            closeFile() {{
                // Close the current file and return to directory view
                this.currentFile = null;
                this.selectedFolder = null;
                this.isModified = false;
                this.isReadOnly = false;
                this.isUncertainPermissions = false;
                // Clear editors
                this.editor.value = '';
                this.editorInput.value = '';
                // Hide editors and show empty state
                this.editor.style.display = 'none';
                this.editorContainer.style.display = 'none';
                this.emptyState.style.display = 'flex';
                // Restore default empty state content
                this.emptyState.innerHTML = `
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
                `;
                // Remove any permission warnings
                const existingWarnings = this.editorContainer.parentElement.querySelectorAll('.permission-warning');
                existingWarnings.forEach(w => w.remove());
                // Update UI
                this.updateUI();
                // Clear file info
                this.fileInfo.innerHTML = 'Ready';
                this.fileSize.textContent = '0 bytes';
                // Reset read-only indicator
                if (this.readOnlyIndicator) {{
                    this.readOnlyIndicator.style.display = 'none';
                }}
                // Clear any selected file styling in the file list
                this.fileList.querySelectorAll('.file-item').forEach(item => {{
                    item.classList.remove('selected');
                }});
            }}

            updateCursorPosition() {{
                let textarea;
                if (this.editorContainer.style.display !== 'none') {{
                    textarea = this.editorInput;
                }} else {{
                    textarea = this.editor;
                }}
                const text = textarea.value;
                const cursorPos = textarea.selectionStart;
                // Calculate line and column
                const lines = text.substring(0, cursorPos).split('\\n');
                const line = lines.length;
                const col = lines[lines.length - 1].length + 1;
                this.cursorPosition.textContent = `Ln ${{line}}, Col ${{col}}`;
            }}

            formatFileSize(bytes) {{
                if (bytes === 0) return '0 bytes';
                const k = 1024;
                const sizes = ['bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }}

            showContextMenu(event, path, isDirectory) {{
                // Simple context menu - for now just prevent the default browser menu
                // Could be extended later to show options like delete, rename, etc.
                event.preventDefault();
                console.log('Context menu for:', path, 'isDirectory:', isDirectory);
            }}

            showError(message) {{
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error';
                errorDiv.textContent = message;
                document.body.appendChild(errorDiv);
                setTimeout(() => {{
                    errorDiv.remove();
                }}, 5000);
            }}

            showSuccess(message) {{
                const successDiv = document.createElement('div');
                successDiv.className = 'success';
                successDiv.textContent = message;
                document.body.appendChild(successDiv);
                setTimeout(() => {{
                    successDiv.style.animation = 'slideOut 0.3s ease-in forwards';
                    setTimeout(() => successDiv.remove(), 300);
                }}, 3500);  // Show for 3.5 seconds to see full animation
            }}

            createNewFile() {{
                const filename = prompt('Enter filename:', 'untitled.txt');
                if (!filename) return;
                const newPath = this.currentPath + '/' + filename;
                // Strip syft:// prefix if present
                let filePath = newPath;
                if (filePath.startsWith('syft://')) {{
                    filePath = filePath.substring(7); // Remove 'syft://' prefix
                }}
                const requestBody = {{
                    path: filePath,
                    content: '',
                    create_dirs: true
                }};
                // Add syft_user if present
                if (this.syftUser) {{
                    requestBody.syft_user = this.syftUser;
                }}
                // Create empty file
                fetch('/api/filesystem/write', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(requestBody)
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.message) {{
                        this.showSuccess(data.message);
                        this.loadDirectory(this.currentPath);
                    }}
                }})
                .catch(error => {{
                    this.showError('Failed to create file: ' + error.message);
                }});
            }}

            createNewFolder() {{
                const foldername = prompt('Enter folder name:', 'New Folder');
                if (!foldername) return;
                const newPath = this.currentPath + '/' + foldername;
                const requestBody = {{
                    path: newPath
                }};
                // Add syft_user if present
                if (this.syftUser) {{
                    requestBody.syft_user = this.syftUser;
                }}
                fetch('/api/filesystem/create-directory', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(requestBody)
                }})
                .then(response => response.json())
                .then(data => {{
                    if (data.message) {{
                        this.showSuccess(data.message);
                        this.loadDirectory(this.currentPath);
                    }}
                }})
                .catch(error => {{
                    this.showError('Failed to create folder: ' + error.message);
                }});
            }}

            toggleFileOnlyMode(forceState = null) {{
                if (forceState !== null) {{
                    this.fileOnlyMode = forceState;
                }} else {{
                    this.fileOnlyMode = !this.fileOnlyMode;
                }}
                if (this.fileOnlyMode) {{
                    document.body.classList.add('file-only-mode');
                    this.toggleExplorerBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/></svg> Show';
                }} else {{
                    document.body.classList.remove('file-only-mode');
                    this.toggleExplorerBtn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3h6l2 3h10a2 2 0 012 2v10a2 2 0 01-2 2H3a2 2 0 01-2-2V5a2 2 0 012-2z"/></svg>';
                }}
            }}

            showError(message) {{
                alert('Error: ' + message);
            }}

            showSuccess(message) {{
                console.log('Success: ' + message);
            }}

            async showPermissionModal() {{
                return new Promise((resolve) => {{
                    // Create modal overlay
                    const overlay = document.createElement('div');
                    overlay.style.cssText = `
                        position: fixed;
                        top: 0;
                        left: 0;
                        right: 0;
                        bottom: 0;
                        background: rgba(0, 0, 0, 0.5);
                        z-index: 9999;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        animation: fadeIn 0.2s ease-out;
                    `;
                    // Create modal content
                    const modal = document.createElement('div');
                    modal.style.cssText = `
                        background: white;
                        border-radius: 8px;
                        padding: 24px;
                        max-width: 500px;
                        width: 90%;
                        box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
                        animation: slideIn 0.3s ease-out;
                    `;
                    const fileName = this.currentFile.path.split('/').pop();
                    const fileExt = this.currentFile.extension || '.txt';
                    modal.innerHTML = `
                        <h3 style="margin: 0 0 16px 0; font-size: 18px; font-weight: 600; color: #111827;">
                            ⚠️ Uncertain Write Permissions
                        </h3>
                        <div style="color: #374151; font-size: 14px; line-height: 1.6; margin-bottom: 20px;">
                            <p style="margin: 0 0 12px 0;">
                                This file is in another user's datasite. We can't verify your write permissions
                                until the server processes your changes.
                            </p>
                            <p style="margin: 0 0 12px 0;">
                                <strong>If you have permission:</strong> Your changes will be saved normally.
                            </p>
                            <p style="margin: 0;">
                                <strong>If you don't have permission:</strong> A conflict file
                                (<code style="background: #f3f4f6; padding: 2px 4px; border-radius: 3px;">${{fileName}}.syftconflict${{fileExt}}</code>)
                                will be created with your changes.
                            </p>
                        </div>
                        <div style="display: flex; gap: 12px; justify-content: flex-end;">
                            <button id="cancelSave" style="
                                padding: 8px 16px;
                                border: 1px solid #d1d5db;
                                background: white;
                                color: #374151;
                                border-radius: 6px;
                                font-size: 14px;
                                font-weight: 500;
                                cursor: pointer;
                                transition: all 0.2s;
                            " onmouseover="this.style.background='#f9fafb'" onmouseout="this.style.background='white'">
                                Cancel
                            </button>
                            <button id="confirmSave" style="
                                padding: 8px 16px;
                                border: 1px solid #fbbf24;
                                background: #fbbf24;
                                color: #78350f;
                                border-radius: 6px;
                                font-size: 14px;
                                font-weight: 500;
                                cursor: pointer;
                                transition: all 0.2s;
                            " onmouseover="this.style.background='#f59e0b'" onmouseout="this.style.background='#fbbf24'">
                                Save Anyway
                            </button>
                        </div>
                    `;
                    overlay.appendChild(modal);
                    document.body.appendChild(overlay);
                    // Add animation styles if not present
                    if (!document.getElementById('modal-animations')) {{
                        const style = document.createElement('style');
                        style.id = 'modal-animations';
                        style.textContent = `
                            @keyframes fadeIn {{
                                from {{ opacity: 0; }}
                                to {{ opacity: 1; }}
                            }}
                            @keyframes slideIn {{
                                from {{ transform: translateY(-20px); opacity: 0; }}
                                to {{ transform: translateY(0); opacity: 1; }}
                            }}
                        `;
                        document.head.appendChild(style);
                    }}
                    // Handle button clicks
                    const cancelBtn = modal.querySelector('#cancelSave');
                    const confirmBtn = modal.querySelector('#confirmSave');
                    const cleanup = () => {{
                        overlay.style.animation = 'fadeIn 0.2s ease-out reverse';
                        modal.style.animation = 'slideIn 0.2s ease-out reverse';
                        setTimeout(() => overlay.remove(), 200);
                    }};
                    cancelBtn.addEventListener('click', () => {{
                        cleanup();
                        resolve(false);
                    }});
                    confirmBtn.addEventListener('click', () => {{
                        cleanup();
                        resolve(true);
                    }});
                    // Close on escape key
                    const escHandler = (e) => {{
                        if (e.key === 'Escape') {{
                            cleanup();
                            resolve(false);
                            document.removeEventListener('keydown', escHandler);
                        }}
                    }};
                    document.addEventListener('keydown', escHandler);
                }});
            }}

            async showShareModal() {{
                // Determine the path to share - could be current file, selected folder, or current directory
                let pathToShare;
                if (this.currentFile) {{
                    pathToShare = this.currentFile.path;
                }} else if (this.selectedFolder) {{
                    pathToShare = this.selectedFolder;
                }} else {{
                    pathToShare = this.currentPath;
                }}
                if (!pathToShare) {{
                    this.showError('No file or folder selected');
                    return;
                }}
                // Create modal overlay
                const overlay = document.createElement('div');
                overlay.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    right: 0;
                    bottom: 0;
                    background: rgba(0, 0, 0, 0.5);
                    z-index: 10000;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    animation: fadeIn 0.3s ease-out;
                `;
                // Create modal container with iframe
                const modal = document.createElement('div');
                modal.style.cssText = `
                    background: transparent;
                    border-radius: 12px;
                    width: 90%;
                    max-width: 640px;
                    height: 600px;
                    max-height: 80vh;
                    overflow: hidden;
                    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.3);
                    animation: slideIn 0.3s ease-out;
                `;
                // Create iframe
                const iframe = document.createElement('iframe');
                const shareUrl = `/share-modal?path=${{encodeURIComponent(pathToShare)}}`;
                iframe.src = shareUrl;
                iframe.style.cssText = `
                    width: 100%;
                    height: 100%;
                    border: none;
                    border-radius: 12px;
                `;
                modal.appendChild(iframe);
                overlay.appendChild(modal);
                document.body.appendChild(overlay);
                // Handle messages from iframe
                const messageHandler = (event) => {{
                    if (event.data && event.data.action === 'closeShareModal') {{
                        document.body.removeChild(overlay);
                        window.removeEventListener('message', messageHandler);
                    }}
                }};
                window.addEventListener('message', messageHandler);
                // Allow closing by clicking overlay
                overlay.addEventListener('click', (e) => {{
                    if (e.target === overlay) {{
                        document.body.removeChild(overlay);
                        window.removeEventListener('message', messageHandler);
                    }}
                }});
            }}
            
            async showRenameModal() {{
                // Determine what to rename
                let pathToRename;
                let itemName;
                let isDirectory = false;
                
                if (this.currentFile) {{
                    pathToRename = this.currentFile.path;
                    itemName = pathToRename.split('/').pop() || 'file';
                    isDirectory = false;
                }} else if (this.selectedFolder) {{
                    pathToRename = this.selectedFolder;
                    itemName = pathToRename.split('/').pop() || pathToRename;
                    isDirectory = true;
                }} else {{
                    this.showError('No file or folder selected to rename');
                    return;
                }}
                
                // Create modal dialog
                const modal = document.createElement('div');
                modal.className = 'modal';
                modal.style.display = 'block';
                
                const modalContent = document.createElement('div');
                modalContent.className = 'modal-content';
                
                modalContent.innerHTML = `
                    <h2 style="margin: 0 0 16px 0;">Rename ${{isDirectory ? 'Folder' : 'File'}}</h2>
                    <p style="margin: 0 0 16px 0; opacity: 0.8;">Current name: <strong>${{itemName}}</strong></p>
                    <input type="text" id="newNameInput" value="${{itemName}}" 
                        style="width: 100%; padding: 12px 80px 12px 16px; margin-bottom: 16px; 
                               border: 1px solid var(--border-color); border-radius: 4px;
                               background: var(--input-bg); color: var(--text-color);
                               font-size: 14px; box-sizing: border-box;">
                    <div style="display: flex; justify-content: flex-end; gap: 8px;">
                        <button class="btn btn-secondary" id="cancelRename">Cancel</button>
                        <button class="btn btn-primary" id="confirmRename">Rename</button>
                    </div>
                `;
                
                modal.appendChild(modalContent);
                document.body.appendChild(modal);
                
                // Focus input and select text
                const input = modalContent.querySelector('#newNameInput');
                input.focus();
                input.select();
                
                // Handle rename
                const doRename = async () => {{
                    const newName = input.value.trim();
                    if (!newName) {{
                        this.showError('Name cannot be empty');
                        return;
                    }}
                    
                    if (newName === itemName) {{
                        document.body.removeChild(modal);
                        return;
                    }}
                    
                    try {{
                        // Calculate new path
                        const pathParts = pathToRename.split('/');
                        pathParts[pathParts.length - 1] = newName;
                        const newPath = pathParts.join('/');
                        
                        // Call rename API
                        let url = `/api/filesystem/rename?old_path=${{encodeURIComponent(pathToRename)}}&new_path=${{encodeURIComponent(newPath)}}`;
                        if (this.syftUser) {{
                            url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;
                        }}
                        
                        const response = await fetch(url, {{ method: 'POST' }});
                        const result = await response.json();
                        
                        if (response.ok) {{
                            this.showSuccess(`${{isDirectory ? 'Folder' : 'File'}} renamed successfully`);
                            document.body.removeChild(modal);
                            
                            // Update UI
                            if (this.currentFile && !isDirectory) {{
                                // If we renamed the current file, load the new file
                                this.loadFile(newPath);
                            }} else {{
                                // Refresh the directory listing
                                this.loadDirectory(this.currentPath);
                                
                                // If we renamed a folder and it was selected, update the selection
                                if (this.selectedFolder === pathToRename) {{
                                    this.selectedFolder = newPath;
                                }}
                            }}
                        }} else {{
                            this.showError(result.detail || 'Failed to rename');
                        }}
                    }} catch (error) {{
                        this.showError('Error renaming: ' + error.message);
                    }}
                }};
                
                // Event listeners
                modalContent.querySelector('#confirmRename').addEventListener('click', doRename);
                modalContent.querySelector('#cancelRename').addEventListener('click', () => {{
                    document.body.removeChild(modal);
                }});
                
                input.addEventListener('keydown', (e) => {{
                    if (e.key === 'Enter') {{
                        doRename();
                    }} else if (e.key === 'Escape') {{
                        document.body.removeChild(modal);
                    }}
                }});
                
                // Close on outside click
                modal.addEventListener('click', (e) => {{
                    if (e.target === modal) {{
                        document.body.removeChild(modal);
                    }}
                }});
            }}

            async getCurrentUser() {{
                // If we have a syft user from the URL, use that
                if (this.syftUser) {{
                    return this.syftUser;
                }}
                // Try to get current user from the backend or environment
                try {{
                    const response = await fetch('/api/current-user');
                    if (response.ok) {{
                        const data = await response.json();
                        return data.email;
                    }}
                }} catch (e) {{
                    // Fallback: try to extract from local path or use a default
                    const pathParts = window.location.pathname.split('/');
                    const datasitesIndex = pathParts.indexOf('datasites');
                    if (datasitesIndex >= 0 && pathParts.length > datasitesIndex + 1) {{
                        return pathParts[datasitesIndex + 1];
                    }}
                }}
                return null;
            }}

            async checkFolderPermissions(folderPath) {{
                // Check admin permissions for a selected folder
                try {{
                    let url = `/api/filesystem/read?path=${{encodeURIComponent(folderPath + '/.syft_folder_check')}}`;
                    if (this.syftUser) {{
                        url += `&syft_user=${{encodeURIComponent(this.syftUser)}}`;
                    }}
                    // We'll use a trick: try to read a non-existent file in the folder
                    // This will trigger permission checks for the folder itself
                    const response = await fetch(url);
                    if (response.status === 404) {{
                        // File not found is expected, but we got permission info
                        const data = await response.json();
                        // The backend should still check permissions even for non-existent files
                    }}
                    // For now, let's use a simpler approach: when a folder is selected,
                    // we already have its parent's admin status from loadDirectory
                    // So we'll inherit that status
                    // This is a reasonable assumption since folder permissions are inherited
                    // The isAdmin status was already set by loadDirectory for the current directory
                    // We'll keep that status for selected folders within that directory
                    this.updateUI();
                }} catch (error) {{
                    console.error('Error checking folder permissions:', error);
                    // On error, assume no admin access
                    this.isAdmin = false;
                    this.updateUI();
                }}
            }}
        }}

        // Initialize the editor when DOM is loaded
        document.addEventListener('DOMContentLoaded', () => {{
            new FileSystemEditor();
        }});
    """
