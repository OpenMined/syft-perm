"""Share modal template for filesystem editor."""

import json
from pathlib import Path
from typing import Optional


def generate_share_modal_html(
    path: str, is_dark_mode: bool = False, syft_user: Optional[str] = None
) -> str:
    """Generate standalone share modal HTML."""

    path_obj = Path(path)

    file_name = path_obj.name

    is_directory = path_obj.is_dir() if path_obj.exists() else False

    item_type = "folder" if is_directory else "file"

    # Define theme colors

    if is_dark_mode:

        bg_color = "#2d2d30"

        text_color = "#d4d4d4"

        border_color = "#3e3e42"

        input_bg = "#1e1e1e"

        hover_bg = "#3e3e42"

        muted_color = "#9ca3af"

        modal_bg = "#252526"

    else:

        bg_color = "white"

        text_color = "#374151"

        border_color = "#e5e7eb"

        input_bg = "white"

        hover_bg = "#f3f4f6"

        muted_color = "#6b7280"

        modal_bg = "#f9fafb"

    return f"""

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>Share {file_name}</title>

    <style>

        body {{

            margin: 0;

            padding: 20px;

            background: {bg_color};

            color: {text_color};

            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;

            display: flex;

            align-items: center;

            justify-content: center;

            min-height: 100vh;

        }}

        .container {{

            background: {bg_color};

            border-radius: 12px;

            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);

            width: 100%;

            max-width: 640px;

            overflow: hidden;

        }}

        .header {{

            padding: 20px 24px;

            border-bottom: 1px solid {border_color};

        }}

        .header h1 {{

            margin: 0;

            font-size: 18px;

            font-weight: 600;

        }}

        .header p {{

            margin: 4px 0 0 0;

            font-size: 14px;

            color: {muted_color};

        }}

        .body {{

            padding: 20px 0;

            max-height: 400px;

            overflow-y: auto;

        }}

        .add-section {{

            padding: 0 24px 16px;

            border-bottom: 1px solid {border_color};

            margin-bottom: 16px;

        }}

        .add-form {{

            display: flex;

            gap: 8px;

            align-items: flex-end;

        }}

        .form-group {{

            flex: 1;

        }}

        .form-label {{

            display: block;

            font-size: 13px;

            font-weight: 500;

            margin-bottom: 6px;

        }}

        .form-input {{

            width: 100%;

            padding: 8px 40px 8px 12px;

            border: 1px solid {border_color};

            border-radius: 6px;

            background: {input_bg};

            color: {text_color};

            font-size: 14px;

            box-sizing: border-box;

        }}

        .form-select {{

            padding: 8px 12px;

            border: 1px solid {border_color};

            border-radius: 6px;

            background: {input_bg};

            color: {text_color};

            font-size: 14px;

            cursor: pointer;

        }}

        .btn {{

            padding: 8px 16px;

            border: none;

            border-radius: 6px;

            font-size: 14px;

            font-weight: 500;

            cursor: pointer;

            transition: all 0.2s;

            white-space: nowrap;

        }}

        .btn-primary {{

            background: #3b82f6;

            color: white;

        }}

        .btn-primary:hover {{

            background: #2563eb;

        }}

        .btn-secondary {{

            background: {modal_bg};

            color: {text_color};

            border: 1px solid {border_color};

        }}

        .btn-secondary:hover {{

            background: {hover_bg};

        }}

        .user-row {{

            display: flex;

            align-items: center;

            padding: 12px 24px;

            border-bottom: 1px solid {border_color};

            gap: 12px;

        }}

        .user-row:hover {{

            background: {hover_bg};

        }}

        .user-info {{

            flex: 1;

            min-width: 0;

        }}

        .user-email {{

            font-weight: 500;

            font-size: 14px;

            overflow: hidden;

            text-overflow: ellipsis;

            white-space: nowrap;

        }}

        .user-role {{

            font-size: 12px;

            color: {muted_color};

            margin-top: 2px;

        }}

        .permission-reasons {{
            margin-top: 4px;
            padding: 6px 0;
            font-size: 11px;
            color: {muted_color};
            font-style: italic;
        }}

        .reason-item {{
            margin: 0;
            display: flex;
            align-items: center;
            gap: 6px;
            line-height: 1.3;
        }}

        .reason-perm {{
            font-weight: 500;
            color: {f'#1d4ed8' if not is_dark_mode else '#60a5fa'};
            text-transform: uppercase;
            font-size: 10px;
            letter-spacing: 0.3px;
        }}

        .reason-text {{
            flex: 1;
            opacity: 0.85;
            font-weight: 400;
            word-break: break-word;
        }}

        .reason-icon {{
            margin-right: 2px;
            opacity: 0.8;
            font-size: 10px;
        }}

        .permission-select {{

            padding: 6px 8px;

            border: 1px solid {border_color};

            border-radius: 6px;

            background: {input_bg};

            color: {text_color};

            font-size: 13px;

            cursor: pointer;

        }}

        .remove-btn {{

            padding: 6px;

            border: none;

            background: none;

            color: {muted_color};

            cursor: pointer;

            border-radius: 4px;

            transition: all 0.2s;

        }}

        .remove-btn:hover {{

            background: {hover_bg};

            color: #ef4444;

        }}

        .footer {{

            padding: 16px 24px;

            border-top: 1px solid {border_color};

            display: flex;

            justify-content: flex-end;

            gap: 12px;

            background: {modal_bg};

        }}

        .loading {{

            text-align: center;

            padding: 40px;

            color: {muted_color};

        }}

        .error {{

            background: #fee2e2;

            color: #dc2626;

            padding: 12px 16px;

            border-radius: 8px;

            margin: 16px 24px;

            font-size: 14px;

        }}

        .success {{

            background: #d1fae5;

            color: #065f46;

            padding: 12px 16px;

            border-radius: 8px;

            margin: 16px 24px;

            font-size: 14px;

        }}

        .empty {{

            padding: 40px;

            text-align: center;

            color: {muted_color};

            font-size: 14px;

        }}

    </style>

</head>

<body>

    <div class="container">

        <div class="header">

            <h1>Share "{file_name}"</h1>

            <p>Manage who can access this {item_type}</p>

        </div>

        <div id="messageArea"></div>

        <div class="body">

            <div class="add-section">

                <div class="add-form">

                    <div class="form-group">

                        <label class="form-label">Add person</label>

                        <input

                            type="email"

                            id="userEmailInput"

                            class="form-input"

                            placeholder="Enter email address"

                        />

                    </div>

                    <select id="newUserPermission" class="form-select">

                        <option value="read">Read</option>

                        <option value="write">Write</option>

                        <option value="admin">Admin</option>

                    </select>

                    <button class="btn btn-primary" onclick="addUser()">Add</button>

                </div>

            </div>

            <div id="usersList" class="loading">Loading permissions...</div>

        </div>

        <div class="footer">

            <button class="btn btn-secondary" onclick="closeModal()">Cancel</button>

            <button class="btn btn-primary" onclick="saveChanges()">Save Changes</button>

        </div>

    </div>

    <script>

        const path = {json.dumps(path)};

        const syftUser = {json.dumps(syft_user) if syft_user else 'null'};

        let currentPermissions = {{}};

        let pendingChanges = {{}};

        async function loadPermissions() {{

            try {{

                const response = await fetch(`/permissions/${{encodeURIComponent(path)}}?include_reasons=true`);

                if (!response.ok) {{

                    throw new Error('Failed to load permissions');

                }}

                const data = await response.json();
                
                // Debug: Log the raw response data
                console.log('Raw response data from /permissions/:', data);

                // Store the full data structure

                currentPermissions = data.permissions || {{}};
                
                // Debug: Log what currentPermissions is set to
                console.log('currentPermissions set to:', currentPermissions);

                renderUsersList();

                // Check if current user has admin permissions

                const currentUser = await getCurrentUser();

                if (currentUser) {{

                    let hasAdmin = false;

                    // Check if we have permission reasons (new format) or simple permissions (old format)

                    const hasReasons = currentPermissions && Object.values(currentPermissions).some(userPerm =>

                        userPerm && typeof userPerm === 'object' && userPerm.reasons

                    );
                    
                    // Debug: Log hasReasons check result
                    console.log('hasReasons check evaluates to:', hasReasons);
                    console.log('Object.values(currentPermissions):', Object.values(currentPermissions));

                    if (hasReasons) {{

                        // New format with reasons - check user's admin permission directly

                        const userData = currentPermissions[currentUser];

                        if (userData && userData.reasons && userData.reasons.admin) {{

                            hasAdmin = userData.reasons.admin.granted;

                        }}

                    }} else {{

                        // Old format without reasons

                        if (currentPermissions.admin) {{

                            hasAdmin = currentPermissions.admin.includes(currentUser) ||

                                     currentPermissions.admin.includes('*');

                        }}

                    }}

                    if (!hasAdmin) {{

                        showError('You need admin permissions to share this {item_type}');

                        document.querySelector('.add-section').style.display = 'none';

                        document.querySelector('.footer').style.display = 'none';

                    }}

                }}

            }} catch (error) {{

                showError('Failed to load permissions: ' + error.message);

            }}

        }}

        async function getCurrentUser() {{

            if (syftUser) return syftUser;

            try {{

                const response = await fetch('/api/current-user');

                if (response.ok) {{

                    const data = await response.json();

                    return data.email;

                }}

            }} catch (e) {{

                console.error('Failed to get current user:', e);

            }}

            return null;

        }}

        function renderUsersList() {{

            const container = document.getElementById('usersList');

            const allUsers = new Set();

            // Debug log to see what we're working with

            console.log('Current permissions:', currentPermissions);

            // Check if we have the permissions format from the API response

            let actualPermissions = currentPermissions;

            if (currentPermissions.permissions) {{

                // We have a response object with a permissions property

                actualPermissions = currentPermissions.permissions;

            }}
            
            // Debug: Log what actualPermissions contains
            console.log('actualPermissions in renderUsersList:', actualPermissions);

            // Check if we have permission reasons (new format) or simple permissions (old format)

            const hasReasons = actualPermissions && Object.values(actualPermissions).some(value =>

                value && typeof value === 'object' && value.reasons && !Array.isArray(value)

            );
            
            // Debug: Log hasReasons check in renderUsersList
            console.log('hasReasons in renderUsersList:', hasReasons);
            console.log('Object.keys(actualPermissions):', Object.keys(actualPermissions));
            console.log('Object.values(actualPermissions):', Object.values(actualPermissions));

            if (hasReasons) {{

                // New format with reasons - users are keys
                
                // Debug: Log what we're treating as users
                console.log('hasReasons is true, treating these as users:', Object.keys(actualPermissions));

                Object.keys(actualPermissions).forEach(user => {{

                    if (user !== 'read' && user !== 'create' && user !== 'write' && user !== 'admin') {{

                        allUsers.add(user);
                        console.log('Adding user:', user);

                    }} else {{
                        console.log('Skipping key (not a user):', user);
                    }}

                }});

            }} else {{

                // Old format - permissions are keys with user arrays as values

                ['read', 'create', 'write', 'admin'].forEach(permType => {{

                    if (actualPermissions[permType] && Array.isArray(actualPermissions[permType])) {{

                        actualPermissions[permType].forEach(user => allUsers.add(user));

                    }}

                }});

            }}

            if (allUsers.size === 0) {{

                container.innerHTML = '<div class="empty">No users have access yet</div>';

                return;

            }}

            const html = Array.from(allUsers).map(user => {{

                let userPerms = {{}};

                let reasons = {{}};

                if (hasReasons) {{

                    // New format with reasons

                    const userData = actualPermissions[user];

                    if (userData && userData.permissions) {{

                        ['read', 'create', 'write', 'admin'].forEach(perm => {{

                            userPerms[perm] = userData.permissions[perm]?.includes(user) || false;

                        }});

                        reasons = userData.reasons || {{}};

                    }}

                }} else {{

                    // Old format without reasons

                    ['read', 'create', 'write', 'admin'].forEach(perm => {{

                        userPerms[perm] = actualPermissions[perm]?.includes(user) || false;

                    }});

                }}

                const role = getUserRole(userPerms);

                const reasonsHtml = hasReasons ? generateReasonsHtml(user, reasons) : '';

                return `

                    <div class="user-row">

                        <div class="user-info">

                            <div class="user-email">${{user}}</div>

                            <div class="user-role">${{role}}</div>

                            ${{reasonsHtml}}

                        </div>

                        <select class="permission-select" onchange="updatePermission('${{user}}', this.value)">

                            <option value="none" ${{!userPerms.read ? 'selected' : ''}}>No access</option>

                            <option value="read" ${{userPerms.read && !userPerms.write && !userPerms.admin ? 'selected' : ''}}>Read</option>

                            <option value="write" ${{userPerms.write && !userPerms.admin ? 'selected' : ''}}>Write</option>

                            <option value="admin" ${{userPerms.admin ? 'selected' : ''}}>Admin</option>

                        </select>

                        <button class="remove-btn" onclick="removeUser('${{user}}')" title="Remove user">

                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">

                                <path d="M3 6h18M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6m3 0V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/>

                            </svg>

                        </button>

                    </div>

                `;

            }}).join('');

            container.innerHTML = html;

        }}

        function generateReasonsHtml(user, reasons) {{

            if (!reasons || Object.keys(reasons).length === 0) {{

                return '';

            }}

            let reasonsHtml = '<div class="permission-reasons">';
            
            // Find the highest granted permission level
            let highestPerm = null;
            ['admin', 'write', 'create', 'read'].forEach(perm => {{
                const permData = reasons[perm];
                if (permData && permData.granted && permData.reasons && permData.reasons.length > 0 && !highestPerm) {{
                    highestPerm = {{ level: perm, data: permData }};
                }}
            }});
            
            if (highestPerm) {{
                const icons = {{
                    'admin': '👑',
                    'write': '✏️', 
                    'create': '📝',
                    'read': '👁️'
                }};
                
                // Clean up the reason text - remove path prefix if it's too long
                let reasonText = highestPerm.data.reasons[0];
                if (reasonText.includes('/Users/') && reasonText.length > 50) {{
                    reasonText = reasonText.replace(/\\/Users\\/[^\\/]+\\/SyftBox\\/datasites\\/[^\\/]+\\//, '...');
                }}
                
                reasonsHtml += `<div class="reason-item">
                    <span class="reason-perm">
                        <span class="reason-icon">${{icons[highestPerm.level] || '📋'}}</span>${{highestPerm.level.toUpperCase()}}:
                    </span>
                    <span class="reason-text">${{reasonText}}</span>
                </div>`;
            }}

            reasonsHtml += '</div>';

            return reasonsHtml;

        }}

        function getUserRole(perms) {{

            if (perms.admin) return 'Admin (can manage permissions)';

            if (perms.write) return 'Write (can edit {item_type})';

            if (perms.read) return 'Read (can view {item_type})';

            return 'No access';

        }}

        function updatePermission(user, level) {{

            if (!pendingChanges[user]) {{

                pendingChanges[user] = {{}};

            }}

            pendingChanges[user].level = level;

        }}

        function removeUser(user) {{

            if (!pendingChanges[user]) {{

                pendingChanges[user] = {{}};

            }}

            pendingChanges[user].remove = true;

            // Update UI immediately

            const newPerms = JSON.parse(JSON.stringify(currentPermissions));

            ['read', 'create', 'write', 'admin'].forEach(perm => {{

                if (newPerms[perm]) {{

                    newPerms[perm] = newPerms[perm].filter(u => u !== user);

                }}

            }});

            currentPermissions = newPerms;

            renderUsersList();

        }}

        async function addUser() {{

            const email = document.getElementById('userEmailInput').value.trim();

            const permission = document.getElementById('newUserPermission').value;

            if (!email) {{

                showError('Please enter an email address');

                return;

            }}

            if (!email.includes('@')) {{

                showError('Please enter a valid email address');

                return;

            }}

            // Check if user already exists

            const allUsers = new Set();

            // Check if we have the new format with reasons
            const hasReasons = currentPermissions && Object.values(currentPermissions).some(value =>

                value && typeof value === 'object' && value.reasons && !Array.isArray(value)

            );

            if (hasReasons) {{

                Object.keys(currentPermissions).forEach(user => {{

                    if (user !== 'read' && user !== 'create' && user !== 'write' && user !== 'admin') {{

                        allUsers.add(user);

                    }}

                }});

            }} else {{

                ['read', 'create', 'write', 'admin'].forEach(permType => {{

                    if (currentPermissions[permType] && Array.isArray(currentPermissions[permType])) {{

                        currentPermissions[permType].forEach(user => allUsers.add(user));

                    }}

                }});

            }}

            if (allUsers.has(email)) {{

                showError('User already has access');

                return;

            }}

            // Add to pending changes

            if (!pendingChanges[email]) {{

                pendingChanges[email] = {{}};

            }}

            pendingChanges[email].level = permission;

            // Update UI immediately - handle both formats correctly

            const newPerms = JSON.parse(JSON.stringify(currentPermissions));

            if (hasReasons) {{

                // Use new format with reasons
                // First check if user already exists in newPerms
                if (!newPerms[email]) {{
                    newPerms[email] = {{
                        permissions: {{
                            read: [],
                            create: [],
                            write: [],
                            admin: []
                        }},
                        reasons: {{}}
                    }};
                }}

                // Update permissions based on level
                const userPerms = newPerms[email].permissions;
                
                // Clear all permissions first
                userPerms.read = [];
                userPerms.create = [];
                userPerms.write = [];
                userPerms.admin = [];
                
                // Add appropriate permissions based on level
                if (permission === 'read' || permission === 'write' || permission === 'admin') {{
                    userPerms.read = [email];
                }}
                if (permission === 'write' || permission === 'admin') {{
                    userPerms.create = [email];
                    userPerms.write = [email];
                }}
                if (permission === 'admin') {{
                    userPerms.admin = [email];
                }}

                // Update reasons
                newPerms[email].reasons = {{
                    read: {{
                        granted: permission === 'read' || permission === 'write' || permission === 'admin',
                        reasons: permission === 'read' || permission === 'write' || permission === 'admin' 
                            ? [`Manually granted ${{permission}} permission`] : []
                    }},
                    create: {{
                        granted: permission === 'write' || permission === 'admin',
                        reasons: permission === 'write' || permission === 'admin' 
                            ? [`Manually granted ${{permission}} permission`] : []
                    }},
                    write: {{
                        granted: permission === 'write' || permission === 'admin',
                        reasons: permission === 'write' || permission === 'admin' 
                            ? [`Manually granted ${{permission}} permission`] : []
                    }},
                    admin: {{
                        granted: permission === 'admin',
                        reasons: permission === 'admin' 
                            ? [`Manually granted ${{permission}} permission`] : []
                    }}
                }};

            }} else {{

                // Use old format

                if (!newPerms.read) newPerms.read = [];

                if (!newPerms.create) newPerms.create = [];

                if (!newPerms.write) newPerms.write = [];

                if (!newPerms.admin) newPerms.admin = [];

                // Remove user from all permissions first

                ['read', 'create', 'write', 'admin'].forEach(perm => {{

                    newPerms[perm] = newPerms[perm].filter(u => u !== email);

                }});

                // Add user with appropriate permissions

                if (permission === 'read') {{

                    newPerms.read.push(email);

                }} else if (permission === 'write') {{

                    newPerms.read.push(email);

                    newPerms.create.push(email);

                    newPerms.write.push(email);

                }} else if (permission === 'admin') {{

                    newPerms.read.push(email);

                    newPerms.create.push(email);

                    newPerms.write.push(email);

                    newPerms.admin.push(email);

                }}

            }}

            // Update currentPermissions with the new data
            currentPermissions = newPerms;

            renderUsersList();

            // Clear input

            document.getElementById('userEmailInput').value = '';

        }}

        async function saveChanges() {{

            const updates = [];

            for (const [user, changes] of Object.entries(pendingChanges)) {{

                if (changes.remove) {{

                    // Remove all permissions

                    ['read', 'create', 'write', 'admin'].forEach(perm => {{

                        updates.push({{

                            path: path,

                            user: user,

                            permission: perm,

                            action: 'revoke'

                        }});

                    }});

                }} else if (changes.level) {{

                    // First remove all permissions

                    ['read', 'create', 'write', 'admin'].forEach(perm => {{

                        updates.push({{

                            path: path,

                            user: user,

                            permission: perm,

                            action: 'revoke'

                        }});

                    }});

                    // Then grant appropriate permissions

                    if (changes.level === 'read') {{

                        updates.push({{

                            path: path,

                            user: user,

                            permission: 'read',

                            action: 'grant'

                        }});

                    }} else if (changes.level === 'write') {{

                        ['read', 'create', 'write'].forEach(perm => {{

                            updates.push({{

                                path: path,

                                user: user,

                                permission: perm,

                                action: 'grant'

                            }});

                        }});

                    }} else if (changes.level === 'admin') {{

                        ['read', 'create', 'write', 'admin'].forEach(perm => {{

                            updates.push({{

                                path: path,

                                user: user,

                                permission: perm,

                                action: 'grant'

                            }});

                        }});

                    }}

                }}

            }}

            try {{

                for (const update of updates) {{

                    const response = await fetch('/permissions/update', {{

                        method: 'POST',

                        headers: {{ 'Content-Type': 'application/json' }},

                        body: JSON.stringify(update)

                    }});

                    if (!response.ok) {{

                        throw new Error('Failed to update permissions');

                    }}

                }}

                showSuccess('Permissions updated successfully');

                pendingChanges = {{}};

                // Close modal after success

                setTimeout(() => {{

                    if (window.parent !== window) {{

                        window.parent.postMessage({{ action: 'closeShareModal' }}, '*');

                    }} else {{

                        window.close();

                    }}

                }}, 1500);

            }} catch (error) {{

                showError('Failed to save permissions: ' + error.message);

            }}

        }}

        function closeModal() {{

            if (window.parent !== window) {{

                window.parent.postMessage({{ action: 'closeShareModal' }}, '*');

            }} else {{

                window.close();

            }}

        }}

        function showError(message) {{

            const area = document.getElementById('messageArea');

            area.innerHTML = `<div class="error">${{message}}</div>`;

            setTimeout(() => area.innerHTML = '', 5000);

        }}

        function showSuccess(message) {{

            const area = document.getElementById('messageArea');

            area.innerHTML = `<div class="success">${{message}}</div>`;

        }}

        // Load permissions on page load

        loadPermissions();

    </script>

</body>

</html>

"""
