"""Transition animations and progressive enhancement for widgets."""

import json
from typing import Dict, Optional


class TransitionRenderer:
    """
    Handles smooth transitions from static to interactive content.

    Features:
    - Multiple transition styles (fade, slide, morph)
    - State preservation during transitions
    - Cross-widget coordination via WebSocket/localStorage
    - Automatic server detection and content swapping
    """

    def __init__(self):
        """Initialize the transition renderer."""
        self._transition_css = self._get_transition_css()
        self._transition_js = self._get_transition_js()

    def render_transition(
        self,
        widget_id: str,
        static_content: str,
        transition_style: str = "fade",
        server_check_interval: int = 1000,
        max_wait_time: int = 30000,
        custom_css: Optional[str] = None,
    ) -> str:
        """
        Render HTML with transition capability.

        Args:
            widget_id: Unique widget identifier
            static_content: Static HTML content to display initially
            transition_style: Style of transition ('fade', 'slide', 'morph')
            server_check_interval: How often to check for server (ms)
            max_wait_time: Maximum time to wait for server (ms)
            custom_css: Additional CSS to include

        Returns:
            HTML string with transition capability
        """
        # Build configuration
        config = {
            "widgetId": widget_id,
            "transitionStyle": transition_style,
            "checkInterval": server_check_interval,
            "maxWaitTime": max_wait_time,
            "discoveryPort": 62050,
            "endpoints": {"files": "/files/widget", "editor": "/editor", "share": "/share-modal"},
        }

        # Generate HTML
        html = f"""
        <div id="{widget_id}_container" class="syft-widget-container" data-widget-state="static">
            <style>
                {self._transition_css}
                {custom_css or ''}
            </style>
            
            <div id="{widget_id}_static" class="syft-widget-content syft-widget-static">
                {static_content}
            </div>
            
            <div id="{widget_id}_interactive" class="syft-widget-content syft-widget-interactive" style="display: none;">
                <!-- Interactive content will be loaded here -->
            </div>
            
            <div id="{widget_id}_loading" class="syft-widget-loading" style="display: none;">
                <div class="syft-widget-spinner"></div>
                <div class="syft-widget-loading-text">Connecting to server...</div>
            </div>
            
            <script>
                (function() {{
                    const config = {json.dumps(config)};
                    {self._transition_js}
                    
                    // Initialize transition handler
                    new SyftWidgetTransition(config);
                }})();
            </script>
        </div>
        """

        return html

    def _get_transition_css(self) -> str:
        """Get CSS for transitions."""
        return """
        .syft-widget-container {
            position: relative;
            min-height: 200px;
        }
        
        .syft-widget-content {
            position: relative;
            width: 100%;
        }
        
        /* Fade transition */
        .syft-widget-container[data-transition="fade"] .syft-widget-content {
            transition: opacity 0.3s ease-in-out;
        }
        
        .syft-widget-container[data-transition="fade"] .syft-widget-static.transitioning-out {
            opacity: 0;
        }
        
        .syft-widget-container[data-transition="fade"] .syft-widget-interactive.transitioning-in {
            opacity: 0;
        }
        
        .syft-widget-container[data-transition="fade"] .syft-widget-interactive {
            opacity: 1;
        }
        
        /* Slide transition */
        .syft-widget-container[data-transition="slide"] {
            overflow: hidden;
        }
        
        .syft-widget-container[data-transition="slide"] .syft-widget-content {
            transition: transform 0.4s ease-in-out;
        }
        
        .syft-widget-container[data-transition="slide"] .syft-widget-static.transitioning-out {
            transform: translateX(-100%);
        }
        
        .syft-widget-container[data-transition="slide"] .syft-widget-interactive {
            position: absolute;
            top: 0;
            left: 0;
            transform: translateX(100%);
        }
        
        .syft-widget-container[data-transition="slide"] .syft-widget-interactive.transitioning-in {
            transform: translateX(0);
        }
        
        /* Morph transition */
        .syft-widget-container[data-transition="morph"] .syft-widget-content {
            transition: all 0.5s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        .syft-widget-container[data-transition="morph"] .syft-widget-static.transitioning-out {
            transform: scale(0.95);
            opacity: 0.5;
            filter: blur(2px);
        }
        
        /* Loading spinner */
        .syft-widget-loading {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            z-index: 1000;
        }
        
        .syft-widget-spinner {
            width: 40px;
            height: 40px;
            margin: 0 auto 10px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            animation: syft-spin 1s linear infinite;
        }
        
        @keyframes syft-spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .syft-widget-loading-text {
            font-size: 14px;
            color: #666;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }
        
        /* Disabled state styling */
        .syft-widget-static .disabled,
        .syft-widget-static [data-interactive-only] {
            opacity: 0.5;
            cursor: not-allowed;
            pointer-events: none;
        }
        
        .syft-widget-static .disabled::after,
        .syft-widget-static [data-interactive-only]::after {
            content: " (requires server)";
            font-size: 0.8em;
            opacity: 0.7;
            font-style: italic;
        }
        """

    def _get_transition_js(self) -> str:
        """Get JavaScript for transitions."""
        return """
        class SyftWidgetTransition {
            constructor(config) {
                this.config = config;
                this.container = document.getElementById(config.widgetId + '_container');
                this.staticContent = document.getElementById(config.widgetId + '_static');
                this.interactiveContent = document.getElementById(config.widgetId + '_interactive');
                this.loadingIndicator = document.getElementById(config.widgetId + '_loading');
                
                this.serverUrl = null;
                this.checkCount = 0;
                this.maxChecks = Math.floor(config.maxWaitTime / config.checkInterval);
                
                // Start checking for server
                this.startServerCheck();
                
                // Listen for server availability broadcasts
                this.listenForServerBroadcast();
            }
            
            startServerCheck() {
                this.checkInterval = setInterval(() => {
                    this.checkServers();
                    this.checkCount++;
                    
                    if (this.checkCount >= this.maxChecks) {
                        clearInterval(this.checkInterval);
                        this.showTimeoutMessage();
                    }
                }, this.config.checkInterval);
                
                // Check immediately
                this.checkServers();
            }
            
            async checkServers() {
                // Check known ports
                const portsToCheck = [8005, 8006, 8007, 8008];
                
                for (const port of portsToCheck) {
                    try {
                        const response = await fetch(`http://localhost:${port}`, {
                            method: 'HEAD',
                            mode: 'no-cors'
                        });
                        
                        // If we get here without error, server might be available
                        const checkUrl = `http://localhost:${port}`;
                        if (await this.verifyServer(checkUrl)) {
                            this.onServerFound(checkUrl);
                            return;
                        }
                    } catch (e) {
                        // Server not available on this port
                    }
                }
                
                // Check discovery port
                try {
                    const response = await fetch(`http://localhost:${this.config.discoveryPort}`);
                    const data = await response.json();
                    
                    if (data.main_server_port) {
                        const serverUrl = `http://localhost:${data.main_server_port}`;
                        if (await this.verifyServer(serverUrl)) {
                            this.onServerFound(serverUrl);
                            return;
                        }
                    }
                } catch (e) {
                    // Discovery port not available
                }
            }
            
            async verifyServer(url) {
                try {
                    // Try to fetch a known endpoint
                    const response = await fetch(url + '/health', {
                        method: 'GET',
                        headers: {'Accept': 'application/json'}
                    });
                    return response.ok;
                } catch (e) {
                    return false;
                }
            }
            
            onServerFound(serverUrl) {
                this.serverUrl = serverUrl;
                clearInterval(this.checkInterval);
                
                // Broadcast server availability to other widgets
                this.broadcastServerAvailability(serverUrl);
                
                // Start transition
                this.transitionToInteractive();
            }
            
            async transitionToInteractive() {
                // Show loading indicator
                this.loadingIndicator.style.display = 'block';
                
                try {
                    // Fetch interactive content
                    const endpoint = this.getEndpointForWidget();
                    const response = await fetch(this.serverUrl + endpoint);
                    const html = await response.text();
                    
                    // Insert interactive content
                    this.interactiveContent.innerHTML = html;
                    
                    // Hide loading indicator
                    this.loadingIndicator.style.display = 'none';
                    
                    // Start transition
                    this.performTransition();
                    
                } catch (e) {
                    console.error('Failed to load interactive content:', e);
                    this.loadingIndicator.style.display = 'none';
                    this.showErrorMessage();
                }
            }
            
            performTransition() {
                // Set transition style
                this.container.setAttribute('data-transition', this.config.transitionStyle);
                this.container.setAttribute('data-widget-state', 'transitioning');
                
                // Preserve form state if needed
                const formData = this.preserveFormState();
                
                // Start transition
                this.staticContent.classList.add('transitioning-out');
                this.interactiveContent.style.display = 'block';
                this.interactiveContent.classList.add('transitioning-in');
                
                // Complete transition after animation
                setTimeout(() => {
                    this.staticContent.style.display = 'none';
                    this.interactiveContent.classList.remove('transitioning-in');
                    this.container.setAttribute('data-widget-state', 'interactive');
                    
                    // Restore form state
                    this.restoreFormState(formData);
                    
                    // Initialize interactive components
                    this.initializeInteractiveComponents();
                }, 500);
            }
            
            preserveFormState() {
                const formData = {};
                const inputs = this.staticContent.querySelectorAll('input, select, textarea');
                
                inputs.forEach(input => {
                    if (input.name) {
                        if (input.type === 'checkbox' || input.type === 'radio') {
                            formData[input.name] = input.checked;
                        } else {
                            formData[input.name] = input.value;
                        }
                    }
                });
                
                return formData;
            }
            
            restoreFormState(formData) {
                const inputs = this.interactiveContent.querySelectorAll('input, select, textarea');
                
                inputs.forEach(input => {
                    if (input.name && formData[input.name] !== undefined) {
                        if (input.type === 'checkbox' || input.type === 'radio') {
                            input.checked = formData[input.name];
                        } else {
                            input.value = formData[input.name];
                        }
                    }
                });
            }
            
            initializeInteractiveComponents() {
                // Trigger custom event for widget initialization
                const event = new CustomEvent('syft-widget-ready', {
                    detail: {
                        widgetId: this.config.widgetId,
                        serverUrl: this.serverUrl
                    }
                });
                this.container.dispatchEvent(event);
            }
            
            getEndpointForWidget() {
                // Determine endpoint based on widget ID
                if (this.config.widgetId.startsWith('files')) {
                    return this.config.endpoints.files;
                } else if (this.config.widgetId.startsWith('editor')) {
                    return this.config.endpoints.editor;
                } else if (this.config.widgetId.startsWith('share')) {
                    return this.config.endpoints.share;
                }
                return '/';
            }
            
            broadcastServerAvailability(serverUrl) {
                // Use localStorage for cross-widget communication
                const data = {
                    serverUrl: serverUrl,
                    timestamp: Date.now()
                };
                localStorage.setItem('syft-server-available', JSON.stringify(data));
                
                // Also dispatch event
                window.dispatchEvent(new CustomEvent('syft-server-available', {
                    detail: data
                }));
            }
            
            listenForServerBroadcast() {
                // Listen for localStorage changes
                window.addEventListener('storage', (e) => {
                    if (e.key === 'syft-server-available' && e.newValue) {
                        try {
                            const data = JSON.parse(e.newValue);
                            if (data.serverUrl && !this.serverUrl) {
                                this.onServerFound(data.serverUrl);
                            }
                        } catch (e) {
                            // Invalid data
                        }
                    }
                });
                
                // Listen for custom events
                window.addEventListener('syft-server-available', (e) => {
                    if (e.detail.serverUrl && !this.serverUrl) {
                        this.onServerFound(e.detail.serverUrl);
                    }
                });
            }
            
            showTimeoutMessage() {
                const message = document.createElement('div');
                message.style.cssText = `
                    position: absolute;
                    bottom: 10px;
                    right: 10px;
                    background: #FEF3C7;
                    border: 1px solid #F59E0B;
                    border-radius: 6px;
                    padding: 8px 12px;
                    font-size: 12px;
                    color: #92400E;
                    z-index: 1001;
                `;
                message.innerHTML = 'Server not available. Using static mode.';
                this.container.appendChild(message);
                
                setTimeout(() => message.remove(), 5000);
            }
            
            showErrorMessage() {
                const message = document.createElement('div');
                message.style.cssText = `
                    position: absolute;
                    bottom: 10px;
                    right: 10px;
                    background: #FEE2E2;
                    border: 1px solid #EF4444;
                    border-radius: 6px;
                    padding: 8px 12px;
                    font-size: 12px;
                    color: #991B1B;
                    z-index: 1001;
                `;
                message.innerHTML = 'Failed to load interactive content.';
                this.container.appendChild(message);
                
                setTimeout(() => message.remove(), 5000);
            }
        }
        """
