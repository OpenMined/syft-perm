# Syft Widget Infrastructure

Unified widget infrastructure for syft-perm that provides consistent server detection, HTML generation, and smooth transitions between static and interactive modes.

## Features

- **Automatic Server Management**: Detects running servers, starts new ones, installs SyftBox apps
- **Progressive Enhancement**: Smooth transitions from static to interactive content
- **Consistent Styling**: Shared HTML generation with dark mode support
- **Cross-Widget Coordination**: Widgets share server instances and communicate state
- **Zero Configuration**: Works out of the box with sensible defaults

## Architecture

```
syft_widget/
├── base.py              # UnifiedWidget base class
├── server_manager.py    # Centralized server management
├── port_registry.py     # Port discovery and coordination
├── transitions.py       # Smooth transition animations
├── html_generator.py    # Consistent HTML generation
└── assets/             # Shared CSS and resources
```

## Quick Start

1. **Create a new widget**:

```python
from syft_widget import UnifiedWidget

class MyWidget(UnifiedWidget):
    def __init__(self):
        super().__init__("my_widget")
    
    def get_static_html(self, **kwargs):
        return "<div>Static content</div>"
    
    def get_interactive_html(self, server_url, **kwargs):
        return f"<iframe src='{server_url}/my-endpoint'></iframe>"
    
    def get_server_endpoint(self):
        return "/my-endpoint"
```

2. **Use in Jupyter**:

```python
widget = MyWidget()
widget  # Displays in notebook with automatic server handling
```

## Components

### UnifiedWidget

Base class for all widgets. Handles:
- Server state detection
- Parallel server startup
- HTML generation based on server availability
- Transition orchestration

### ServerManager

Singleton that manages server lifecycle:
- Checks for running servers
- Starts thread-based servers
- Installs and monitors SyftBox apps
- Prevents duplicate server instances

### TransitionRenderer

Handles smooth transitions:
- Multiple transition styles (fade, slide, morph)
- State preservation during transitions
- Cross-widget coordination
- Automatic server detection

### HTMLGenerator

Creates consistent HTML components:
- Mode-aware rendering (static vs interactive)
- Dark mode support
- Accessible components
- Responsive design

### PortRegistry

File-based port discovery:
- Cross-process coordination
- Automatic cleanup of stale entries
- Service discovery
- Port conflict resolution

## Server Deployment Paradigms

The infrastructure supports three deployment paradigms:

1. **Static HTML in Jupyter**: Read-only fallback when no server available
2. **FastAPI in Python Thread**: Quick startup for notebook sessions
3. **FastAPI via SyftBox App**: Persistent server for production use

## Transition Behavior

When a widget is displayed:

1. **Quick Check** (< 100ms): Look for running servers
2. **Immediate Display**: Show static content with transition wrapper
3. **Background Startup**: Launch servers in parallel
4. **Progressive Enhancement**: Smoothly transition when server ready

## Configuration

### Environment Variables

- `SYFT_USE_UNIFIED_WIDGETS`: Enable unified widgets (for gradual rollout)
- `SYFT_WIDGET_TRANSITION_STYLE`: Default transition style
- `SYFT_WIDGET_SERVER_TIMEOUT`: Maximum wait time for servers

### Widget Options

```python
widget.render_with_options(
    mode="auto",              # "auto", "static", "interactive"
    force_static=False,       # Force static rendering
    transition_style="fade",  # "fade", "slide", "morph"
    custom_css=None          # Additional CSS
)
```

## Best Practices

1. **Always implement meaningful static content** - Don't just show "Loading..."
2. **Use `interactive_only=True`** for elements that require a server
3. **Leverage HTMLGenerator** for consistent styling
4. **Test both modes** - Ensure widgets work without servers
5. **Handle state preservation** during transitions

## Migration

See [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md) for detailed instructions on migrating existing widgets.

## Development

### Running Tests

```bash
python -m pytest src/syft_perm/syft_widget/tests/
```

### Adding a New Widget

1. Create a class extending `UnifiedWidget`
2. Implement the three required methods
3. Add tests for both static and interactive modes
4. Update documentation

## Future Enhancements

- WebSocket support for real-time updates
- Offline-first with service workers
- Widget composition and nesting
- Performance monitoring
- A/B testing framework