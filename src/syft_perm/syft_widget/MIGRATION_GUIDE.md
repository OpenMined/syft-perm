# Migration Guide: Adopting the Unified Widget Infrastructure

This guide explains how to migrate existing widgets to use the new unified widget infrastructure.

## Overview

The unified widget infrastructure provides:
- Automatic server detection and startup
- Smooth transitions from static to interactive content
- Consistent HTML generation across all widgets
- Cross-widget server coordination
- Built-in dark mode support

## Migration Steps

### 1. Create a New Widget Class

Extend the `UnifiedWidget` base class:

```python
from syft_widget import UnifiedWidget, HTMLGenerator

class YourWidget(UnifiedWidget):
    def __init__(self, data=None):
        super().__init__("your_widget_name")
        self.data = data
        self.html_generator = HTMLGenerator()
```

### 2. Implement Required Methods

#### `get_static_html()`
Generate HTML that works without a server:

```python
def get_static_html(self, **kwargs) -> str:
    # Use HTMLGenerator for consistent styling
    return self.html_generator.render_card(
        title="Your Widget",
        content="Static content here",
        actions=[
            self.html_generator.render_button(
                "Action",
                interactive_only=True  # Disabled in static mode
            )
        ]
    )
```

#### `get_interactive_html()`
Generate HTML that connects to the server:

```python
def get_interactive_html(self, server_url: str, **kwargs) -> str:
    # Option 1: Use iframe
    return f'<iframe src="{server_url}{self.get_server_endpoint()}"></iframe>'
    
    # Option 2: Fetch and embed content
    # return fetch_and_embed_content(server_url)
```

#### `get_server_endpoint()`
Return the server endpoint for this widget:

```python
def get_server_endpoint(self) -> str:
    return "/your-widget-endpoint"
```

### 3. Update Existing Widget Integration

In your existing code (e.g., `_public.py` or `_impl.py`):

```python
# Old approach
def _repr_html_(self) -> str:
    # Complex server detection logic
    # Manual HTML generation
    # No transition support
    
# New approach
def _repr_html_(self) -> str:
    from syft_widget.examples import YourWidgetUnified
    widget = YourWidgetUnified(data=self._data)
    return widget._repr_html_()
```

## Migration Examples

### Files Widget Migration

Before:
```python
# In _public.py
def _repr_html_(self) -> str:
    server_url = self._check_server()
    if server_url:
        # Generate interactive HTML
    else:
        # Generate static HTML with complex fallback logic
```

After:
```python
# In _public.py
def _repr_html_(self) -> str:
    from syft_widget.widgets import FilesWidgetUnified
    widget = FilesWidgetUnified(files_data=self._cache)
    return widget._repr_html_()
```

### Share Widget Migration

Before:
```python
# In visualization.py
def _repr_html_(self) -> str:
    # Manual server detection
    # No transition support
    # Duplicate HTML generation logic
```

After:
```python
# In visualization.py
def _repr_html_(self) -> str:
    from syft_widget.widgets import ShareWidgetUnified
    widget = ShareWidgetUnified(syft_object=self._object)
    return widget._repr_html_()
```

## Feature Flags for Gradual Rollout

Use environment variables for gradual migration:

```python
import os

def _repr_html_(self) -> str:
    if os.environ.get('SYFT_USE_UNIFIED_WIDGETS', '').lower() == 'true':
        # Use new unified widget
        from syft_widget.widgets import YourWidgetUnified
        widget = YourWidgetUnified(data=self._data)
        return widget._repr_html_()
    else:
        # Use existing implementation
        return self._old_repr_html_()
```

## Testing During Migration

1. **Unit Tests**: Test both old and new implementations
2. **Integration Tests**: Verify server startup and transitions
3. **Visual Tests**: Compare static and interactive rendering

```python
def test_widget_migration():
    # Test with unified widget
    os.environ['SYFT_USE_UNIFIED_WIDGETS'] = 'true'
    unified_html = widget._repr_html_()
    
    # Test with old implementation
    os.environ['SYFT_USE_UNIFIED_WIDGETS'] = 'false'
    old_html = widget._repr_html_()
    
    # Verify both work correctly
    assert 'syft-widget-container' in unified_html
    assert check_functionality(old_html)
```

## Benefits After Migration

1. **Reduced Code Duplication**: Remove duplicate server detection logic
2. **Better User Experience**: Smooth transitions, consistent styling
3. **Easier Maintenance**: Centralized server management
4. **Cross-Widget Coordination**: Shared server instances
5. **Future-Proof**: Easy to add new features to all widgets

## Common Pitfalls

1. **Don't forget to implement all three required methods**
2. **Use `interactive_only=True` for elements that need a server**
3. **Test both light and dark modes**
4. **Ensure static content is functional (not just a placeholder)**
5. **Use HTMLGenerator for consistent styling**

## Support

For questions or issues during migration:
1. Check the examples in `syft_widget/examples/`
2. Review the tests in `syft_widget/tests/`
3. Use the debugging tools in ServerManager
4. File issues with the [migration] tag