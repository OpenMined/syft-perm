"""FastAPI Files widget for server-based file browsing."""

from typing import Dict, List, Optional

from ._public import Files as _Files
from ._public import FilteredFiles as _FilteredFiles
from ._public import is_dark as _is_dark


class FastAPIFiles(_FilteredFiles):
    """Files browser served via FastAPI server."""

    def __init__(self, server_url: str):
        """Initialize with server URL."""
        self.server_url = server_url.rstrip("/")

    def search(
        self,
        files: Optional[str] = None,
        admin: Optional[str] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        folders: Optional[List[str]] = None,
    ):
        """Search files with filters."""
        url = f"{self.server_url}/files-widget"
        params = []
        if files:
            params.append(f"search={files}")
        if admin:
            params.append(f"admin={admin}")
        if limit is not None:
            params.append(f"items_per_page={limit}")
        if offset is not None:
            page = (offset // (limit or 50)) + 1
            params.append(f"page={page}")
        if folders:
            for folder in folders:
                params.append(f"folders={folder}")

        if params:
            url += "?" + "&".join(params)

        result = FastAPIFiles(self.server_url)
        result._url = url
        return result

    def filter(self, folders: List[str]):
        """Filter by folders."""
        return self.search(folders=folders)

    def get(self, limit: Optional[int] = None, offset: Optional[int] = None):
        """Get paginated results."""
        return self.search(limit=limit, offset=offset)

    def all(self, search: Optional[str] = None):
        """Return URL for all files."""
        url = f"{self.server_url}/files-widget"
        result = FastAPIFiles(self.server_url)
        result._url = url
        return result

    def __repr__(self) -> str:
        """Return the URL when printed."""
        if hasattr(self, "_url"):
            return f"FastAPI Files Widget: {self._url}"
        return f"FastAPI Files Widget: {self.server_url}/files-widget"

    def _repr_html_(self) -> str:
        """Display as iframe in Jupyter."""
        url = getattr(self, "_url", f"{self.server_url}/files-widget")
        is_dark_mode = _is_dark()
        border_color = "#3e3e42" if is_dark_mode else "#ddd"

        return f"""
        <div style="width: 100%; height: 600px; border: 1px solid {border_color}; border-radius: 8px; overflow: hidden;">
            <iframe 
                src="{url}" 
                width="100%" 
                height="100%" 
                frameborder="0"
                style="border: none;"
                allow="clipboard-read; clipboard-write">
            </iframe>
        </div>
        """
