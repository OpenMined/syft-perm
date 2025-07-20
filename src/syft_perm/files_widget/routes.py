"""FastAPI routes for the files widget."""

from typing import List, Optional

from fastapi import Query
from fastapi.responses import HTMLResponse

from ..filesystem_editor import get_current_user_email
from .widget import get_files_widget_html


def register_routes(app):
    """Register files widget routes with the FastAPI app."""

    @app.get("/files-widget", response_class=HTMLResponse)
    async def files_widget(
        search: Optional[str] = Query(None, description="Search term for file names"),
        admin: Optional[str] = Query(None, description="Filter by admin email"),
        folders: Optional[str] = Query(None, description="Comma-separated folder paths"),
        page: int = Query(1, ge=1, description="Page number (1-based)"),
        items_per_page: int = Query(50, ge=1, le=1000, description="Items per page"),
        start: Optional[int] = Query(None, ge=0, description="Start index for slicing"),
        end: Optional[int] = Query(None, ge=0, description="End index for slicing"),
        filetype: Optional[str] = Query(
            None, description="Filter by file type: 'file' or 'folder'"
        ),
    ) -> str:
        """Serve the files widget interface with filtering support."""
        # Get current user email
        current_user_email = get_current_user_email() or ""

        # Parse folders if provided
        folder_list = None
        if folders:
            folder_list = [f.strip() for f in folders.split(",") if f.strip()]

        # Generate the widget HTML with parameters
        return get_files_widget_html(
            search=search,
            admin=admin,
            folders=folder_list,
            page=page,
            items_per_page=items_per_page,
            start=start,
            end=end,
            current_user_email=current_user_email,
            filetype=filetype,
        )
