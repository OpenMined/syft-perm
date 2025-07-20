"""FastAPI routes for the share modal and permission editor."""

from typing import Optional

from fastapi import Query
from fastapi.responses import HTMLResponse

from .._public import is_dark as _is_dark
from .modal import generate_share_modal_html
from .permission_editor import get_editor_html


def register_routes(app):
    """Register share modal and permission editor routes with the FastAPI app."""

    @app.get("/share-modal", response_class=HTMLResponse)
    async def share_modal(
        path: str = Query(...), syft_user: Optional[str] = Query(None)
    ) -> HTMLResponse:
        """Serve the share modal as a standalone page."""
        return HTMLResponse(
            content=generate_share_modal_html(
                path=path, is_dark_mode=_is_dark(), syft_user=syft_user
            )
        )

    @app.get("/editor/{path:path}", response_class=HTMLResponse)
    async def permission_editor(path: str) -> str:
        """Serve the Google Drive-style permission editor."""
        return get_editor_html(path)
