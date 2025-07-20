"""FastAPI routes for the file editor."""

from typing import Optional

from fastapi import Query
from fastapi.responses import HTMLResponse

from .._public import is_dark as _is_dark
from .editor import generate_editor_html


def register_routes(app):
    """Register file editor routes with the FastAPI app."""

    @app.get("/file-editor", response_class=HTMLResponse)
    async def file_editor_interface(syft_user: Optional[str] = Query(None)) -> HTMLResponse:
        """Serve the file editor interface."""
        return HTMLResponse(
            content=generate_editor_html(is_dark_mode=_is_dark(), syft_user=syft_user)
        )

    @app.get("/file-editor/{path:path}", response_class=HTMLResponse)
    async def file_editor_with_path(
        path: str, syft_user: Optional[str] = Query(None), new: Optional[str] = Query(None)
    ) -> HTMLResponse:
        """Serve the file editor interface with a specific path."""
        is_new_file = new == "true"
        return HTMLResponse(
            content=generate_editor_html(
                initial_path=path,
                is_dark_mode=_is_dark(),
                syft_user=syft_user,
                is_new_file=is_new_file,
            )
        )
