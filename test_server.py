#!/usr/bin/env python3
"""Simple test server for the file editor."""

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from src.syft_perm.filesystem_editor import generate_editor_html, FileSystemManager
from pathlib import Path
import json

app = FastAPI()

# Create a filesystem manager for the current directory
fs_manager = FileSystemManager(str(Path.cwd()))

@app.get("/", response_class=HTMLResponse)
async def file_editor():
    """File editor interface."""
    return HTMLResponse(content=generate_editor_html(is_dark_mode=False))

@app.get("/api/filesystem/list")
async def list_directory(path: str = "."):
    """List directory contents."""
    try:
        result = fs_manager.list_directory(path)
        return result
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/filesystem/read")
async def read_file(path: str):
    """Read a file."""
    try:
        result = fs_manager.read_file(path)
        return result
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/filesystem/write")
async def write_file(request: dict):
    """Write to a file."""
    try:
        path = request.get("path")
        content = request.get("content")
        result = fs_manager.write_file(path, content)
        return result
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    print("Starting test server for file editor...")
    print("Open http://localhost:8889 in your browser")
    uvicorn.run(app, host="127.0.0.1", port=8889, log_level="info")