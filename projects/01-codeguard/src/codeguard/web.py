"""Web server launcher for the CodeGuard local-first web application."""

from __future__ import annotations

from pathlib import Path

import uvicorn

from codeguard.api import create_app


def serve_ui(host: str = "127.0.0.1", port: int = 8765, db_path: Path | None = None) -> None:
    """Launch the CodeGuard FastAPI web workbench with Uvicorn."""
    app = create_app(db_path=db_path)
    print(f"CodeGuard Web Workbench running at http://{host}:{port} (Ctrl+C to stop)")
    uvicorn.run(app, host=host, port=port, log_level="warning")
