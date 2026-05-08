"""iStrix API server — FastAPI application with WebSocket support.

Provides REST + WebSocket API for the iStrix backend, shared by CLI and GUI.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from istrix.api.routes import scans, jobs, findings, reports, plugins, cve, ai
from istrix.api.websocket import ws_router
from istrix.plugins.registry import plugin_registry

GUI_DIR = Path(__file__).parent.parent / "gui" / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown: discover plugins, init DB on startup."""
    plugin_registry.discover()
    yield


app = FastAPI(
    title="iStrix API",
    version="0.2.0",
    description="AI-powered penetration testing orchestration toolkit — Backend API",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# REST routes
app.include_router(scans.router, prefix="/api/scans", tags=["Scans"])
app.include_router(jobs.router, prefix="/api/jobs", tags=["Jobs"])
app.include_router(findings.router, prefix="/api/findings", tags=["Findings"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(plugins.router, prefix="/api/plugins", tags=["Plugins"])
app.include_router(cve.router, prefix="/api/cve", tags=["CVE Feed"])
app.include_router(ai.router, prefix="/api/ai", tags=["AI"])

# WebSocket
app.include_router(ws_router)

# Health
@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "0.2.0"}

# Serve GUI static files
if GUI_DIR.exists():
    app.mount("/", StaticFiles(directory=str(GUI_DIR), html=True), name="gui")


def main():
    """Entry point for istrix-server command."""
    import uvicorn
    uvicorn.run("istrix.api.server:app", host="0.0.0.0", port=8443, reload=True)
