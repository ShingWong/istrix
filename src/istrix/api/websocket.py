"""WebSocket endpoint for real-time job progress."""

import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

ws_router = APIRouter()

# Active connections: {job_id: set(WebSocket)}
_connections: dict[str, set[WebSocket]] = {}


async def broadcast_job_progress(job_id: str, data: dict) -> None:
    """Send progress update to all clients watching a job."""
    dead: set[WebSocket] = set()
    for ws in _connections.get(job_id, set()):
        try:
            await ws.send_text(json.dumps(data))
        except Exception:
            dead.add(ws)
    _connections.get(job_id, set()).difference_update(dead)


@ws_router.websocket("/ws/jobs/{job_id}")
async def job_progress_ws(websocket: WebSocket, job_id: str):
    await websocket.accept()
    _connections.setdefault(job_id, set()).add(websocket)
    try:
        while True:
            # Keep connection alive; client can send pings
            msg = await websocket.receive_text()
            if msg == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        pass
    finally:
        _connections.get(job_id, set()).discard(websocket)
