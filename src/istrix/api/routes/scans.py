"""REST endpoints for scans and job progress tracking."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def list_scans():
    return {"scans": [], "total": 0}


@router.get("/{scan_id}")
async def get_scan(scan_id: str):
    return {"id": scan_id, "status": "not_implemented"}
