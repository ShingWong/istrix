"""CVE feed endpoints — get latest CVEs, force-sync."""

from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def list_cves(limit: int = 50, min_cvss: float = 7.0):
    return {"cves": [], "total": 0, "filters": {"limit": limit, "min_cvss": min_cvss}}


@router.post("/sync")
async def sync_cve_feed():
    return {"status": "queued", "message": "CVE feed sync scheduled"}
