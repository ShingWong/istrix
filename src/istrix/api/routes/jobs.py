"""REST endpoints for jobs."""
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
async def list_jobs():
    return {"jobs": [], "total": 0}

@router.get("/{job_id}")
async def get_job(job_id: str):
    return {"id": job_id, "status": "not_implemented"}
