from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def list_findings():
    return {"findings": [], "total": 0}
