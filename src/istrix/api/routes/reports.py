from fastapi import APIRouter
router = APIRouter()

@router.get("/")
async def list_reports():
    return {"reports": [], "total": 0}
