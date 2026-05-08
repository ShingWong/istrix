"""AI chat endpoints."""
from fastapi import APIRouter

router = APIRouter()


@router.post("/chat")
async def ai_chat():
    return {"response": "AI chat endpoint — not yet implemented"}
