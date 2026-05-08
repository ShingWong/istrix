"""Plugin discovery and management endpoints."""

from fastapi import APIRouter

from istrix.plugins.registry import plugin_registry

router = APIRouter()


@router.get("/")
async def list_plugins():
    plugin_registry.discover()
    return {
        "tools": plugin_registry.list_tools(),
        "skills": plugin_registry.list_skills(),
        "knowledge": plugin_registry.list_knowledge(),
    }
