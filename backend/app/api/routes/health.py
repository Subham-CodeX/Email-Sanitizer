from fastapi import APIRouter
from app.core.database import get_database

router = APIRouter(prefix="/health", tags=["Health"])

@router.get("")
async def health():
    db_status = "disconnected"
    try:
        await get_database().command("ping")
        db_status = "connected"
    except Exception:
        pass
    return {"status": "ok", "service": "PhishingTrack API", "database": db_status, "phase": "Phase 1"}
