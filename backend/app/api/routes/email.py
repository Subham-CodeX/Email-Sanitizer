from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.database import get_database
from app.schemas.email import EmailIngestionResponse
from app.services.email_parser import parse_email
from app.services.evidence_service import save_evidence

router = APIRouter(prefix="/emails", tags=["Email Ingestion"])

class RawEmailRequest(BaseModel):
    raw_email: str = Field(..., min_length=1)
    filename: str | None = None

@router.post("/ingest/eml", response_model=EmailIngestionResponse)
async def ingest_eml(file: UploadFile = File(...)):
    filename = file.filename or "uploaded.eml"
    if not filename.lower().endswith(".eml"):
        raise HTTPException(400, "Only .eml files are accepted.")
    raw = await file.read()
    if not raw:
        raise HTTPException(400, "The .eml file is empty.")
    return await _process(raw, "eml", filename)

@router.post("/ingest/raw", response_model=EmailIngestionResponse)
async def ingest_raw(payload: RawEmailRequest):
    raw = payload.raw_email.encode("utf-8")
    return await _process(raw, "raw_email", payload.filename)

async def _process(raw, input_type, filename):
    if len(raw) > settings.max_email_size_bytes:
        raise HTTPException(413, f"Email exceeds {settings.max_email_size_mb} MB.")
    try:
        parsed = parse_email(raw)
        return await save_evidence(raw, input_type, filename, parsed)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, f"Email ingestion failed: {exc}") from exc

@router.get("/evidence/{evidence_id}")
async def get_evidence(evidence_id: str):
    doc = await get_database().email_evidence.find_one({"evidence_id": evidence_id}, {"_id": 0})
    if not doc:
        raise HTTPException(404, "Evidence record not found.")
    for field in ("received_at", "created_at"):
        if doc.get(field):
            doc[field] = doc[field].isoformat()
    return doc
