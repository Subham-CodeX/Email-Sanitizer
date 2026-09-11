from datetime import datetime, timezone
from uuid import uuid4

from app.core.database import get_database
from app.schemas.email import EmailIngestionResponse
from app.services.email_parser import sha256_bytes

async def save_evidence(raw, input_type, filename, parsed):
    evidence_id = f"EV-{uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc)
    evidence_hash = sha256_bytes(raw)

    document = {
        "evidence_id": evidence_id,
        "input_type": input_type,
        "filename": filename,
        "received_at": now,
        "evidence_sha256": evidence_hash,
        "metadata": parsed.metadata.model_dump(by_alias=True),
        "attachments": [x.model_dump() for x in parsed.attachments],
        "urls": [x.model_dump() for x in parsed.urls],
        "body_preview": parsed.body_preview,
        "raw_size_bytes": len(raw),
        "phase": "phase_1_email_ingestion",
        "created_at": now,
    }
    await get_database().email_evidence.insert_one(document)

    return EmailIngestionResponse(
        evidence_id=evidence_id,
        input_type=input_type,
        filename=filename,
        received_at=now.isoformat(),
        evidence_sha256=evidence_hash,
        metadata=parsed.metadata,
        attachments=parsed.attachments,
        urls=parsed.urls,
        body_preview=parsed.body_preview,
        status="ingested",
    )
