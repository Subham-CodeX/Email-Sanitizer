from fastapi import (
    APIRouter,
    File,
    HTTPException,
    UploadFile,
)

from pydantic import BaseModel, Field
from app.core.config import settings
from app.core.database import (
    get_database,
)

from app.schemas.email import (
    EmailIngestionResponse,
    HeaderForensicsResponse,
)

from app.services.email_parser import (
    parse_email,
)

from app.services.evidence_service import (
    save_evidence,
)

from app.services.header_forensics import (
    analyze_headers,
)

router = APIRouter(
    prefix="/emails",
    tags=["Email Ingestion"],
)

class RawEmailRequest(BaseModel):

    raw_email: str = Field(
        ...,
        min_length=1,
    )

    filename: str | None = None

@router.post(
    "/ingest/eml",
    response_model=EmailIngestionResponse,
)
async def ingest_eml(
    file: UploadFile = File(...),
):

    filename = (
        file.filename
        or "uploaded.eml"
    )

    if not filename.lower().endswith(
        ".eml"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Only .eml files "
                "are accepted."
            ),
        )

    raw = await file.read()

    if not raw:

        raise HTTPException(
            status_code=400,
            detail=(
                "The .eml file "
                "is empty."
            ),
        )

    return await process_email(
        raw=raw,
        input_type="eml",
        filename=filename,
    )

@router.post(
    "/ingest/raw",
    response_model=EmailIngestionResponse,
)
async def ingest_raw(
    payload: RawEmailRequest,
):

    raw = payload.raw_email.encode(
        "utf-8"
    )

    return await process_email(
        raw=raw,
        input_type="raw_email",
        filename=payload.filename,
    )

async def process_email(
    raw,
    input_type,
    filename,
):

    if len(raw) > settings.max_email_size_bytes:

        raise HTTPException(
            status_code=413,
            detail=(
                f"Email exceeds "
                f"{settings.max_email_size_mb} MB."
            ),
        )

    try:

        parsed = parse_email(
            raw
        )

        return await save_evidence(
            raw=raw,
            input_type=input_type,
            filename=filename,
            parsed=parsed,
        )

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Email ingestion failed: "
                f"{exc}"
            ),
        ) from exc


@router.get(
    "/evidence/{evidence_id}",
)
async def get_evidence(
    evidence_id: str,
):

    document = await get_database()[
        "email_evidence"
    ].find_one(
        {
            "evidence_id":
                evidence_id
        },
        {
            "_id": 0
        },
    )

    if not document:

        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence record "
                "not found."
            ),
        )

    for field in (
        "received_at",
        "created_at",
    ):

        if document.get(field):

            document[field] = (
                document[field]
                .isoformat()
            )

    return document

@router.get(
    "/evidence/{evidence_id}/headers",
    response_model=HeaderForensicsResponse,
)
async def analyze_email_headers(
    evidence_id: str,
):

    document = await get_database()[
        "email_evidence"
    ].find_one(
        {
            "evidence_id":
                evidence_id
        },
        {
            "_id": 0,
        },
    )

    if not document:

        raise HTTPException(
            status_code=404,
            detail=(
                "Evidence record "
                "not found."
            ),
        )

    raw_headers = document.get(
        "raw_headers"
    )

    if not raw_headers:

        raise HTTPException(
            status_code=422,
            detail=(
                "Raw headers are not "
                "available for this "
                "evidence record. "
                "Re-ingest the email "
                "with the Phase 2 "
                "ingestion parser."
            ),
        )

    try:

        result = analyze_headers(
            evidence_id=evidence_id,
            raw_headers=raw_headers,
        )

        await get_database()[
            "email_evidence"
        ].update_one(
            {
                "evidence_id":
                    evidence_id
            },
            {
                "$set": {
                    "header_forensics":
                        result.model_dump(),
                    "phase_2":
                        "header_forensics",
                }
            },
        )

        return {
            "evidence_id":
                evidence_id,
            "header_forensics":
                result,
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=(
                "Header analysis failed: "
                f"{exc}"
            ),
        ) from exc