from fastapi import (
    APIRouter,
    File,
    HTTPException,
    UploadFile,
)

from pydantic import (
    BaseModel,
    Field,
)

from app.core.config import settings

from app.core.database import (
    get_database,
)

from app.schemas.email import (
    EmailIngestionResponse,
    HeaderForensicsResponse,
)

from app.schemas.intelligence import (
    EmailIntelligenceResponse,
)

from app.services.email_intelligence import (
    analyze_email_intelligence,
)

from app.services.email_parser import (
    parse_email,
)

from app.services.evidence_service import (
    save_evidence,
)

# Phase 2
from app.services.header_forensics import (
    analyze_headers,
)

from app.schemas.url_intelligence import (
    URLIntelligenceResponse,
)

from app.services.url_intelligence import (
    analyze_email_urls,
)


router = APIRouter(
    prefix="/emails",
    tags=[
        "Email Ingestion & Intelligence"
    ],
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
            400,
            "Only .eml files are accepted.",
        )

    raw = await file.read()

    if not raw:

        raise HTTPException(
            400,
            "The .eml file is empty.",
        )

    return await _process(
        raw,
        "eml",
        filename,
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

    return await _process(
        raw,
        "raw_email",
        payload.filename,
    )

async def _process(
    raw,
    input_type,
    filename,
):

    if len(raw) > settings.max_email_size_bytes:

        raise HTTPException(
            413,
            (
                f"Email exceeds "
                f"{settings.max_email_size_mb} MB."
            ),
        )

    try:

        parsed = parse_email(
            raw
        )

        return await save_evidence(
            raw,
            input_type,
            filename,
            parsed,
        )

    except ValueError as exc:

        raise HTTPException(
            400,
            str(exc),
        ) from exc

    except Exception as exc:

        raise HTTPException(
            500,
            f"Email ingestion failed: {exc}",
        ) from exc

@router.get(
    "/evidence/{evidence_id}"
)
async def get_evidence(
    evidence_id: str,
):

    doc = await get_database().email_evidence.find_one(
        {
            "evidence_id": evidence_id
        },
        {
            "_id": 0
        },
    )

    if not doc:

        raise HTTPException(
            404,
            "Evidence record not found.",
        )

    for field in (
        "received_at",
        "created_at",
    ):

        if doc.get(field):

            doc[field] = (
                doc[field]
                .isoformat()
            )

    return doc

@router.get(
    "/evidence/{evidence_id}/headers",
    response_model=HeaderForensicsResponse,
)
async def analyze_email_headers(
    evidence_id: str,
):

    document = await get_database().email_evidence.find_one(
        {
            "evidence_id": evidence_id
        },
        {
            "_id": 0
        },
    )

    if not document:

        raise HTTPException(
            404,
            "Evidence record not found.",
        )

    raw_headers = document.get(
        "raw_headers"
    )

    if not raw_headers:

        raise HTTPException(
            422,
            (
                "Raw headers are not available "
                "for this evidence record. "
                "Re-ingest the email with the "
                "Phase 2 ingestion parser."
            ),
        )

    try:

        result = analyze_headers(
            evidence_id=evidence_id,
            raw_headers=raw_headers,
        )

    except Exception as exc:

        raise HTTPException(
            422,
            (
                "Header forensics analysis failed: "
                f"{exc}"
            ),
        ) from exc

    await get_database().email_evidence.update_one(
        {
            "evidence_id": evidence_id
        },
        {
            "$set": {
                "header_forensics": (
                    result.model_dump()
                ),
                "phase_2": (
                    "header_forensics"
                ),
            }
        },
    )

    return {
        "evidence_id": evidence_id,
        "header_forensics": result,
    }

@router.get(
    "/evidence/{evidence_id}/intelligence",
    response_model=EmailIntelligenceResponse,
)
async def analyze_email_intelligence_route(
    evidence_id: str,
):

    document = await get_database().email_evidence.find_one(
        {
            "evidence_id": evidence_id
        },
        {
            "_id": 0
        },
    )

    if not document:

        raise HTTPException(
            404,
            "Evidence record not found.",
        )

    header_forensics = document.get(
        "header_forensics"
    )

    if not header_forensics:

        raise HTTPException(
            422,
            (
                "Phase 2 header forensics are "
                "not available. Run Phase 2 "
                "Header Forensics first."
            ),
        )

    try:

        result = await analyze_email_intelligence(
            evidence_id=evidence_id,
            header_forensics=header_forensics,
        )

    except Exception as exc:

        raise HTTPException(
            502,
            (
                "Phase 3 intelligence enrichment "
                f"failed: {exc}"
            ),
        ) from exc

    await get_database().email_evidence.update_one(
        {
            "evidence_id": evidence_id
        },
        {
            "$set": {
                "intelligence": (
                    result.model_dump()
                ),
                "phase_3": (
                    "ip_sender_intelligence"
                ),
            }
        },
    )

    return {
        "evidence_id": evidence_id,
        "intelligence": result,
    }

@router.get(
    "/evidence/{evidence_id}/url-intelligence",
    response_model=URLIntelligenceResponse,
)
async def analyze_email_url_intelligence(
    evidence_id: str,
):

    document = (
        await get_database()
        .email_evidence
        .find_one(
            {
                "evidence_id":
                    evidence_id
            },
            {
                "_id": 0
            },
        )
    )

    if not document:

        raise HTTPException(
            404,
            "Evidence record not found.",
        )

    urls = (
        document.get(
            "urls"
        )
        or []
    )

    if not urls:

        raise HTTPException(
            422,
            (
                "No URLs were extracted from "
                "this email. There is nothing "
                "for Phase 4 to analyze."
            ),
        )

    try:

        result = await analyze_email_urls(
            evidence_id=evidence_id,
            urls=urls,
        )

    except Exception as exc:

        raise HTTPException(
            502,
            (
                "Phase 4 URL intelligence "
                f"failed: {exc}"
            ),
        ) from exc


    await get_database().email_evidence.update_one(
        {
            "evidence_id":
                evidence_id
        },
        {
            "$set": {
                "url_intelligence":
                    result.model_dump(),

                "phase_4":
                    "url_domain_intelligence",
            }
        },
    )

    return {
        "evidence_id":
            evidence_id,

        "intelligence":
            result,
    }