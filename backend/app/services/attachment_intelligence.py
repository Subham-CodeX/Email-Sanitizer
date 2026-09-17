import asyncio
from datetime import datetime, timezone

from app.core.config import settings
from app.core.database import get_database
from app.schemas.attachment_intelligence import (
    AttachmentIntelligenceResult,
    AttachmentIntelligenceSummary,
    AttachmentNode,
)
from app.services.attachment_analyzer import (
    analyze_attachment_bytes,
)
from app.services.malware_reputation import (
    lookup_malwarebazaar,
)

from app.schemas.attachment_intelligence import (
    AttachmentFinding,
)

def iter_nodes(
    node: AttachmentNode,
):

    yield node

    for child in node.nested:

        yield from iter_nodes(
            child
        )


async def enrich_reputation(
    node: AttachmentNode,
):

    reputation = (
        await lookup_malwarebazaar(
            node.hashes.sha256
        )
    )

    node.reputation = reputation

    if reputation.known_sample:

        node.findings.append(
            AttachmentFinding(
                code="MALWARE_REPUTATION_MATCH",

                title=(
                    "Hash found in malware intelligence"
                ),

                severity="critical",

                description=(
                    "The SHA-256 hash is known to the configured malware-intelligence provider."
                ),
            )
        )

        node.score = min(
            100,
            node.score + 80,
        )

        node.level = "critical"


async def analyze_email_attachments(
    evidence_id: str,
) -> AttachmentIntelligenceResult:

    documents = (
        get_database()
        .email_attachments
        .find(
            {
                "evidence_id":
                    evidence_id
            },
            {
                "_id": 0,

                "attachment_id": 1,

                "filename": 1,

                "content_type": 1,

                "content": 1,
            },
        )
    )

    attachments = []

    async for document in documents:

        if (
            len(attachments)
            >= settings.attachment_intelligence_max_attachments
        ):
            break

        content = document.get(
            "content"
        )

        if not isinstance(
            content,
            bytes,
        ):

            continue

        node = analyze_attachment_bytes(

            filename=(
                document.get(
                    "filename"
                )
                or "unnamed"
            ),

            content_type=(
                document.get(
                    "content_type"
                )
            ),

            data=content,

            path=(
                document.get(
                    "filename"
                )
                or "unnamed"
            ),

            depth=0,
        )

        attachments.append(
            node
        )

    all_nodes = []

    for attachment in attachments:

        all_nodes.extend(
            list(
                iter_nodes(
                    attachment
                )
            )
        )

    reputation_targets = []

    for node in all_nodes:

        reputation_targets.append(
            enrich_reputation(
                node
            )
        )

    if reputation_targets:

        await asyncio.gather(
            *reputation_targets
        )

    summary = (
        AttachmentIntelligenceSummary(
            total_attachments=len(
                attachments
            ),

            analyzed_attachments=len(
                attachments
            ),

            nested_files=max(
                0,
                len(all_nodes)
                - len(attachments),
            ),

            executable_files=sum(
                1
                for node in all_nodes
                if node.magic.signature
                in {
                    "PE",
                    "ELF",
                }
            ),

            macro_files=sum(
                1
                for node in all_nodes
                if node.office.has_vba_macro
            ),

            suspicious_filenames=sum(
                1
                for node in all_nodes
                if node.filename_analysis.suspicious
            ),

            mime_mismatches=sum(
                1
                for node in all_nodes
                if node.mime_consistency.suspicious_mismatch
            ),

            magic_mismatches=sum(
                1
                for node in all_nodes
                if (
                    node.mime_consistency
                    .suspicious_mismatch
                )
            ),

            high_entropy_files=sum(
                1
                for node in all_nodes
                if node.entropy.high_entropy
            ),

            archive_files=sum(
                1
                for node in all_nodes
                if node.archive
            ),

            pdf_files=sum(
                1
                for node in all_nodes
                if node.pdf.is_pdf
            ),

            office_files=sum(
                1
                for node in all_nodes
                if node.office.is_office_document
            ),

            reputation_matches=sum(
                1
                for node in all_nodes
                if (
                    node.reputation
                    and node.reputation.known_sample
                )
            ),

            high_risk_attachments=sum(
                1
                for node in all_nodes
                if node.level
                in {
                    "high",
                    "critical",
                }
            ),
        )
    )

    provider_notes = [

        "Phase 5 performs static analysis only.",

        "Attachments are never executed.",

        "Office macros are inspected as file structures; they are never executed.",

        "PDF indicators are detected by byte/string analysis; PDFs are never rendered.",

        "Archives are inspected in memory with strict size and depth limits.",

        "Malware reputation uses SHA-256 hash lookup only.",

        "A reputation match is an intelligence signal and should be correlated with other evidence.",
    ]

    if not settings.malwarebazaar_api_key:

        provider_notes.append(
            "MalwareBazaar reputation is not configured."
        )

    return AttachmentIntelligenceResult(

        evidence_id=evidence_id,

        analyzed_at=(
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        attachments=attachments,

        summary=summary,

        provider_notes=provider_notes,
    )