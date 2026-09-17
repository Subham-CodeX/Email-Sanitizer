from datetime import datetime, timezone

from app.core.database import get_database

COLLECTION_NAME = "email_attachments"

async def store_email_attachments(
    evidence_id: str,
    attachment_payloads: list[dict],
):
    collection = get_database()[
        COLLECTION_NAME
    ]

    stored = []

    now = datetime.now(timezone.utc)

    for item in attachment_payloads:

        document = {
            "evidence_id": evidence_id,

            "attachment_id":
                item["attachment_id"],

            "filename":
                item["filename"],

            "content_type":
                item["content_type"],

            "content_disposition":
                item["content_disposition"],

            "content":
                item["content"],

            "created_at": now,
        }

        await collection.insert_one(
            document
        )

        stored.append(
            item["attachment_id"]
        )

    return stored