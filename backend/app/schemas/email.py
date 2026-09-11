from typing import Literal, Optional
from pydantic import BaseModel, Field

class EmailAddress(BaseModel):
    display_name: Optional[str] = None
    address: Optional[str] = None

class AttachmentMetadata(BaseModel):
    filename: str
    content_type: Optional[str] = None
    content_disposition: Optional[str] = None
    size_bytes: int
    sha256: str

class UrlMetadata(BaseModel):
    url: str
    scheme: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None
    path: Optional[str] = None

class EmailMetadata(BaseModel):
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    from_: list[EmailAddress] = Field(default_factory=list, alias="from")
    to: list[EmailAddress] = Field(default_factory=list)
    cc: list[EmailAddress] = Field(default_factory=list)
    bcc: list[EmailAddress] = Field(default_factory=list)
    reply_to: list[EmailAddress] = Field(default_factory=list, alias="replyTo")
    return_path: Optional[str] = Field(default=None, alias="returnPath")
    mime_type: Optional[str] = None
    content_type: Optional[str] = None
    size_bytes: int = 0
    has_plain_text: bool = False
    has_html: bool = False
    attachment_count: int = 0
    url_count: int = 0
    model_config = {"populate_by_name": True}

class EmailIngestionResponse(BaseModel):
    evidence_id: str
    input_type: Literal["eml", "raw_email"]
    filename: Optional[str] = None
    received_at: str
    evidence_sha256: str
    metadata: EmailMetadata
    attachments: list[AttachmentMetadata]
    urls: list[UrlMetadata]
    body_preview: Optional[str] = None
    status: str
