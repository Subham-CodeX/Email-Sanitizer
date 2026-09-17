from typing import Literal, Optional

from pydantic import BaseModel, Field


class EmailAddress(BaseModel):
    display_name: Optional[str] = None
    address: Optional[str] = None


class AttachmentMetadata(BaseModel):
    attachment_id: str
    filename: str
    content_type: Optional[str] = None
    content_disposition: Optional[str] = None
    size_bytes: int
    sha256: str
    content_available: bool = False


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

    from_: list[EmailAddress] = Field(
        default_factory=list,
        alias="from",
    )

    to: list[EmailAddress] = Field(default_factory=list)
    cc: list[EmailAddress] = Field(default_factory=list)
    bcc: list[EmailAddress] = Field(default_factory=list)

    reply_to: list[EmailAddress] = Field(
        default_factory=list,
        alias="replyTo",
    )

    return_path: Optional[str] = Field(
        default=None,
        alias="returnPath",
    )

    mime_type: Optional[str] = None
    content_type: Optional[str] = None

    size_bytes: int = 0

    has_plain_text: bool = False
    has_html: bool = False

    attachment_count: int = 0
    url_count: int = 0

    model_config = {
        "populate_by_name": True,
    }


class ReceivedHop(BaseModel):
    hop_number: int

    raw: str

    from_host: Optional[str] = None
    from_ip: Optional[str] = None

    by_host: Optional[str] = None
    by_ip: Optional[str] = None

    protocol: Optional[str] = None

    timestamp: Optional[str] = None

    is_private_ip: Optional[bool] = None
    is_public_ip: Optional[bool] = None


class AuthenticationResult(BaseModel):
    service: Optional[str] = None
    result: Optional[str] = None
    method: Optional[str] = None

    domain: Optional[str] = None
    selector: Optional[str] = None

    raw: Optional[str] = None


class HeaderFinding(BaseModel):
    severity: Literal[
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]

    code: str

    title: str

    description: str

    evidence: Optional[str] = None


class HeaderForensicsResult(BaseModel):
    evidence_id: str

    received_hops: list[ReceivedHop] = Field(
        default_factory=list
    )

    authentication_results: list[AuthenticationResult] = Field(
        default_factory=list
    )

    spf_result: Optional[str] = None
    spf_domain: Optional[str] = None

    dkim_result: Optional[str] = None
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None

    dmarc_result: Optional[str] = None
    dmarc_domain: Optional[str] = None

    from_address: Optional[str] = None
    from_domain: Optional[str] = None

    reply_to_address: Optional[str] = None
    reply_to_domain: Optional[str] = None

    return_path: Optional[str] = None
    return_path_domain: Optional[str] = None

    message_id_domain: Optional[str] = None

    relay_count: int = 0
    public_ip_count: int = 0
    private_ip_count: int = 0

    findings: list[HeaderFinding] = Field(
        default_factory=list
    )


class EmailIngestionResponse(BaseModel):
    evidence_id: str

    input_type: Literal[
        "eml",
        "raw_email",
    ]

    filename: Optional[str] = None

    received_at: str

    evidence_sha256: str

    metadata: EmailMetadata

    attachments: list[AttachmentMetadata]

    urls: list[UrlMetadata]

    body_preview: Optional[str] = None

    raw_headers: Optional[str] = None

    status: str


class HeaderForensicsResponse(BaseModel):
    evidence_id: str

    header_forensics: HeaderForensicsResult