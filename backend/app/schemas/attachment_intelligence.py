from typing import Optional

from pydantic import BaseModel, Field

class AttachmentHashes(BaseModel):

    md5: str
    sha1: str
    sha256: str

class MagicByteResult(BaseModel):

    detected_type: str
    detected_mime: Optional[str] = None
    signature: Optional[str] = None
    confidence: str = "medium"

class MIMEConsistency(BaseModel):

    declared_mime: Optional[str] = None
    detected_mime: Optional[str] = None
    extension: Optional[str] = None
    extension_expected_mime: Optional[str] = None
    mime_matches_magic: bool = True
    extension_matches_magic: bool = True
    suspicious_mismatch: bool = False

class EntropyResult(BaseModel):

    entropy: float
    sample_size: int
    high_entropy: bool = False


class FilenameAnalysis(BaseModel):

    filename: str
    extension: Optional[str] = None
    suspicious: bool = False
    double_extension: bool = False
    executable_extension: bool = False
    misleading_extension: bool = False
    suspicious_tokens: list[str] = Field(
        default_factory=list
    )


class ArchiveEntry(BaseModel):

    name: str
    size_bytes: int
    compressed_size_bytes: Optional[int] = None
    is_directory: bool = False
    encrypted: bool = False
    detected_type: Optional[str] = None
    sha256: Optional[str] = None
    suspicious: bool = False


class OfficeIndicators(BaseModel):

    is_office_document: bool = False
    office_family: Optional[str] = None
    has_vba_macro: bool = False
    has_embedded_objects: bool = False
    has_active_x: bool = False
    has_external_links: bool = False
    has_custom_ui: bool = False
    indicators: list[str] = Field(
        default_factory=list
    )


class PDFIndicators(BaseModel):

    is_pdf: bool = False

    javascript: bool = False

    open_action: bool = False

    auto_action: bool = False

    launch_action: bool = False

    embedded_file: bool = False

    rich_media: bool = False

    xfa: bool = False

    acroform: bool = False

    indicators: list[str] = Field(
        default_factory=list
    )


class ReputationResult(BaseModel):

    provider: str

    checked: bool = False

    known_sample: bool = False

    malicious_label: Optional[str] = None

    signature: Optional[str] = None

    first_seen: Optional[str] = None

    last_seen: Optional[str] = None

    file_type: Optional[str] = None

    file_format: Optional[str] = None

    tags: list[str] = Field(
        default_factory=list
    )

    error: Optional[str] = None


class AttachmentFinding(BaseModel):

    code: str

    title: str

    severity: str

    description: str


class AttachmentNode(BaseModel):

    name: str

    path: str

    size_bytes: int

    hashes: AttachmentHashes

    magic: MagicByteResult

    mime_consistency: MIMEConsistency

    entropy: EntropyResult

    filename_analysis: FilenameAnalysis

    office: OfficeIndicators

    pdf: PDFIndicators

    archive: bool = False

    archive_entries: list[ArchiveEntry] = Field(
        default_factory=list
    )

    nested: list["AttachmentNode"] = Field(
        default_factory=list
    )

    reputation: Optional[ReputationResult] = None

    findings: list[AttachmentFinding] = Field(
        default_factory=list
    )

    score: int = 0

    level: str = "unknown"


class AttachmentIntelligenceSummary(BaseModel):

    total_attachments: int = 0
    analyzed_attachments: int = 0
    nested_files: int = 0
    executable_files: int = 0
    macro_files: int = 0
    suspicious_filenames: int = 0
    mime_mismatches: int = 0
    magic_mismatches: int = 0
    high_entropy_files: int = 0
    archive_files: int = 0
    pdf_files: int = 0
    office_files: int = 0
    reputation_matches: int = 0
    high_risk_attachments: int = 0


class AttachmentIntelligenceResult(BaseModel):

    evidence_id: str

    analyzed_at: str

    attachments: list[AttachmentNode]

    summary: AttachmentIntelligenceSummary

    provider_notes: list[str] = Field(
        default_factory=list
    )


class AttachmentIntelligenceResponse(BaseModel):

    evidence_id: str

    intelligence: AttachmentIntelligenceResult

AttachmentNode.model_rebuild()