import hashlib
import io
import math
import mimetypes
import re
import tarfile
import zipfile
from collections import Counter
from pathlib import PurePosixPath

import olefile

from app.core.config import settings
from app.schemas.attachment_intelligence import (
    ArchiveEntry,
    AttachmentFinding,
    AttachmentHashes,
    AttachmentNode,
    EntropyResult,
    FilenameAnalysis,
    MagicByteResult,
    MIMEConsistency,
    OfficeIndicators,
    PDFIndicators,
)


EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".cpl",
    ".msi",
    ".msp",
    ".bat",
    ".cmd",
    ".ps1",
    ".psm1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
    ".jar",
    ".lnk",
    ".reg",
}


SUSPICIOUS_FILENAME_TOKENS = {
    "invoice",
    "payment",
    "urgent",
    "secure",
    "verify",
    "verification",
    "password",
    "credential",
    "account",
    "login",
    "document",
    "scan",
    "refund",
    "salary",
    "bank",
    "transfer",
    "wire",
    "statement",
}


EXPECTED_MIME_BY_EXTENSION = {
    ".pdf": {
        "application/pdf",
    },

    ".txt": {
        "text/plain",
    },

    ".csv": {
        "text/csv",
        "application/csv",
    },

    ".jpg": {
        "image/jpeg",
    },

    ".jpeg": {
        "image/jpeg",
    },

    ".png": {
        "image/png",
    },

    ".gif": {
        "image/gif",
    },

    ".bmp": {
        "image/bmp",
        "image/x-ms-bmp",
    },

    ".zip": {
        "application/zip",
    },

    ".docx": {
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    },

    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    },

    ".pptx": {
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    },

    ".doc": {
        "application/msword",
    },

    ".xls": {
        "application/vnd.ms-excel",
    },

    ".ppt": {
        "application/vnd.ms-powerpoint",
    },

    ".rtf": {
        "application/rtf",
        "text/rtf",
    },
}


MAGIC_SIGNATURES = [
    (
        b"%PDF-",
        "PDF document",
        "application/pdf",
        "PDF",
    ),

    (
        b"MZ",
        "Windows PE / DOS executable",
        "application/vnd.microsoft.portable-executable",
        "PE",
    ),

    (
        b"\x7fELF",
        "ELF executable",
        "application/x-elf",
        "ELF",
    ),

    (
        b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        "OLE Compound Document",
        "application/x-ole-storage",
        "OLE",
    ),

    (
        b"\x89PNG\r\n\x1a\n",
        "PNG image",
        "image/png",
        "PNG",
    ),

    (
        b"\xff\xd8\xff",
        "JPEG image",
        "image/jpeg",
        "JPEG",
    ),

    (
        b"GIF87a",
        "GIF image",
        "image/gif",
        "GIF",
    ),

    (
        b"GIF89a",
        "GIF image",
        "image/gif",
        "GIF",
    ),

    (
        b"BM",
        "Bitmap image",
        "image/bmp",
        "BMP",
    ),

    (
        b"PK\x03\x04",
        "ZIP archive",
        "application/zip",
        "ZIP",
    ),

    (
        b"PK\x05\x06",
        "ZIP archive",
        "application/zip",
        "ZIP",
    ),

    (
        b"PK\x07\x08",
        "ZIP archive",
        "application/zip",
        "ZIP",
    ),

    (
        b"\x1f\x8b",
        "GZIP archive",
        "application/gzip",
        "GZIP",
    ),

    (
        b"7z\xbc\xaf\x27\x1c",
        "7-Zip archive",
        "application/x-7z-compressed",
        "7Z",
    ),

    (
        b"Rar!\x1a\x07\x00",
        "RAR archive",
        "application/vnd.rar",
        "RAR",
    ),
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def calculate_hashes(
    data: bytes,
) -> AttachmentHashes:

    return AttachmentHashes(
        md5=md5_bytes(data),
        sha1=sha1_bytes(data),
        sha256=sha256_bytes(data),
    )


def calculate_entropy(
    data: bytes,
) -> EntropyResult:

    if not data:
        return EntropyResult(
            entropy=0.0,
            sample_size=0,
            high_entropy=False,
        )

    sample_size = min(
        len(data),
        settings.attachment_entropy_sample_bytes,
    )

    sample = data[:sample_size]

    counts = Counter(sample)

    entropy = 0.0

    for count in counts.values():

        probability = (
            count / sample_size
        )

        entropy -= (
            probability
            * math.log2(probability)
        )

    return EntropyResult(
        entropy=round(entropy, 4),
        sample_size=sample_size,
        high_entropy=entropy >= 7.2,
    )


def get_extension(
    filename: str,
) -> str | None:

    name = filename.lower().strip()

    if "." not in name:
        return None

    return (
        "." + name.rsplit(".", 1)[1]
    )


def analyze_filename(
    filename: str,
) -> FilenameAnalysis:

    lower = filename.lower()

    extension = get_extension(
        filename
    )

    parts = [
        x
        for x in PurePosixPath(
            lower
        ).name.split(".")
        if x
    ]

    executable_extension = (
        extension in EXECUTABLE_EXTENSIONS
    )

    double_extension = False

    misleading_extension = False

    if len(parts) >= 3:

        first_extension = (
            "." + parts[-2]
        )

        if (
            first_extension in {
                ".pdf",
                ".doc",
                ".docx",
                ".xls",
                ".xlsx",
                ".jpg",
                ".jpeg",
                ".png",
                ".txt",
            }
            and executable_extension
        ):
            double_extension = True
            misleading_extension = True

    suspicious_tokens = [
        token
        for token in SUSPICIOUS_FILENAME_TOKENS
        if token in lower
    ]

    suspicious = (
        executable_extension
        or double_extension
        or misleading_extension
        or bool(suspicious_tokens)
    )

    return FilenameAnalysis(
        filename=filename,
        extension=extension,
        suspicious=suspicious,
        double_extension=double_extension,
        executable_extension=executable_extension,
        misleading_extension=misleading_extension,
        suspicious_tokens=sorted(
            suspicious_tokens
        ),
    )


def detect_magic(
    data: bytes,
) -> MagicByteResult:

    for (
        signature,
        detected_type,
        detected_mime,
        family,
    ) in MAGIC_SIGNATURES:

        if data.startswith(signature):

            return MagicByteResult(
                detected_type=detected_type,
                detected_mime=detected_mime,
                signature=family,
                confidence="high",
            )

    return MagicByteResult(
        detected_type="Unknown binary/text data",
        detected_mime=None,
        signature=None,
        confidence="low",
    )


def is_zip(
    data: bytes,
) -> bool:

    return (
        data.startswith(b"PK\x03\x04")
        or data.startswith(b"PK\x05\x06")
        or data.startswith(b"PK\x07\x08")
    )


def analyze_mime_consistency(
    filename: str,
    declared_mime: str | None,
    magic: MagicByteResult,
) -> MIMEConsistency:

    extension = get_extension(
        filename
    )

    guessed_mime = None

    if extension:
        guessed_mime = (
            mimetypes.guess_type(
                filename
            )[0]
        )

    extension_expected = None

    if extension:
        expected = (
            EXPECTED_MIME_BY_EXTENSION.get(
                extension
            )
        )

        if expected:
            extension_expected = (
                sorted(expected)[0]
            )

    mime_matches_magic = True

    if (
        declared_mime
        and magic.detected_mime
    ):

        mime_matches_magic = (
            declared_mime.lower()
            == magic.detected_mime.lower()
        )

        if not mime_matches_magic:

            if (
                declared_mime.lower()
                in {
                    "application/octet-stream",
                    "binary/octet-stream",
                }
            ):
                mime_matches_magic = True

    extension_matches_magic = True

    if (
        extension
        and magic.detected_mime
    ):

        expected = (
            EXPECTED_MIME_BY_EXTENSION.get(
                extension
            )
        )

        if expected:

            extension_matches_magic = (
                magic.detected_mime
                in expected
            )

    suspicious_mismatch = (
        not mime_matches_magic
        or not extension_matches_magic
    )

    return MIMEConsistency(
        declared_mime=declared_mime,

        detected_mime=(
            magic.detected_mime
        ),

        extension=extension,

        extension_expected_mime=(
            extension_expected
        ),

        mime_matches_magic=(
            mime_matches_magic
        ),

        extension_matches_magic=(
            extension_matches_magic
        ),

        suspicious_mismatch=(
            suspicious_mismatch
        ),
    )


def analyze_office(
    data: bytes,
    magic: MagicByteResult,
) -> OfficeIndicators:

    if not is_zip(data):

        if magic.signature != "OLE":
            return OfficeIndicators()

        return analyze_ole_office(
            data
        )

    try:

        with zipfile.ZipFile(
            io.BytesIO(data),
            "r",
        ) as archive:

            names = [
                name.lower()
                for name in archive.namelist()
            ]

    except Exception:

        return OfficeIndicators()

    if (
        "[content_types].xml"
        not in names
    ):
        return OfficeIndicators()

    family = None

    if any(
        name.startswith("word/")
        for name in names
    ):
        family = "Word"

    elif any(
        name.startswith("xl/")
        for name in names
    ):
        family = "Excel"

    elif any(
        name.startswith("ppt/")
        for name in names
    ):
        family = "PowerPoint"

    indicators = []

    has_vba = any(
        "vbaproject.bin" in name
        for name in names
    )

    has_embedded = any(
        "/embeddings/" in name
        or name.startswith("embeddings/")
        for name in names
    )

    has_activex = any(
        "activex" in name
        for name in names
    )

    has_external_links = any(
        "externallinks" in name
        or "externalLink" in name
        for name in names
    )

    has_custom_ui = any(
        "customui" in name
        for name in names
    )

    if has_vba:
        indicators.append(
            "vbaProject.bin present"
        )

    if has_embedded:
        indicators.append(
            "Embedded object detected"
        )

    if has_activex:
        indicators.append(
            "ActiveX-related content detected"
        )

    if has_external_links:
        indicators.append(
            "External Office links detected"
        )

    if has_custom_ui:
        indicators.append(
            "Custom UI XML detected"
        )

    return OfficeIndicators(
        is_office_document=bool(
            family
        ),

        office_family=family,

        has_vba_macro=has_vba,

        has_embedded_objects=(
            has_embedded
        ),

        has_active_x=has_activex,

        has_external_links=(
            has_external_links
        ),

        has_custom_ui=has_custom_ui,

        indicators=indicators,
    )


def analyze_ole_office(
    data: bytes,
) -> OfficeIndicators:

    indicators = []

    has_vba = False

    has_embedded = False

    try:

        ole = olefile.OleFileIO(
            io.BytesIO(data)
        )

        entries = [
            "/".join(
                part.lower()
                for part in entry
            )
            for entry in ole.listdir()
        ]

        for entry in entries:

            if (
                "vba"
                in entry
                or "vba_project"
                in entry
                or "dir"
                in entry
            ):

                has_vba = True

            if (
                "objectpool"
                in entry
                or "embedding"
                in entry
            ):

                has_embedded = True

        ole.close()

    except Exception:
        return OfficeIndicators()

    if has_vba:

        indicators.append(
            "OLE VBA-related stream detected"
        )

    if has_embedded:

        indicators.append(
            "OLE embedded object stream detected"
        )

    return OfficeIndicators(
        is_office_document=True,

        office_family="OLE Compound Document",

        has_vba_macro=has_vba,

        has_embedded_objects=has_embedded,

        indicators=indicators,
    )


def analyze_pdf(
    data: bytes,
    magic: MagicByteResult,
) -> PDFIndicators:

    if magic.signature != "PDF":
        return PDFIndicators()

    text = data[: min(
        len(data),
        settings.attachment_max_analysis_bytes,
    )].decode(
        "latin-1",
        errors="ignore",
    )

    def contains(
        pattern: str,
    ) -> bool:

        return bool(
            re.search(
                pattern,
                text,
                re.IGNORECASE,
            )
        )

    javascript = contains(
        r"/JavaScript\b"
    ) or contains(
        r"/JS\b"
    )

    open_action = contains(
        r"/OpenAction\b"
    )

    auto_action = contains(
        r"/AA\b"
    )

    launch_action = contains(
        r"/Launch\b"
    )

    embedded_file = contains(
        r"/EmbeddedFile\b"
    )

    rich_media = contains(
        r"/RichMedia\b"
    )

    xfa = contains(
        r"/XFA\b"
    )

    acroform = contains(
        r"/AcroForm\b"
    )

    indicators = []

    if javascript:
        indicators.append(
            "JavaScript action detected"
        )

    if open_action:
        indicators.append(
            "OpenAction detected"
        )

    if auto_action:
        indicators.append(
            "Additional Actions detected"
        )

    if launch_action:
        indicators.append(
            "Launch action detected"
        )

    if embedded_file:
        indicators.append(
            "Embedded file detected"
        )

    if rich_media:
        indicators.append(
            "Rich media detected"
        )

    if xfa:
        indicators.append(
            "XFA content detected"
        )

    if acroform:
        indicators.append(
            "AcroForm detected"
        )

    return PDFIndicators(
        is_pdf=True,

        javascript=javascript,

        open_action=open_action,

        auto_action=auto_action,

        launch_action=launch_action,

        embedded_file=embedded_file,

        rich_media=rich_media,

        xfa=xfa,

        acroform=acroform,

        indicators=indicators,
    )


def inspect_zip(
    data: bytes,
) -> tuple[
    bool,
    list[ArchiveEntry],
    list[tuple[str, bytes]],
    list[str],
]:

    entries = []

    nested = []

    warnings = []

    try:

        with zipfile.ZipFile(
            io.BytesIO(data),
            "r",
        ) as archive:

            infos = archive.infolist()

            for info in infos[
                : settings.attachment_intelligence_max_nested_files
            ]:

                name = info.filename

                is_directory = (
                    info.is_dir()
                )

                encrypted = bool(
                    info.flag_bits & 0x1
                )

                suspicious = (
                    name.startswith("/")
                    or ".." in name.split("/")
                    or "\\" in name
                )

                detected_type = None

                content = None

                if (
                    not is_directory
                    and not encrypted
                    and info.file_size
                    <= settings.attachment_max_nested_member_bytes
                ):

                    try:

                        with archive.open(
                            info,
                            "r",
                        ) as stream:

                            content = stream.read(
                                settings.attachment_max_nested_member_bytes
                                + 1
                            )

                        if (
                            len(content)
                            > settings.attachment_max_nested_member_bytes
                        ):
                            content = None
                            warnings.append(
                                f"Nested file too large: {name}"
                            )

                    except Exception:

                        warnings.append(
                            f"Could not read ZIP member: {name}"
                        )

                if content is not None:

                    magic = detect_magic(
                        content
                    )

                    detected_type = (
                        magic.signature
                    )

                    nested.append(
                        (
                            name,
                            content,
                        )
                    )

                entries.append(
                    ArchiveEntry(
                        name=name,

                        size_bytes=(
                            info.file_size
                        ),

                        compressed_size_bytes=(
                            info.compress_size
                        ),

                        is_directory=(
                            is_directory
                        ),

                        encrypted=(
                            encrypted
                        ),

                        detected_type=(
                            detected_type
                        ),

                        sha256=(
                            sha256_bytes(content)
                            if content is not None
                            else None
                        ),

                        suspicious=suspicious,
                    )
                )

    except zipfile.BadZipFile:

        warnings.append(
            "ZIP signature detected but archive could not be parsed."
        )

    return (
        True,
        entries,
        nested,
        warnings,
    )


def inspect_tar(
    data: bytes,
) -> tuple[
    bool,
    list[ArchiveEntry],
    list[tuple[str, bytes]],
    list[str],
]:

    entries = []

    nested = []

    warnings = []

    try:

        with tarfile.open(
            fileobj=io.BytesIO(data),
            mode="r:*",
        ) as archive:

            members = archive.getmembers()

            for member in members[
                : settings.attachment_intelligence_max_nested_files
            ]:

                name = member.name

                suspicious = (
                    name.startswith("/")
                    or ".." in name.split("/")
                    or member.issym()
                    or member.islnk()
                )

                content = None

                if (
                    member.isfile()
                    and member.size
                    <= settings.attachment_max_nested_member_bytes
                ):

                    try:

                        stream = (
                            archive.extractfile(
                                member
                            )
                        )

                        if stream:

                            content = stream.read(
                                settings.attachment_max_nested_member_bytes
                                + 1
                            )

                            if (
                                len(content)
                                > settings.attachment_max_nested_member_bytes
                            ):
                                content = None

                    except Exception:

                        content = None

                if content is not None:

                    magic = detect_magic(
                        content
                    )

                    nested.append(
                        (
                            name,
                            content,
                        )
                    )

                    detected_type = (
                        magic.signature
                    )

                else:

                    detected_type = None

                entries.append(
                    ArchiveEntry(
                        name=name,

                        size_bytes=(
                            member.size
                        ),

                        compressed_size_bytes=None,

                        is_directory=(
                            member.isdir()
                        ),

                        encrypted=False,

                        detected_type=(
                            detected_type
                        ),

                        sha256=(
                            sha256_bytes(content)
                            if content is not None
                            else None
                        ),

                        suspicious=suspicious,
                    )
                )

    except Exception:

        return (
            False,
            [],
            [],
            [
                "Tar archive could not be parsed."
            ],
        )

    return (
        True,
        entries,
        nested,
        warnings,
    )


def inspect_archive(
    data: bytes,
    magic: MagicByteResult,
):

    if magic.signature == "ZIP":

        return inspect_zip(
            data
        )

    if magic.signature in {
        "GZIP",
    }:

        return (
            True,
            [],
            [],
            [
                "GZIP container detected; nested payload expansion is disabled."
            ],
        )

    if magic.signature in {
        "RAR",
        "7Z",
    }:

        return (
            True,
            [],
            [],
            [
                f"{magic.signature} archive detected; deep expansion is disabled in the safe stdlib analyzer."
            ],
        )

    if tarfile.is_tarfile(
        io.BytesIO(data)
    ):

        return inspect_tar(
            data
        )

    return (
        False,
        [],
        [],
        [],
    )


def build_findings(
    filename_analysis: FilenameAnalysis,
    mime: MIMEConsistency,
    magic: MagicByteResult,
    entropy: EntropyResult,
    office: OfficeIndicators,
    pdf: PDFIndicators,
    archive_entries: list[ArchiveEntry],
) -> list[AttachmentFinding]:

    findings = []

    if (
        filename_analysis.double_extension
    ):

        findings.append(
            AttachmentFinding(
                code="DOUBLE_EXTENSION",

                title="Double extension",

                severity="high",

                description=(
                    "Filename uses a document-like extension followed by an executable extension."
                ),
            )
        )

    if (
        filename_analysis.executable_extension
    ):

        findings.append(
            AttachmentFinding(
                code="EXECUTABLE_EXTENSION",

                title="Executable attachment extension",

                severity="high",

                description=(
                    "The filename uses an extension commonly associated with executable or script content."
                ),
            )
        )

    if mime.suspicious_mismatch:

        findings.append(
            AttachmentFinding(
                code="MIME_MAGIC_MISMATCH",

                title="Declared type differs from detected type",

                severity="high",

                description=(
                    "The declared MIME type or filename extension does not agree with the observed file signature."
                ),
            )
        )

    if magic.signature in {
        "PE",
        "ELF",
    }:

        findings.append(
            AttachmentFinding(
                code="EXECUTABLE_MAGIC",

                title="Executable magic signature",

                severity="critical",

                description=(
                    "Magic-byte analysis identifies an executable binary."
                ),
            )
        )

    if entropy.high_entropy:

        findings.append(
            AttachmentFinding(
                code="HIGH_ENTROPY",

                title="High byte entropy",

                severity="medium",

                description=(
                    "The sampled bytes have unusually high entropy. This can occur with compression, encryption or packed content and is not proof of malware."
                ),
            )
        )

    if office.has_vba_macro:

        findings.append(
            AttachmentFinding(
                code="VBA_MACRO",

                title="VBA macro content",

                severity="high",

                description=(
                    "Office/OLE inspection found VBA-related macro content."
                ),
            )
        )

    if office.has_embedded_objects:

        findings.append(
            AttachmentFinding(
                code="EMBEDDED_OBJECT",

                title="Embedded Office object",

                severity="medium",

                description=(
                    "The document contains embedded object content."
                ),
            )
        )

    if office.has_active_x:

        findings.append(
            AttachmentFinding(
                code="ACTIVEX_CONTENT",

                title="ActiveX-related content",

                severity="high",

                description=(
                    "Office package inspection found ActiveX-related content."
                ),
            )
        )

    if office.has_external_links:

        findings.append(
            AttachmentFinding(
                code="OFFICE_EXTERNAL_LINK",

                title="External Office link",

                severity="medium",

                description=(
                    "The Office package contains external-link structures."
                ),
            )
        )

    if pdf.javascript:

        findings.append(
            AttachmentFinding(
                code="PDF_JAVASCRIPT",

                title="PDF JavaScript",

                severity="high",

                description=(
                    "PDF static analysis found JavaScript-related objects."
                ),
            )
        )

    if pdf.launch_action:

        findings.append(
            AttachmentFinding(
                code="PDF_LAUNCH",

                title="PDF launch action",

                severity="high",

                description=(
                    "PDF static analysis found a launch action."
                ),
            )
        )

    if pdf.embedded_file:

        findings.append(
            AttachmentFinding(
                code="PDF_EMBEDDED_FILE",

                title="Embedded PDF file",

                severity="medium",

                description=(
                    "PDF contains an embedded-file object."
                ),
            )
        )

    if any(
        entry.suspicious
        for entry in archive_entries
    ):

        findings.append(
            AttachmentFinding(
                code="SUSPICIOUS_ARCHIVE_PATH",

                title="Suspicious archive path",

                severity="high",

                description=(
                    "Archive metadata contains absolute, parent-directory or link-like paths."
                ),
            )
        )

    if filename_analysis.suspicious_tokens:

        findings.append(
            AttachmentFinding(
                code="SUSPICIOUS_FILENAME",

                title="Suspicious filename",

                severity="low",

                description=(
                    "Filename contains terms commonly associated with social-engineering delivery."
                ),
            )
        )

    return findings


def score_findings(
    findings: list[AttachmentFinding],
) -> tuple[int, str]:

    weights = {
        "critical": 80,
        "high": 35,
        "medium": 15,
        "low": 5,
        "info": 0,
    }

    score = min(
        100,
        sum(
            weights.get(
                finding.severity,
                0,
            )
            for finding in findings
        ),
    )

    if score >= 80:
        level = "critical"

    elif score >= 50:
        level = "high"

    elif score >= 25:
        level = "medium"

    elif score > 0:
        level = "low"

    else:
        level = "unknown"

    return score, level


def analyze_attachment_bytes(
    *,
    filename: str,
    content_type: str | None,
    data: bytes,
    path: str,
    depth: int = 0,
    reputation=None,
    nested_context=None,
) -> AttachmentNode:

    if len(data) > (
        settings.attachment_max_analysis_bytes
    ):

        data_for_analysis = data[
            : settings.attachment_max_analysis_bytes
        ]

    else:

        data_for_analysis = data

    hashes = calculate_hashes(
        data
    )

    magic = detect_magic(
        data_for_analysis
    )

    filename_analysis = (
        analyze_filename(
            filename
        )
    )

    mime_consistency = (
        analyze_mime_consistency(
            filename,
            content_type,
            magic,
        )
    )

    entropy = calculate_entropy(
        data_for_analysis
    )

    office = analyze_office(
        data_for_analysis,
        magic,
    )

    pdf = analyze_pdf(
        data_for_analysis,
        magic,
    )

    (
        archive,
        archive_entries,
        nested_candidates,
        archive_warnings,
    ) = inspect_archive(
        data_for_analysis,
        magic,
    )

    findings = build_findings(
        filename_analysis,
        mime_consistency,
        magic,
        entropy,
        office,
        pdf,
        archive_entries,
    )

    for warning in archive_warnings:

        findings.append(
            AttachmentFinding(
                code="ARCHIVE_WARNING",

                title="Archive inspection warning",

                severity="medium",

                description=warning,
            )
        )

    if len(data) > len(
        data_for_analysis
    ):

        findings.append(
            AttachmentFinding(
                code="ANALYSIS_TRUNCATED",

                title="Analysis size limit",

                severity="info",

                description=(
                    "Static analysis used only the configured maximum number of bytes."
                ),
            )
        )

    score, level = score_findings(
        findings
    )

    node = AttachmentNode(
        name=filename,

        path=path,

        size_bytes=len(data),

        hashes=hashes,

        magic=magic,

        mime_consistency=mime_consistency,

        entropy=entropy,

        filename_analysis=filename_analysis,

        office=office,

        pdf=pdf,

        archive=archive,

        archive_entries=archive_entries,

        nested=[],

        reputation=reputation,

        findings=findings,

        score=score,

        level=level,
    )

    if (
        depth
        < settings.attachment_intelligence_max_depth
    ):

        total_nested_bytes = 0

        for (
            nested_name,
            nested_data,
        ) in nested_candidates:

            if (
                len(node.nested)
                >= settings.attachment_intelligence_max_nested_files
            ):
                break

            if (
                total_nested_bytes
                + len(nested_data)
                > settings.attachment_max_total_nested_bytes
            ):
                break

            total_nested_bytes += (
                len(nested_data)
            )

            nested_node = (
                analyze_attachment_bytes(
                    filename=PurePosixPath(
                        nested_name
                    ).name
                    or "unnamed",

                    content_type=None,

                    data=nested_data,

                    path=(
                        f"{path}!/{nested_name}"
                    ),

                    depth=depth + 1,
                )
            )

            node.nested.append(
                nested_node
            )

    return node