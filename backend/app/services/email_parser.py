import hashlib
import re
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from html import unescape
from urllib.parse import urlparse
from typing import Optional
from bs4 import BeautifulSoup

from app.core.config import settings
from app.schemas.email import AttachmentMetadata, EmailAddress, EmailMetadata, UrlMetadata

URL_RE = re.compile(r'''(?i)\b(?:(?:https?|ftp)://|www\.)[^\s<>"'`()\[\]{}]+''')
TRAILING = ".,;:!?)]}>\"'"

class ParseResult:
    def __init__(self, metadata, attachments, urls, body_preview):
        self.metadata = metadata
        self.attachments = attachments
        self.urls = urls
        self.body_preview = body_preview

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def parse_email(raw: bytes) -> ParseResult:
    if not raw:
        raise ValueError("Email input is empty.")
    if len(raw) > settings.max_email_size_bytes:
        raise ValueError(f"Email exceeds {settings.max_email_size_mb} MB.")
    message = BytesParser(policy=policy.default).parsebytes(raw)
    plain, html, attachments = [], [], []
    walk_parts(message, plain, html, attachments)

    plain_text = "\n".join(plain)
    html_text = "\n".join(html)
    urls = normalize_urls(extract_urls(message, plain_text, html_text))

    metadata = EmailMetadata(
        subject=header(message, "Subject"),
        date=header(message, "Date"),
        message_id=header(message, "Message-ID"),
        from_=parse_addresses(header(message, "From")),
        to=parse_addresses(header(message, "To")),
        cc=parse_addresses(header(message, "Cc")),
        bcc=parse_addresses(header(message, "Bcc")),
        reply_to=parse_addresses(header(message, "Reply-To")),
        return_path=header(message, "Return-Path"),
        mime_type=message.get_content_type(),
        content_type=header(message, "Content-Type"),
        size_bytes=len(raw),
        has_plain_text=bool(plain_text.strip()),
        has_html=bool(html_text.strip()),
        attachment_count=len(attachments),
        url_count=len(urls),
    )

    text = plain_text.strip() or html_to_text(html_text)
    preview = re.sub(r"\s+", " ", text).strip()[:3000] if text else None
    return ParseResult(metadata, attachments, urls, preview)

def walk_parts(message: Message, plain, html, attachments):
    if message.is_multipart():
        for part in message.iter_parts():
            walk_parts(part, plain, html, attachments)
        return

    disposition = (message.get_content_disposition() or "").lower()
    filename = message.get_filename()

    if disposition == "attachment" or filename:
        payload = message.get_payload(decode=True) or b""
        if len(attachments) < settings.max_attachment_metadata_items:
            attachments.append(AttachmentMetadata(
                filename=filename or "unnamed",
                content_type=message.get_content_type(),
                content_disposition=disposition or None,
                size_bytes=len(payload),
                sha256=sha256_bytes(payload),
            ))
        return

    try:
        content = message.get_content()
    except Exception:
        payload = message.get_payload(decode=True)
        content = payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else str(payload or "")

    if message.get_content_type() == "text/plain":
        plain.append(str(content))
    elif message.get_content_type() == "text/html":
        html.append(str(content))

def extract_urls(message, plain_text, html_text):
    candidates = URL_RE.findall(plain_text) + URL_RE.findall(html_text)
    if html_text:
        soup = BeautifulSoup(html_text, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = str(tag["href"]).strip()
            if href.lower().startswith(("http://", "https://", "ftp://")):
                candidates.append(href)
    for name in ("List-Unsubscribe", "List-Help", "List-Post"):
        value = message.get(name)
        if value:
            candidates.extend(URL_RE.findall(value))
    return candidates

def normalize_urls(candidates):
    result, seen = [], set()
    for item in candidates:
        url = item.strip().rstrip(TRAILING)
        normalized = "http://" + url if url.lower().startswith("www.") else url
        if normalized in seen or len(result) >= settings.max_url_items:
            continue
        parsed = urlparse(normalized)
        if not parsed.hostname:
            continue
        result.append(UrlMetadata(
            url=normalized,
            scheme=parsed.scheme or None,
            hostname=parsed.hostname.lower(),
            domain=parsed.hostname.lower(),
            path=parsed.path or None,
        ))
        seen.add(normalized)
    return result

def parse_addresses(value: Optional[str]):
    if not value:
        return []
    result = []
    for name, address in getaddresses([value]):
        name, address = name.strip(), address.strip()
        if name or address:
            result.append(EmailAddress(display_name=name or None, address=address or None))
    return result

def header(message, name):
    value = message.get(name)
    return str(value).strip() if value is not None and str(value).strip() else None

def html_to_text(html):
    if not html:
        return ""
    try:
        return BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
    except Exception:
        return re.sub(r"<[^>]+>", " ", unescape(html))
