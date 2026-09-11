import asyncio
import re

import dns.exception
import dns.resolver

from app.core.config import settings
from app.schemas.intelligence import (
    SenderDomainIntelligence,
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:"
    r"[a-z0-9]"
    r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"\."
    r")+"
    r"[a-z]{2,63}$",
    re.I,
)

def normalize_domain(
    value: str | None,
) -> str | None:

    if not value:
        return None

    domain = (
        value
        .strip()
        .lower()
        .rstrip(".")
    )

    if not DOMAIN_RE.fullmatch(
        domain
    ):
        return None

    return domain

def extract_domains(
    header_forensics: dict,
) -> dict[str, set[str]]:

    candidates: dict[
        str,
        set[str]
    ] = {}

    def add(
        role: str,
        value: str | None,
    ):

        domain = normalize_domain(
            value
        )

        if not domain:
            return

        candidates.setdefault(
            domain,
            set(),
        ).add(role)

    add(
        "from",
        header_forensics.get(
            "from_domain"
        ),
    )

    add(
        "reply_to",
        header_forensics.get(
            "reply_to_domain"
        ),
    )

    add(
        "return_path",
        header_forensics.get(
            "return_path_domain"
        ),
    )

    add(
        "dkim",
        header_forensics.get(
            "dkim_domain"
        ),
    )

    add(
        "spf",
        header_forensics.get(
            "spf_domain"
        ),
    )

    add(
        "message_id",
        header_forensics.get(
            "message_id_domain"
        ),
    )

    return candidates

async def _resolve(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
) -> list[str]:

    def run():

        answers = resolver.resolve(
            name,
            record_type,
            lifetime=(
                settings
                .intelligence_timeout_seconds
            ),
        )

        return [
            answer.to_text()
            .strip()
            .rstrip(".")
            for answer in answers
        ]

    try:

        return await asyncio.to_thread(
            run
        )

    except (
        dns.exception.DNSException,
        OSError,
    ):

        return []


async def _resolve_text(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
) -> list[str]:

    def run():

        answers = resolver.resolve(
            name,
            record_type,
            lifetime=(
                settings
                .intelligence_timeout_seconds
            ),
        )

        return [
            answer.to_text().strip()
            for answer in answers
        ]

    try:

        return await asyncio.to_thread(
            run
        )

    except (
        dns.exception.DNSException,
        OSError,
    ):

        return []


async def enrich_domain(
    domain: str,
    roles: set[str],
    dkim_selector: str | None = None,
) -> SenderDomainIntelligence:

    result = SenderDomainIntelligence(
        domain=domain,
        roles=sorted(roles),
    )

    if not settings.enable_domain_dns:

        result.errors.append(
            "Domain DNS enrichment is disabled."
        )

        return result

    resolver = dns.resolver.Resolver()

    async def query(
        record_name: str,
        record_type: str,
    ):

        return await _resolve(
            resolver,
            record_name,
            record_type,
        )

    async def query_text(
        record_name: str,
        record_type: str,
    ):

        return await _resolve_text(
            resolver,
            record_name,
            record_type,
        )

    # =====================================================
    # DNS TASKS
    # =====================================================

    tasks = {
        "a": query(
            domain,
            "A",
        ),

        "aaaa": query(
            domain,
            "AAAA",
        ),

        "mx": query(
            domain,
            "MX",
        ),

        "ns": query(
            domain,
            "NS",
        ),

        "txt": query_text(
            domain,
            "TXT",
        ),

        "dmarc": query_text(
            f"_dmarc.{domain}",
            "TXT",
        ),
    }

    # =====================================================
    # DKIM SELECTOR
    # =====================================================

    if dkim_selector:

        safe_selector = re.sub(
            r"[^a-zA-Z0-9._-]",
            "",
            dkim_selector,
        )[:100]

        if safe_selector:

            tasks["dkim"] = query_text(
                f"{safe_selector}._domainkey.{domain}",
                "TXT",
            )

    names = list(
        tasks.keys()
    )

    values = await asyncio.gather(
        *tasks.values()
    )

    data = dict(
        zip(
            names,
            values,
        )
    )

    # =====================================================
    # STORE DNS RESULTS
    # =====================================================

    result.a_records = data["a"]

    result.aaaa_records = data["aaaa"]

    result.mx_records = data["mx"]

    result.ns_records = data["ns"]

    result.spf_records = [
        value
        for value in data["txt"]
        if value.lower().startswith(
            "v=spf1"
        )
    ]

    result.dmarc_records = [
        value
        for value in data["dmarc"]
        if value.lower().startswith(
            "v=dmarc1"
        )
    ]

    if (
        "dkim" in data
        and data["dkim"]
    ):

        result.dkim_record = (
            data["dkim"][0]
        )

    # =====================================================
    # BOOLEAN STATE
    # =====================================================

    result.has_a = bool(
        result.a_records
    )

    result.has_aaaa = bool(
        result.aaaa_records
    )

    result.has_mx = bool(
        result.mx_records
    )

    result.has_spf = bool(
        result.spf_records
    )

    result.has_dmarc = bool(
        result.dmarc_records
    )

    result.has_dkim_selector = bool(
        result.dkim_record
    )

    return result