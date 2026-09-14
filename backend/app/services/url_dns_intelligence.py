import asyncio
import dns.exception
import dns.resolver
from app.core.config import settings

from app.schemas.url_intelligence import (
    URLDNSIntelligence,
)

async def resolve_records(
    resolver: dns.resolver.Resolver,
    name: str,
    record_type: str,
) -> list[str]:

    def resolve_sync():

        answers = resolver.resolve(
            name,
            record_type,
            lifetime=(
                settings
                .url_intelligence_timeout_seconds
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
            resolve_sync
        )

    except (
        dns.exception.DNSException,
        OSError,
    ):

        return []

async def analyze_domain_dns(
    domain: str,
) -> URLDNSIntelligence:

    result = URLDNSIntelligence(
        domain=domain
    )

    if not settings.enable_url_dns:

        result.errors.append(
            "Passive DNS analysis is disabled."
        )

        return result

    resolver = dns.resolver.Resolver()

    tasks = {

        "a": resolve_records(
            resolver,
            domain,
            "A",
        ),

        "aaaa": resolve_records(
            resolver,
            domain,
            "AAAA",
        ),

        "mx": resolve_records(
            resolver,
            domain,
            "MX",
        ),

        "ns": resolve_records(
            resolver,
            domain,
            "NS",
        ),

        "txt": resolve_records(
            resolver,
            domain,
            "TXT",
        ),

        "dmarc": resolve_records(
            resolver,
            f"_dmarc.{domain}",
            "TXT",
        ),
    }

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

    result.a_records = data["a"]

    result.aaaa_records = data["aaaa"]

    result.mx_records = data["mx"]

    result.ns_records = data["ns"]

    result.txt_records = data["txt"]

    result.dmarc_records = [
        record
        for record in data["dmarc"]
        if record.lower().startswith(
            "v=dmarc1"
        )
    ]

    result.spf_records = [
        record
        for record in result.txt_records
        if record.lower().startswith(
            "v=spf1"
        )
    ]

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

    return result