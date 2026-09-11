import asyncio
import ipaddress
import socket
from typing import Any

import httpx

from app.core.config import settings
from app.schemas.intelligence import IPIntelligence

IPINFO_URL = "https://api.ipinfo.io/lite/{ip}"

ABUSEIPDB_URL = (
    "https://api.abuseipdb.com/api/v2/check"
)


def classify_ip(
    value: str,
) -> tuple[int | None, str]:

    try:
        address = ipaddress.ip_address(value)

    except ValueError:
        return None, "invalid"

    if address.is_unspecified:
        return address.version, "unspecified"

    if address.is_loopback:
        return address.version, "loopback"

    if address.is_link_local:
        return address.version, "link_local"

    if address.is_multicast:
        return address.version, "multicast"

    if address.is_private:
        return address.version, "private"


    if address.version == 4:

        documentation_ranges = [
            ipaddress.ip_network(
                "192.0.2.0/24"
            ),
            ipaddress.ip_network(
                "198.51.100.0/24"
            ),
            ipaddress.ip_network(
                "203.0.113.0/24"
            ),
        ]

        if any(
            address in network
            for network in documentation_ranges
        ):
            return address.version, "documentation"

    if address.is_reserved:
        return address.version, "reserved"

    return address.version, "public"


def _safe_hostname(
    value: str | None,
) -> str | None:

    if not value:
        return None

    value = value.strip().rstrip(".")

    if len(value) > 253:
        return None

    if any(
        char.isspace()
        for char in value
    ):
        return None

    return value.lower()

async def reverse_dns(
    ip: str,
) -> str | None:

    try:

        host, _, _ = await asyncio.to_thread(
            socket.gethostbyaddr,
            ip,
        )

        return _safe_hostname(host)

    except (
        socket.herror,
        socket.gaierror,
        OSError,
    ):
        return None

async def _ipinfo_lookup(
    client: httpx.AsyncClient,
    ip: str,
) -> dict[str, Any]:

    if not settings.ipinfo_token:
        return {}

    response = await client.get(
        IPINFO_URL.format(ip=ip),
        params={
            "token": settings.ipinfo_token
        },
        headers={
            "Accept": "application/json"
        },
    )

    response.raise_for_status()

    return response.json()

async def _abuseipdb_lookup(
    client: httpx.AsyncClient,
    ip: str,
) -> dict[str, Any]:

    if not settings.abuseipdb_api_key:
        return {}

    response = await client.get(
        ABUSEIPDB_URL,
        params={
            "ipAddress": ip,
            "maxAgeInDays": (
                settings.abuseipdb_max_age_days
            ),
        },
        headers={
            "Accept": "application/json",
            "Key": settings.abuseipdb_api_key,
        },
    )

    response.raise_for_status()
    payload = response.json()
    return payload.get("data") or {}


async def enrich_ip(
    ip: str,
    client: httpx.AsyncClient,
) -> IPIntelligence:

    version, scope = classify_ip(ip)

    result = IPIntelligence(
        ip=ip,
        version=version,
        scope=scope,
    )

    # Don't send private/reserved/documentation IPs to external intelligence providers.

    if scope != "public":

        result.provider_status[
            "ipinfo"
        ] = "skipped_non_public"

        result.provider_status[
            "abuseipdb"
        ] = "skipped_non_public"

        return result

    tasks = []

    task_names = []

    # Reverse DNS

    if settings.enable_reverse_dns:

        tasks.append(
            reverse_dns(ip)
        )

        task_names.append(
            "reverse_dns"
        )

    # IPinfo

    if settings.ipinfo_token:

        tasks.append(
            _ipinfo_lookup(
                client,
                ip,
            )
        )

        task_names.append(
            "ipinfo"
        )

    # AbuseIPDB

    if settings.abuseipdb_api_key:

        tasks.append(
            _abuseipdb_lookup(
                client,
                ip,
            )
        )

        task_names.append(
            "abuseipdb"
        )

    values = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    # PROCESS RESULTS

    for name, value in zip(
        task_names,
        values,
    ):

        if isinstance(
            value,
            Exception,
        ):

            result.provider_status[
                name
            ] = "error"

            result.errors.append(
                f"{name}: "
                f"{type(value).__name__}"
            )

            continue

        result.provider_status[
            name
        ] = "ok"

        # -------------------------------------------------
        # Reverse DNS
        # -------------------------------------------------

        if name == "reverse_dns":

            result.reverse_dns = value

        # -------------------------------------------------
        # IPinfo
        # -------------------------------------------------

        elif name == "ipinfo":

            data = value or {}

            result.asn = data.get(
                "asn"
            )

            result.as_name = data.get(
                "as_name"
            )

            result.as_domain = data.get(
                "as_domain"
            )

            result.country_code = data.get(
                "country_code"
            )

            result.country = data.get(
                "country"
            )

            result.continent_code = data.get(
                "continent_code"
            )

            result.continent = data.get(
                "continent"
            )

            result.ipinfo_bogon = data.get(
                "bogon"
            )

        # -------------------------------------------------
        # AbuseIPDB
        # -------------------------------------------------

        elif name == "abuseipdb":

            data = value or {}

            result.abuse_confidence_score = (
                _int_or_none(
                    data.get(
                        "abuseConfidenceScore"
                    )
                )
            )

            result.abuse_total_reports = (
                _int_or_none(
                    data.get(
                        "totalReports"
                    )
                )
            )

            result.abuse_last_reported_at = (
                data.get(
                    "lastReportedAt"
                )
            )

            result.abuse_usage_type = (
                data.get(
                    "usageType"
                )
            )

            result.abuse_isp = (
                data.get(
                    "isp"
                )
            )

            result.abuse_domain = (
                data.get(
                    "domain"
                )
            )

            result.abuse_is_whitelisted = (
                data.get(
                    "isWhitelisted"
                )
            )

            result.abuse_is_tor = (
                data.get(
                    "isTor"
                )
            )

    return result

def _int_or_none(
    value: Any,
) -> int | None:

    if value is None:
        return None

    try:
        return int(value)

    except (
        TypeError,
        ValueError,
    ):
        return None