import asyncio
import hashlib
import re
from datetime import datetime, timezone

from app.core.config import settings

from app.schemas.url_intelligence import (
    URLDomainSummary,
    URLFinding,
    URLIntelligence,
    URLIntelligenceResult,
    URLIntelligenceSummary,
)

from app.services.rdap_intelligence import (
    analyze_domain_rdap,
)

from app.services.url_analyzer import (
    analyze_url_structure,
)

from app.services.url_dns_intelligence import (
    analyze_domain_dns,
)

from app.services.web_risk import (
    check_web_risk,
)

def create_url_id(
    url: str,
) -> str:

    return hashlib.sha256(
        url.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()[:24]


async def analyze_single_url(
    url: str,
) -> URLIntelligence:

    url_id = create_url_id(
        url
    )

    structure, findings = (
        analyze_url_structure(
            url
        )
    )

    domain = (
        structure.registrable_domain
    )

    dns_task = (
        analyze_domain_dns(
            domain
        )
        if (
            domain
            and settings.enable_url_dns
        )
        else None
    )

    rdap_task = (
        analyze_domain_rdap(
            domain
        )
        if (
            domain
            and settings.enable_rdap
        )
        else None
    )

    reputation_task = (
        check_web_risk(
            url
        )
        if settings.enable_web_risk
        else None
    )

    tasks = []

    task_names = []

    if dns_task is not None:

        tasks.append(
            dns_task
        )

        task_names.append(
            "dns"
        )

    if rdap_task is not None:

        tasks.append(
            rdap_task
        )

        task_names.append(
            "rdap"
        )

    if reputation_task is not None:

        tasks.append(
            reputation_task
        )

        task_names.append(
            "reputation"
        )

    results = await asyncio.gather(
        *tasks,
        return_exceptions=True,
    )

    dns_result = None

    rdap_result = None

    reputation_result = None

    for name, value in zip(
        task_names,
        results,
    ):

        if isinstance(
            value,
            Exception,
        ):

            continue

        if name == "dns":

            dns_result = value

        elif name == "rdap":

            rdap_result = value

        elif name == "reputation":

            reputation_result = value

    reputation = []

    if reputation_result:

        reputation.append(
            reputation_result
        )

        if (
            reputation_result.malicious
        ):

            findings.append(
                URLFinding(
                    severity="critical",
                    code="KNOWN_UNSAFE_URL",
                    title="Known unsafe URL",
                    description=(
                        "The URL matched a threat "
                        "category in the configured "
                        "web reputation provider."
                    ),
                    evidence=", ".join(
                        reputation_result
                        .threat_types
                    ),
                )
            )

    # Domain age signal

    if (
        rdap_result
        and rdap_result.registration_age_days
        is not None
    ):

        age = (
            rdap_result
            .registration_age_days
        )

        if age < 30:

            findings.append(
                URLFinding(
                    severity="high",
                    code="VERY_NEW_DOMAIN",
                    title="Very recently registered domain",
                    description=(
                        "The URL's registrable domain "
                        "was registered less than 30 days ago."
                    ),
                    evidence=f"{age} days old",
                )
            )

        elif age < 90:

            findings.append(
                URLFinding(
                    severity="medium",
                    code="NEW_DOMAIN",
                    title="Recently registered domain",
                    description=(
                        "The URL's registrable domain "
                        "was registered less than 90 days ago."
                    ),
                    evidence=f"{age} days old",
                )
            )


    if dns_result:

        if not dns_result.has_mx:

            findings.append(
                URLFinding(
                    severity="low",
                    code="NO_MX",
                    title="No MX record",
                    description=(
                        "The URL domain has no observed "
                        "MX record. This can be legitimate "
                        "for a web-only domain."
                    ),
                    evidence=dns_result.domain,
                )
            )

        if not dns_result.has_spf:

            findings.append(
                URLFinding(
                    severity="low",
                    code="NO_SPF",
                    title="No SPF record",
                    description=(
                        "The domain has no observed SPF "
                        "record. This is not proof of "
                        "maliciousness."
                    ),
                    evidence=dns_result.domain,
                )
            )

        if not dns_result.has_dmarc:

            findings.append(
                URLFinding(
                    severity="low",
                    code="NO_DMARC",
                    title="No DMARC record",
                    description=(
                        "The domain has no observed DMARC "
                        "record."
                    ),
                    evidence=dns_result.domain,
                )
            )


    if (
        structure.hostname
        and domain
    ):

        hostname = (
            structure.hostname.lower()
        )

        domain_lower = (
            domain.lower()
        )

        if (
            hostname != domain_lower
            and not hostname.endswith(
                "." + domain_lower
            )
        ):

            # This is normal for many subdomains,
            # therefore informational only.

            findings.append(
                URLFinding(
                    severity="info",
                    code="SUBDOMAIN_HOST",
                    title="Subdomain host",
                    description=(
                        "The URL uses a hostname below "
                        "its registrable domain."
                    ),
                    evidence=hostname,
                )
            )

    score, level = (
        calculate_url_score(
            findings
        )
    )

    return URLIntelligence(

        url_id=url_id,

        original_url=url,

        structure=structure,

        dns=dns_result,

        registration=rdap_result,

        reputation=reputation,

        findings=findings,

        score=score,

        level=level,
    )


def calculate_url_score(
    findings: list[URLFinding],
) -> tuple[
    int,
    str,
]:

    score = 0

    for finding in findings:

        severity = (
            finding.severity
        )

        if severity == "critical":

            score += 80

        elif severity == "high":

            score += 35

        elif severity == "medium":

            score += 15

        elif severity == "low":

            score += 5

    score = min(
        score,
        100,
    )

    if score >= 80:

        return score, "critical"

    if score >= 50:

        return score, "high"

    if score >= 25:

        return score, "medium"

    if score > 0:

        return score, "low"

    return 0, "unknown"


async def analyze_email_urls(
    evidence_id: str,
    urls: list[dict],
) -> URLIntelligenceResult:


    unique_urls = []

    seen = set()

    for item in urls:

        value = (
            item.get(
                "url"
            )
            if isinstance(
                item,
                dict,
            )
            else str(item)
        )

        if not value:
            continue

        value = value.strip()

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)

        unique_urls.append(
            value
        )

    unique_urls = unique_urls[
        : settings.url_intelligence_max_urls
    ]


    results = await asyncio.gather(
        *(
            analyze_single_url(
                url
            )
            for url in unique_urls
        ),
        return_exceptions=True,
    )

    analyzed = []

    for url, result in zip(
        unique_urls,
        results,
    ):

        if isinstance(
            result,
            Exception,
        ):

            # Keep the URL visible even when
            # enrichment fails.

            structure, findings = (
                analyze_url_structure(
                    url
                )
            )

            findings.append(
                URLFinding(
                    severity="info",
                    code="ENRICHMENT_ERROR",
                    title="Partial enrichment",
                    description=(
                        "The URL was parsed, but one "
                        "or more intelligence lookups failed."
                    ),
                    evidence=(
                        type(result).__name__
                    ),
                )
            )

            score, level = (
                calculate_url_score(
                    findings
                )
            )

            analyzed.append(
                URLIntelligence(
                    url_id=create_url_id(
                        url
                    ),
                    original_url=url,
                    structure=structure,
                    findings=findings,
                    score=score,
                    level=level,
                )
            )

        else:

            analyzed.append(
                result
            )

    domain_map: dict[
        str,
        list[URLIntelligence]
    ] = {}

    for item in analyzed:

        domain = (
            item.structure.registrable_domain
        )

        if not domain:
            continue

        domain_map.setdefault(
            domain,
            [],
        ).append(item)

    domain_summaries = []

    for domain, items in sorted(
        domain_map.items()
    ):

        registration_age = None

        dns = None

        for item in items:

            if (
                item.registration
                and
                item.registration
                .registration_age_days
                is not None
            ):

                registration_age = (
                    item.registration
                    .registration_age_days
                )

                break

        for item in items:

            if item.dns:

                dns = item.dns

                break

        domain_summaries.append(
            URLDomainSummary(
                domain=domain,

                url_count=len(
                    items
                ),

                url_ids=[
                    item.url_id
                    for item in items
                ],

                registration_age_days=(
                    registration_age
                ),

                countries_not_available=True,

                has_spf=(
                    dns.has_spf
                    if dns
                    else None
                ),

                has_dmarc=(
                    dns.has_dmarc
                    if dns
                    else None
                ),

                has_mx=(
                    dns.has_mx
                    if dns
                    else None
                ),
            )
        )


    malicious_urls = [
        item
        for item in analyzed
        if any(
            reputation.malicious
            for reputation
            in item.reputation
        )
    ]

    suspicious_urls = [
        item
        for item in analyzed
        if item.level
        in {
            "medium",
            "high",
            "critical",
        }
    ]

    high_risk_urls = [
        item.original_url
        for item in analyzed
        if item.level
        in {
            "high",
            "critical",
        }
    ]

    suspicious_domains = sorted(
        {
            item.structure
            .registrable_domain

            for item in analyzed

            if (
                item.level
                in {
                    "high",
                    "critical",
                }
                and
                item.structure
                .registrable_domain
            )
        }
    )

    summary = URLIntelligenceSummary(

        total_urls=len(
            unique_urls
        ),

        analyzed_urls=len(
            analyzed
        ),

        unique_domains=len(
            domain_map
        ),

        malicious_urls=len(
            malicious_urls
        ),

        suspicious_urls=len(
            suspicious_urls
        ),

        high_risk_urls=(
            high_risk_urls
        ),

        suspicious_domains=(
            suspicious_domains
        ),

        shortener_urls=sum(
            item.structure.is_shortener
            for item in analyzed
        ),

        punycode_urls=sum(
            item.structure.is_punycode
            for item in analyzed
        ),

        ip_host_urls=sum(
            item.structure.is_ip_host
            for item in analyzed
        ),
    )

    provider_notes = []

    if not settings.web_risk_api_key:

        provider_notes.append(
            "Google Web Risk is not configured. "
            "URL reputation will rely on local "
            "structural analysis."
        )

    if not settings.enable_rdap:

        provider_notes.append(
            "RDAP registration analysis is disabled."
        )

    if not settings.enable_url_dns:

        provider_notes.append(
            "Passive DNS analysis is disabled."
        )

    provider_notes.append(
        "PhishingTrack does not open or follow "
        "email URLs during Phase 4."
    )

    provider_notes.append(
        "A suspicious URL finding is an investigation "
        "signal, not proof that the URL is malicious."
    )

    return URLIntelligenceResult(

        evidence_id=evidence_id,

        analyzed_at=(
            datetime.now(
                timezone.utc
            ).isoformat()
        ),

        urls=analyzed,

        domains=domain_summaries,

        summary=summary,

        provider_notes=provider_notes,
    )