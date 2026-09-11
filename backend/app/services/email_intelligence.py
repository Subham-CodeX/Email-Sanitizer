import asyncio
from datetime import datetime, timezone

import httpx

from app.core.config import settings
from app.schemas.intelligence import (
    EmailIntelligenceResult,
    IPIntelligence,
    IntelligenceSummary,
    SenderDomainIntelligence,
    ThreatAssessment,
)

from app.services.ip_intelligence import (
    enrich_ip,
)

from app.services.sender_intelligence import (
    enrich_domain,
    extract_domains,
)

async def analyze_email_intelligence(
    evidence_id: str,
    header_forensics: dict,
) -> EmailIntelligenceResult:

    received_hops = (
        header_forensics.get(
            "received_hops"
        )
        or []
    )

    source_ips = (
        _extract_unique_source_ips(
            received_hops
        )
    )

    if len(source_ips) > settings.intelligence_max_ips:

        source_ips = source_ips[
            : settings.intelligence_max_ips
        ]

    domains = extract_domains(
        header_forensics
    )

    limited_domains = dict(
        list(domains.items())[
            : settings.intelligence_max_domains
        ]
    )

    dkim_selector = (
        header_forensics.get(
            "dkim_selector"
        )
    )

    async with httpx.AsyncClient(
        timeout=(
            settings
            .intelligence_timeout_seconds
        )
    ) as client:

        ip_results = await asyncio.gather(
            *(
                enrich_ip(
                    ip,
                    client,
                )
                for ip in source_ips
            ),
            return_exceptions=True,
        )

    ip_intel: list[
        IPIntelligence
    ] = []

    for ip, result in zip(
        source_ips,
        ip_results,
    ):

        if isinstance(
            result,
            Exception,
        ):

            ip_intel.append(
                IPIntelligence(
                    ip=ip,
                    scope="invalid",
                    errors=[
                        "IP enrichment failed: "
                        f"{type(result).__name__}"
                    ],
                )
            )

        else:

            ip_intel.append(
                result
            )

    domain_results = await asyncio.gather(
        *(
            enrich_domain(
                domain=domain,
                roles=roles,
                dkim_selector=(
                    dkim_selector
                    if domain
                    == header_forensics.get(
                        "dkim_domain"
                    )
                    else None
                ),
            )
            for domain, roles
            in limited_domains.items()
        ),
        return_exceptions=True,
    )

    sender_domains: list[
        SenderDomainIntelligence
    ] = []

    for domain, result in zip(
        limited_domains.keys(),
        domain_results,
    ):

        if isinstance(
            result,
            Exception,
        ):

            sender_domains.append(
                SenderDomainIntelligence(
                    domain=domain,
                    roles=sorted(
                        limited_domains[
                            domain
                        ]
                    ),
                    errors=[
                        "Domain enrichment failed: "
                        f"{type(result).__name__}"
                    ],
                )
            )

        else:

            sender_domains.append(
                result
            )

    summary = build_summary(
        ip_intel,
        sender_domains,
    )

    assessment = build_threat_assessment(
        ip_intel,
        header_forensics,
    )

    provider_notes = []

    if not settings.ipinfo_token:

        provider_notes.append(
            "IPinfo is not configured. "
            "Country/ASN enrichment will be unavailable "
            "for public IPs."
        )

    if not settings.abuseipdb_api_key:

        provider_notes.append(
            "AbuseIPDB is not configured. "
            "IP abuse reputation will be unavailable."
        )

    provider_notes.append(
        "Phase 3 performs passive enrichment only: "
        "it does not connect to email URLs or execute attachments."
    )

    return EmailIntelligenceResult(
        evidence_id=evidence_id,
        analyzed_at=(
            datetime.now(
                timezone.utc
            ).isoformat()
        ),
        source_ips=ip_intel,
        sender_domains=sender_domains,
        summary=summary,
        threat_assessment=assessment,
        provider_notes=provider_notes,
    )

def _extract_unique_source_ips(
    received_hops: list[dict],
) -> list[str]:

    values: list[str] = []

    seen: set[str] = set()

    # IMPORTANT:
    # We use from_ip only.
    # from_ip = upstream host
    # by_ip = receiving server
    # Therefore by_ip should not be treated as the
    # sender's infrastructure.

    for hop in received_hops:

        value = hop.get(
            "from_ip"
        )

        if not value:
            continue

        if value in seen:
            continue

        seen.add(value)

        values.append(
            value
        )

    return values


def build_summary(
    ips: list[IPIntelligence],
    domains: list[
        SenderDomainIntelligence
    ],
) -> IntelligenceSummary:

    countries = sorted(
        {
            item.country
            for item in ips
            if item.country
        }
    )

    asns = sorted(
        {
            item.asn
            for item in ips
            if item.asn
        }
    )

    high_risk_ips = sorted(
        {
            item.ip
            for item in ips
            if (
                item.abuse_confidence_score
                is not None
                and item.abuse_confidence_score
                >= 75
            )
        }
    )

    suspicious_domains = sorted(
        {
            item.domain
            for item in domains
            if (
                not item.has_mx
                or not item.has_spf
                or not item.has_dmarc
            )
        }
    )

    return IntelligenceSummary(
        public_ip_count=sum(
            item.scope == "public"
            for item in ips
        ),

        private_ip_count=sum(
            item.scope == "private"
            for item in ips
        ),

        countries=countries,

        asns=asns,

        high_risk_ips=high_risk_ips,

        suspicious_domains=suspicious_domains,
    )

def build_threat_assessment(
    ips: list[IPIntelligence],
    header_forensics: dict,
) -> ThreatAssessment:

    reputation_values = [
        item.abuse_confidence_score
        for item in ips
        if (
            item.abuse_confidence_score
            is not None
        )
    ]

    reputation_score = (
        max(reputation_values)
        if reputation_values
        else None
    )

    findings = (
        header_forensics.get(
            "findings"
        )
        or []
    )

    adjustment = 0

    # -----------------------------------------------------
    # Phase 2 finding contribution
    # -----------------------------------------------------

    for finding in findings:

        severity = str(
            finding.get(
                "severity",
                ""
            )
        ).lower()

        if severity == "critical":
            adjustment += 15

        elif severity == "high":
            adjustment += 10

        elif severity == "medium":
            adjustment += 5

    adjustment = min(
        adjustment,
        30,
    )

    # -----------------------------------------------------
    # No AbuseIPDB result
    # -----------------------------------------------------

    if reputation_score is None:

        return ThreatAssessment(
            score=None,

            level="unknown",

            reputation_score=None,

            header_finding_adjustment=(
                adjustment
            ),

            reasons=[
                "No AbuseIPDB reputation score "
                "is available, so Phase 3 cannot "
                "produce a numeric IP reputation score."
            ],
        )

    score = min(
        100,
        reputation_score
        + adjustment,
    )

    if score >= 75:
        level = "critical"

    elif score >= 50:
        level = "high"

    elif score >= 25:
        level = "medium"

    else:
        level = "low"

    reasons = []

    if reputation_score >= 75:

        reasons.append(
            "At least one observed public IP "
            f"has an AbuseIPDB confidence score "
            f"of {reputation_score}/100."
        )

    elif reputation_score >= 25:

        reasons.append(
            "The highest observed IP abuse "
            f"confidence score is "
            f"{reputation_score}/100."
        )

    else:

        reasons.append(
            "Observed IP abuse confidence is "
            f"low at {reputation_score}/100."
        )

    if adjustment:

        reasons.append(
            "Phase 2 header findings contributed "
            f"a +{adjustment} triage adjustment."
        )

    return ThreatAssessment(
        score=score,

        level=level,

        reputation_score=reputation_score,

        header_finding_adjustment=(
            adjustment
        ),

        reasons=reasons,
    )