from typing import Literal, Optional
from pydantic import BaseModel, Field

class IPIntelligence(BaseModel):
    ip: str

    version: Optional[int] = None

    scope: Literal[
        "public",
        "private",
        "loopback",
        "link_local",
        "multicast",
        "reserved",
        "documentation",
        "unspecified",
        "invalid",
    ] = "invalid"

    reverse_dns: Optional[str] = None

    asn: Optional[str] = None

    as_name: Optional[str] = None

    as_domain: Optional[str] = None

    country_code: Optional[str] = None

    country: Optional[str] = None

    continent_code: Optional[str] = None

    continent: Optional[str] = None

    ipinfo_bogon: Optional[bool] = None

    abuse_confidence_score: Optional[int] = None

    abuse_total_reports: Optional[int] = None

    abuse_last_reported_at: Optional[str] = None

    abuse_usage_type: Optional[str] = None

    abuse_isp: Optional[str] = None

    abuse_domain: Optional[str] = None

    abuse_is_whitelisted: Optional[bool] = None

    abuse_is_tor: Optional[bool] = None

    provider_status: dict[str, str] = Field(
        default_factory=dict
    )

    errors: list[str] = Field(
        default_factory=list
    )


class SenderDomainIntelligence(BaseModel):
    domain: str

    roles: list[str] = Field(
        default_factory=list
    )

    # DNS
    a_records: list[str] = Field(
        default_factory=list
    )

    aaaa_records: list[str] = Field(
        default_factory=list
    )

    mx_records: list[str] = Field(
        default_factory=list
    )

    ns_records: list[str] = Field(
        default_factory=list
    )

    spf_records: list[str] = Field(
        default_factory=list
    )

    dmarc_records: list[str] = Field(
        default_factory=list
    )

    dkim_record: Optional[str] = None

    # DNS state
    has_a: bool = False

    has_aaaa: bool = False

    has_mx: bool = False

    has_spf: bool = False

    has_dmarc: bool = False

    has_dkim_selector: bool = False

    errors: list[str] = Field(
        default_factory=list
    )

class ThreatAssessment(BaseModel):
    score: Optional[int] = None

    level: Literal[
        "unknown",
        "low",
        "medium",
        "high",
        "critical",
    ] = "unknown"

    reputation_score: Optional[int] = None

    header_finding_adjustment: int = 0

    reasons: list[str] = Field(
        default_factory=list
    )

    disclaimer: str = (
        "This is an intelligence triage score, not a "
        "final phishing verdict. IP reputation and "
        "header signals can be incomplete or inaccurate."
    )

class IntelligenceSummary(BaseModel):
    public_ip_count: int = 0

    private_ip_count: int = 0

    countries: list[str] = Field(
        default_factory=list
    )

    asns: list[str] = Field(
        default_factory=list
    )

    high_risk_ips: list[str] = Field(
        default_factory=list
    )

    suspicious_domains: list[str] = Field(
        default_factory=list
    )

class EmailIntelligenceResult(BaseModel):
    evidence_id: str

    phase: Literal[
        "phase_3_ip_sender_intelligence"
    ] = "phase_3_ip_sender_intelligence"

    analyzed_at: str

    source_ips: list[IPIntelligence] = Field(
        default_factory=list
    )

    sender_domains: list[SenderDomainIntelligence] = Field(
        default_factory=list
    )

    summary: IntelligenceSummary

    threat_assessment: ThreatAssessment

    provider_notes: list[str] = Field(
        default_factory=list
    )

class EmailIntelligenceResponse(BaseModel):
    evidence_id: str

    intelligence: EmailIntelligenceResult