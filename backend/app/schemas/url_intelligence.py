from typing import Literal, Optional

from pydantic import BaseModel, Field

class URLStructure(BaseModel):

    original_url: str

    normalized_url: Optional[str] = None

    scheme: Optional[str] = None

    hostname: Optional[str] = None

    registrable_domain: Optional[str] = None

    port: Optional[int] = None

    path: Optional[str] = None

    query: Optional[str] = None

    fragment_present: bool = False

    username_present: bool = False

    password_present: bool = False

    is_ip_host: bool = False

    ip_version: Optional[int] = None

    is_punycode: bool = False

    contains_unicode: bool = False

    is_shortener: bool = False

    is_https: bool = False

    is_http: bool = False

    is_non_standard_port: bool = False

    suspicious_tokens: list[str] = Field(
        default_factory=list
    )

    structural_findings: list[str] = Field(
        default_factory=list
    )

class URLDNSIntelligence(BaseModel):

    domain: str

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

    txt_records: list[str] = Field(
        default_factory=list
    )

    spf_records: list[str] = Field(
        default_factory=list
    )

    dmarc_records: list[str] = Field(
        default_factory=list
    )

    has_a: bool = False

    has_aaaa: bool = False

    has_mx: bool = False

    has_spf: bool = False

    has_dmarc: bool = False

    errors: list[str] = Field(
        default_factory=list
    )

class DomainRegistrationIntelligence(BaseModel):

    domain: str

    rdap_available: bool = False

    registrar_name: Optional[str] = None

    registrar_iana_id: Optional[str] = None

    registration_date: Optional[str] = None

    last_changed_date: Optional[str] = None

    expiration_date: Optional[str] = None

    registration_age_days: Optional[int] = None

    domain_status: list[str] = Field(
        default_factory=list
    )

    nameservers: list[str] = Field(
        default_factory=list
    )

    errors: list[str] = Field(
        default_factory=list
    )

class URLReputation(BaseModel):

    provider: str

    checked: bool = False

    malicious: bool = False

    threat_types: list[str] = Field(
        default_factory=list
    )

    expires_at: Optional[str] = None

    error: Optional[str] = None

class URLFinding(BaseModel):

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

class URLIntelligence(BaseModel):

    url_id: str

    original_url: str

    structure: URLStructure

    dns: Optional[
        URLDNSIntelligence
    ] = None

    registration: Optional[
        DomainRegistrationIntelligence
    ] = None

    reputation: list[
        URLReputation
    ] = Field(
        default_factory=list
    )

    findings: list[
        URLFinding
    ] = Field(
        default_factory=list
    )

    score: Optional[int] = None

    level: Literal[
        "unknown",
        "low",
        "medium",
        "high",
        "critical",
    ] = "unknown"

class URLDomainSummary(BaseModel):

    domain: str

    url_count: int = 0

    url_ids: list[str] = Field(
        default_factory=list
    )

    registration_age_days: Optional[int] = None

    countries_not_available: bool = True

    has_spf: Optional[bool] = None

    has_dmarc: Optional[bool] = None

    has_mx: Optional[bool] = None

class URLIntelligenceSummary(BaseModel):

    total_urls: int = 0

    analyzed_urls: int = 0

    unique_domains: int = 0

    malicious_urls: int = 0

    suspicious_urls: int = 0

    high_risk_urls: list[str] = Field(
        default_factory=list
    )

    suspicious_domains: list[str] = Field(
        default_factory=list
    )

    shortener_urls: int = 0

    punycode_urls: int = 0

    ip_host_urls: int = 0

class URLIntelligenceResult(BaseModel):

    evidence_id: str

    phase: Literal[
        "phase_4_url_domain_intelligence"
    ] = "phase_4_url_domain_intelligence"

    analyzed_at: str

    urls: list[
        URLIntelligence
    ] = Field(
        default_factory=list
    )

    domains: list[
        URLDomainSummary
    ] = Field(
        default_factory=list
    )

    summary: URLIntelligenceSummary

    provider_notes: list[str] = Field(
        default_factory=list
    )

class URLIntelligenceResponse(BaseModel):

    evidence_id: str

    intelligence: URLIntelligenceResult