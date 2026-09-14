import axios from "axios";

export const api = axios.create({
  baseURL:
    import.meta.env.VITE_API_URL ||
    "http://localhost:8000/api/v1",

  timeout: 60000,
});

export type Address = {
  display_name?: string | null;
  address?: string | null;
};


export type Attachment = {
  filename: string;
  content_type?: string | null;
  content_disposition?: string | null;
  size_bytes: number;
  sha256: string;
};


export type Url = {
  url: string;
  scheme?: string | null;
  hostname?: string | null;
  domain?: string | null;
  path?: string | null;
};


export type Metadata = {
  subject?: string | null;
  date?: string | null;
  message_id?: string | null;

  from: Address[];

  to: Address[];

  cc: Address[];

  bcc: Address[];

  replyTo: Address[];

  returnPath?: string | null;

  mime_type?: string | null;

  content_type?: string | null;

  size_bytes: number;

  has_plain_text: boolean;

  has_html: boolean;

  attachment_count: number;

  url_count: number;
};


export type Result = {
  evidence_id: string;

  input_type:
    | "eml"
    | "raw_email";

  filename?: string | null;

  received_at: string;

  evidence_sha256: string;

  metadata: Metadata;

  attachments: Attachment[];

  urls: Url[];

  body_preview?: string | null;

  raw_headers?: string | null;

  status: string;
};

export type ReceivedHop = {
  hop_number: number;

  raw: string;

  from_host?: string | null;

  from_ip?: string | null;

  by_host?: string | null;

  by_ip?: string | null;

  protocol?: string | null;

  timestamp?: string | null;

  is_private_ip?: boolean | null;

  is_public_ip?: boolean | null;
};


export type AuthenticationResult = {
  service?: string | null;

  result?: string | null;

  method?: string | null;

  domain?: string | null;

  selector?: string | null;

  raw?: string | null;
};


export type HeaderFinding = {
  severity:
    | "info"
    | "low"
    | "medium"
    | "high"
    | "critical";

  code: string;

  title: string;

  description: string;

  evidence?: string | null;
};


export type HeaderForensics = {
  evidence_id: string;

  received_hops: ReceivedHop[];

  authentication_results:
    AuthenticationResult[];

  spf_result?: string | null;

  spf_domain?: string | null;

  dkim_result?: string | null;

  dkim_domain?: string | null;

  dkim_selector?: string | null;

  dmarc_result?: string | null;

  dmarc_domain?: string | null;

  from_address?: string | null;

  from_domain?: string | null;

  reply_to_address?: string | null;

  reply_to_domain?: string | null;

  return_path?: string | null;

  return_path_domain?: string | null;

  message_id_domain?: string | null;

  relay_count: number;

  public_ip_count: number;

  private_ip_count: number;

  findings: HeaderFinding[];
};

export type IPIntelligence = {
  ip: string;

  version?: number | null;

  scope:
    | "public"
    | "private"
    | "loopback"
    | "link_local"
    | "multicast"
    | "reserved"
    | "documentation"
    | "unspecified"
    | "invalid";

  reverse_dns?: string | null;

  asn?: string | null;
  as_name?: string | null;
  as_domain?: string | null;
  country_code?: string | null;
  country?: string | null;
  continent_code?: string | null;
  continent?: string | null;
  ipinfo_bogon?: boolean | null;

  abuse_confidence_score?: number | null;

  abuse_total_reports?: number | null;

  abuse_last_reported_at?: string | null;

  abuse_usage_type?: string | null;

  abuse_isp?: string | null;

  abuse_domain?: string | null;

  abuse_is_whitelisted?: boolean | null;

  abuse_is_tor?: boolean | null;

  provider_status:
    Record<string, string>;

  errors: string[];
};

export type SenderDomainIntelligence = {
  domain: string;
  roles: string[];
  a_records: string[];
  aaaa_records: string[];
  mx_records: string[];
  ns_records: string[];
  spf_records: string[];
  dmarc_records: string[];
  dkim_record?: string | null;
  has_a: boolean;
  has_aaaa: boolean;
  has_mx: boolean;
  has_spf: boolean;
  has_dmarc: boolean;
  has_dkim_selector: boolean;
  errors: string[];
};


export type ThreatAssessment = {
  score?: number | null;

  level:
    | "unknown"
    | "low"
    | "medium"
    | "high"
    | "critical";

  reputation_score?: number | null;

  header_finding_adjustment: number;

  reasons: string[];

  disclaimer: string;
};


export type IntelligenceSummary = {
  public_ip_count: number;
  private_ip_count: number;
  countries: string[];
  asns: string[];
  high_risk_ips: string[];
  suspicious_domains: string[];
};


export type EmailIntelligence = {
  evidence_id: string;

  phase:
    "phase_3_ip_sender_intelligence";

  analyzed_at: string;

  source_ips: IPIntelligence[];

  sender_domains:
    SenderDomainIntelligence[];

  summary: IntelligenceSummary;

  threat_assessment: ThreatAssessment;

  provider_notes: string[];
};


export async function getHealth() {

  return (
    await api.get(
      "/health"
    )
  ).data;
}

export async function ingestEml(
  file: File,
) {

  const fd =
    new FormData();

  fd.append(
    "file",
    file,
  );

  return (
    await api.post<Result>(
      "/emails/ingest/eml",
      fd,
    )
  ).data;
}


export async function ingestRaw(
  raw_email: string,
) {

  return (
    await api.post<Result>(
      "/emails/ingest/raw",
      {
        raw_email,
      },
    )
  ).data;
}

// PHASE 2 API

export async function analyzeHeaders(
  evidenceId: string,
) {

  return (
    await api.get<{
      evidence_id: string;

      header_forensics:
        HeaderForensics;
    }>(
      `/emails/evidence/${evidenceId}/headers`,
    )
  ).data;
}

//  PHASE 3 API

export async function analyzeIntelligence(
  evidenceId: string,
) {

  return (
    await api.get<{
      evidence_id: string;

      intelligence:
        EmailIntelligence;
    }>(
      `/emails/evidence/${evidenceId}/intelligence`,
    )
  ).data;
}

//PHASE 4 — URL STRUCTURE

export type URLStructure = {
  original_url: string;

  normalized_url?: string | null;

  scheme?: string | null;

  hostname?: string | null;

  registrable_domain?: string | null;

  port?: number | null;

  path?: string | null;

  query?: string | null;

  fragment_present: boolean;

  username_present: boolean;

  password_present: boolean;

  is_ip_host: boolean;

  ip_version?: number | null;

  is_punycode: boolean;

  contains_unicode: boolean;

  is_shortener: boolean;

  is_https: boolean;

  is_http: boolean;

  is_non_standard_port: boolean;

  suspicious_tokens: string[];

  structural_findings: string[];
};

export type URLDNSIntelligence = {
  domain: string;

  a_records: string[];

  aaaa_records: string[];

  mx_records: string[];

  ns_records: string[];

  txt_records: string[];

  spf_records: string[];

  dmarc_records: string[];

  has_a: boolean;

  has_aaaa: boolean;

  has_mx: boolean;

  has_spf: boolean;

  has_dmarc: boolean;

  errors: string[];
};


export type DomainRegistrationIntelligence = {
  domain: string;

  rdap_available: boolean;

  registrar_name?: string | null;

  registrar_iana_id?: string | null;

  registration_date?: string | null;

  last_changed_date?: string | null;

  expiration_date?: string | null;

  registration_age_days?: number | null;

  domain_status: string[];

  nameservers: string[];

  errors: string[];
};

export type URLReputation = {
  provider: string;

  checked: boolean;

  malicious: boolean;

  threat_types: string[];

  expires_at?: string | null;

  error?: string | null;
};


export type URLFinding = {
  severity:
    | "info"
    | "low"
    | "medium"
    | "high"
    | "critical";

  code: string;

  title: string;

  description: string;

  evidence?: string | null;
};


export type URLIntelligence = {
  url_id: string;

  original_url: string;

  structure: URLStructure;

  dns?: URLDNSIntelligence | null;

  registration?:
    DomainRegistrationIntelligence | null;

  reputation: URLReputation[];

  findings: URLFinding[];

  score?: number | null;

  level:
    | "unknown"
    | "low"
    | "medium"
    | "high"
    | "critical";
};

export type URLDomainSummary = {
  domain: string;

  url_count: number;

  url_ids: string[];

  registration_age_days?: number | null;

  countries_not_available: boolean;

  has_spf?: boolean | null;

  has_dmarc?: boolean | null;

  has_mx?: boolean | null;
};

export type URLIntelligenceSummary = {
  total_urls: number;

  analyzed_urls: number;

  unique_domains: number;

  malicious_urls: number;

  suspicious_urls: number;

  high_risk_urls: string[];

  suspicious_domains: string[];

  shortener_urls: number;

  punycode_urls: number;

  ip_host_urls: number;
};


export type URLIntelligenceResult = {
  evidence_id: string;

  phase:
    "phase_4_url_domain_intelligence";

  analyzed_at: string;

  urls: URLIntelligence[];

  domains: URLDomainSummary[];

  summary: URLIntelligenceSummary;

  provider_notes: string[];
};


export async function analyzeUrlIntelligence(
  evidenceId: string,
) {

  return (
    await api.get<{
      evidence_id: string;

      intelligence:
        URLIntelligenceResult;

    }>(
      `/emails/evidence/${evidenceId}/url-intelligence`,
    )
  ).data;
}