import axios from "axios";

export const api = axios.create({

  baseURL:
    import.meta.env.VITE_API_URL ||
    "http://localhost:8000/api/v1",

  timeout: 30000,

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


export type EmailResult = {

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


export async function getHealth() {

  return (
    await api.get("/health")
  ).data;

}


export async function ingestEml(
  file: File,
) {

  const formData =
    new FormData();

  formData.append(
    "file",
    file,
  );

  return (
    await api.post<EmailResult>(
      "/emails/ingest/eml",
      formData,
    )
  ).data;

}

export async function ingestRaw(
  raw_email: string,
) {

  return (
    await api.post<EmailResult>(
      "/emails/ingest/raw",
      {
        raw_email,
      },
    )
  ).data;

}


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