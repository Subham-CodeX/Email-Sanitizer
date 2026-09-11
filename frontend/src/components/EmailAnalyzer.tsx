import {
  ChangeEvent,
  useRef,
  useState,
} from "react";

import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Link2,
  Mail,
  Paperclip,
  Search,
  ShieldCheck,
  Upload,
} from "lucide-react";

import {
  analyzeHeaders,
  EmailResult,
  HeaderForensics,
  ingestEml,
  ingestRaw,
} from "../services/api";


export default function EmailAnalyzer() {

  const [
    mode,
    setMode,
  ] = useState<
    "upload" | "raw"
  >("upload");


  const [
    file,
    setFile,
  ] = useState<File | null>(
    null
  );


  const [
    raw,
    setRaw,
  ] = useState("");


  const [
    result,
    setResult,
  ] = useState<EmailResult | null>(
    null
  );


  const [
    forensicResult,
    setForensicResult,
  ] = useState<
    HeaderForensics | null
  >(null);


  const [
    loading,
    setLoading,
  ] = useState(false);


  const [
    analyzing,
    setAnalyzing,
  ] = useState(false);


  const [
    error,
    setError,
  ] = useState("");


  const inputRef =
    useRef<HTMLInputElement>(
      null
    );


  const chooseFile = (
    event: ChangeEvent<HTMLInputElement>
  ) => {

    setFile(
      event.target.files?.[0]
      ?? null
    );

    setResult(null);

    setForensicResult(
      null
    );

    setError("");
  };


  const submit = async () => {

    setError("");

    setResult(null);

    setForensicResult(null);

    setLoading(true);

    try {

      if (mode === "upload") {

        if (!file) {

          throw new Error(
            "Select an .eml file first."
          );
        }

        const response =
          await ingestEml(
            file
          );

        setResult(
          response
        );

      } else {

        if (!raw.trim()) {

          throw new Error(
            "Paste a raw email first."
          );
        }

        const response =
          await ingestRaw(
            raw
          );

        setResult(
          response
        );
      }

    } catch (error: any) {

      setError(
        error?.response?.data?.detail
        ||
        error?.message
        ||
        "Email ingestion failed."
      );

    } finally {

      setLoading(false);
    }
  };


  const runHeaderAnalysis =
    async () => {

      if (!result) {
        return;
      }

      setError("");

      setAnalyzing(true);

      try {

        const response =
          await analyzeHeaders(
            result.evidence_id
          );

        setForensicResult(
          response.header_forensics
        );

      } catch (error: any) {

        setError(
          error?.response?.data?.detail
          ||
          error?.message
          ||
          "Header analysis failed."
        );

      } finally {

        setAnalyzing(false);
      }
    };


  return (

    <section className="analyzer">

      <div className="section-head">

        <div>

          <p className="eyebrow">
            PHASE 1 + PHASE 2
          </p>

          <h2>
            Email Evidence Analysis
          </h2>

          <p>
            Ingest an email, preserve its
            evidence fingerprint, then
            perform header-level forensic
            analysis.
          </p>

        </div>

        <ShieldCheck
          size={30}
        />

      </div>


      <div className="tabs">

        <button
          className={
            mode === "upload"
              ? "active"
              : ""
          }
          onClick={() => {

            setMode("upload");

            setError("");

          }}
        >

          <Upload size={16} />

          Upload .eml

        </button>


        <button
          className={
            mode === "raw"
              ? "active"
              : ""
          }
          onClick={() => {

            setMode("raw");

            setError("");

          }}
        >

          <FileText
            size={16}
          />

          Raw Email

        </button>

      </div>


      {mode === "upload" ? (

        <div
          className="drop"
          onClick={() =>
            inputRef.current?.click()
          }
        >

          <input
            ref={inputRef}
            hidden
            type="file"
            accept=".eml,message/rfc822"
            onChange={
              chooseFile
            }
          />

          <Upload size={34} />

          <strong>

            {file
              ? file.name
              : "Choose an .eml evidence file"}

          </strong>

          <span>
            Maximum 15 MB
            • attachments are never executed
          </span>

        </div>

      ) : (

        <textarea
          className="raw"
          value={raw}
          onChange={(event) =>
            setRaw(
              event.target.value
            )
          }
          spellCheck={false}
          placeholder={
`From: security@example.com
To: analyst@example.org
Reply-To: attacker@example.net
Subject: Urgent Account Notice
Date: Fri, 11 Sep 2026 10:00:00 +0530
Message-ID: <abc@example.com>
Received: from mail.example.com (mail.example.com [203.0.113.10])
    by mx.example.org with ESMTP id ABC123;
    Fri, 11 Sep 2026 10:00:00 +0530
Authentication-Results: mx.example.org;
    spf=fail smtp.mailfrom=example.net;
    dkim=fail;
    dmarc=fail header.from=example.com

Paste complete raw email here...`
          }
        />

      )}


      <button
        className="primary"
        onClick={submit}
        disabled={loading}
      >

        <Mail size={18} />

        {loading
          ? "Ingesting evidence..."
          : "Ingest Email"}

      </button>


      {error && (

        <div className="error">

          <AlertTriangle
            size={17}
          />

          {error}

        </div>

      )}


      {result && (

        <ResultView
          result={result}
          forensicResult={
            forensicResult
          }
          analyzing={
            analyzing
          }
          onAnalyzeHeaders={
            runHeaderAnalysis
          }
        />

      )}

    </section>
  );
}


function ResultView({
  result,
  forensicResult,
  analyzing,
  onAnalyzeHeaders,
}: {
  result: EmailResult;

  forensicResult:
    HeaderForensics | null;

  analyzing: boolean;

  onAnalyzeHeaders:
    () => void;

}) {

  return (

    <div className="result">

      <div className="success">

        <CheckCircle2
          size={19}
        />

        Evidence ingested

        <span>
          {result.evidence_id}
        </span>

      </div>


      <div className="hash">

        <small>
          SHA-256 EVIDENCE FINGERPRINT
        </small>

        <code>
          {result.evidence_sha256}
        </code>

      </div>


      <div className="grid">

        <Item
          label="Subject"
          value={
            result.metadata.subject
            || "—"
          }
        />

        <Item
          label="From"
          value={
            addresses(
              result.metadata.from
            )
            || "—"
          }
        />

        <Item
          label="To"
          value={
            addresses(
              result.metadata.to
            )
            || "—"
          }
        />

        <Item
          label="Reply-To"
          value={
            addresses(
              result.metadata.replyTo
            )
            || "—"
          }
        />

        <Item
          label="Message-ID"
          value={
            result.metadata.message_id
            || "—"
          }
        />

        <Item
          label="MIME"
          value={
            result.metadata.mime_type
            || "—"
          }
        />

      </div>


      <div className="two">

        <Panel
          title={`Attachments (${result.attachments.length})`}
          icon={
            <Paperclip size={17}/>
          }
        >

          {result.attachments.length
            ? result.attachments.map(
                attachment => (

                  <div
                    className="row"
                    key={
                      attachment.sha256
                    }
                  >

                    <div>

                      <b>
                        {attachment.filename}
                      </b>

                      <small>
                        {
                          attachment.content_type
                          || "unknown"
                        }

                        {" • "}

                        {
                          formatBytes(
                            attachment.size_bytes
                          )
                        }

                      </small>

                    </div>

                    <code>
                      {
                        attachment.sha256
                          .slice(0, 16)
                      }…
                    </code>

                  </div>

                )
              )

            : (

              <p className="muted">
                No attachments detected.
              </p>

            )}

        </Panel>


        <Panel
          title={`URLs (${result.urls.length})`}
          icon={
            <Link2 size={17}/>
          }
        >

          {result.urls.length
            ? result.urls.map(
                url => (

                  <div
                    className="url"
                    key={url.url}
                  >

                    <b>
                      {url.hostname}
                    </b>

                    <span>
                      {url.url}
                    </span>

                  </div>

                )
              )

            : (

              <p className="muted">
                No URLs detected.
              </p>

            )}

        </Panel>

      </div>


      <button
        className="forensic-button"
        onClick={
          onAnalyzeHeaders
        }
        disabled={analyzing}
      >

        <Search size={18}/>

        {analyzing
          ? "Analyzing headers..."
          : "Run Phase 2 Header Forensics"}

      </button>


      {forensicResult && (

        <HeaderForensicsView
          result={
            forensicResult
          }
        />

      )}


      {result.body_preview && (

        <div className="body">

          <h3>
            Body Preview
          </h3>

          <p>
            {result.body_preview}
          </p>

        </div>

      )}

    </div>
  );
}


function HeaderForensicsView({
  result,
}: {
  result: HeaderForensics;
}) {

  return (

    <div className="forensics">

      <div className="forensics-header">

        <div>

          <p className="eyebrow">
            PHASE 2 • HEADER FORENSICS
          </p>

          <h3>
            Header Investigation
          </h3>

        </div>

        <ShieldCheck
          size={24}
        />

      </div>


      <div className="auth-grid">

        <AuthCard
          label="SPF"
          value={
            result.spf_result
            || "not detected"
          }
          domain={
            result.spf_domain
          }
        />

        <AuthCard
          label="DKIM"
          value={
            result.dkim_result
            || "not detected"
          }
          domain={
            result.dkim_domain
          }
        />

        <AuthCard
          label="DMARC"
          value={
            result.dmarc_result
            || "not detected"
          }
          domain={
            result.dmarc_domain
          }
        />

      </div>


      <div className="route-summary">

        <Summary
          label="Relay Hops"
          value={
            String(
              result.relay_count
            )
          }
        />

        <Summary
          label="Public IPs"
          value={
            String(
              result.public_ip_count
            )
          }
        />

        <Summary
          label="Private IPs"
          value={
            String(
              result.private_ip_count
            )
          }
        />

      </div>


      <div className="identity-grid">

        <Item
          label="From Domain"
          value={
            result.from_domain
            || "—"
          }
        />

        <Item
          label="Reply-To Domain"
          value={
            result.reply_to_domain
            || "—"
          }
        />

        <Item
          label="Return-Path Domain"
          value={
            result.return_path_domain
            || "—"
          }
        />

        <Item
          label="DKIM Domain"
          value={
            result.dkim_domain
            || "—"
          }
        />

        <Item
          label="SPF Domain"
          value={
            result.spf_domain
            || "—"
          }
        />

        <Item
          label="Message-ID Domain"
          value={
            result.message_id_domain
            || "—"
          }
        />

      </div>


      <div className="panel">

        <h3>
          Received Chain
        </h3>

        {result.received_hops.map(
          hop => (

            <div
              className="hop"
              key={
                hop.hop_number
              }
            >

              <div className="hop-number">
                {hop.hop_number}
              </div>

              <div className="hop-content">

                <strong>
                  {hop.from_host
                    || "Unknown source"}
                </strong>

                <span>

                  {hop.from_ip
                    || "No source IP"}

                  {" → "}

                  {hop.by_host
                    || "Unknown destination"}

                </span>

                <small>

                  {hop.protocol
                    || "Unknown protocol"}

                  {" • "}

                  {hop.timestamp
                    || "No timestamp"}

                </small>

              </div>

              <div
                className={
                  hop.is_public_ip
                    ? "ip-badge public"
                    : hop.is_private_ip
                      ? "ip-badge private"
                      : "ip-badge"
                }
              >

                {hop.is_public_ip
                  ? "PUBLIC"
                  : hop.is_private_ip
                    ? "PRIVATE"
                    : "UNKNOWN"}

              </div>

            </div>

          )
        )}

      </div>


      <div className="panel">

        <h3>
          Forensic Findings
        </h3>

        {result.findings.length === 0 ? (

          <div className="clean">
            No header anomalies detected.
          </div>

        ) : (

          result.findings.map(
            finding => (

              <div
                className={
                  `finding ${finding.severity}`
                }
                key={
                  finding.code
                }
              >

                <div>

                  <strong>
                    {finding.title}
                  </strong>

                  <span>
                    {finding.description}
                  </span>

                </div>

                <b>
                  {finding.severity.toUpperCase()}
                </b>

              </div>

            )
          )

        )}

      </div>


      <div className="panel">

        <h3>
          Authentication Results
        </h3>

        {result.authentication_results.length === 0 ? (

          <p className="muted">
            No Authentication-Results
            headers detected.
          </p>

        ) : (

          result.authentication_results.map(
            (auth, index) => (

              <div
                className="auth-row"
                key={`${auth.method}-${index}`}
              >

                <strong>
                  {
                    auth.method
                    || "unknown"
                  }
                </strong>

                <span>
                  {
                    auth.result
                    || "unknown"
                  }
                </span>

                <small>
                  {
                    auth.domain
                    || "domain unavailable"
                  }
                </small>

              </div>

            )
          )

        )}

      </div>

    </div>
  );
}


function AuthCard({
  label,
  value,
  domain,
}: {
  label: string;
  value: string;
  domain?: string | null;
}) {

  const normalized =
    value.toLowerCase();

  const failed =
    normalized.includes(
      "fail"
    );

  const passed =
    normalized === "pass";


  return (

    <div
      className={
        `auth-card ${
          failed
            ? "failed"
            : passed
              ? "passed"
              : ""
        }`
      }
    >

      <small>
        {label}
      </small>

      <strong>
        {value}
      </strong>

      <span>
        {domain || "—"}
      </span>

    </div>
  );
}


function Summary({
  label,
  value,
}: {
  label: string;
  value: string;
}) {

  return (

    <div className="summary">

      <small>
        {label}
      </small>

      <strong>
        {value}
      </strong>

    </div>
  );
}


function Item({
  label,
  value,
}: {
  label: string;
  value: string;
}) {

  return (

    <div className="item">

      <small>
        {label}
      </small>

      <span>
        {value}
      </span>

    </div>
  );
}


function Panel({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {

  return (

    <div className="panel">

      <h3>
        {icon}
        {title}
      </h3>

      {children}

    </div>
  );
}


function addresses(
  values: {
    display_name?: string | null;
    address?: string | null;
  }[]
) {

  return values

    .map(
      item =>
        item.display_name
          ? `${item.display_name} <${
              item.address || ""
            }>`
          : item.address || ""
    )

    .filter(Boolean)

    .join(", ");
}


function formatBytes(
  bytes: number
) {

  if (bytes < 1024) {

    return `${bytes} B`;

  }

  if (
    bytes <
    1024 * 1024
  ) {

    return `${
      (bytes / 1024)
        .toFixed(1)
    } KB`;

  }

  return `${
    (bytes /
      (1024 * 1024)
    ).toFixed(2)
  } MB`;
}


function HopPlaceholder() {
  return null;
}