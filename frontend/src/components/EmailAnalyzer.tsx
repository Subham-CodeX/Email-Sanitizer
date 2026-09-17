import {
  ChangeEvent,
  useRef,
  useState,
} from "react";

import {
  Activity,
  AlertTriangle,
  Building2,
  CheckCircle2,
  CircleDot,
  FileText,
  Globe2,
  Link2,
  Mail,
  MapPin,
  Network,
  Paperclip,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from "lucide-react";


import {
  analyzeHeaders,
  analyzeIntelligence,
  EmailIntelligence,
  HeaderForensics,
  ingestEml,
  ingestRaw,
  IPIntelligence,
  Result,
  SenderDomainIntelligence,
  analyzeUrlIntelligence,
  URLIntelligenceResult,
  analyzeAttachmentIntelligence,
  AttachmentIntelligenceResult,
} from "../services/api";

import AttachmentIntelligenceView from "./AttachmentIntelligenceView";
import UrlIntelligenceView from "./UrlIntelligenceView";
import "../intelligence.css";

export default function EmailAnalyzer() {

  const [mode, setMode] =
    useState<
      "upload" | "raw"
    >("upload");

  const [file, setFile] =
    useState<File | null>(
      null,
    );

  const [raw, setRaw] =
    useState("");

  const [result, setResult] =
    useState<Result | null>(
      null,
    );

  const [headers, setHeaders] =
    useState<HeaderForensics | null>(
      null,
    );

  const [intelligence, setIntelligence] =
    useState<EmailIntelligence | null>(
      null,
    );

  const [
      urlIntelligence,
      setUrlIntelligence,
    ] = useState<URLIntelligenceResult | null>(
      null,
    );

    const [
      urlIntelLoading,
      setUrlIntelLoading,
    ] = useState(false);

  const [error, setError] =
    useState("");

  const [loading, setLoading] =
    useState(false);

  const [headerLoading, setHeaderLoading] =
    useState(false);

  const [intelLoading, setIntelLoading] =
    useState(false);

  const [
    attachmentIntelligence,
    setAttachmentIntelligence,
  ] = useState<
    AttachmentIntelligenceResult | null
  >(null);

  const [
    attachmentIntelLoading,
    setAttachmentIntelLoading,
  ] = useState(false);

  const ref =
    useRef<HTMLInputElement>(
      null,
    );

  const choose = (
    e: ChangeEvent<HTMLInputElement>,
  ) => {

    setFile(
      e.target.files?.[0]
      ?? null,
    );

    setResult(null);

    setHeaders(null);

    setIntelligence(null);

    setError("");
  };

  const submit = async () => {

    setError("");

    setResult(null);

    setHeaders(null);

    setIntelligence(null);

    setLoading(true);

    try {

      if (
        mode === "upload"
      ) {

        if (!file) {

          throw new Error(
            "Select an .eml file first.",
          );
        }

        setResult(
          await ingestEml(
            file,
          ),
        );

      } else {

        if (!raw.trim()) {

          throw new Error(
            "Paste a raw email first.",
          );
        }

        setResult(
          await ingestRaw(
            raw,
          ),
        );
      }

    } catch (e: any) {

      setError(
        e?.response?.data?.detail
        ||
        e?.message
        ||
        "Email ingestion failed.",
      );

    } finally {

      setLoading(false);
    }
  };

  const runHeaders = async () => {

    if (!result)
      return;

    setError("");

    setHeaderLoading(true);

    try {

      const response =
        await analyzeHeaders(
          result.evidence_id,
        );

      setHeaders(
        response.header_forensics,
      );

      setIntelligence(null);

    } catch (e: any) {

      setError(
        e?.response?.data?.detail
        ||
        e?.message
        ||
        "Header forensics analysis failed.",
      );

    } finally {

      setHeaderLoading(false);
    }
  };

  const runIntelligence = async () => {

    if (!result)
      return;

    setError("");

    setIntelLoading(true);

    try {

      const response =
        await analyzeIntelligence(
          result.evidence_id,
        );

      setIntelligence(
        response.intelligence,
      );

    } catch (e: any) {

      setError(
        e?.response?.data?.detail
        ||
        e?.message
        ||
        "IP and sender intelligence analysis failed.",
      );

    } finally {

      setIntelLoading(false);
    }
  };

  const runUrlIntelligence = async () => {

    if (!result)
      return;

    if (
      result.urls.length === 0
    ) {

      setError(
        "No URLs were extracted from this email.",
      );

      return;
    }

    setError("");

    setUrlIntelLoading(true);

    try {

      const response =
        await analyzeUrlIntelligence(
          result.evidence_id,
        );

      setUrlIntelligence(
        response.intelligence,
      );

    } catch (e: any) {

      setError(
        e?.response?.data?.detail
        ||
        e?.message
        ||
        "URL intelligence analysis failed.",
      );

    } finally {

      setUrlIntelLoading(false);
    }
  };

  const runAttachmentIntelligence =
  async () => {

    if (!result)
      return;

    if (
      result.attachments.length === 0
    ) {

      setError(
        "No attachments were extracted from this email.",
      );

      return;
    }

    setError("");

    setAttachmentIntelLoading(
      true
    );

    try {

      const response =
        await analyzeAttachmentIntelligence(
          result.evidence_id,
        );

      setAttachmentIntelligence(
        response.intelligence,
      );

    } catch (e: any) {

      setError(
        e?.response?.data?.detail
        ||
        e?.message
        ||
        "Attachment intelligence analysis failed.",
      );

    } finally {

      setAttachmentIntelLoading(
        false
      );

    }
  };


  return (
    <section className="analyzer">

      {/* ==================================================
          HEADER
      ================================================== */}

      <div className="section-head">

        <div>

          <p className="eyebrow">
            PHASE 1 → 2 → 3 → 4 → 5 • EMAIL FORENSICS
          </p>

          <h2>
            Analyze email evidence
          </h2>

          <p>
            Ingest the sample, inspect authentication and
            routing headers, enrich observed infrastructure,
            analyze URLs and domains, then perform safe
            attachment threat intelligence without executing
            any attachment.
          </p>

        </div>

        <ShieldCheck size={30} />

      </div>

        {/* INPUT TABS */}

      <div className="tabs">

        <button
          className={
            mode === "upload"
              ? "active"
              : ""
          }
          onClick={() =>
            setMode("upload")
          }
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
          onClick={() =>
            setMode("raw")
          }
        >

          <FileText size={16} />

          Raw Email

        </button>

      </div>

        {/* UPLOAD */}

      {mode === "upload" ? (

        <div
          className="drop"
          onClick={() =>
            ref.current?.click()
          }
        >

          <input
            ref={ref}
            hidden
            type="file"
            accept=".eml,message/rfc822"
            onChange={choose}
          />

          <Upload size={34} />

          <strong>
            {
              file
                ? file.name
                : "Choose an .eml evidence file"
            }
          </strong>

          <span>
            Maximum 15 MB • attachments are never executed
          </span>

        </div>

      ) : (

        <textarea
          className="raw"
          value={raw}
          onChange={(e) =>
            setRaw(
              e.target.value,
            )
          }
          spellCheck={false}
          placeholder={`From: security@example.com
To: analyst@example.org
Subject: Example
Date: Fri, 11 Sep 2026 10:00:00 +0530
Message-ID: <example@example.com>
Content-Type: text/plain; charset="UTF-8"

Paste complete raw email here...`}
        />

      )}

        {/* INGEST */}

      <button
        className="primary"
        onClick={submit}
        disabled={loading}
      >

        <Mail size={18} />

        {
          loading
            ? "Ingesting evidence..."
            : "Ingest Email"
        }

      </button>

        {/* ERROR */}

      {error && (

        <div className="error">

          <AlertTriangle size={17} />

          {error}

        </div>

      )}

        {/* RESULT */}

      {result && (

        <ResultView
          result={result}
          headers={headers}
          intelligence={intelligence}
          urlIntelligence={urlIntelligence}
          attachmentIntelligence={attachmentIntelligence}
          headerLoading={headerLoading}
          intelLoading={intelLoading}
          urlIntelLoading={urlIntelLoading}
          attachmentIntelLoading={attachmentIntelLoading}
          onRunHeaders={runHeaders}
          onRunIntelligence={runIntelligence}
          onRunUrlIntelligence={runUrlIntelligence}
          onRunAttachmentIntelligence={runAttachmentIntelligence}
        />

      )}

    </section>
  );
}

function ResultView({
  result,
  headers,
  intelligence,
  urlIntelligence,
  attachmentIntelligence,
  headerLoading,
  intelLoading,
  urlIntelLoading,
  attachmentIntelLoading,
  onRunHeaders,
  onRunIntelligence,
  onRunUrlIntelligence,
  onRunAttachmentIntelligence,
}: {
  result: Result;

  headers:
    HeaderForensics | null;

  intelligence:
    EmailIntelligence | null;

  urlIntelligence:
    URLIntelligenceResult | null;

  attachmentIntelligence:
    AttachmentIntelligenceResult | null;

  headerLoading: boolean;

  intelLoading: boolean;

  urlIntelLoading: boolean;

  attachmentIntelLoading: boolean;

  onRunHeaders: () => void;

  onRunIntelligence: () => void;

  onRunUrlIntelligence: () => void;

  onRunAttachmentIntelligence: () => void;
}) {

  return (

    <div className="result">

        {/* EVIDENCE SUCCESS */}

      <div className="success">

        <CheckCircle2 size={19} />

        Evidence ingested

        <span>
          {result.evidence_id}
        </span>

      </div>

        {/* HASH */}

      <div className="hash">

        <small>
          SHA-256 EVIDENCE FINGERPRINT
        </small>

        <code>
          {result.evidence_sha256}
        </code>

      </div>


      {/* ==================================================
          METADATA
      ================================================== */}

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
              result.metadata.from,
            )
            || "—"
          }
        />

        <Item
          label="To"
          value={
            addresses(
              result.metadata.to,
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

        <Item
          label="Size"
          value={
            bytes(
              result.metadata.size_bytes,
            )
          }
        />

      </div>


      {/* ==================================================
          ATTACHMENTS + URLS
      ================================================== */}

      <div className="two">

        <Panel
          title={
            `Attachments (${result.attachments.length})`
          }
          icon={
            <Paperclip size={17} />
          }
        >

          {
            result.attachments.length
              ? result.attachments.map(
                  (a) => (

                    <div
                      className="row"
                      key={a.sha256}
                    >

                      <div>

                        <b>
                          {a.filename}
                        </b>

                        <small>
                          {
                            a.content_type
                            || "unknown"
                          }

                          {" • "}

                          {
                            bytes(
                              a.size_bytes,
                            )
                          }
                        </small>

                      </div>

                      <code>
                        {
                          a.sha256.slice(
                            0,
                            16,
                          )
                        }
                        …
                      </code>

                    </div>

                  ),
                )

              : (
                <p className="muted">
                  No attachments detected.
                </p>
              )
          }

        </Panel>


        <Panel
          title={
            `URLs (${result.urls.length})`
          }
          icon={
            <Link2 size={17} />
          }
        >

          {
            result.urls.length
              ? result.urls.map(
                  (u) => (

                    <div
                      className="url"
                      key={u.url}
                    >

                      <b>
                        {u.hostname}
                      </b>

                      <span>
                        {u.url}
                      </span>

                    </div>

                  ),
                )

              : (
                <p className="muted">
                  No URLs detected.
                </p>
              )
          }

        </Panel>

      </div>


      {/* ==================================================
          BODY
      ================================================== */}

      {
        result.body_preview && (

          <div className="body">

            <h3>
              Body Preview
            </h3>

            <p>
              {result.body_preview}
            </p>

          </div>

        )
      }


      {/* ==================================================
          PHASE ACTIONS
      ================================================== */}

      <div className="phase-actions">

        <button
          className="secondary-action"
          onClick={
            onRunHeaders
          }
          disabled={
            headerLoading
          }
        >

          <Search size={17} />

          {
            headerLoading
              ? "Running Header Forensics..."
              : "Run Phase 2 Header Forensics"
          }

        </button>


        <button
          className="secondary-action intel-action"
          onClick={
            onRunIntelligence
          }
          disabled={
            intelLoading
            || !headers
          }
          title={
            !headers
              ? "Run Phase 2 Header Forensics first"
              : "Enrich observed IPs and sender domains"
          }
        >

          <Network size={17} />

          {
            intelLoading
              ? "Enriching Intelligence..."
              : "Run Phase 3 IP & Sender Intelligence"
          }

        </button>

        <button
          className="secondary-action url-intelligence-action"
          onClick={
            onRunUrlIntelligence
          }
          disabled={
            urlIntelLoading
            ||
            !result
            ||
            result.urls.length === 0
          }
        >

          <Globe2 size={17} />

          {
            urlIntelLoading
              ? "Analyzing URLs..."
              : "Run Phase 4 URL Intelligence"
          }

        </button>

        <button
          className="secondary-action"
          onClick={
            onRunAttachmentIntelligence
          }
          disabled={
            attachmentIntelLoading ||
            result.attachments.length === 0
          }
        >

          <ShieldAlert size={17} />

          {
            attachmentIntelLoading
              ? "Analyzing Attachments..."
              : "Run Phase 5 Attachment Intelligence"
          }

        </button>

      </div>


      {/* ==================================================
          PHASE 2
      ================================================== */}

      {
        headers && (
          <HeaderForensicsView
            data={headers}
          />
        )
      }


      {/* ==================================================
          PHASE 3
      ================================================== */}

      {
        intelligence && (
          <IntelligenceView
            data={
              intelligence
            }
          />
        )
      }

      {
        urlIntelligence && (
          <UrlIntelligenceView
            data={
              urlIntelligence
            }
          />
        )
      }

      {
        attachmentIntelligence && (
          <AttachmentIntelligenceView
            data={
              attachmentIntelligence
            }
          />
        )
      }

    </div>
  );
}

function HeaderForensicsView({
  data,
}: {
  data: HeaderForensics;
}) {

  return (

    <div className="forensics">

      <div className="forensics-head">

        <div>

          <p className="eyebrow">
            PHASE 2 • HEADER FORENSICS
          </p>

          <h3>
            Routing & authentication evidence
          </h3>

        </div>

        <ShieldAlert size={23} />

      </div>


      <div className="auth-grid">

        <AuthCard
          label="SPF"
          value={data.spf_result}
          domain={data.spf_domain}
        />

        <AuthCard
          label="DKIM"
          value={data.dkim_result}
          domain={data.dkim_domain}
        />

        <AuthCard
          label="DMARC"
          value={data.dmarc_result}
          domain={data.dmarc_domain}
        />

      </div>


      <div className="route-summary">

        <Metric
          label="Relays"
          value={
            String(
              data.relay_count,
            )
          }
        />

        <Metric
          label="Public IPs"
          value={
            String(
              data.public_ip_count,
            )
          }
        />

        <Metric
          label="Private IPs"
          value={
            String(
              data.private_ip_count,
            )
          }
        />

      </div>


      <div className="identity-grid">

        <Identity
          label="From"
          value={
            data.from_address
          }
        />

        <Identity
          label="Reply-To"
          value={
            data.reply_to_address
          }
        />

        <Identity
          label="Return-Path"
          value={
            data.return_path
          }
        />

        <Identity
          label="DKIM domain"
          value={
            data.dkim_domain
          }
        />

        <Identity
          label="SPF domain"
          value={
            data.spf_domain
          }
        />

        <Identity
          label="Message-ID domain"
          value={
            data.message_id_domain
          }
        />

      </div>


      {/* RECEIVED CHAIN */}

      <div className="forensic-block">

        <h4>
          <Activity size={16} />

          Received chain

        </h4>

        {
          data.received_hops.length
            ? data.received_hops.map(
                (hop) => (

                  <div
                    className="hop"
                    key={
                      `${hop.hop_number}-${hop.raw}`
                    }
                  >

                    <div className="hop-number">
                      {hop.hop_number}
                    </div>

                    <div>

                      <b>
                        {
                          hop.from_host
                          || "unknown"
                        }

                        {" → "}

                        {
                          hop.by_host
                          || "unknown"
                        }
                      </b>

                      <span>

                        {
                          hop.from_ip
                          || "no source IP"
                        }

                        {
                          hop.protocol
                            ? ` • ${hop.protocol}`
                            : ""
                        }

                        {
                          hop.timestamp
                            ? ` • ${hop.timestamp}`
                            : ""
                        }

                      </span>

                    </div>

                  </div>

                ),
              )

            : (
              <p className="muted">
                No Received headers were parsed.
              </p>
            )
        }

      </div>


      {/* FINDINGS */}

      <div className="forensic-block">

        <h4>

          <ShieldAlert size={16} />

          Findings

        </h4>

        {
          data.findings.length
            ? data.findings.map(
                (finding) => (

                  <div
                    className={
                      `finding ${finding.severity}`
                    }
                    key={
                      `${finding.code}-${finding.title}`
                    }
                  >

                    <div>

                      <b>
                        {finding.title}
                      </b>

                      <span>
                        {
                          finding.description
                        }
                      </span>

                    </div>

                    <small>
                      {
                        finding.severity
                          .toUpperCase()
                      }
                    </small>

                  </div>

                ),
              )

            : (
              <p className="muted">
                No Phase 2 findings were generated.
              </p>
            )
        }

      </div>


      {/* AUTH RESULTS */}

      {
        data.authentication_results.length > 0 && (

          <div className="forensic-block">

            <h4>

              <CircleDot size={16} />

              Authentication-Results

            </h4>

            {
              data.authentication_results.map(
                (
                  auth,
                  index,
                ) => (

                  <div
                    className="auth-row"
                    key={
                      `${auth.service}-${auth.method}-${index}`
                    }
                  >

                    <b>
                      {
                        auth.method
                        || auth.service
                        || "authentication"
                      }
                    </b>

                    <span>
                      {
                        auth.result
                        || "unknown"
                      }
                    </span>

                    <code>
                      {
                        auth.domain
                        || "—"
                      }
                    </code>

                  </div>

                ),
              )
            }

          </div>

        )
      }

    </div>
  );
}


function IntelligenceView({
  data,
}: {
  data: EmailIntelligence;
}) {

  const threat =
    data.threat_assessment;


  return (

    <div className="intel-shell">

      {/* ==================================================
          HEADER
      ================================================== */}

      <div className="intel-head">

        <div>

          <p className="eyebrow">
            PHASE 3 • IP & SENDER INTELLIGENCE
          </p>

          <h3>
            Infrastructure intelligence
          </h3>

          <p>
            Passive enrichment of observed
            relay IPs and sender-related domains.
            No email URL is opened and no
            attachment is executed.
          </p>

        </div>

        <Network size={24} />

      </div>


      {/* ==================================================
          THREAT
      ================================================== */}

      <div className="intel-threat">

        <div>

          <span>
            INTELLIGENCE TRIAGE
          </span>

          <strong>
            {
              threat.score == null
                ? "UNRATED"
                : threat.score
            }
          </strong>

        </div>


        <div
          className={
            `intel-level ${threat.level}`
          }
        >

          {
            threat.level.toUpperCase()
          }

        </div>


        <p>
          {threat.disclaimer}
        </p>

      </div>


      {/* ==================================================
          SUMMARY
      ================================================== */}

      <div className="intel-summary-grid">

        <IntelMetric
          icon={
            <Globe2 size={17} />
          }
          label="Public IPs"
          value={
            String(
              data.summary.public_ip_count,
            )
          }
        />

        <IntelMetric
          icon={
            <Server size={17} />
          }
          label="Private IPs"
          value={
            String(
              data.summary.private_ip_count,
            )
          }
        />

        <IntelMetric
          icon={
            <MapPin size={17} />
          }
          label="Countries"
          value={
            String(
              data.summary.countries.length,
            )
          }
        />

        <IntelMetric
          icon={
            <Building2 size={17} />
          }
          label="ASNs"
          value={
            String(
              data.summary.asns.length,
            )
          }
        />

      </div>


      {/* COUNTRIES */}

      {
        data.summary.countries.length > 0 && (

          <div className="intel-chip-row">

            {
              data.summary.countries.map(
                (country) => (

                  <span
                    key={country}
                  >
                    {country}
                  </span>

                ),
              )
            }

          </div>

        )
      }


      {/* ==================================================
          IP INTELLIGENCE
      ================================================== */}

      <div className="intel-block">

        <div className="intel-block-title">

          <h4>

            <MapPin size={16} />

            Observed IP intelligence

          </h4>

          <small>
            {
              data.source_ips.length
            } indicators
          </small>

        </div>


        {
          data.source_ips.length

            ? (

              <div className="intel-ip-list">

                {
                  data.source_ips.map(
                    (ip) => (

                      <IPCard
                        key={ip.ip}
                        ip={ip}
                      />

                    ),
                  )
                }

              </div>

            )

            : (

              <p className="muted">
                No IP indicators were available
                from the Phase 2 Received chain.
              </p>

            )
        }

      </div>


      {/* ==================================================
          DOMAIN INTELLIGENCE
      ================================================== */}

      <div className="intel-block">

        <div className="intel-block-title">

          <h4>

            <Globe2 size={16} />

            Sender domain intelligence

          </h4>

          <small>
            {
              data.sender_domains.length
            } domains
          </small>

        </div>


        {
          data.sender_domains.length

            ? (

              <div className="intel-domain-list">

                {
                  data.sender_domains.map(
                    (domain) => (

                      <DomainCard
                        key={
                          domain.domain
                        }
                        domain={
                          domain
                        }
                      />

                    ),
                  )
                }

              </div>

            )

            : (

              <p className="muted">
                No valid sender-related domains
                were available.
              </p>

            )
        }

      </div>


      {/* ==================================================
          INVESTIGATION LEADS
      ================================================== */}

      {
        (
          data.summary.high_risk_ips.length
          > 0
          ||
          data.summary.suspicious_domains.length
          > 0
        ) && (

          <div className="intel-alert">

            <AlertTriangle size={17} />

            <div>

              <b>
                Investigation leads detected
              </b>

              {
                data.summary.high_risk_ips.length
                > 0 && (

                  <span>
                    High-reputation-risk IPs:
                    {" "}
                    {
                      data.summary.high_risk_ips.join(
                        ", ",
                      )
                    }
                  </span>

                )
              }

              {
                data.summary.suspicious_domains.length
                > 0 && (

                  <span>
                    Domains missing expected DNS
                    records:
                    {" "}
                    {
                      data.summary.suspicious_domains.join(
                        ", ",
                      )
                    }
                  </span>

                )
              }

            </div>

          </div>

        )
      }


      {/* ==================================================
          PROVIDER NOTES
      ================================================== */}

      <div className="intel-notes">

        {
          data.provider_notes.map(
            (note) => (

              <span
                key={note}
              >
                • {note}
              </span>

            ),
          )
        }

      </div>

    </div>
  );
}

function IPCard({
  ip,
}: {
  ip: IPIntelligence;
}) {

  const score =
    ip.abuse_confidence_score;


  const scoreClass =
    score == null
      ? "unknown"
      : score >= 75
        ? "critical"
        : score >= 50
          ? "high"
          : score >= 25
            ? "medium"
            : "low";


  return (

    <div className="intel-ip-card">

      <div className="intel-ip-top">

        <div>

          <code>
            {ip.ip}
          </code>

          <span
            className={
              `scope-pill ${ip.scope}`
            }
          >
            {
              ip.scope.replace(
                "_",
                " ",
              )
            }
          </span>

        </div>


        {
          score != null

            ? (

              <strong
                className={
                  `abuse-score ${scoreClass}`
                }
              >
                {score}/100
              </strong>

            )

            : (

              <strong className="abuse-score unknown">
                unrated
              </strong>

            )
        }

      </div>


      <div className="intel-detail-grid">

        <Detail
          label="Reverse DNS"
          value={
            ip.reverse_dns
          }
        />

        <Detail
          label="Country"
          value={
            ip.country
              ? `${ip.country}${
                  ip.country_code
                    ? ` (${ip.country_code})`
                    : ""
                }`
              : null
          }
        />

        <Detail
          label="ASN"
          value={
            ip.asn
              ? `${ip.asn}${
                  ip.as_name
                    ? ` • ${ip.as_name}`
                    : ""
                }`
              : null
          }
        />

        <Detail
          label="AS Domain"
          value={
            ip.as_domain
          }
        />

        <Detail
          label="Usage"
          value={
            ip.abuse_usage_type
          }
        />

        <Detail
          label="ISP"
          value={
            ip.abuse_isp
          }
        />

        <Detail
          label="Reports"
          value={
            ip.abuse_total_reports != null
              ? String(
                  ip.abuse_total_reports,
                )
              : null
          }
        />

        <Detail
          label="Last Report"
          value={
            ip.abuse_last_reported_at
          }
        />

      </div>


      <div className="provider-row">

        {
          Object.entries(
            ip.provider_status,
          ).map(
            (
              [
                name,
                status,
              ],
            ) => (

              <span
                key={name}
                className={
                  status === "ok"
                    ? "ok"
                    : "muted-provider"
                }
              >

                {name}: {status}

              </span>

            ),
          )
        }

      </div>

    </div>
  );
}

function DomainCard({
  domain,
}: {
  domain: SenderDomainIntelligence;
}) {

  return (

    <div className="intel-domain-card">

      <div className="domain-title">

        <div>

          <code>
            {domain.domain}
          </code>

          <div className="role-row">

            {
              domain.roles.map(
                (role) => (

                  <span
                    key={role}
                  >
                    {role}
                  </span>

                ),
              )
            }

          </div>

        </div>


        <div className="dns-state">

          <DnsFlag
            label="MX"
            value={
              domain.has_mx
            }
          />

          <DnsFlag
            label="SPF"
            value={
              domain.has_spf
            }
          />

          <DnsFlag
            label="DMARC"
            value={
              domain.has_dmarc
            }
          />

          {
            domain.dkim_record && (

              <DnsFlag
                label="DKIM"
                value={
                  domain.has_dkim_selector
                }
              />

            )
          }

        </div>

      </div>


      <div className="domain-record-grid">

        <RecordList
          label="A"
          values={
            domain.a_records
          }
        />

        <RecordList
          label="AAAA"
          values={
            domain.aaaa_records
          }
        />

        <RecordList
          label="MX"
          values={
            domain.mx_records
          }
        />

        <RecordList
          label="NS"
          values={
            domain.ns_records
          }
        />

        <RecordList
          label="SPF"
          values={
            domain.spf_records
          }
        />

        <RecordList
          label="DMARC"
          values={
            domain.dmarc_records
          }
        />

      </div>

    </div>
  );
}


/* ========================================================
   DNS FLAG
======================================================== */

function DnsFlag({
  label,
  value,
}: {
  label: string;
  value: boolean;
}) {

  return (

    <span
      className={
        value
          ? "dns-good"
          : "dns-missing"
      }
    >
      {label}
    </span>

  );
}

function RecordList({
  label,
  values,
}: {
  label: string;
  values: string[];
}) {

  return (

    <div className="record-list">

      <small>
        {label}
      </small>

      {
        values.length

          ? values.map(
              (value) => (

                <code
                  key={value}
                >
                  {value}
                </code>

              ),
            )

          : (
            <span>
              none
            </span>
          )
      }

    </div>
  );
}


function AuthCard({
  label,
  value,
  domain,
}: {
  label: string;

  value?: string | null;

  domain?: string | null;
}) {

  const normalized =
    (
      value
      || "unknown"
    ).toLowerCase();


  const good =
    normalized === "pass";


  return (

    <div
      className={
        `auth-card ${
          good
            ? "pass"
            : normalized === "unknown"
              ? "unknown"
              : "fail"
        }`
      }
    >

      <div>

        <b>
          {label}
        </b>

        <strong>
          {
            value
            || "unknown"
          }
        </strong>

      </div>

      <small>
        {
          domain
          || "domain unavailable"
        }
      </small>

    </div>
  );
}

function Metric({
  label,
  value,
}: {
  label: string;
  value: string;
}) {

  return (

    <div className="metric">

      <small>
        {label}
      </small>

      <b>
        {value}
      </b>

    </div>
  );
}


function Identity({
  label,
  value,
}: {
  label: string;
  value?: string | null;
}) {

  return (

    <div className="identity">

      <small>
        {label}
      </small>

      <span>
        {
          value
          || "—"
        }
      </span>

    </div>
  );
}

function IntelMetric({
  icon,
  label,
  value,
}: {
  icon: React.ReactNode;

  label: string;

  value: string;
}) {

  return (

    <div className="intel-metric">

      <span>

        {icon}

        {label}

      </span>

      <b>
        {value}
      </b>

    </div>
  );
}

function Detail({
  label,
  value,
}: {
  label: string;

  value?: string | null;
}) {

  return (

    <div className="intel-detail">

      <small>
        {label}
      </small>

      <span>
        {
          value
          || "—"
        }
      </span>

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
  a: {
    display_name?: string | null;
    address?: string | null;
  }[],
) {

  return a

    .map(
      (x) =>
        x.display_name
          ? `${x.display_name} <${x.address || ""}>`
          : x.address || "",
    )

    .filter(Boolean)

    .join(", ");
}


function bytes(
  n: number,
) {

  return n < 1024

    ? `${n} B`

    : n < 1048576

      ? `${(
          n / 1024
        ).toFixed(1)} KB`

      : `${(
          n / 1048576
        ).toFixed(2)} MB`;
}