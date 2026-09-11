import { ChangeEvent, useRef, useState } from "react";

import {
  AlertTriangle,
  CheckCircle2,
  FileText,
  Link2,
  Mail,
  Paperclip,
  ShieldCheck,
  Upload,
} from "lucide-react";

import {
  ingestEml,
  ingestRaw,
  Result,
} from "../services/api";

export default function EmailAnalyzer() {
  const [mode, setMode] = useState<"upload" | "raw">("upload");
  const [file, setFile] = useState<File | null>(null);
  const [raw, setRaw] = useState("");
  const [result, setResult] = useState<Result | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const ref = useRef<HTMLInputElement>(null);

  /* -----------------------------------------
     File Selection
  ----------------------------------------- */

  const choose = (e: ChangeEvent<HTMLInputElement>) => {
    setFile(e.target.files?.[0] ?? null);
    setResult(null);
    setError("");
  };

  /* -----------------------------------------
     Email Submission
  ----------------------------------------- */

  const submit = async () => {
    setError("");
    setResult(null);
    setLoading(true);

    try {
      if (mode === "upload") {
        if (!file) {
          throw new Error("Select an .eml file first.");
        }

        setResult(await ingestEml(file));
      } else {
        if (!raw.trim()) {
          throw new Error("Paste a raw email first.");
        }

        setResult(await ingestRaw(raw));
      }
    } catch (e: any) {
      setError(
        e?.response?.data?.detail ||
          e?.message ||
          "Email ingestion failed."
      );
    } finally {
      setLoading(false);
    }
  };

  /* -----------------------------------------
     Render
  ----------------------------------------- */

  return (
    <section className="analyzer">

      {/* Section Header */}
      <div className="section-head">
        <div>
          <p className="eyebrow">
            PHASE 1 • EMAIL INGESTION
          </p>

          <h2>Analyze email evidence</h2>

          <p>
            Parse headers, body, MIME parts, attachments and
            URLs. Every sample receives a SHA-256 evidence
            fingerprint.
          </p>
        </div>

        <ShieldCheck size={30} />
      </div>

      {/* Input Mode Tabs */}
      <div className="tabs">
        <button
          className={mode === "upload" ? "active" : ""}
          onClick={() => setMode("upload")}
        >
          <Upload size={16} />
          Upload .eml
        </button>

        <button
          className={mode === "raw" ? "active" : ""}
          onClick={() => setMode("raw")}
        >
          <FileText size={16} />
          Raw Email
        </button>
      </div>

      {/* Email Input */}
      {mode === "upload" ? (
        <div
          className="drop"
          onClick={() => ref.current?.click()}
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
            {file
              ? file.name
              : "Choose an .eml evidence file"}
          </strong>

          <span>
            Maximum 15 MB • attachments are never executed
          </span>
        </div>
      ) : (
        <textarea
          className="raw"
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
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

      {/* Submit Button */}
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

      {/* Error */}
      {error && (
        <div className="error">
          <AlertTriangle size={17} />
          {error}
        </div>
      )}

      {/* Result */}
      {result && <ResultView result={result} />}
    </section>
  );
}

/* =========================================
   RESULT VIEW
========================================= */

function ResultView({ result }: { result: Result }) {
  return (
    <div className="result">

      {/* Success */}
      <div className="success">
        <CheckCircle2 size={19} />

        Evidence ingested

        <span>{result.evidence_id}</span>
      </div>

      {/* SHA-256 Evidence Hash */}
      <div className="hash">
        <small>
          SHA-256 EVIDENCE FINGERPRINT
        </small>

        <code>{result.evidence_sha256}</code>
      </div>

      {/* Metadata Grid */}
      <div className="grid">
        <Item
          label="Subject"
          value={result.metadata.subject || "—"}
        />

        <Item
          label="From"
          value={addresses(result.metadata.from) || "—"}
        />

        <Item
          label="To"
          value={addresses(result.metadata.to) || "—"}
        />

        <Item
          label="Message-ID"
          value={result.metadata.message_id || "—"}
        />

        <Item
          label="MIME"
          value={result.metadata.mime_type || "—"}
        />

        <Item
          label="Size"
          value={bytes(result.metadata.size_bytes)}
        />
      </div>

      {/* Attachments + URLs */}
      <div className="two">

        {/* Attachments */}
        <Panel
          title={`Attachments (${result.attachments.length})`}
          icon={<Paperclip size={17} />}
        >
          {result.attachments.length ? (
            result.attachments.map((a) => (
              <div
                className="row"
                key={a.sha256}
              >
                <div>
                  <b>{a.filename}</b>

                  <small>
                    {a.content_type || "unknown"} •{" "}
                    {bytes(a.size_bytes)}
                  </small>
                </div>

                <code>
                  {a.sha256.slice(0, 16)}…
                </code>
              </div>
            ))
          ) : (
            <p className="muted">
              No attachments detected.
            </p>
          )}
        </Panel>

        {/* URLs */}
        <Panel
          title={`URLs (${result.urls.length})`}
          icon={<Link2 size={17} />}
        >
          {result.urls.length ? (
            result.urls.map((u) => (
              <div
                className="url"
                key={u.url}
              >
                <b>{u.hostname}</b>

                <span>{u.url}</span>
              </div>
            ))
          ) : (
            <p className="muted">
              No URLs detected.
            </p>
          )}
        </Panel>
      </div>

      {/* Body Preview */}
      {result.body_preview && (
        <div className="body">
          <h3>Body Preview</h3>

          <p>{result.body_preview}</p>
        </div>
      )}
    </div>
  );
}

/* =========================================
   METADATA ITEM
========================================= */

function Item({
  label,
  value,
}: {
  label: string;
  value: string;
}) {
  return (
    <div className="item">
      <small>{label}</small>

      <span>{value}</span>
    </div>
  );
}

/* =========================================
   PANEL
========================================= */

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

/* =========================================
   ADDRESS FORMATTER
========================================= */

function addresses(
  a: {
    display_name?: string | null;
    address?: string | null;
  }[]
) {
  return a
    .map((x) =>
      x.display_name
        ? `${x.display_name} <${x.address || ""}>`
        : x.address || ""
    )
    .filter(Boolean)
    .join(", ");
}

/* =========================================
   BYTE FORMATTER
========================================= */

function bytes(n: number) {
  if (n < 1024) {
    return `${n} B`;
  }

  if (n < 1048576) {
    return `${(n / 1024).toFixed(1)} KB`;
  }

  return `${(n / 1048576).toFixed(2)} MB`;
}