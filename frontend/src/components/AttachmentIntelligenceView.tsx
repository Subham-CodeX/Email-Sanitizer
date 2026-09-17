import {
  AlertTriangle,
  Archive,
  FileWarning,
  Fingerprint,
  FileSearch,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import "../attachment-intelligence.css";

import type {
  AttachmentIntelligenceResult,
  AttachmentNode,
} from "../services/api";


interface Props {
  data: AttachmentIntelligenceResult;
}

function bytes(
  value: number,
) {

  if (value < 1024)
    return `${value} B`;

  if (value < 1024 * 1024)
    return `${(
      value / 1024
    ).toFixed(1)} KB`;

  return `${(
    value /
    (1024 * 1024)
  ).toFixed(2)} MB`;
}


function severityClass(
  severity: string,
) {

  return (
    `attachment-severity attachment-${severity}`
  );
}

function NodeView({
  node,
  depth = 0,
}: {
  node: AttachmentNode;
  depth?: number;
}) {

  return (
    <div
      className="attachment-node"
      style={{
        marginLeft:
          depth * 18,
      }}
    >

      <div className="attachment-node-head">

        <div>

          <strong>
            {node.name}
          </strong>

          <small>
            {node.path}
          </small>

        </div>

        <span
          className={`attachment-risk ${node.level}`}
        >
          {node.level.toUpperCase()}
        </span>

      </div>


      <div className="attachment-grid">

        <div className="attachment-stat">

          <span>Size</span>

          <strong>
            {bytes(
              node.size_bytes
            )}
          </strong>

        </div>


        <div className="attachment-stat">

          <span>Magic</span>

          <strong>
            {
              node.magic
                .detected_type
            }
          </strong>

        </div>


        <div className="attachment-stat">

          <span>Entropy</span>

          <strong>
            {
              node.entropy.entropy.toFixed(
                3
              )
            }
          </strong>

        </div>


        <div className="attachment-stat">

          <span>Score</span>

          <strong>
            {node.score}
          </strong>

        </div>

      </div>


      <div className="attachment-section">

        <h4>
          <Fingerprint size={15} />

          Hashes
        </h4>

        <code>
          SHA-256: {node.hashes.sha256}
        </code>

        <code>
          SHA-1: {node.hashes.sha1}
        </code>

        <code>
          MD5: {node.hashes.md5}
        </code>

      </div>


      <div className="attachment-section">

        <h4>
          <FileSearch size={15} />

          File Identity
        </h4>

        <div className="attachment-kv">

          <span>
            Declared MIME
          </span>

          <b>
            {
              node.mime_consistency
                .declared_mime
              || "Unknown"
            }
          </b>


          <span>
            Detected MIME
          </span>

          <b>
            {
              node.mime_consistency
                .detected_mime
              || "Unknown"
            }
          </b>


          <span>
            Extension
          </span>

          <b>
            {
              node.mime_consistency
                .extension
              || "None"
            }
          </b>

        </div>

      </div>


      {
        node.mime_consistency
          .suspicious_mismatch
        && (
          <div className="attachment-alert">

            <AlertTriangle size={16} />

            MIME / magic-byte mismatch detected.

          </div>
        )
      }


      {
        node.filename_analysis
          .suspicious
        && (
          <div className="attachment-alert">

            <FileWarning size={16} />

            Suspicious filename pattern detected.

          </div>
        )
      }


      {
        node.office
          .has_vba_macro
        && (
          <div className="attachment-alert">

            <ShieldAlert size={16} />

            VBA macro content detected.

          </div>
        )
      }


      {
        node.pdf
          .javascript
        && (
          <div className="attachment-alert">

            <ShieldAlert size={16} />

            PDF JavaScript detected.

          </div>
        )
      }


      {
        node.reputation
        && (
          <div className="attachment-section">

            <h4>
              <ShieldCheck size={15} />

              Malware Reputation
            </h4>

            {
              node.reputation
                .known_sample
              ? (
                <div className="reputation-hit">

                  <strong>
                    Known sample
                  </strong>

                  {
                    node.reputation
                      .signature
                    && (
                      <span>
                        {
                          node.reputation
                            .signature
                        }
                      </span>
                    )
                  }

                </div>
              )
              : (
                <span className="reputation-clean">
                  No MalwareBazaar hash match
                </span>
              )
            }

            {
              node.reputation
                .error
              && (
                <small>
                  {
                    node.reputation
                      .error
                  }
                </small>
              )
            }

          </div>
        )
      }


      {
        node.findings.length > 0
        && (
          <div className="attachment-section">

            <h4>
              <AlertTriangle size={15} />

              Findings
            </h4>

            <div className="attachment-findings">

              {
                node.findings.map(
                  (
                    finding,
                    index,
                  ) => (
                    <div
                      className={
                        severityClass(
                          finding.severity
                        )
                      }
                      key={`${finding.code}-${index}`}
                    >

                      <strong>
                        {finding.title}
                      </strong>

                      <span>
                        {
                          finding.description
                        }
                      </span>

                    </div>
                  )
                )
              }

            </div>

          </div>
        )
      }


      {
        node.archive_entries.length > 0
        && (
          <div className="attachment-section">

            <h4>
              <Archive size={15} />

              Archive Contents
            </h4>

            <div className="archive-list">

              {
                node.archive_entries.map(
                  (
                    entry,
                    index,
                  ) => (
                    <div
                      className="archive-entry"
                      key={`${entry.name}-${index}`}
                    >

                      <div>

                        <strong>
                          {entry.name}
                        </strong>

                        <small>
                          {bytes(
                            entry.size_bytes
                          )}

                          {" • "}

                          {
                            entry.detected_type
                            || "unknown"
                          }
                        </small>

                      </div>

                      {
                        entry.suspicious
                        && (
                          <span>
                            suspicious
                          </span>
                        )
                      }

                    </div>
                  )
                )
              }

            </div>

          </div>
        )
      }


      {
        node.nested.length > 0
        && (
          <div className="nested-attachments">

            <h4>
              Nested files
            </h4>

            {
              node.nested.map(
                (
                  child,
                  index,
                ) => (
                  <NodeView
                    key={`${child.path}-${index}`}
                    node={child}
                    depth={depth + 1}
                  />
                )
              )
            }

          </div>
        )
      }

    </div>
  );
}

export default function AttachmentIntelligenceView({
  data,
}: Props) {

  const summary =
    data.summary;

  return (
    <section className="attachment-intelligence">

      <div className="attachment-header">

        <div>

          <p className="attachment-eyebrow">
            PHASE 5 • MALWARE FORENSICS
          </p>

          <h2>
            Attachment Threat Intelligence
          </h2>

          <p>
            Static attachment analysis,
            file identity validation,
            archive inspection and
            hash-based malware intelligence.
          </p>

        </div>

        <ShieldAlert size={30} />

      </div>


      <div className="attachment-safety">

        <ShieldCheck size={18} />

        <span>
          Attachments are analyzed
          statically. PhishingTrack never
          executes attachments, Office macros
          or embedded code.
        </span>

      </div>


      <div className="attachment-summary">

        <div>
          <span>
            Attachments
          </span>

          <strong>
            {summary.total_attachments}
          </strong>
        </div>


        <div>
          <span>
            Nested
          </span>

          <strong>
            {summary.nested_files}
          </strong>
        </div>


        <div>
          <span>
            Executables
          </span>

          <strong>
            {summary.executable_files}
          </strong>
        </div>


        <div>
          <span>
            Macros
          </span>

          <strong>
            {summary.macro_files}
          </strong>
        </div>


        <div>
          <span>
            MIME mismatches
          </span>

          <strong>
            {summary.mime_mismatches}
          </strong>
        </div>


        <div>
          <span>
            Reputation matches
          </span>

          <strong>
            {summary.reputation_matches}
          </strong>
        </div>

      </div>


      {
        summary.high_risk_attachments > 0
        && (
          <div className="attachment-high-risk">

            <AlertTriangle size={19} />

            <div>

              <strong>
                High-risk attachment indicators detected
              </strong>

              <span>
                {
                  summary.high_risk_attachments
                }
                {" "}
                attachment objects require
                investigation.
              </span>

            </div>

          </div>
        )
      }


      <div className="attachment-list">

        {
          data.attachments.map(
            (
              attachment,
              index,
            ) => (
              <NodeView
                key={`${attachment.path}-${index}`}
                node={attachment}
              />
            )
          )
        }

      </div>


      <div className="attachment-provider-notes">

        <h3>
          Analysis notes
        </h3>

        {
          data.provider_notes.map(
            (
              note,
              index,
            ) => (
              <p key={index}>
                • {note}
              </p>
            )
          )
        }

      </div>

    </section>
  );
}