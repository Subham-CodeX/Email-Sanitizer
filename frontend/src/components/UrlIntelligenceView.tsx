import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Globe2,
  Lock,
  Network,
  Search,
  ShieldAlert,
  ShieldCheck,
  Tag,
} from "lucide-react";

import {
  URLIntelligence,
  URLIntelligenceResult,
} from "../services/api";

import "../url-intelligence.css";

export default function UrlIntelligenceView({
  data,
}: {
  data: URLIntelligenceResult;
}) {

  return (

    <section className="url-intel-shell">

        {/* HEADER */}

      <div className="url-intel-header">

        <div>

          <p className="url-eyebrow">
            PHASE 4 • URL & DOMAIN INTELLIGENCE
          </p>

          <h3>
            URL threat intelligence
          </h3>

          <p>
            Passive analysis of URLs extracted
            from the email. PhishingTrack does
            not open, crawl, follow or download
            from these URLs.
          </p>

        </div>

        <Network size={25} />

      </div>

        {/* SUMMARY */}

      <div className="url-summary">

        <SummaryMetric
          label="URLs"
          value={
            data.summary.total_urls
          }
          icon={
            <Globe2 size={17} />
          }
        />

        <SummaryMetric
          label="Domains"
          value={
            data.summary.unique_domains
          }
          icon={
            <Network size={17} />
          }
        />

        <SummaryMetric
          label="Known Malicious"
          value={
            data.summary.malicious_urls
          }
          icon={
            <ShieldAlert size={17} />
          }
        />

        <SummaryMetric
          label="Suspicious"
          value={
            data.summary.suspicious_urls
          }
          icon={
            <AlertTriangle size={17} />
          }
        />

        <SummaryMetric
          label="Shorteners"
          value={
            data.summary.shortener_urls
          }
          icon={
            <ExternalLink size={17} />
          }
        />

        <SummaryMetric
          label="Punycode"
          value={
            data.summary.punycode_urls
          }
          icon={
            <Tag size={17} />
          }
        />

      </div>

        {/* HIGH RISK */}

      {
        data.summary.high_risk_urls.length > 0 && (

          <div className="url-danger-banner">

            <ShieldAlert size={18} />

            <div>

              <b>
                High-risk URL indicators detected
              </b>

              <span>
                {
                  data.summary.high_risk_urls.length
                }
                {" "}
                URL(s) require investigation.
              </span>

            </div>

          </div>

        )
      }

        {/* URL CARDS */}

      <div className="url-section">

        <div className="url-section-title">

          <h4>
            <Search size={16} />
            URL indicators
          </h4>

          <small>
            {
              data.urls.length
            }
          </small>

        </div>


        <div className="url-list">

          {
            data.urls.map(
              (item) => (

                <URLCard
                  key={
                    item.url_id
                  }
                  item={
                    item
                  }
                />

              ),
            )
          }

        </div>

      </div>

        {/* DOMAIN SUMMARY */}


      <div className="url-section">

        <div className="url-section-title">

          <h4>
            <Globe2 size={16} />
            Domain intelligence
          </h4>

          <small>
            {
              data.domains.length
            }
          </small>

        </div>


        <div className="domain-intel-grid">

          {
            data.domains.map(
              (domain) => (

                <div
                  className="domain-intel-card"
                  key={
                    domain.domain
                  }
                >

                  <code>
                    {
                      domain.domain
                    }
                  </code>

                  <div className="domain-stats">

                    <Stat
                      label="URLs"
                      value={
                        String(
                          domain.url_count,
                        )
                      }
                    />

                    <Stat
                      label="Age"
                      value={
                        domain.registration_age_days
                        != null
                          ? `${domain.registration_age_days}d`
                          : "unknown"
                      }
                    />

                    <Stat
                      label="MX"
                      value={
                        boolLabel(
                          domain.has_mx,
                        )
                      }
                    />

                    <Stat
                      label="SPF"
                      value={
                        boolLabel(
                          domain.has_spf,
                        )
                      }
                    />

                    <Stat
                      label="DMARC"
                      value={
                        boolLabel(
                          domain.has_dmarc,
                        )
                      }
                    />

                  </div>

                </div>

              ),
            )
          }

        </div>

      </div>

        {/* PROVIDER NOTES */}

      <div className="url-provider-notes">

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

    </section>
  );
}

function URLCard({
  item,
}: {
  item: URLIntelligence;
}) {

  const level =
    item.level;


  const score =
    item.score;


  return (

    <article className="url-card">

        {/* TOP */}

      <div className="url-card-top">

        <div className="url-main">

          <div className="url-icon">

            {
              item.structure.is_https

                ? (
                  <Lock size={17} />
                )

                : (
                  <Globe2 size={17} />
                )
            }

          </div>


          <div>

            <code className="url-original">
              {
                item.original_url
              }
            </code>

            {
              item.structure
                .registrable_domain && (

                <span className="url-domain">

                  {
                    item.structure
                      .registrable_domain
                  }

                </span>

              )
            }

          </div>

        </div>


        <div className="url-score">

          <strong
            className={
              `url-score-number ${level}`
            }
          >
            {
              score == null
                ? "—"
                : score
            }
          </strong>

          <span
            className={
              `url-level ${level}`
            }
          >
            {
              level
                .toUpperCase()
            }
          </span>

        </div>

      </div>

        {/* SIGNALS */}

      <div className="url-signal-row">

        <Signal
          label={
            item.structure.is_https
              ? "HTTPS"
              : "HTTP"
          }
          good={
            item.structure.is_https
          }
        />

        {
          item.structure.is_shortener && (

            <Signal
              label="SHORTENER"
              warning
            />

          )
        }

        {
          item.structure.is_punycode && (

            <Signal
              label="PUNYCODE"
              warning
            />

          )
        }

        {
          item.structure.is_ip_host && (

            <Signal
              label="IP HOST"
              warning
            />

          )
        }

        {
          item.structure
            .is_non_standard_port && (

            <Signal
              label="CUSTOM PORT"
              warning
            />

          )
        }

        {
          item.structure
            .username_present && (

            <Signal
              label="USERINFO"
              warning
            />

          )
        }

      </div>

        {/* REPUTATION */}

      {
        item.reputation.length > 0 && (

          <div className="reputation-box">

            {
              item.reputation.map(
                (rep) => (

                  <div
                    className="reputation-row"
                    key={
                      rep.provider
                    }
                  >

                    {
                      rep.malicious

                        ? (
                          <ShieldAlert
                            size={16}
                          />
                        )

                        : (
                          <ShieldCheck
                            size={16}
                          />
                        )
                    }

                    <div>

                      <b>
                        {
                          rep.provider
                        }
                      </b>

                      <span>

                        {
                          rep.malicious
                            ? (
                              `Threat match: ${
                                rep.threat_types.join(
                                  ", ",
                                )
                              }`
                            )
                            : rep.checked
                              ? "No listed threat match"
                              : (
                                rep.error
                                || "Not checked"
                              )
                        }

                      </span>

                    </div>

                  </div>

                ),
              )
            }

          </div>

        )
      }

        {/* STRUCTURE */}

      <div className="url-detail-grid">

        <Detail
          label="Scheme"
          value={
            item.structure.scheme
          }
        />

        <Detail
          label="Hostname"
          value={
            item.structure.hostname
          }
        />

        <Detail
          label="Port"
          value={
            item.structure.port
              ? String(
                  item.structure.port,
                )
              : "default"
          }
        />

        <Detail
          label="Domain"
          value={
            item.structure
              .registrable_domain
          }
        />

        <Detail
          label="Path"
          value={
            item.structure.path
          }
        />

        <Detail
          label="Query"
          value={
            item.structure.query
          }
        />

      </div>

        {/* DNS */}

      {
        item.dns && (

          <div className="url-subsection">

            <h5>
              DNS intelligence
            </h5>

            <div className="dns-flags">

              <Flag
                label="A"
                value={
                  item.dns.has_a
                }
              />

              <Flag
                label="AAAA"
                value={
                  item.dns.has_aaaa
                }
              />

              <Flag
                label="MX"
                value={
                  item.dns.has_mx
                }
              />

              <Flag
                label="SPF"
                value={
                  item.dns.has_spf
                }
              />

              <Flag
                label="DMARC"
                value={
                  item.dns.has_dmarc
                }
              />

            </div>

            {
              item.dns.a_records.length > 0 && (

                <Record
                  label="A"
                  values={
                    item.dns.a_records
                  }
                />

              )
            }

            {
              item.dns.mx_records.length > 0 && (

                <Record
                  label="MX"
                  values={
                    item.dns.mx_records
                  }
                />

              )
            }

          </div>

        )
      }


        {/* REGISTRATION */}

      {
        item.registration && (

          <div className="url-subsection">

            <h5>
              Registration intelligence
            </h5>

            <div className="registration-grid">

              <Detail
                label="Registrar"
                value={
                  item.registration
                    .registrar_name
                }
              />

              <Detail
                label="Registration age"
                value={
                  item.registration
                    .registration_age_days
                    != null
                    ? `${item.registration.registration_age_days} days`
                    : null
                }
              />

              <Detail
                label="Registered"
                value={
                  item.registration
                    .registration_date
                }
              />

              <Detail
                label="Expires"
                value={
                  item.registration
                    .expiration_date
                }
              />

            </div>

          </div>

        )
      }

        {/* FINDINGS */}

      {
        item.findings.length > 0 && (

          <div className="url-findings">

            <h5>
              Investigation findings
            </h5>

            {
              item.findings.map(
                (
                  finding,
                  index,
                ) => (

                  <div
                    className={
                      `url-finding ${finding.severity}`
                    }
                    key={
                      `${finding.code}-${index}`
                    }
                  >

                    <div>

                      <b>
                        {
                          finding.title
                        }
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
            }

          </div>

        )
      }

    </article>
  );
}


function SummaryMetric({
  label,
  value,
  icon,
}: {
  label: string;

  value: number;

  icon: React.ReactNode;
}) {

  return (

    <div className="url-summary-metric">

      <span>
        {icon}
        {label}
      </span>

      <strong>
        {value}
      </strong>

    </div>
  );
}

function Signal({
  label,
  good,
  warning,
}: {
  label: string;

  good?: boolean;

  warning?: boolean;
}) {

  return (

    <span
      className={
        `url-signal ${
          good
            ? "good"
            : ""
        } ${
          warning
            ? "warning"
            : ""
        }`
      }
    >
      {label}
    </span>
  );
}

function Flag({
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
          ? "dns-flag yes"
          : "dns-flag no"
      }
    >
      {label}
    </span>
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

    <div className="url-detail">

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

function Record({
  label,
  values,
}: {
  label: string;

  values: string[];
}) {

  return (

    <div className="url-record">

      <small>
        {label}
      </small>

      {
        values.map(
          (value) => (

            <code
              key={value}
            >
              {value}
            </code>

          ),
        )
      }

    </div>
  );
}

function Stat({
  label,
  value,
}: {
  label: string;

  value: string;
}) {

  return (

    <div>

      <small>
        {label}
      </small>

      <b>
        {value}
      </b>

    </div>
  );
}

function boolLabel(
  value?: boolean | null,
) {

  if (value == null)
    return "—";

  return value
    ? "YES"
    : "NO";
}