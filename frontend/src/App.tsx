import {
  useEffect,
  useState,
} from "react";

import {
  Activity,
  Database,
  Server,
  ShieldCheck,
} from "lucide-react";

import EmailAnalyzer from "./components/EmailAnalyzer";

import {
  getHealth,
} from "./services/api";


export default function App() {

  const [
    health,
    setHealth,
  ] = useState<any>(
    null,
  );

  const [
    error,
    setError,
  ] = useState("");


  useEffect(() => {

    getHealth()

      .then(
        setHealth,
      )

      .catch(
        () =>
          setError(
            "Unable to connect to the PhishingTrack backend.",
          ),
      );

  }, []);


  const ok =
    health?.status === "ok";

  const db =
    health?.database ===
    "connected";


  return (

    <main className="app">

      {/* ==================================================
          NAV
      ================================================== */}

      <nav>

        <div className="brand">

          <div className="logo">

            <ShieldCheck
              size={22}
            />

          </div>

          <div>

            <b>
              PhishingTrack
            </b>

            <span>
              Threat Intelligence Platform
            </span>

          </div>

        </div>


        <div className="badge">
          PHASE 4
        </div>

      </nav>


      {/* ==================================================
          HERO
      ================================================== */}

      <section className="hero">

        <div>

          <p className="eyebrow">
            EMAIL SECURITY • FORENSICS • INTELLIGENCE
          </p>

          <h1>

            Ingest the evidence.

            <br />

            <span>
              Build the investigation.
            </span>

          </h1>

          <p className="desc">

            Phase 3 enriches the
            infrastructure discovered
            in Phase 2 with passive
            IP geolocation, ASN,
            reverse DNS, abuse reputation
            and sender-domain DNS intelligence.

          </p>

        </div>


        <div className="status">

          <h3>

            <Activity size={18} />

            System Status

          </h3>


          <Status
            icon={
              <Server size={17} />
            }
            label="FastAPI Backend"
            value={
              ok
                ? "Connected"
                : "Offline"
            }
            good={ok}
          />


          <Status
            icon={
              <Database size={17} />
            }
            label="MongoDB"
            value={
              db
                ? "Connected"
                : "Offline"
            }
            good={db}
          />

        </div>

      </section>


      {/* ERROR */}

      {
        error && (
          <div className="error">
            {error}
          </div>
        )
      }


      {/* ANALYZER */}

      <EmailAnalyzer />


      {/* FOOTER */}

      <footer>

        <span>
          PhishingTrack v0.5.0
        </span>

        <span>
          Phase 4 — URL & Domain Intelligence
        </span>

      </footer>

    </main>
  );
}

function Status({
  icon,
  label,
  value,
  good,
}: {
  icon: React.ReactNode;

  label: string;

  value: string;

  good: boolean;
}) {

  return (

    <div className="status-row">

      <span>

        {icon}

        {label}

      </span>


      <b
        className={
          good
            ? "good"
            : "bad"
        }
      >

        <i />

        {value}

      </b>

    </div>
  );
}