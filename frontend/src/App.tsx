import { useEffect, useState } from "react";

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
  ] = useState<any>(null);


  const [
    error,
    setError,
  ] = useState("");


  useEffect(() => {

    getHealth()

      .then(
        setHealth
      )

      .catch(
        () =>
          setError(
            "Unable to connect to the PhishingTrack backend."
          )
      );

  }, []);


  const backendConnected =
    health?.status === "ok";


  const databaseConnected =
    health?.database === "connected";


  return (

    <main className="app">

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
          PHASE 2
        </div>

      </nav>


      <section className="hero">

        <div>

          <p className="eyebrow">
            EMAIL SECURITY • FORENSICS •
            THREAT INTELLIGENCE
          </p>

          <h1>

            Follow the trail.

            <br />

            <span>
              Find the anomaly.
            </span>

          </h1>

          <p className="desc">

            Phase 2 performs forensic
            analysis of email headers,
            including Received chains,
            SPF, DKIM, DMARC, sender
            identity correlation and
            routing anomalies.

          </p>

        </div>


        <div className="status">

          <h3>

            <Activity
              size={18}
            />

            System Status

          </h3>


          <Status
            icon={
              <Server size={17}/>
            }
            label="FastAPI Backend"
            value={
              backendConnected
                ? "Connected"
                : "Offline"
            }
            good={
              backendConnected
            }
          />


          <Status
            icon={
              <Database size={17}/>
            }
            label="MongoDB"
            value={
              databaseConnected
                ? "Connected"
                : "Offline"
            }
            good={
              databaseConnected
            }
          />

        </div>

      </section>


      {error && (

        <div className="error">
          {error}
        </div>

      )}


      <EmailAnalyzer />


      <footer>

        <span>
          PhishingTrack v0.3.0
        </span>

        <span>
          Phase 2 — Header Forensics
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