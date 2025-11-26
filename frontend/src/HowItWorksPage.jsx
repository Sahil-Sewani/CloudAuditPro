// frontend/src/HowItWorksPage.jsx
import React from "react";
import GlowDot from "./GlowDot";

const APP_VERSION = import.meta.env.VITE_APP_VERSION || "v0.1.0";

export default function HowItWorksPage() {
  const path = window.location.pathname;

  const navLinkBase =
    "text-[11px] md:text-xs px-2 py-1 rounded-full border border-transparent hover:border-indigo-400/60 hover:bg-indigo-900/40 transition";
  const activeNav =
    "border-emerald-400/70 bg-emerald-500/10 text-emerald-200";
  const inactiveNav = "text-indigo-200/80";

  const steps = [
    {
      id: 1,
      title: "Connect your AWS account",
      blurb:
        "Deploy the read-only IAM role (CloudAuditProReadRole) using the provided CloudFormation template.",
      detail:
        "You control which account and environment are connected. The app stores the account ID, role name, and region you provide.",
    },
    {
      id: 2,
      title: "Run core security checks",
      blurb:
        "From the dashboard, trigger checks against Security Hub, S3, CloudTrail, Config, EBS, and IAM.",
      detail:
        "Each check pulls posture metadata only — like whether CloudTrail is multi-region, which buckets are public, or whether EBS encryption is on by default.",
    },
    {
      id: 3,
      title: "Calculate your compliance score",
      blurb:
        "The Compliance Score summarizes your core controls into a single 0–100 number.",
      detail:
        "Instead of drowning you in findings, CloudAuditPro focuses on a curated list of high-signal controls and shows pass/fail status for each.",
    },
    {
      id: 4,
      title: "Read fix guidance and cost notes",
      blurb:
        "For failing controls, the app generates written remediation guidance with links to the AWS console and docs.",
      detail:
        "You see which page in the AWS console to visit, which setting to change, and how that might impact your AWS bill.",
    },
    {
      id: 5,
      title: "Share outcomes with stakeholders",
      blurb:
        "Optionally email yourself a report via SES with the key posture details and scores.",
      detail:
        "Use this in review meetings, audit prep, or to build an internal backlog of hardening tasks for your infra/security team.",
    },
  ];

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100">
      {/* Top bar */}
      <header className="w-full border-b border-indigo-900/60 px-6 py-3 flex items-center justify-between bg-black/40 backdrop-blur">
        <div className="flex items-center gap-3">
          <GlowDot size={16} />
          <div className="flex items-center gap-2">
            <span className="text-lg md:text-xl font-bold tracking-tight text-indigo-300">
              CloudAuditPro
            </span>
            <span className="text-[10px] md:text-xs text-indigo-200/80 border border-indigo-500/40 rounded-full px-2 py-0.5">
              v{APP_VERSION}
            </span>
            <span className="hidden md:inline text-xs text-indigo-200/70">
              • From AWS noise to executive-ready signals
            </span>
          </div>
        </div>

        <nav className="flex items-center gap-2">
          <a
            href="/"
            className={`${navLinkBase} ${
              path === "/" || path.startsWith("/about")
                ? activeNav
                : inactiveNav
            }`}
          >
            About
          </a>
          <a
            href="/security"
            className={`${navLinkBase} ${
              path.startsWith("/security") ? activeNav : inactiveNav
            }`}
          >
            Security
          </a>
          <a
            href="/how-it-works"
            className={`${navLinkBase} ${
              path.startsWith("/how-it-works") ? activeNav : inactiveNav
            }`}
          >
            How it works
          </a>
          <a
            href="/app"
            className="ml-2 text-[11px] md:text-xs px-3 py-1.5 rounded-xl bg-indigo-500/90 hover:bg-indigo-400 text-white font-medium shadow-lg shadow-indigo-900/70"
          >
            Open app
          </a>
        </nav>
      </header>

      <main className="flex-1 px-4 md:px-10 lg:px-16 py-8">
        <div className="max-w-6xl mx-auto space-y-8">
          {/* Hero */}
          <section className="grid lg:grid-cols-[1.3fr,1fr] gap-8 items-start">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-indigo-500/60 bg-indigo-950/60 px-3 py-1 text-[11px] text-indigo-100 mb-4">
                <GlowDot size={14} />
                <span>Opinionated workflow for AWS security reviews.</span>
              </div>

              <h1 className="text-2xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-indigo-50 mb-4">
                From role deployment to{" "}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-300 via-sky-300 to-indigo-300">
                  audit-ready summary
                </span>{" "}
                in a few clicks.
              </h1>

              <p className="text-sm md:text-base text-indigo-100/80 max-w-2xl mb-6">
                CloudAuditPro is a guided flow: connect a role, run curated
                checks, read the story behind your score, and walk away with a
                concrete improvement plan you can explain to leadership and
                auditors.
              </p>

              <div className="grid sm:grid-cols-2 gap-4 mb-4">
                <StepHighlight
                  label="No YAML, no agents"
                  body="Everything is driven from the dashboard. No sidecars, daemons, or agents to deploy."
                />
                <StepHighlight
                  label="Fast time-to-value"
                  body="You can usually get a first score and S3 posture summary in under 10 minutes."
                />
              </div>
            </div>

            {/* “Timeline” card */}
            <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-5 shadow-xl shadow-indigo-950/70">
              <h2 className="text-sm font-semibold text-indigo-200 mb-3">
                High-level flow
              </h2>
              <ol className="space-y-3 text-xs text-gray-300">
                <li>
                  <span className="font-mono text-[10px] text-indigo-300 mr-2">
                    01
                  </span>
                  Deploy the read-only role in the target AWS account.
                </li>
                <li>
                  <span className="font-mono text-[10px] text-indigo-300 mr-2">
                    02
                  </span>
                  Enter account ID, role name, and region in the dashboard.
                </li>
                <li>
                  <span className="font-mono text-[10px] text-indigo-300 mr-2">
                    03
                  </span>
                  Run individual checks (S3, CloudTrail, Config, EBS, IAM) or a
                  full compliance score.
                </li>
                <li>
                  <span className="font-mono text-[10px] text-indigo-300 mr-2">
                    04
                  </span>
                  Review pass/fail status and fix guidance in one pane.
                </li>
                <li>
                  <span className="font-mono text-[10px] text-indigo-300 mr-2">
                    05
                  </span>
                  Email a report or export the score to bring into reviews.
                </li>
              </ol>
              <p className="mt-3 text-[11px] text-gray-500">
                As the product evolves, this page can link to deeper docs and
                example walkthroughs for different team sizes and industries.
              </p>
            </div>
          </section>

          {/* Detailed step cards */}
          <section className="grid md:grid-cols-2 gap-5">
            {steps.map((step) => (
              <div
                key={step.id}
                className="bg-black/40 border border-slate-800 rounded-2xl p-4 flex gap-3"
              >
                <div className="mt-1">
                  <div className="flex items-center justify-center h-7 w-7 rounded-full bg-indigo-900/70 border border-indigo-500/70">
                    <span className="font-mono text-[11px] text-indigo-100">
                      {String(step.id).padStart(2, "0")}
                    </span>
                  </div>
                </div>
                <div>
                  <h3 className="text-xs font-semibold text-indigo-100 mb-1">
                    {step.title}
                  </h3>
                  <p className="text-[11px] text-gray-300 mb-1">
                    {step.blurb}
                  </p>
                  <p className="text-[11px] text-gray-500">{step.detail}</p>
                </div>
              </div>
            ))}
          </section>

          <footer className="border-t border-slate-800 pt-4 text-[11px] text-gray-500 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <span className="font-mono text-indigo-200">
              CloudAuditPro • Version {APP_VERSION}
            </span>
            <span>
              Next steps could include video walkthroughs, sample reports, or a
              sandbox mode linked from this page.
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function StepHighlight({ label, body }) {
  return (
    <div className="bg-black/50 border border-indigo-900/60 rounded-xl px-4 py-3 shadow-md shadow-indigo-950/60">
      <div className="text-[11px] font-semibold text-indigo-100 mb-1">
        {label}
      </div>
      <div className="text-[11px] text-gray-400">{body}</div>
    </div>
  );
}
