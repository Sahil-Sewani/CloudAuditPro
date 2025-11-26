// frontend/src/SecurityPage.jsx
import React from "react";
import GlowDot from "./GlowDot";

const APP_VERSION = import.meta.env.VITE_APP_VERSION || "v0.1.0";

export default function SecurityPage() {
  const path = window.location.pathname;

  const navLinkBase =
    "text-[11px] md:text-xs px-2 py-1 rounded-full border border-transparent hover:border-indigo-400/60 hover:bg-indigo-900/40 transition";
  const activeNav =
    "border-emerald-400/70 bg-emerald-500/10 text-emerald-200";
  const inactiveNav = "text-indigo-200/80";

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
              • AWS Security &amp; Compliance Platform
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
          <section className="grid lg:grid-cols-[1.4fr,1fr] gap-8 items-start">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-emerald-400/60 bg-emerald-500/10 px-3 py-1 text-[11px] text-emerald-100 mb-4">
                <GlowDot size={14} />
                <span>Security-first, read-only by design.</span>
              </div>

              <h1 className="text-2xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-indigo-50 mb-4">
                Built like an internal{" "}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-300 via-sky-300 to-indigo-300">
                  security product
                </span>
                , not a side project.
              </h1>

              <p className="text-sm md:text-base text-indigo-100/80 max-w-2xl mb-6">
                CloudAuditPro follows a simple principle:{" "}
                <span className="font-semibold text-emerald-200">
                  visibility without surprise changes
                </span>
                . The platform assumes a tightly scoped read-only role in your
                AWS account and surfaces the controls most auditors and security
                teams care about first.
              </p>

              <div className="grid sm:grid-cols-3 gap-4 mb-6">
                <SecurityPill
                  title="Read-only IAM role"
                  body="No write or mutation APIs. Designed for assessment, not automation."
                />
                <SecurityPill
                  title="Single, scoped trust"
                  body="You control the role, trust policy, and which accounts are connected."
                />
                <SecurityPill
                  title="Transparent checks"
                  body="Every check is explainable and maps to visible AWS settings."
                />
              </div>

              <p className="text-[11px] md:text-xs text-gray-400">
                Note: CloudAuditPro is currently focused on AWS accounts where
                you fully control IAM and security baselines. Think of it as
                your opinionated cockpit for posture reviews and audit prep.
              </p>
            </div>

            {/* Right column: quick facts */}
            <div className="space-y-4">
              <div className="bg-black/40 border border-emerald-500/40 rounded-2xl p-5 shadow-lg shadow-emerald-900/50">
                <h2 className="text-sm font-semibold text-emerald-200 mb-2">
                  Trust &amp; access model
                </h2>
                <ul className="space-y-2 text-xs text-gray-200">
                  <li>
                    ▹ CloudAuditPro connects via a{" "}
                    <span className="font-mono text-[11px]">
                      CloudAuditProReadRole
                    </span>{" "}
                    in your AWS account.
                  </li>
                  <li>
                    ▹ The role is{" "}
                    <span className="font-semibold">
                      read-only and least privilege
                    </span>{" "}
                    for Security Hub, S3, CloudTrail, Config, EBS, and IAM
                    metadata.
                  </li>
                  <li>
                    ▹ You can delete or rotate the role at any time — you are in
                    full control.
                  </li>
                </ul>
              </div>

              <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-5">
                <h2 className="text-sm font-semibold text-indigo-200 mb-2">
                  Data handling expectations
                </h2>
                <ul className="space-y-1.5 text-xs text-gray-300">
                  <li>▹ Focus on configuration &amp; posture, not raw payloads.</li>
                  <li>▹ No customer data export from S3 objects or databases.</li>
                  <li>▹ Findings and scores are derived from AWS APIs you can audit.</li>
                </ul>
                <p className="mt-3 text-[11px] text-gray-500">
                  In future versions, this page can link to a full security
                  whitepaper, DPA terms, and external audit reports.
                </p>
              </div>
            </div>
          </section>

          {/* Grid of deeper security commitments */}
          <section className="grid md:grid-cols-3 gap-5">
            <CommitCard
              label="Principle of least privilege"
              text="Each AWS permission is deliberate. The recommended IAM template is kept small and focused on posture telemetry."
            />
            <CommitCard
              label="Environment isolation"
              text="Use separate roles per environment (dev, test, prod) so posture signals never bleed across accounts."
            />
            <CommitCard
              label="You own remediation"
              text="CloudAuditPro shows you what to fix and where. Actual change is executed in your AWS account under your control."
            />
          </section>

          <footer className="border-t border-slate-800 pt-4 text-[11px] text-gray-500 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
            <span className="font-mono text-indigo-200">
              CloudAuditPro • Version {APP_VERSION}
            </span>
            <span>
              Questions about security posture? This page can later link to a
              dedicated security contact or trust center.
            </span>
          </footer>
        </div>
      </main>
    </div>
  );
}

function SecurityPill({ title, body }) {
  return (
    <div className="bg-black/50 border border-indigo-900/60 rounded-xl px-4 py-3 shadow-md shadow-indigo-950/60">
      <div className="text-[11px] font-semibold text-indigo-100 mb-1">
        {title}
      </div>
      <div className="text-[11px] text-gray-400">{body}</div>
    </div>
  );
}

function CommitCard({ label, text }) {
  return (
    <div className="bg-black/40 border border-slate-800 rounded-2xl p-4">
      <div className="flex items-center gap-2 mb-2">
        <GlowDot size={10} />
        <h3 className="text-xs font-semibold text-indigo-100">{label}</h3>
      </div>
      <p className="text-[11px] text-gray-400">{text}</p>
    </div>
  );
}
