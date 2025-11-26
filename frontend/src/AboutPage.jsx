// frontend/src/AboutPage.jsx
import React, { useState, useEffect } from "react";
import GlowDot from "./GlowDot";

const APP_VERSION = import.meta.env.VITE_APP_VERSION || "v0.1.0";

const SLIDES = [
  {
    id: 1,
    title: "Unified AWS security cockpit",
    subtitle:
      "Bring Security Hub, S3, CloudTrail, Config, EBS, and IAM into one opinionated view.",
    badge: "Security posture at a glance",
  },
  {
    id: 2,
    title: "Audit-ready in minutes, not months",
    subtitle:
      "Give auditors and stakeholders a single source of truth for AWS controls and evidence.",
    badge: "Built for compliance teams",
  },
  {
    id: 3,
    title: "Designed for modern cloud teams",
    subtitle:
      "From solo builders to enterprise platforms, CloudAuditPro scales with your AWS footprint.",
    badge: "From lab to enterprise",
  },
];

export default function AboutPage() {
  const [activeIndex, setActiveIndex] = useState(0);

  // Simple auto-advance for the slider
  useEffect(() => {
    const interval = setInterval(() => {
      setActiveIndex((prev) => (prev + 1) % SLIDES.length);
    }, 6000);
    return () => clearInterval(interval);
  }, []);

  const activeSlide = SLIDES[activeIndex];

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100">
      {/* Top bar */}
      <header className="w-full border-b border-indigo-900/60 px-6 py-3 flex items-center justify-between bg-black/40 backdrop-blur">
        <div className="flex items-center gap-3">
          <GlowDot size={14} />
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

        <div className="flex items-center gap-4 text-xs md:text-sm">
          {/* Simple marketing nav */}
          <nav className="hidden sm:flex items-center gap-4">
            <a
              href="/"
              className="text-indigo-100 hover:text-white underline-offset-4 hover:underline"
            >
              About
            </a>
            <a
              href="/security"
              className="text-indigo-200 hover:text-white underline-offset-4 hover:underline"
            >
              Security
            </a>
            <a
              href="/how-it-works"
              className="text-indigo-200 hover:text-white underline-offset-4 hover:underline"
            >
              How it works
            </a>
          </nav>

          <button
            onClick={() => {
              window.location.href = "/app";
            }}
            className="px-3 py-1.5 rounded-xl bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-400/60 text-xs md:text-sm text-indigo-100 font-medium"
          >
            Sign in / Sign up
          </button>
        </div>
      </header>

      <main className="flex-1 flex flex-col px-4 md:px-10 lg:px-16 py-8 gap-10">
        {/* HERO + SLIDER */}
        <section className="grid lg:grid-cols-[1.4fr,1fr] gap-8 items-center">
          {/* Left: Hero copy */}
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-indigo-500/50 bg-indigo-950/60 px-3 py-1 text-[11px] text-indigo-100 mb-4">
              <GlowDot size={14} />
              <span>Trusted AWS security intelligence, in one pane.</span>
            </div>

            <h1 className="text-2xl md:text-4xl lg:text-5xl font-semibold tracking-tight text-indigo-50 mb-4">
              Turning AWS noise into{" "}
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-indigo-300 via-sky-300 to-emerald-300">
                actionable security signals.
              </span>
            </h1>

            <p className="text-sm md:text-base text-indigo-100/80 max-w-2xl mb-6">
              CloudAuditPro is an opinionated AWS security &amp; compliance
              platform that surfaces the controls that matter most — and shows
              you exactly how to fix them. Security Hub, S3, CloudTrail, Config,
              EBS, and IAM, brought together in a single, human-readable score.
            </p>

            <div className="grid sm:grid-cols-3 gap-4 mb-8">
              <StatCard
                label="Controls evaluated"
                value="35+"
                note="Across core AWS security &amp; compliance domains."
              />
              <StatCard
                label="Time to first insight"
                value="<10 min"
                note="Deploy the read-only role and get a score."
              />
              <StatCard
                label="Audit-ready posture"
                value="1 view"
                note="Summaries you can put in front of auditors."
              />
            </div>

            <div className="flex flex-wrap items-center gap-3 text-xs md:text-[13px]">
              <button
                onClick={() => (window.location.href = "/app")}
                className="px-4 py-2 rounded-xl bg-indigo-500 hover:bg-indigo-600 text-white font-medium shadow-lg shadow-indigo-900/60"
              >
                Open CloudAuditPro
              </button>
              <span className="text-gray-400">
                Read-only by design • No production changes applied.
              </span>
            </div>
          </div>

          {/* Right: Slider / visual */}
          <div className="relative">
            <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-5 md:p-6 shadow-2xl shadow-indigo-950/70 overflow-hidden">
              {/* Fake “screenshot” card that slides content */}
              <div className="mb-4 flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs text-gray-300">
                  <span className="inline-flex h-2.5 w-2.5 rounded-full bg-emerald-400/80"></span>
                  <span className="font-mono text-[11px] text-gray-400">
                    overview / posture
                  </span>
                </div>
                <span className="text-[11px] text-indigo-300">
                  {activeSlide.badge}
                </span>
              </div>

              {/* SMOOTH SLIDING SECTION */}
              <div className="relative h-40 md:h-44 lg:h-48 overflow-hidden">
                <div className="absolute inset-0">
                  <div
                    className="flex h-full w-full transition-transform duration-700 ease-[cubic-bezier(0.22,0.61,0.36,1)]"
                    style={{
                      transform: `translateX(-${activeIndex * 100}%)`,
                    }}
                  >
                    {SLIDES.map((slide) => (
                      <div key={slide.id} className="min-w-full pr-1">
                        <div className="h-full w-full rounded-xl border border-slate-800 bg-gradient-to-br from-slate-950 via-indigo-950/70 to-slate-900 p-4 flex flex-col justify-between">
                          <div>
                            <h3 className="text-sm md:text-base font-semibold text-indigo-100 mb-2">
                              {slide.title}
                            </h3>
                            <p className="text-[11px] md:text-xs text-gray-300">
                              {slide.subtitle}
                            </p>
                          </div>
                          <div className="grid grid-cols-3 gap-2 text-[10px] md:text-[11px] text-gray-300 mt-3">
                            <MiniPill label="Security Hub timeline" />
                            <MiniPill label="S3 public access map" />
                            <MiniPill label="CloudTrail multi-region" />
                            <MiniPill label="Config recorder health" />
                            <MiniPill label="EBS encryption coverage" />
                            <MiniPill label="IAM password policy" />
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Slider controls */}
              <div className="mt-4 flex items-center justify-between">
                <div className="flex gap-1.5">
                  {SLIDES.map((slide, idx) => (
                    <button
                      key={slide.id}
                      onClick={() => setActiveIndex(idx)}
                      className={`h-1.5 rounded-full transition-all ${
                        idx === activeIndex
                          ? "w-6 bg-indigo-400"
                          : "w-2 bg-slate-600"
                      }`}
                    />
                  ))}
                </div>
                <button
                  onClick={() =>
                    setActiveIndex((prev) => (prev + 1) % SLIDES.length)
                  }
                  className="text-[11px] text-indigo-200 hover:text-white underline-offset-4 hover:underline"
                >
                  Next highlight →
                </button>
              </div>
            </div>
          </div>
        </section>

        {/* WHAT IT CHECKS / WHY IT EXISTS */}
        <section className="grid md:grid-cols-2 gap-6">
          <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/50">
            <h2 className="text-sm font-semibold text-indigo-200 mb-2">
              What CloudAuditPro sees for you
            </h2>
            <p className="text-xs text-gray-300 mb-4">
              The platform is opinionated by design. It focuses on the AWS
              controls that tend to show up first in audits and incident
              reviews.
            </p>
            <ul className="space-y-2 text-xs text-gray-300 list-disc list-inside">
              <li>Security Hub findings and control coverage</li>
              <li>S3 public access, encryption defaults, and risky buckets</li>
              <li>CloudTrail multi-region trails and log destinations</li>
              <li>AWS Config recorder and configuration item coverage</li>
              <li>EBS default encryption and unencrypted volumes</li>
              <li>IAM account password policy health</li>
            </ul>
          </div>

          <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/50">
            <h2 className="text-sm font-semibold text-indigo-200 mb-2">
              Why teams adopt CloudAuditPro
            </h2>
            <p className="text-xs text-gray-300 mb-4">
              CloudAuditPro exists to bridge the gap between raw AWS signals and
              the conversations you need to have with leadership, customers, and
              auditors.
            </p>
            <ul className="space-y-2 text-xs text-gray-300 list-disc list-inside">
              <li>Reduce hours spent screenshotting consoles for audit decks.</li>
              <li>Give non-technical stakeholders a score they can understand.</li>
              <li>Track improvements over time, not just one-off remediations.</li>
              <li>Standardize how you talk about AWS security posture.</li>
            </ul>
          </div>
        </section>

        {/* HOW IT WORKS / TIMELINE */}
        <section className="grid lg:grid-cols-[1.2fr,1fr] gap-6 items-start">
          <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/60">
            <h2 className="text-sm font-semibold text-indigo-200 mb-2">
              How it works (high level)
            </h2>
            <p className="text-xs text-gray-300 mb-3">
              CloudAuditPro assumes a read-only IAM role in your AWS account,
              runs a curated set of checks, and composes everything into a
              single, exportable view.
            </p>
            <ol className="space-y-3 text-xs text-gray-300 list-decimal list-inside">
              <li>
                <span className="font-semibold text-gray-100">
                  Assume read-only role.
                </span>{" "}
                The platform uses a tightly scoped IAM role deployed via your
                CloudFormation template.
              </li>
              <li>
                <span className="font-semibold text-gray-100">
                  Run core security checks.
                </span>{" "}
                Security Hub, S3, CloudTrail, Config, EBS, and IAM are queried
                in sequence for posture data.
              </li>
              <li>
                <span className="font-semibold text-gray-100">
                  Calculate compliance score.
                </span>{" "}
                Each control contributes to a 0–100 score you can track over
                time.
              </li>
              <li>
                <span className="font-semibold text-gray-100">
                  Surface fix guidance.
                </span>{" "}
                Failing controls come with written remediation steps, console
                links, and cost notes.
              </li>
              <li>
                <span className="font-semibold text-gray-100">
                  Share with stakeholders.
                </span>{" "}
                Optionally email a report via SES and use the dashboard live in
                reviews.
              </li>
            </ol>
          </div>

          <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/60">
            <h2 className="text-sm font-semibold text-indigo-200 mb-2">
              Built for modern cloud teams
            </h2>
            <p className="text-xs text-gray-300 mb-4">
              Whether you&apos;re a single engineer owning security or part of a
              larger platform team, the approach is the same.
            </p>
            <ul className="space-y-2 text-xs text-gray-300">
              <li className="flex items-start gap-2">
                <span className="mt-0.5 text-indigo-300">▹</span>
                <div>
                  <div className="font-semibold text-gray-100">
                    Opinionated, not overwhelming
                  </div>
                  <div className="text-[11px] text-gray-400">
                    Focus on a carefully chosen set of controls instead of
                    hundreds of noisy signals.
                  </div>
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-0.5 text-indigo-300">▹</span>
                <div>
                  <div className="font-semibold text-gray-100">
                    Read-only by principle
                  </div>
                  <div className="text-[11px] text-gray-400">
                    The platform reads from AWS; any remediation remains under
                    your direct control.
                  </div>
                </div>
              </li>
              <li className="flex items-start gap-2">
                <span className="mt-0.5 text-indigo-300">▹</span>
                <div>
                  <div className="font-semibold text-gray-100">
                    Clear path to next steps
                  </div>
                  <div className="text-[11px] text-gray-400">
                    Use the remediation guidance as a backlog for your infra or
                    security team.
                  </div>
                </div>
              </li>
            </ul>

            <div className="mt-5 text-[11px] text-gray-500 border-t border-slate-800 pt-3">
              For partnership, enterprise, or roadmap discussions, you can
              customize this page to link to a public site, docs portal, or
              dedicated contact address.
            </div>
          </div>
        </section>

        {/* FOOTER STRIP */}
        <footer className="mt-4 border-t border-slate-800 pt-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-[11px] text-gray-500">
          <div>
            <span className="font-mono text-indigo-200">
              CloudAuditPro • Version {APP_VERSION}
            </span>
            <span className="ml-2 text-gray-500">
              (set via <code className="font-mono">VITE_APP_VERSION</code>)
            </span>
          </div>
          <div className="text-gray-400">
            Security-first. Read-only. Built to make AWS security reviews less
            painful.
          </div>
        </footer>
      </main>
    </div>
  );
}

function StatCard({ label, value, note }) {
  return (
    <div className="bg-black/50 border border-indigo-900/70 rounded-xl px-4 py-3 shadow-md shadow-indigo-950/50">
      <div className="text-[11px] text-gray-400 mb-1">{label}</div>
      <div className="text-xl font-semibold text-indigo-100 mb-1">
        {value}
      </div>
      <div className="text-[11px] text-gray-500">{note}</div>
    </div>
  );
}

function MiniPill({ label }) {
  return (
    <div className="inline-flex items-center justify-center rounded-full border border-slate-700 bg-slate-950/80 px-2 py-1">
      <span className="text-[10px] text-gray-300 truncate">{label}</span>
    </div>
  );
}
