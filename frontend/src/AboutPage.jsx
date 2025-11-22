// frontend/src/AboutPage.jsx
import React from "react";

const APP_VERSION =
  import.meta.env.VITE_APP_VERSION || "v0.1.0";

export default function AboutPage() {
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100">
      {/* Top bar */}
      <header className="w-full border-b border-indigo-900/60 px-6 py-3 flex items-center justify-between bg-black/40 backdrop-blur">
        <div className="flex items-center gap-2">
          <span className="text-lg font-bold text-indigo-300">
            CloudAuditPro
          </span>
          <span className="text-[10px] text-indigo-200/80 border border-indigo-500/40 rounded-full px-2 py-0.5">
            v{APP_VERSION}
          </span>
        </div>
        <button
          onClick={() => {
            // If user is logged in, this will go to the dashboard;
            // otherwise it will show the login page.
            window.location.href = "/";
          }}
          className="text-xs text-indigo-200 hover:text-white underline-offset-4 hover:underline"
        >
          ← Back to app
        </button>
      </header>

      <main className="flex-1 flex items-center justify-center px-4 py-8">
        <div className="w-full max-w-3xl bg-black/40 border border-indigo-900/60 rounded-2xl p-8 shadow-2xl shadow-indigo-900/50">
          <h1 className="text-2xl md:text-3xl font-semibold text-indigo-100 mb-3">
            About CloudAuditPro
          </h1>
          <p className="text-sm text-indigo-100/80 mb-6">
            CloudAuditPro is an opinionated AWS security &amp; compliance
            dashboard designed to give you fast, human-readable insight into
            how secure your AWS account really is.
          </p>

          <div className="grid md:grid-cols-2 gap-6 mb-8 text-sm text-gray-200">
            <div>
              <h2 className="text-sm font-semibold text-indigo-200 mb-2">
                What it checks
              </h2>
              <ul className="space-y-1.5 list-disc list-inside text-gray-300">
                <li>Security Hub findings overview</li>
                <li>S3 public access & default encryption</li>
                <li>CloudTrail multi-region audit logging</li>
                <li>AWS Config recorder status</li>
                <li>EBS default encryption & unencrypted volumes</li>
                <li>IAM account password policy</li>
              </ul>
            </div>

            <div>
              <h2 className="text-sm font-semibold text-indigo-200 mb-2">
                Why it exists
              </h2>
              <ul className="space-y-1.5 list-disc list-inside text-gray-300">
                <li>Turn noisy AWS security signals into a single score</li>
                <li>Help you quickly see what&apos;s broken — and how to fix it</li>
                <li>Make it easier to talk to auditors &amp; stakeholders</li>
                <li>Provide an at-a-glance view for demos and reviews</li>
              </ul>
            </div>
          </div>

          <div className="border border-slate-800 rounded-xl p-4 bg-slate-950/60 mb-6">
            <h3 className="text-sm font-semibold text-indigo-200 mb-1">
              How it works (high level)
            </h3>
            <p className="text-xs text-gray-300">
              CloudAuditPro assumes a read-only IAM role in your AWS account,
              runs a set of focused checks (Security Hub, S3, CloudTrail,
              Config, EBS, IAM), and then:
            </p>
            <ul className="mt-2 text-xs text-gray-300 space-y-1 list-disc list-inside">
              <li>Calculates an overall compliance score</li>
              <li>Surfaces failing controls with concrete remediation steps</li>
              <li>Tracks recently fixed items so you can see progress</li>
              <li>Optionally emails you an HTML report via SES</li>
            </ul>
          </div>

          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs text-gray-400">
            <div>
              <span className="font-mono text-indigo-200">
                Version {APP_VERSION}
              </span>
              <span className="ml-2 text-gray-500">
                (set via <code className="font-mono">VITE_APP_VERSION</code>)
              </span>
            </div>
            <div className="text-[11px] text-gray-400">
              For feedback or ideas, you can update this page to link to your
              preferred contact or docs.
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
