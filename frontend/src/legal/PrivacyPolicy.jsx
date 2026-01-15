import React from "react";

const EFFECTIVE_DATE = "January 14, 2026";
const CONTACT_EMAIL = "sasewani@gmail.com";

export default function PrivacyPolicy() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100">
      <div className="max-w-4xl mx-auto px-6 py-10">
        <h1 className="text-3xl font-bold text-indigo-200">Privacy Policy</h1>
        <p className="mt-2 text-sm text-indigo-100/70">
          Effective: {EFFECTIVE_DATE}
        </p>

        <div className="mt-8 space-y-6 text-sm leading-relaxed text-indigo-100/80">
          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              1. What this policy covers
            </h2>
            <p className="mt-2">
              This Privacy Policy explains how CloudAuditPro collects, uses, and
              shares information when you use the Service.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              2. Information we collect
            </h2>
            <ul className="mt-2 list-disc pl-5 space-y-2">
              <li>
                <span className="font-semibold">Account information:</span>{" "}
                email address and authentication identifiers used to sign in.
              </li>
              <li>
                <span className="font-semibold">Cloud configuration inputs:</span>{" "}
                AWS account ID, region, and role/ARN you provide to run scans.
              </li>
              <li>
                <span className="font-semibold">Scan outputs:</span>{" "}
                findings, summaries, and metadata generated from checks (e.g.,
                bucket posture, configuration status, inventory summaries).
              </li>
              <li>
                <span className="font-semibold">Usage data:</span>{" "}
                logs and basic telemetry needed to operate, secure, and improve
                the Service (e.g., timestamps, request diagnostics).
              </li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              3. How we use information
            </h2>
            <ul className="mt-2 list-disc pl-5 space-y-2">
              <li>Provide and operate the Service (run scans, show results).</li>
              <li>Send reports or notifications you request.</li>
              <li>Maintain security, prevent abuse, and debug issues.</li>
              <li>Improve product functionality and user experience.</li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              4. How we share information
            </h2>
            <p className="mt-2">
              We do not sell your personal information. We may share information
              with service providers that help us operate the Service (e.g.,
              hosting, databases, email delivery), and when required by law or
              to protect rights and safety.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              5. Data retention
            </h2>
            <p className="mt-2">
              We retain information as needed to provide the Service, comply
              with legal obligations, resolve disputes, and enforce agreements.
              You may request deletion of your account data where applicable.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              6. Security
            </h2>
            <p className="mt-2">
              We implement reasonable safeguards designed to protect
              information. However, no method of transmission or storage is
              completely secure.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              7. Contact
            </h2>
            <p className="mt-2">
              Questions about privacy? Contact{" "}
              <a className="text-indigo-200 underline" href={`mailto:${CONTACT_EMAIL}`}>
                {CONTACT_EMAIL}
              </a>
              .
            </p>
          </section>

          <p className="text-xs text-indigo-100/60">
            This template is provided for general informational purposes and is
            not legal advice.
          </p>
        </div>
      </div>
    </div>
  );
}

