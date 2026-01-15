import React from "react";

const EFFECTIVE_DATE = "January 14, 2026"; // update anytime
const CONTACT_EMAIL = "sasewani@gmail.com"; // change to yours

export default function TermsOfService() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100">
      <div className="max-w-4xl mx-auto px-6 py-10">
        <h1 className="text-3xl font-bold text-indigo-200">Terms of Service</h1>
        <p className="mt-2 text-sm text-indigo-100/70">
          Effective: {EFFECTIVE_DATE}
        </p>

        <div className="mt-8 space-y-6 text-sm leading-relaxed text-indigo-100/80">
          <section>
            <h2 className="text-lg font-semibold text-indigo-100">1. Overview</h2>
            <p className="mt-2">
              These Terms of Service (“Terms”) govern your access to and use of
              CloudAuditPro (the “Service”). By accessing or using the Service,
              you agree to these Terms.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              2. No legal, regulatory, or audit certification
            </h2>
            <p className="mt-2">
              CloudAuditPro provides automated security assessments and control
              mappings. It does not provide legal, regulatory, or audit
              certification services. You are solely responsible for evaluating
              results and determining applicability to your environment.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              3. Accounts & acceptable use
            </h2>
            <ul className="mt-2 list-disc pl-5 space-y-2">
              <li>
                You must provide accurate information and maintain the security
                of your account credentials.
              </li>
              <li>
                You will not misuse the Service, attempt to gain unauthorized
                access, interfere with operations, or violate applicable laws.
              </li>
              <li>
                You are responsible for all activity under your account.
              </li>
            </ul>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              4. Your data & permissions
            </h2>
            <p className="mt-2">
              The Service may access cloud metadata you authorize (e.g., via
              read-only roles) to generate findings and reports. You represent
              and warrant that you have the rights and permissions to grant that
              access.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              5. Disclaimers (as-is / no warranties)
            </h2>
            <p className="mt-2">
              THE SERVICE IS PROVIDED “AS IS” AND “AS AVAILABLE,” WITHOUT
              WARRANTIES OF ANY KIND, WHETHER EXPRESS, IMPLIED, OR STATUTORY,
              INCLUDING IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
              PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT. We do not warrant
              that the Service will be uninterrupted, error-free, accurate, or
              meet your requirements.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              6. Limitation of liability
            </h2>
            <p className="mt-2">
              TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT WILL
              CLOUDAUDITPRO BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL,
              CONSEQUENTIAL, OR PUNITIVE DAMAGES, OR ANY LOSS OF PROFITS,
              REVENUE, DATA, OR GOODWILL, ARISING OUT OF OR RELATED TO YOUR USE
              OF THE SERVICE.
            </p>
            <p className="mt-2">
              TO THE MAXIMUM EXTENT PERMITTED BY LAW, OUR TOTAL LIABILITY FOR
              ANY CLAIM ARISING OUT OF OR RELATING TO THE SERVICE WILL NOT
              EXCEED THE AMOUNT YOU PAID FOR THE SERVICE IN THE 12 MONTHS
              PRECEDING THE EVENT GIVING RISE TO THE CLAIM (OR $100 IF YOU HAVE
              NOT PAID ANY AMOUNTS).
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">
              7. Changes & termination
            </h2>
            <p className="mt-2">
              We may update these Terms from time to time. We may suspend or
              terminate access to the Service at any time for violation of these
              Terms or to protect the Service.
            </p>
          </section>

          <section>
            <h2 className="text-lg font-semibold text-indigo-100">8. Contact</h2>
            <p className="mt-2">
              Questions about these Terms? Contact us at{" "}
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

