// src/pages/Privacy.jsx
import React from "react";
import SiteFooter from "../components/SiteFooter";

export default function Privacy() {
  return (
    <div className="min-h-screen flex flex-col bg-black text-white">
      <main className="flex-1">
        <div className="mx-auto max-w-4xl px-6 py-12">
          <h1 className="text-3xl font-semibold tracking-tight">Privacy Policy</h1>
          <p className="mt-2 text-white/70">Last updated: January 2026</p>

          <div className="mt-8 space-y-6 text-white/85 leading-relaxed">
            <p>
              CloudAuditPro respects your privacy. This Privacy Policy explains how we collect, use, and protect
              information.
            </p>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">1. Information We Collect</h2>
              <p className="mt-2">CloudAuditPro may collect:</p>
              <ul className="mt-3 list-disc pl-6 space-y-1 text-white/80">
                <li>Account information (email, organization name)</li>
                <li>Technical metadata related to AWS configurations</li>
                <li>Scan results and security findings</li>
                <li>Usage and diagnostic data</li>
              </ul>

              <p className="mt-4">We do not collect:</p>
              <ul className="mt-3 list-disc pl-6 space-y-1 text-white/80">
                <li>AWS credentials</li>
                <li>Customer content stored inside AWS resources</li>
                <li>Payment card data (unless explicitly handled by a third-party provider)</li>
              </ul>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">2. How We Use Information</h2>
              <p className="mt-2">We use information to:</p>
              <ul className="mt-3 list-disc pl-6 space-y-1 text-white/80">
                <li>Provide and operate the service</li>
                <li>Generate security findings and reports</li>
                <li>Improve performance and reliability</li>
                <li>Communicate service-related updates</li>
              </ul>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">3. Data Access & Security</h2>
              <ul className="mt-3 list-disc pl-6 space-y-1 text-white/80">
                <li>Access is performed via customer-controlled IAM roles</li>
                <li>Permissions are read-only by default</li>
                <li>We follow least-privilege principles</li>
              </ul>
              <p className="mt-3">
                No method of transmission or storage is 100% secure, but we take reasonable measures to protect data.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">4. Data Sharing</h2>
              <p className="mt-2">We do not sell customer data.</p>
              <p className="mt-2">We may share data:</p>
              <ul className="mt-3 list-disc pl-6 space-y-1 text-white/80">
                <li>With service providers necessary to operate the platform</li>
                <li>When required by law</li>
                <li>To protect security or prevent abuse</li>
              </ul>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">5. Data Retention</h2>
              <p className="mt-2">
                We retain data only as long as necessary to provide the service or meet legal obligations. Customers may
                request deletion of their data.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">6. Cookies & Analytics</h2>
              <p className="mt-2">
                We may use cookies or analytics tools to understand usage patterns and improve the service.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">7. Your Rights</h2>
              <p className="mt-2">
                Depending on your location, you may have rights to access your data, request correction or deletion, or
                object to certain processing.
              </p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">8. Changes to This Policy</h2>
              <p className="mt-2">We may update this Privacy Policy periodically.</p>
            </section>

            <section>
              <h2 className="text-xl font-semibold text-white mt-8">9. Contact</h2>
              <p className="mt-2">
                For privacy-related questions:{" "}
                <span className="text-white font-medium">support@cloudauditpro.com</span>{" "}
                <span className="text-white/60">(replace with your real address)</span>
              </p>
            </section>
          </div>
        </div>
      </main>

      <SiteFooter />
    </div>
  );
}