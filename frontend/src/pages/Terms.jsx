// src/pages/Terms.jsx
import React from "react";

export default function Terms() {
  return (
    <div className="min-h-screen bg-black text-white">
      <div className="mx-auto max-w-4xl px-6 py-12">
        <h1 className="text-3xl font-semibold tracking-tight">Terms of Service</h1>
        <p className="mt-2 text-white/70">Last updated: January 2026</p>

        <div className="mt-8 space-y-6 text-white/85 leading-relaxed">
          <p>
            These Terms of Service (“Terms”) govern your access to and use of CloudAuditPro (“CloudAuditPro,” “we,”
            “our,” or “us”). By accessing or using the service, you agree to be bound by these Terms.
          </p>
          <p>If you do not agree, do not use the service.</p>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">1. Description of Service</h2>
            <p className="mt-2">
              CloudAuditPro provides automated cloud security posture assessments, configuration analysis, and
              compliance-related control mappings for Amazon Web Services (AWS) environments. CloudAuditPro analyzes
              cloud configuration data made available through customer-authorized access and presents informational
              findings and insights.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">2. No Compliance Certification or Legal Advice</h2>
            <p className="mt-2">
              CloudAuditPro does not provide legal, regulatory, audit, or certification services.
            </p>
            <ul className="mt-3 list-disc pl-6 space-y-1 text-white/80">
              <li>CloudAuditPro does not guarantee compliance with any law, regulation, or framework.</li>
              <li>CloudAuditPro does not certify PCI DSS, SOC 2, CIS, or any other compliance status.</li>
              <li>CloudAuditPro does not replace independent audits, assessments, or professional advice.</li>
            </ul>
            <p className="mt-3">
              All compliance-related outputs are informational only and intended to support internal security and
              compliance efforts.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">3. User Responsibilities</h2>
            <p className="mt-2">
              You are solely responsible for configuring and maintaining your cloud environments, determining how
              CloudAuditPro findings are interpreted or used, and ensuring compliance with applicable laws,
              regulations, and contractual obligations. CloudAuditPro findings should not be relied upon as the sole
              basis for security, compliance, or business decisions.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">4. Authorized Access</h2>
            <p className="mt-2">
              You are responsible for ensuring that you have authorization to grant CloudAuditPro access to your AWS
              environments, that IAM roles and permissions are configured correctly, and that access is revoked when
              no longer required.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">5. Service Provided “As Is” (No Warranties)</h2>
            <p className="mt-2">
              CloudAuditPro is provided “as is” and “as available”, without warranties of any kind. To the maximum
              extent permitted by law, we disclaim all warranties, including but not limited to merchantability,
              fitness for a particular purpose, accuracy or completeness of findings, and non-infringement.
            </p>
            <p className="mt-2">
              We do not warrant that the service will be uninterrupted, error-free, or free of defects.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">6. Limitation of Liability</h2>
            <p className="mt-2">
              To the maximum extent permitted by law, CloudAuditPro shall not be liable for indirect, incidental,
              special, consequential, or punitive damages, including loss of data, revenue, profits, or business
              opportunities, or for security incidents, misconfigurations, or compliance failures.
            </p>
            <p className="mt-2">
              Our total liability for any claim related to the service shall not exceed the amount paid by you to
              CloudAuditPro in the prior 12 months (or $100 if no fees were paid).
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">7. Intellectual Property</h2>
            <p className="mt-2">
              All intellectual property rights in CloudAuditPro, including software, content, and documentation, are
              owned by CloudAuditPro. No rights are granted except as expressly stated in these Terms.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">8. Termination</h2>
            <p className="mt-2">
              We may suspend or terminate access to the service at any time for violation of these Terms, security
              risks, or operational or legal reasons. You may stop using the service at any time.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">9. Changes to These Terms</h2>
            <p className="mt-2">
              We may update these Terms from time to time. Continued use of the service after changes constitutes
              acceptance.
            </p>
          </section>

          <section>
            <h2 className="text-xl font-semibold text-white mt-8">10. Contact</h2>
            <p className="mt-2">
              For questions regarding these Terms:{" "}
              <span className="text-white font-medium">support@cloudauditpro.com</span>{" "}
              <span className="text-white/60">(replace with your real address)</span>
            </p>
          </section>
        </div>
      </div>
    </div>
  );
}

