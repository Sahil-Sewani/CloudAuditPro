import React from "react";

export default function SiteFooter() {
  const year = new Date().getFullYear();

  return (
    <footer className="mt-auto border-t border-indigo-900/60 bg-black/30 backdrop-blur px-6 py-6 text-xs text-indigo-100/80">
      <div className="max-w-6xl mx-auto flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <a href="/terms" className="hover:text-indigo-200">
          Terms
        </a>
        <a href="/privacy" className="hover:text-indigo-200">
          Privacy
        </a>
          <span className="text-indigo-200/40">•</span>
          <span>© {year} CloudAuditPro. All rights reserved.</span>
        </div>

        <div className="rounded-xl border border-indigo-500/20 bg-indigo-950/30 p-4 leading-relaxed">
          <div className="font-semibold text-indigo-100">
            Important compliance disclaimer
          </div>
          <div className="mt-1 text-indigo-100/80">
            CloudAuditPro provides automated security assessments and control
            mappings. It does not provide legal, regulatory, or audit
            certification services.
          </div>
          <div className="mt-2 text-indigo-100/70">
            Use of this service does not guarantee compliance with PCI DSS, SOC
            2, CIS benchmarks, or any other standard. You are responsible for
            validating results and determining applicability to your environment.
          </div>
        </div>
      </div>
    </footer>
  );
}
