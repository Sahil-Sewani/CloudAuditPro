// src/components/SiteFooter.jsx
import React from "react";
import { Link } from "react-router-dom";

export default function SiteFooter() {
  return (
    <footer className="border-t border-white/10 bg-black">
      <div className="mx-auto max-w-6xl px-6 py-8">
        <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
          <div className="text-sm text-white/70">
            <div className="leading-relaxed">
              CloudAuditPro provides automated security assessments and control mappings.
              <br />
              It does not provide legal, regulatory, or audit certification services.
            </div>
            <div className="mt-3 text-white/50">© 2026 CloudAuditPro. All rights reserved.</div>
          </div>

          <div className="flex gap-4 text-sm">
            <Link className="text-white/70 hover:text-white" to="/terms">
              Terms
            </Link>
            <Link className="text-white/70 hover:text-white" to="/privacy">
              Privacy
            </Link>
          </div>
        </div>
      </div>
    </footer>
  );
}

