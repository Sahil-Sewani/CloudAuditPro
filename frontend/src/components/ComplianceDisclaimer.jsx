// src/components/ComplianceDisclaimer.jsx
import React from "react";

export default function ComplianceDisclaimer({ variant = "block" }) {
  const text1 =
    "CloudAuditPro provides automated security assessments and control mappings.";
  const text2 =
    "It does not provide legal, regulatory, or audit certification services.";

  if (variant === "inline") {
    return (
      <span className="text-white/70">
        {text1} {text2}
      </span>
    );
  }

  return (
    <div className="rounded-2xl border border-white/10 bg-white/5 p-4">
      <p className="text-sm text-white/80">{text1}</p>
      <p className="text-sm text-white/80 mt-1">{text2}</p>
    </div>
  );
}

