import React from "react";

function statusColor(status) {
  if (status === "pass") return "bg-green-500";
  if (status === "warn") return "bg-yellow-500";
  return "bg-red-500"; // fail
}

export default function ComplianceScoreCard({ score, controls }) {
  const safeScore = Math.max(0, Math.min(score ?? 0, 100));

  return (
    <div className="w-full bg-white/80 rounded-2xl shadow-md border border-slate-100 p-5 md:p-6 flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg md:text-xl font-semibold text-slate-900">
            Compliance Score
          </h2>
          <p className="text-sm text-slate-500">
            Based on your latest AWS security checks
          </p>
        </div>
        <div className="text-right">
          <div className="text-3xl md:text-4xl font-bold text-slate-900">
            {safeScore}%
          </div>
          <div className="text-xs text-slate-500">overall posture</div>
        </div>
      </div>

      {/* Progress bar */}
      <div className="w-full">
        <div className="w-full h-3 rounded-full bg-slate-100 overflow-hidden">
          <div
            className="h-3 rounded-full transition-all duration-500"
            style={{
              width: `${safeScore}%`,
              background:
                safeScore >= 90
                  ? "linear-gradient(to right, #22c55e, #16a34a)"
                  : safeScore >= 70
                  ? "linear-gradient(to right, #22c55e, #eab308)"
                  : "linear-gradient(to right, #f97316, #ef4444)",
            }}
          />
        </div>
        <div className="mt-1 flex justify-between text-[11px] text-slate-400">
          <span>0%</span>
          <span>50%</span>
          <span>100%</span>
        </div>
      </div>

      {/* Checklist */}
      <div className="mt-2">
        <p className="text-xs font-medium text-slate-500 uppercase tracking-wide mb-1">
          Controls
        </p>
        <ul className="space-y-1.5">
          {controls?.map((control) => (
            <li
              key={control.id}
              className="flex items-center justify-between gap-2 text-sm"
            >
              <div className="flex items-center gap-2">
                <span
                  className={`inline-block w-2.5 h-2.5 rounded-full ${statusColor(
                    control.status
                  )}`}
                />
                <span className="text-slate-700">{control.label}</span>
              </div>
              <span
                className={
                  control.status === "pass"
                    ? "text-xs font-semibold text-green-600"
                    : control.status === "warn"
                    ? "text-xs font-semibold text-yellow-600"
                    : "text-xs font-semibold text-red-600"
                }
              >
                {control.status === "pass"
                  ? "PASS"
                  : control.status === "warn"
                  ? "WARN"
                  : "FAIL"}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
