// frontend/src/GlowDot.jsx
import React from "react";

export default function GlowDot({ size = 14, className = "" }) {
  const px = typeof size === "number" ? `${size}px` : size;

  return (
    <span
      className={`relative inline-flex items-center justify-center ${className}`}
      style={{ width: px, height: px }}
    >
      {/* Stronger outer pulse */}
      <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400/70 blur-[3px] animate-ping" />

      {/* Constant soft glow ring */}
      <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400/30 blur-[7px]" />

      {/* Core dot */}
      <span className="relative inline-flex h-2/3 w-2/3 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(52,211,153,0.9)]" />
    </span>
  );
}
