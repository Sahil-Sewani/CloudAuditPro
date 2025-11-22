// frontend/src/GlowDot.jsx
import React from "react";

export default function GlowDot({ size = 14 }) {
  const outer = size;
  const inner = size - 4;

  return (
    <span
      className="relative inline-flex items-center justify-center"
      style={{ width: outer, height: outer }}
    >
      {/* Outer glow / ping */}
      <span className="absolute inline-flex w-full h-full rounded-full bg-emerald-400/70 blur-md opacity-70 animate-pulse" />
      {/* Core dot */}
      <span
        className="relative inline-flex rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(52,211,153,0.9)]"
        style={{ width: inner, height: inner }}
      />
    </span>
  );
}

