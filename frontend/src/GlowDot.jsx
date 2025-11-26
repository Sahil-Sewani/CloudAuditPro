// frontend/src/GlowDot.jsx
import React from "react";

export default function GlowDot({ size = 14 }) {
  // Outer wrapper size
  const wrapper = size;
  const core = size * 0.65;

  return (
    <span
      className="relative flex items-center justify-center"
      style={{ width: wrapper, height: wrapper }}
    >
      {/* Softer, slower pulse */}
      <span
        className="absolute rounded-full bg-emerald-400 blur-md animate-[ping_2.2s_cubic-bezier(0.22,0.61,0.36,1)_infinite]"
        style={{
          width: wrapper,
          height: wrapper,
          opacity: 0.45,
        }}
      />

      {/* Core dot */}
      <span
        className="relative rounded-full bg-emerald-400 shadow-[0_0_22px_rgba(52,211,153,0.9)]"
        style={{
          width: core,
          height: core,
        }}
      />
    </span>
  );
}
