// frontend/src/ResetPasswordPage.jsx
import React, { useMemo, useState } from "react";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "https://api.cloudauditpro.app";

export default function ResetPasswordPage() {
  const token = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    return params.get("token") || "";
  }, []);

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const hasToken = Boolean(token);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setMessage("");
    setError("");

    if (password !== confirm) {
      setError("Passwords do not match");
      setSubmitting(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/auth/reset-password`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token,
          new_password: password,
        }),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(data.detail || "Failed to reset password");
      }

      setMessage("Password updated successfully. You can now log in.");
    } catch (err) {
      setError(err.message || "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100 px-4">
      <div className="w-full max-w-md">
        {/* Brand pill (same vibe as login) */}
        <div className="flex flex-col items-center mb-6">
          <div className="px-4 py-1.5 rounded-full bg-black/50 border border-indigo-500/50 shadow-lg shadow-indigo-900/50 flex items-center gap-2 text-xs text-indigo-100">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="font-medium">CloudAuditPro</span>
          </div>
          <p className="mt-2 text-[11px] text-indigo-200/70">
            AWS Security &amp; Compliance Dashboard
          </p>
        </div>

        {/* Glowy card wrapper with animated gradient border */}
        <div className="relative group">
          {/* Gradient border glow */}
          <div className="absolute -inset-[1px] rounded-3xl bg-gradient-to-br from-indigo-500 via-purple-500 to-sky-500 opacity-60 blur-xl group-hover:opacity-90 transition duration-700 animate-pulse pointer-events-none" />

          {/* Inner glass card */}
          <div className="relative rounded-3xl border border-indigo-500/40 bg-black/60 backdrop-blur-xl shadow-[0_20px_60px_rgba(15,23,42,0.9)] px-8 py-7">
            <h1 className="text-xl sm:text-2xl font-semibold mb-2 text-indigo-100">
              Reset your password
            </h1>

            {!hasToken ? (
              <p className="text-sm text-red-300">
                Reset token is missing. Please use the link from your email.
              </p>
            ) : (
              <>
                <p className="text-sm text-slate-300/90 mb-6">
                  Choose a new password for your account.
                </p>

                <form onSubmit={handleSubmit} className="space-y-4">
                  <label className="block text-sm">
                    New password
                    <input
                      type="password"
                      required
                      className="mt-1 w-full bg-slate-950/80 border border-slate-700/80 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 placeholder:text-slate-500"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                    />
                  </label>

                  <label className="block text-sm">
                    Confirm password
                    <input
                      type="password"
                      required
                      className="mt-1 w-full bg-slate-950/80 border border-slate-700/80 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 placeholder:text-slate-500"
                      value={confirm}
                      onChange={(e) => setConfirm(e.target.value)}
                    />
                  </label>

                  {error && (
                    <div className="bg-red-500/10 border border-red-500/70 text-red-200 text-xs rounded-lg p-3">
                      {error}
                    </div>
                  )}

                  {message && (
                    <div className="bg-emerald-500/10 border border-emerald-500/70 text-emerald-200 text-xs rounded-lg p-3">
                      {message}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={submitting || !hasToken}
                    className="w-full mt-2 py-2.5 rounded-lg bg-gradient-to-r from-indigo-500 via-violet-500 to-purple-500 hover:from-indigo-400 hover:via-violet-400 hover:to-purple-400 disabled:opacity-60 font-medium text-sm shadow-lg shadow-indigo-900/60 transition-colors"
                  >
                    {submitting ? "Updating..." : "Reset password"}
                  </button>
                </form>
              </>
            )}

            <div className="mt-5 text-xs text-slate-400 flex justify-between">
              <a
                href="/"
                className="inline-flex items-center gap-1 hover:text-indigo-300 transition-colors"
              >
                <span>←</span>
                <span>Back to login</span>
              </a>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
