import React, { useState } from "react";

const API_BASE =
  import.meta.env.VITE_API_BASE_URL || "https://api.cloudauditpro.app";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setMessage("");
    setError("");

    try {
      const res = await fetch(`${API_BASE}/auth/request-password-reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || "Failed to request password reset");
      }

      setMessage(
        "If that email exists, a password reset link has been sent."
      );
    } catch (err) {
      setError(err.message || "Something went wrong");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100 p-4">
      <div className="w-full max-w-md">
        <div className="mb-5 text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-black/40 border border-indigo-900/60 shadow-md shadow-indigo-900/40">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-sm font-medium tracking-wide text-indigo-200">
              CloudAuditPro
            </span>
          </div>
        </div>

        <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-2xl shadow-indigo-900/50 backdrop-blur-md">
          <h1 className="text-2xl font-bold mb-2 text-indigo-100">
            Forgot your password?
          </h1>
          <p className="text-sm text-slate-300/80 mb-6">
            Enter the email associated with your account, and we&apos;ll send you
            a password reset link.
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <label className="block text-sm text-slate-200">
              Email
              <input
                type="email"
                required
                className="mt-1 w-full bg-slate-950/80 border border-indigo-800 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </label>

            {error && (
              <div className="bg-red-500/10 border border-red-600 text-red-200 text-xs rounded p-3">
                {error}
              </div>
            )}

            {message && (
              <div className="bg-emerald-500/10 border border-emerald-600 text-emerald-200 text-xs rounded p-3">
                {message}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting || !email}
              className="w-full bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-medium shadow-lg shadow-indigo-500/30 transition"
            >
              {submitting ? "Sending..." : "Send reset link"}
            </button>
          </form>

          <div className="mt-4 text-xs text-slate-400 flex justify-between">
            <a href="/" className="hover:text-indigo-300">
              ← Back to login
            </a>
          </div>
        </div>
      </div>
    </div>
  );
}
