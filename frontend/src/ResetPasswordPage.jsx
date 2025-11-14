// frontend/src/ResetPasswordPage.jsx
import React, { useMemo, useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

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
    <div className="min-h-screen flex items-center justify-center bg-gray-900 text-gray-100 p-4">
      <div className="w-full max-w-md bg-gray-800 border border-gray-700 rounded-xl p-6 shadow-lg">
        <h1 className="text-2xl font-bold mb-2 text-indigo-400">
          Reset your password
        </h1>

        {!hasToken ? (
          <p className="text-sm text-red-300">
            Reset token is missing. Please use the link from your email.
          </p>
        ) : (
          <>
            <p className="text-sm text-gray-400 mb-6">
              Choose a new password for your account.
            </p>

            <form onSubmit={handleSubmit} className="space-y-4">
              <label className="block text-sm">
                New password
                <input
                  type="password"
                  required
                  className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </label>

              <label className="block text-sm">
                Confirm password
                <input
                  type="password"
                  required
                  className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
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
                disabled={submitting || !hasToken}
                className="w-full bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm font-medium"
              >
                {submitting ? "Updating..." : "Reset password"}
              </button>
            </form>
          </>
        )}

        <div className="mt-4 text-xs text-gray-400 flex justify-between">
          <a href="/" className="hover:text-indigo-400">
            ← Back to login
          </a>
        </div>
      </div>
    </div>
  );
}

