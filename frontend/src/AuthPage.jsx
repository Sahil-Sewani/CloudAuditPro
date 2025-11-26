// frontend/src/AuthPage.jsx
import React, { useState } from "react";
import { useAuth } from "./AuthContext";

const APP_VERSION = import.meta.env.VITE_APP_VERSION || "v0.1.0";

export default function AuthPage() {
  const { login, register, error, sessionExpired } = useAuth();
  const [mode, setMode] = useState("login"); // "login" | "signup"
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState("");

  const onSubmit = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setLocalError("");

    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(name, email, password);
      }
    } catch (err) {
      setLocalError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const effectiveError = error || localError;

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-[#06021c] via-[#050016] to-black text-slate-100">
      {/* Top bar matching dashboard/about */}
      <header className="w-full border-b border-indigo-900/60 px-6 py-3 flex items-center justify-between bg-black/40 backdrop-blur">
        <div className="flex items-center gap-3">
          <span className="text-lg md:text-xl font-bold tracking-tight text-indigo-300">
            CloudAuditPro
          </span>
          <span className="text-[10px] md:text-xs text-indigo-200/80 border border-indigo-500/40 rounded-full px-2 py-0.5">
            v{APP_VERSION}
          </span>
          <span className="hidden md:inline text-xs text-indigo-200/70">
            • AWS Security &amp; Compliance Platform
          </span>
        </div>
        <button
          onClick={() => (window.location.href = "/")}
          className="text-xs md:text-sm text-indigo-200 hover:text-white underline-offset-4 hover:underline"
        >
          About
        </button>
      </header>

      <main className="flex-1 flex flex-col items-center justify-center px-4">
        {/* Top pill / logo */}
        <div className="mb-6 flex flex-col items-center gap-2">
          <div className="inline-flex items-center gap-2 rounded-full border border-purple-400/40 bg-black/70 px-4 py-1 shadow-lg shadow-purple-500/40">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-semibold tracking-wide text-slate-100">
              CloudAuditPro
            </span>
          </div>
          <p className="text-[11px] text-slate-400">
            AWS Security &amp; Compliance Dashboard
          </p>
        </div>

        {/* Main auth card */}
        <div className="w-full max-w-lg rounded-3xl bg-black/70 border border-purple-500/30 shadow-[0_0_120px_rgba(139,92,246,0.55)] backdrop-blur-xl p-8 sm:p-10">
          {/* Session expired banner */}
          {sessionExpired && (
            <div className="mb-4 rounded-xl border border-amber-500/60 bg-amber-500/10 px-3 py-2 text-xs text-amber-100">
              Your session has expired for security reasons. Please log in
              again to continue using CloudAuditPro.
            </div>
          )}

          {/* Tabs */}
          <div className="flex justify-center mb-6">
            <div className="inline-flex items-center bg-slate-900/80 rounded-full p-1">
              <button
                type="button"
                onClick={() => setMode("login")}
                className={`px-4 py-1.5 text-xs font-medium rounded-full transition ${
                  mode === "login"
                    ? "bg-purple-500 text-white shadow shadow-purple-500/40"
                    : "text-slate-300 hover:text-white"
                }`}
              >
                Log in
              </button>
              <button
                type="button"
                onClick={() => setMode("signup")}
                className={`px-4 py-1.5 text-xs font-medium rounded-full transition ${
                  mode === "signup"
                    ? "bg-emerald-500 text-white shadow shadow-emerald-500/40"
                    : "text-slate-300 hover:text-white"
                }`}
              >
                Sign up
              </button>
            </div>
          </div>

          {/* Heading */}
          <div className="text-center mb-6">
            <h1 className="text-2xl sm:text-3xl font-semibold mb-1">
              {mode === "login" ? "Welcome back" : "Create your account"}
            </h1>
            <p className="text-sm text-slate-400">
              Secure visibility into your AWS environment.
            </p>
          </div>

          {/* Form */}
          <form onSubmit={onSubmit} className="space-y-4">
            {mode === "signup" && (
              <div>
                <label className="block text-sm mb-1">Name</label>
                <input
                  type="text"
                  className="w-full px-3 py-2.5 rounded-lg bg-slate-950/80 border border-slate-800 focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                />
              </div>
            )}

            <div>
              <label className="block text-sm mb-1">Email</label>
              <input
                type="email"
                className="w-full px-3 py-2.5 rounded-lg bg-slate-950/80 border border-slate-800 focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
              />
            </div>

            <div>
              <label className="block text-sm mb-1">Password</label>
              <input
                type="password"
                className="w-full px-3 py-2.5 rounded-lg bg-slate-950/80 border border-slate-800 focus:outline-none focus:ring-2 focus:ring-purple-500 text-sm"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={
                  mode === "login" ? "current-password" : "new-password"
                }
              />

              {mode === "login" && (
                <div className="mt-2 text-xs text-slate-400 text-right">
                  <a
                    href="/forgot-password"
                    className="text-purple-300 hover:text-purple-200 underline"
                  >
                    Forgot password?
                  </a>
                </div>
              )}
            </div>

            {effectiveError && (
              <p className="text-sm text-red-400">{effectiveError}</p>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 rounded-lg bg-gradient-to-r from-purple-500 to-indigo-500 hover:from-purple-500 hover:to-purple-400 disabled:opacity-60 font-medium text-sm shadow-lg shadow-purple-500/40 transition"
            >
              {submitting
                ? mode === "login"
                  ? "Logging in..."
                  : "Creating account..."
                : mode === "login"
                ? "Log in"
                : "Sign up"}
            </button>
          </form>

          {/* Switch mode */}
          <div className="mt-6 text-center text-sm text-slate-400">
            {mode === "login" ? (
              <>
                Don&apos;t have an account?{" "}
                <button
                  type="button"
                  className="text-purple-300 hover:text-purple-200 underline"
                  onClick={() => setMode("signup")}
                >
                  Sign up
                </button>
              </>
            ) : (
              <>
                Already have an account?{" "}
                <button
                  type="button"
                  className="text-purple-300 hover:text-purple-200 underline"
                  onClick={() => setMode("login")}
                >
                  Log in
                </button>
              </>
            )}
          </div>
        </div>

        {/* Footer tagline */}
        <p className="mt-6 text-[11px] text-slate-500 text-center max-w-md">
          Built for AWS engineers who actually care about security &amp;
          compliance hygiene.
        </p>
      </main>
    </div>
  );
}
