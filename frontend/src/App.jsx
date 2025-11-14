import React, { useState } from "react";
import { useAuth } from "./AuthContext";
import { apiFetch } from "./apiClient";

export default function App({ user, onLogout }) {
  const { token } = useAuth();

  const [accountId, setAccountId] = useState("");
  const [roleName, setRoleName] = useState("CloudAuditProReadRole");
  const [region, setRegion] = useState("us-east-1");
  const [emailTo, setEmailTo] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [loadingScan, setLoadingScan] = useState(false);
  const [loadingEmail, setLoadingEmail] = useState(false);
  const [error, setError] = useState("");
  const [s3Summary, setS3Summary] = useState(null);
  const [loadingS3, setLoadingS3] = useState(false);

  // -------------------- Handlers --------------------

  const handleScan = async () => {
    setLoadingScan(true);
    setError("");
    setScanResult(null);

    try {
      const data = await apiFetch("/scan", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: accountId,
          role_name: roleName,
          region: region,
        }),
      });

      setScanResult(data);
    } catch (err) {
      console.error("Scan error:", err);
      setError(err.message || "Scan failed");
    } finally {
      setLoadingScan(false);
    }
  };

  const handleEmailReport = async () => {
    setLoadingEmail(true);
    setError("");

    try {
      const data = await apiFetch("/report/email", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: accountId,
          role_name: roleName,
          region: region,
          email_to: emailTo || undefined,
        }),
      });

      alert(`Report sent to: ${data.sent_to}`);
    } catch (err) {
      console.error("Email report error:", err);
      setError(err.message || "Email send failed");
    } finally {
      setLoadingEmail(false);
    }
  };

  const handleS3Summary = async () => {
    setLoadingS3(true);
    setError("");
    setS3Summary(null);

    try {
      const data = await apiFetch("/aws/s3-summary", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: accountId,
          role_name: roleName,
          region: region,
        }),
      });

      setS3Summary(data);
    } catch (err) {
      console.error("S3 summary error:", err);
      setError(err.message || "S3 summary failed");
    } finally {
      setLoadingS3(false);
    }
  };

  // -------------------- UI --------------------

  return (
    <div className="min-h-screen flex flex-col bg-gray-950 text-gray-100">
      {/* Top bar with user + logout */}
      <header className="w-full border-b border-gray-800 px-6 py-3 flex items-center justify-between bg-gray-900/80">
        <div className="flex items-center gap-2">
          <span className="text-xl font-bold text-indigo-400">
            CloudAuditPro
          </span>
          <span className="text-xs text-gray-400">
            • AWS Security & Compliance Dashboard
          </span>
        </div>
        <div className="flex items-center gap-3 text-sm">
          {user && (
            <span className="text-gray-300 hidden sm:inline">
              {user.email}
            </span>
          )}
          {onLogout && (
            <button
              onClick={onLogout}
              className="px-3 py-1 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 text-xs"
            >
              Log out
            </button>
          )}
        </div>
      </header>

      <main className="flex-1 flex justify-center p-6">
        <div className="w-full max-w-5xl grid md:grid-cols-2 gap-6">
          {/* Left panel: form */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-lg">
            <h2 className="text-lg font-semibold mb-1 text-indigo-300">
              Run a scan
            </h2>
            <p className="text-gray-400 mb-6 text-sm">
              Connect your AWS account and run a Security Hub or S3 security
              scan.
            </p>

            <label className="block mb-3 text-sm">
              AWS Account ID
              <input
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                value={accountId}
                onChange={(e) => setAccountId(e.target.value)}
                placeholder="123456789012"
              />
            </label>

            <label className="block mb-3 text-sm">
              IAM Role Name
              <input
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm"
                value={roleName}
                onChange={(e) => setRoleName(e.target.value)}
              />
              <span className="text-xs text-gray-500">
                This should match the role from your CloudFormation template.
              </span>
            </label>

            <label className="block mb-3 text-sm">
              AWS Region
              <input
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm"
                value={region}
                onChange={(e) => setRegion(e.target.value)}
                placeholder="us-east-1"
              />
            </label>

            <label className="block mb-5 text-sm">
              Email (optional, for report)
              <input
                className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm"
                value={emailTo}
                onChange={(e) => setEmailTo(e.target.value)}
                placeholder="you@gmail.com"
              />
            </label>

            {error && (
              <div className="bg-red-500/10 border border-red-600 text-red-200 text-xs rounded p-3 mb-4">
                {error}
              </div>
            )}

            <div className="flex gap-3 flex-wrap">
              <button
                onClick={handleScan}
                disabled={loadingScan || !accountId}
                className="bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingScan ? "Running scan..." : "Run scan"}
              </button>
              <button
                onClick={handleEmailReport}
                disabled={loadingEmail || !accountId}
                className="bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingEmail ? "Sending..." : "Email report"}
              </button>
              <button
                onClick={handleS3Summary}
                disabled={loadingS3 || !accountId}
                className="bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingS3 ? "Checking S3..." : "S3 security"}
              </button>
            </div>
          </div>

          {/* Right panel: results */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 overflow-auto">
            <h2 className="text-lg font-semibold mb-3 text-indigo-300">
              Scan results
            </h2>

            {!scanResult && !s3Summary && (
              <p className="text-gray-400 text-sm">
                Run a scan to see Security Hub or S3 findings summarized here.
              </p>
            )}

            {/* Security Hub results */}
            {scanResult && (
              <div className="space-y-3">
                <div className="bg-gray-950 rounded p-3 text-sm">
                  <p className="text-gray-200">
                    <strong>Total findings:</strong> {scanResult.count}
                  </p>
                </div>
                <div className="bg-black/80 rounded p-3 text-xs whitespace-pre-wrap font-mono leading-relaxed text-gray-200">
                  {scanResult.summary}
                </div>
              </div>
            )}

            {/* S3 security summary */}
            {s3Summary && (
              <div className="mt-6 bg-gray-950 rounded p-3 text-xs">
                <h3 className="text-sm font-semibold mb-2 text-emerald-300">
                  S3 Security Summary
                </h3>
                <p className="mb-2">
                  Total: {s3Summary.total_buckets} • Public:{" "}
                  {s3Summary.public_buckets} • Unencrypted:{" "}
                  {s3Summary.unencrypted_buckets}
                </p>
                <div className="max-h-48 overflow-auto space-y-1">
                  {s3Summary.buckets.map((b) => (
                    <div
                      key={b.bucket}
                      className="flex justify-between gap-2 border-b border-gray-800/40 pb-1"
                    >
                      <span>{b.bucket}</span>
                      <span className="text-xs">
                        {b.public ? "🌐 public" : "🔒 private"} •{" "}
                        {b.encryption_enabled
                          ? "🔐 encrypted"
                          : "⚠️ no encryption"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="mt-6 text-xs text-gray-500">
              Tip: make sure your IAM role trust policy allows your app account
              and that Security Hub is enabled in the selected region.
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
