import React, { useState } from "react";

const API_BASE = "http://127.0.0.1:8000"; // your FastAPI backend

export default function App() {
  const [accountId, setAccountId] = useState("");
  const [roleName, setRoleName] = useState("CloudAuditProReadRole");
  const [region, setRegion] = useState("us-east-1");
  const [emailTo, setEmailTo] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [loadingScan, setLoadingScan] = useState(false);
  const [loadingEmail, setLoadingEmail] = useState(false);
  const [error, setError] = useState("");

  const handleScan = async () => {
    setLoadingScan(true);
    setError("");
    setScanResult(null);
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: accountId,
          role_name: roleName,
          region: region,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Scan failed");
      }
      const data = await res.json();
      setScanResult(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingScan(false);
    }
  };

  const handleEmailReport = async () => {
    setLoadingEmail(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/report/email`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: accountId,
          role_name: roleName,
          region: region,
          email_to: emailTo || undefined,
        }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || "Email send failed");
      }
      const data = await res.json();
      alert(`Report sent to: ${data.sent_to}`);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingEmail(false);
    }
  };

  return (
    <div className="min-h-screen flex justify-center p-6 bg-gray-900 text-gray-100">
      <div className="w-full max-w-5xl grid md:grid-cols-2 gap-6">
        {/* Left panel: form */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 shadow-lg">
          <h1 className="text-2xl font-bold mb-1 text-indigo-400">
            CloudAuditPro
          </h1>
          <p className="text-gray-400 mb-6 text-sm">
            Connect your AWS account and run a Security Hub scan.
          </p>

          <label className="block mb-3 text-sm">
            AWS Account ID
            <input
              className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              placeholder="123456789012"
            />
          </label>

          <label className="block mb-3 text-sm">
            IAM Role Name
            <input
              className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
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
              className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              placeholder="us-east-1"
            />
          </label>

          <label className="block mb-5 text-sm">
            Email (optional, for report)
            <input
              className="mt-1 w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
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

          <div className="flex gap-3">
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
          </div>
        </div>

        {/* Right panel: results */}
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 overflow-auto">
          <h2 className="text-lg font-semibold mb-3 text-indigo-400">
            Scan results
          </h2>
          {!scanResult && (
            <p className="text-gray-400 text-sm">
              Run a scan to see Security Hub findings summarized here.
            </p>
          )}
          {scanResult && (
            <div className="space-y-3">
              <div className="bg-gray-900 rounded p-3 text-sm">
                <p className="text-gray-200">
                  <strong>Total findings:</strong> {scanResult.count}
                </p>
              </div>
              <div className="bg-gray-950 rounded p-3 text-xs whitespace-pre-wrap font-mono leading-relaxed text-gray-200">
                {scanResult.summary}
              </div>
            </div>
          )}

          <div className="mt-6 text-xs text-gray-500">
            Tip: make sure your IAM role trust policy allows your app account
            and that Security Hub is enabled in the selected region.
          </div>
        </div>
      </div>
    </div>
  );
}
