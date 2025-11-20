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
  const [s3Summary, setS3Summary] = useState(null);
  const [complianceSummary, setComplianceSummary] = useState(null);

  const [cloudTrailResult, setCloudTrailResult] = useState(null);
  const [configResult, setConfigResult] = useState(null);
  const [ebsResult, setEbsResult] = useState(null);
  const [iamResult, setIamResult] = useState(null);

  const [loadingScan, setLoadingScan] = useState(false);
  const [loadingEmail, setLoadingEmail] = useState(false);
  const [loadingS3, setLoadingS3] = useState(false);
  const [loadingCompliance, setLoadingCompliance] = useState(false);
  const [loadingCloudTrail, setLoadingCloudTrail] = useState(false);
  const [loadingConfig, setLoadingConfig] = useState(false);
  const [loadingEbs, setLoadingEbs] = useState(false);
  const [loadingIam, setLoadingIam] = useState(false);

  const [error, setError] = useState("");

  // ---------- Helpers ----------

  const ensureAccountSet = () => {
    if (!accountId) {
      setError("Please enter an AWS Account ID first.");
      return false;
    }
    return true;
  };

  const buildPayload = () => ({
    account_id: accountId,
    role_name: roleName,
    region: region,
  });

  // ---------- Handlers: main scan / email / S3 ----------

  const handleScan = async () => {
    if (!ensureAccountSet()) return;

    setLoadingScan(true);
    setError("");
    setScanResult(null);

    try {
      const data = await apiFetch("/scan", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
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
    if (!ensureAccountSet()) return;

    setLoadingEmail(true);
    setError("");

    try {
      const data = await apiFetch("/report/email", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ...buildPayload(),
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
    if (!ensureAccountSet()) return;

    setLoadingS3(true);
    setError("");
    setS3Summary(null);

    try {
      const data = await apiFetch("/aws/s3-summary", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });

      setS3Summary(data);
    } catch (err) {
      console.error("S3 summary error:", err);
      setError(err.message || "S3 summary failed");
    } finally {
      setLoadingS3(false);
    }
  };

  // ---------- Handlers: compliance + individual checks ----------

  const handleComplianceSummary = async () => {
    if (!ensureAccountSet()) return;

    setLoadingCompliance(true);
    setError("");

    try {
      const data = await apiFetch("/compliance/summary", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      setComplianceSummary(data);
    } catch (err) {
      console.error("Compliance summary error:", err);
      setError(err.message || "Compliance summary failed");
    } finally {
      setLoadingCompliance(false);
    }
  };

  const handleCloudTrailCheck = async () => {
    if (!ensureAccountSet()) return;

    setLoadingCloudTrail(true);
    setError("");
    setCloudTrailResult(null);

    try {
      const data = await apiFetch("/checks/cloudtrail", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      setCloudTrailResult(data);
    } catch (err) {
      console.error("CloudTrail check error:", err);
      setError(err.message || "CloudTrail check failed");
    } finally {
      setLoadingCloudTrail(false);
    }
  };

  const handleConfigCheck = async () => {
    if (!ensureAccountSet()) return;

    setLoadingConfig(true);
    setError("");
    setConfigResult(null);

    try {
      const data = await apiFetch("/checks/config", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      setConfigResult(data);
    } catch (err) {
      console.error("Config check error:", err);
      setError(err.message || "Config check failed");
    } finally {
      setLoadingConfig(false);
    }
  };

  const handleEbsCheck = async () => {
    if (!ensureAccountSet()) return;

    setLoadingEbs(true);
    setError("");
    setEbsResult(null);

    try {
      const data = await apiFetch("/checks/ebs-encryption", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      setEbsResult(data);
    } catch (err) {
      console.error("EBS check error:", err);
      setError(err.message || "EBS encryption check failed");
    } finally {
      setLoadingEbs(false);
    }
  };

  const handleIamPasswordPolicyCheck = async () => {
    if (!ensureAccountSet()) return;

    setLoadingIam(true);
    setError("");
    setIamResult(null);

    try {
      const data = await apiFetch("/checks/iam-password-policy", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(buildPayload()),
      });
      setIamResult(data);
    } catch (err) {
      console.error("IAM password policy check error:", err);
      setError(err.message || "IAM password policy check failed");
    } finally {
      setLoadingIam(false);
    }
  };

  // ---------- Derived values ----------

  const scoreValue = complianceSummary?.score ?? 0;
  const scoreMax = complianceSummary?.max_score ?? 100;
  const scorePercent =
    scoreMax > 0 ? Math.round((scoreValue / scoreMax) * 100) : 0;

  const checks = Array.isArray(complianceSummary?.checks)
    ? complianceSummary.checks
    : [];

  // ---------- UI ----------

  return (
    <div className="min-h-screen flex flex-col bg-gray-950 text-gray-100">
      {/* Top bar with user + logout */}
      <header className="w-full border-b border-gray-800 px-6 py-3 flex items-center justify-between bg-gray-900/80">
        <div className="flex items-center gap-2">
          <span className="text-xl font-bold text-indigo-400">
            CloudAuditPro
          </span>
          <span className="text-xs text-gray-400">
            • AWS Security &amp; Compliance Dashboard
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
          {/* Left: Inputs + action buttons */}
          <div className="space-y-4">
            {/* Connection / form card */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-lg font-semibold mb-1 text-indigo-300">
                Connect &amp; run checks
              </h2>
              <p className="text-gray-400 mb-6 text-sm">
                Enter your AWS account and role, then run individual checks or a
                full Security Hub scan.
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

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={handleScan}
                  disabled={loadingScan}
                  className="bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                >
                  {loadingScan ? "Running scan..." : "Run scan"}
                </button>

                <button
                  onClick={handleEmailReport}
                  disabled={loadingEmail}
                  className="bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                >
                  {loadingEmail ? "Sending..." : "Email report"}
                </button>

                <button
                  onClick={handleS3Summary}
                  disabled={loadingS3}
                  className="bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                >
                  {loadingS3 ? "Checking S3..." : "S3 security"}
                </button>
              </div>
            </div>

            {/* Individual checks card */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-lg">
              <h2 className="text-lg font-semibold mb-3 text-indigo-300">
                Individual controls
              </h2>
              <p className="text-gray-400 text-xs mb-4">
                Run focused checks without doing a full Security Hub scan.
              </p>

              <div className="flex flex-wrap gap-3 mb-4">
                <button
                  onClick={handleCloudTrailCheck}
                  disabled={loadingCloudTrail}
                  className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-3 py-2 rounded text-xs"
                >
                  {loadingCloudTrail ? "Checking..." : "CloudTrail"}
                </button>

                <button
                  onClick={handleConfigCheck}
                  disabled={loadingConfig}
                  className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-3 py-2 rounded text-xs"
                >
                  {loadingConfig ? "Checking..." : "AWS Config"}
                </button>

                <button
                  onClick={handleIamPasswordPolicyCheck}
                  disabled={loadingIam}
                  className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-3 py-2 rounded text-xs"
                >
                  {loadingIam ? "Checking..." : "IAM password policy"}
                </button>

                <button
                  onClick={handleEbsCheck}
                  disabled={loadingEbs}
                  className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-3 py-2 rounded text-xs"
                >
                  {loadingEbs ? "Checking..." : "EBS encryption"}
                </button>
              </div>

              <p className="text-[11px] text-gray-500">
                Each button hits its own backend endpoint with the same account,
                role, and region.
              </p>
            </div>
          </div>

          {/* Right: Compliance + results */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 overflow-auto space-y-6">
            {/* Compliance score card (always present) */}
            <section>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold text-indigo-300">
                  Compliance score
                </h2>
                <button
                  onClick={handleComplianceSummary}
                  disabled={loadingCompliance}
                  className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-3 py-1 rounded text-xs"
                >
                  {loadingCompliance ? "Refreshing..." : "Refresh score"}
                </button>
              </div>

              {complianceSummary ? (
                <div>
                  <div className="mb-3">
                    <div className="flex justify-between text-xs text-gray-300">
                      <span>
                        Score: {scoreValue} / {scoreMax}
                      </span>
                      <span>{scorePercent}% compliant</span>
                    </div>
                    <div className="mt-2 h-2 w-full bg-gray-800 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${
                          scorePercent >= 80
                            ? "bg-emerald-500"
                            : scorePercent >= 50
                            ? "bg-yellow-400"
                            : "bg-red-500"
                        }`}
                        style={{ width: `${scorePercent}%` }}
                      />
                    </div>
                  </div>

                  <ul className="text-xs space-y-1">
                    {checks.map((check) => (
                      <li
                        key={check.id || check.label}
                        className="flex justify-between items-center border-b border-gray-800/60 pb-1"
                      >
                        <span className="text-gray-300">
                          {check.label || check.id}
                        </span>
                        <span className="ml-2">
                          {check.passed ? "✅" : "❌"}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-xs text-gray-500">
                  Enter an account ID and click{" "}
                  <span className="font-semibold">Refresh score</span> to see an
                  overall compliance score for this account.
                </p>
              )}
            </section>

            {/* Security Hub results */}
            <section>
              <h3 className="text-sm font-semibold mb-2 text-indigo-300">
                Security Hub findings
              </h3>
              {!scanResult ? (
                <p className="text-gray-500 text-xs">
                  Run a scan to see Security Hub results.
                </p>
              ) : (
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
            </section>

            {/* S3 summary */}
            <section>
              <h3 className="text-sm font-semibold mb-2 text-emerald-300">
                S3 security summary
              </h3>
              {!s3Summary ? (
                <p className="text-gray-500 text-xs">
                  Click{" "}
                  <span className="font-semibold">S3 security</span> to see
                  bucket-level checks.
                </p>
              ) : (
                <div className="bg-gray-950 rounded p-3 text-xs">
                  <p className="mb-2">
                    Total: {s3Summary.total_buckets} • Public:{" "}
                    {s3Summary.public_buckets} • Unencrypted:{" "}
                    {s3Summary.unencrypted_buckets}
                  </p>
                  <div className="max-h-40 overflow-auto space-y-1">
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
            </section>

            {/* Individual check outputs */}
            <section className="space-y-3 text-xs">
              {cloudTrailResult && (
                <div className="bg-gray-950 rounded p-3">
                  <h4 className="font-semibold text-indigo-200 mb-1">
                    CloudTrail
                  </h4>
                  <p>
                    Has trail:{" "}
                    {cloudTrailResult.has_trail ? "✅ yes" : "❌ no"}
                  </p>
                  <p>
                    Multi-region trail:{" "}
                    {cloudTrailResult.multi_region_trail ? "✅ yes" : "❌ no"}
                  </p>
                  <p>Trail count: {cloudTrailResult.trail_count}</p>
                </div>
              )}

              {configResult && (
                <div className="bg-gray-950 rounded p-3">
                  <h4 className="font-semibold text-indigo-200 mb-1">
                    AWS Config
                  </h4>
                  <p>
                    Recorder configured:{" "}
                    {configResult.recorder_configured ? "✅ yes" : "❌ no"}
                  </p>
                  <p>
                    Recording enabled:{" "}
                    {configResult.recording_enabled ? "✅ yes" : "❌ no"}
                  </p>
                  <p>Recorder count: {configResult.recorder_count}</p>
                </div>
              )}

              {ebsResult && (
                <div className="bg-gray-950 rounded p-3">
                  <h4 className="font-semibold text-indigo-200 mb-1">
                    EBS encryption
                  </h4>
                  <p>
                    Default encryption:{" "}
                    {ebsResult.default_encryption_enabled
                      ? "✅ enabled"
                      : "❌ disabled"}
                  </p>
                  <p>Total volumes: {ebsResult.total_volumes}</p>
                  {ebsResult.unencrypted_volume_ids &&
                    ebsResult.unencrypted_volume_ids.length > 0 && (
                      <div className="mt-1">
                        <p>Unencrypted volumes:</p>
                        <ul className="list-disc ml-4">
                          {ebsResult.unencrypted_volume_ids.map((id) => (
                            <li key={id}>{id}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                </div>
              )}

              {iamResult && (
                <div className="bg-gray-950 rounded p-3">
                  <h4 className="font-semibold text-indigo-200 mb-1">
                    IAM password policy
                  </h4>
                  <p>
                    Policy present:{" "}
                    {iamResult.policy_present ? "✅ yes" : "❌ no"}
                  </p>
                  {iamResult.error && (
                    <p className="text-red-300 mt-1">
                      Error: {iamResult.error}
                    </p>
                  )}
                </div>
              )}
            </section>

            <div className="text-[11px] text-gray-500">
              Tip: make sure your IAM role trust policy allows your app account
              to assume it, and that Security Hub, CloudTrail, and Config are
              all enabled in the selected region.
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
