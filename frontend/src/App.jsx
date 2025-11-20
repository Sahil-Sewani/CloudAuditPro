import React, { useState } from "react";
import { useAuth } from "./AuthContext";
import { apiFetch } from "./apiClient";

export default function App({ user, onLogout }) {
  const { token } = useAuth();

  // Account config
  const [accountId, setAccountId] = useState("");
  const [roleName, setRoleName] = useState("CloudAuditProReadRole");
  const [region, setRegion] = useState("us-east-1");
  const [emailTo, setEmailTo] = useState("");

  // Results
  const [scanResult, setScanResult] = useState(null);
  const [s3Summary, setS3Summary] = useState(null);
  const [cloudTrailResult, setCloudTrailResult] = useState(null);
  const [configResult, setConfigResult] = useState(null);
  const [ebsResult, setEbsResult] = useState(null);
  const [iamPasswordResult, setIamPasswordResult] = useState(null);
  const [complianceSummary, setComplianceSummary] = useState(null);

  // Loading / error
  const [loadingScan, setLoadingScan] = useState(false);
  const [loadingEmail, setLoadingEmail] = useState(false);
  const [loadingS3, setLoadingS3] = useState(false);
  const [loadingCloudTrail, setLoadingCloudTrail] = useState(false);
  const [loadingConfig, setLoadingConfig] = useState(false);
  const [loadingEbs, setLoadingEbs] = useState(false);
  const [loadingIam, setLoadingIam] = useState(false);
  const [loadingCompliance, setLoadingCompliance] = useState(false);
  const [error, setError] = useState("");

  const hasAccountConfig = !!accountId;

  // ---------- Helpers ----------

  const refreshComplianceSummary = async () => {
    if (!hasAccountConfig) return;
    setLoadingCompliance(true);
    setError("");
    try {
      const data = await apiFetch("/compliance/summary", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          account_id: accountId,
          role_name: roleName,
          region,
        }),
      });
      setComplianceSummary(data);
    } catch (err) {
      console.error("Compliance summary error:", err);
      setError(err.message || "Failed to refresh compliance score");
    } finally {
      setLoadingCompliance(false);
    }
  };

  const commonBody = () => ({
    account_id: accountId,
    role_name: roleName,
    region,
  });

  // ---------- Action handlers ----------

  const handleScan = async () => {
    setLoadingScan(true);
    setError("");
    setScanResult(null);
    try {
      const data = await apiFetch("/scan", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody()),
      });
      setScanResult(data);
      await refreshComplianceSummary();
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
          ...commonBody(),
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
        body: JSON.stringify(commonBody()),
      });
      setS3Summary(data);
      await refreshComplianceSummary();
    } catch (err) {
      console.error("S3 summary error:", err);
      setError(err.message || "S3 summary failed");
    } finally {
      setLoadingS3(false);
    }
  };

  const handleCloudTrail = async () => {
    setLoadingCloudTrail(true);
    setError("");
    setCloudTrailResult(null);
    try {
      const data = await apiFetch("/checks/cloudtrail", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody()),
      });
      setCloudTrailResult(data);
      await refreshComplianceSummary();
    } catch (err) {
      console.error("CloudTrail check error:", err);
      setError(err.message || "CloudTrail check failed");
    } finally {
      setLoadingCloudTrail(false);
    }
  };

  const handleConfig = async () => {
    setLoadingConfig(true);
    setError("");
    setConfigResult(null);
    try {
      const data = await apiFetch("/checks/config", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody()),
      });
      setConfigResult(data);
      await refreshComplianceSummary();
    } catch (err) {
      console.error("Config check error:", err);
      setError(err.message || "Config check failed");
    } finally {
      setLoadingConfig(false);
    }
  };

  const handleEbs = async () => {
    setLoadingEbs(true);
    setError("");
    setEbsResult(null);
    try {
      const data = await apiFetch("/checks/ebs-encryption", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody()),
      });
      setEbsResult(data);
      await refreshComplianceSummary();
    } catch (err) {
      console.error("EBS check error:", err);
      setError(err.message || "EBS encryption check failed");
    } finally {
      setLoadingEbs(false);
    }
  };

  const handleIamPassword = async () => {
    setLoadingIam(true);
    setError("");
    setIamPasswordResult(null);
    try {
      const data = await apiFetch("/checks/iam-password-policy", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody()),
      });
      setIamPasswordResult(data);
      await refreshComplianceSummary();
    } catch (err) {
      console.error("IAM password check error:", err);
      setError(err.message || "IAM password policy check failed");
    } finally {
      setLoadingIam(false);
    }
  };

  const handleRefreshScore = async () => {
    await refreshComplianceSummary();
  };

  // ---------- Render helpers ----------

  const compliancePercent =
    complianceSummary && typeof complianceSummary.score === "number"
      ? Math.round(complianceSummary.score)
      : 0;

  const compliancePoints =
    complianceSummary && typeof complianceSummary.score === "number"
      ? complianceSummary.score.toFixed(1)
      : "0.0";

  const maxPoints =
    complianceSummary && typeof complianceSummary.max_points === "number"
      ? complianceSummary.max_points
      : 100;

  const controls = complianceSummary?.controls || [];

  const pill = (ok) =>
    ok ? (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-emerald-500/10 text-emerald-300 border border-emerald-500/40">
        ✅ Passed
      </span>
    ) : (
      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-red-500/10 text-red-300 border border-red-500/40">
        ❌ Failing
      </span>
    );

  // ---------- UI ----------

  return (
    <div className="min-h-screen flex flex-col bg-gray-950 text-gray-100">
      {/* Top bar */}
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

      <main className="flex-1 px-6 py-6">
        <div className="grid lg:grid-cols-2 gap-6">
          {/* LEFT: single unified Account & Actions card */}
          <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-lg">
            <h2 className="text-lg font-semibold mb-1 text-indigo-300">
              Account &amp; Actions
            </h2>
            <p className="text-gray-400 mb-6 text-sm">
              Configure your AWS account and run checks. Each action updates the
              Compliance Score.
            </p>

            {/* Account fields */}
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

            <label className="block mb-4 text-sm">
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

            {/* Unified Actions section */}
            <h3 className="text-sm font-semibold text-gray-300 mb-2">
              Actions
            </h3>
            <div className="grid sm:grid-cols-2 gap-3 mb-2">
              <button
                onClick={handleScan}
                disabled={loadingScan || !hasAccountConfig}
                className="bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingScan ? "Running scan..." : "Run scan"}
              </button>
              <button
                onClick={handleS3Summary}
                disabled={loadingS3 || !hasAccountConfig}
                className="bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingS3 ? "Checking S3..." : "S3 security"}
              </button>
              <button
                onClick={handleEmailReport}
                disabled={loadingEmail || !hasAccountConfig}
                className="bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingEmail ? "Sending..." : "Email report"}
              </button>
              <button
                onClick={handleCloudTrail}
                disabled={loadingCloudTrail || !hasAccountConfig}
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-100 px-4 py-2 rounded text-sm"
              >
                {loadingCloudTrail ? "Checking..." : "CloudTrail"}
              </button>
              <button
                onClick={handleConfig}
                disabled={loadingConfig || !hasAccountConfig}
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-100 px-4 py-2 rounded text-sm"
              >
                {loadingConfig ? "Checking..." : "Config"}
              </button>
              <button
                onClick={handleEbs}
                disabled={loadingEbs || !hasAccountConfig}
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-100 px-4 py-2 rounded text-sm"
              >
                {loadingEbs ? "Checking..." : "EBS encryption"}
              </button>
              <button
                onClick={handleIamPassword}
                disabled={loadingIam || !hasAccountConfig}
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-gray-100 px-4 py-2 rounded text-sm"
              >
                {loadingIam ? "Checking..." : "IAM password policy"}
              </button>
              <button
                onClick={handleRefreshScore}
                disabled={loadingCompliance || !hasAccountConfig}
                className="bg-gray-900 hover:bg-gray-800 disabled:opacity-50 text-gray-200 px-4 py-2 rounded text-sm border border-gray-700"
              >
                {loadingCompliance ? "Refreshing..." : "Refresh score"}
              </button>
            </div>

            <p className="mt-2 text-xs text-gray-500">
              Tip: make sure your IAM role trust policy allows your app account
              and that Security Hub, CloudTrail, and Config are enabled.
            </p>
          </div>

          {/* RIGHT: Compliance + Details */}
          <div className="flex flex-col gap-6">
            {/* Compliance Score */}
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-lg">
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold text-indigo-300">
                  Compliance Score
                </h2>
                <span className="text-xs text-gray-400">
                  Based on latest checks
                </span>
              </div>

              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-bold text-emerald-400">
                  {compliancePercent}%
                </span>
                <span className="text-xs text-gray-400">
                  ({compliancePoints} / {maxPoints} points)
                </span>
              </div>

              {/* Progress bar */}
              <div className="mt-4 h-2 w-full bg-gray-800 rounded-full overflow-hidden">
                <div
                  className="h-2 bg-emerald-500"
                  style={{ width: `${Math.min(compliancePercent, 100)}%` }}
                />
              </div>

              {/* Control checklist */}
              {controls.length > 0 && (
                <ul className="mt-4 space-y-1 text-xs">
                  {controls.map((c) => (
                    <li
                      key={c.id}
                      className="flex items-center justify-between text-gray-200"
                    >
                      <span className="flex items-center gap-2">
                        <span>{c.passed ? "✅" : "❌"}</span>
                        <span>{c.label}</span>
                      </span>
                      {typeof c.weight === "number" && (
                        <span className="text-gray-400">
                          {c.weight} pts
                        </span>
                      )}
                    </li>
                  ))}
                </ul>
              )}

              {controls.length === 0 && (
                <p className="mt-3 text-xs text-gray-500">
                  Run some checks on the left to populate your control
                  breakdown.
                </p>
              )}
            </div>

            {/* Details */}
            <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 shadow-lg max-h-[540px] overflow-auto">
              <h2 className="text-lg font-semibold mb-3 text-indigo-300">
                Details
              </h2>
              <p className="text-xs text-gray-400 mb-4">
                Use the actions on the left to run scans and checks. Results
                will appear here in a human-readable format.
              </p>

              <div className="space-y-4 text-sm">
                {/* Security Hub */}
                {scanResult && (
                  <section>
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">
                      Security Hub scan
                    </h3>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-400">
                        Total findings:
                      </span>
                      <span className="text-xs font-semibold">
                        {scanResult.count}
                      </span>
                    </div>
                    <div className="text-xs text-gray-300 bg-black/40 border border-gray-800 rounded p-2 whitespace-pre-wrap font-mono">
                      {scanResult.summary}
                    </div>
                  </section>
                )}

                {/* S3 */}
                {s3Summary && (
                  <section>
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">
                      S3 security
                    </h3>
                    <div className="flex flex-wrap gap-3 text-xs mb-2">
                      <span>
                        🪣 Buckets:{" "}
                        <strong>{s3Summary.total_buckets}</strong>
                      </span>
                      <span>
                        🌐 Public:{" "}
                        <strong>{s3Summary.public_buckets}</strong>
                      </span>
                      <span>
                        🔐 Unencrypted:{" "}
                        <strong>{s3Summary.unencrypted_buckets}</strong>
                      </span>
                    </div>
                    <div className="space-y-1 text-xs">
                      {s3Summary.buckets.map((b) => (
                        <div
                          key={b.bucket}
                          className="flex justify-between items-center border border-gray-800 rounded px-2 py-1"
                        >
                          <span className="truncate mr-2">{b.bucket}</span>
                          <span className="flex gap-2 text-[11px]">
                            <span>
                              {b.public ? "🌐 Public" : "🔒 Private"}
                            </span>
                            <span>
                              {b.encryption_enabled
                                ? "✅ Encrypted"
                                : "⚠️ No encryption"}
                            </span>
                          </span>
                        </div>
                      ))}
                    </div>
                  </section>
                )}

                {/* CloudTrail */}
                {cloudTrailResult && (
                  <section>
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">
                      CloudTrail
                    </h3>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-400">
                        Trail configured
                      </span>
                      {pill(cloudTrailResult.has_trail)}
                    </div>
                    <ul className="text-xs text-gray-300 list-disc ml-5">
                      <li>
                        Multi-region trail:{" "}
                        {cloudTrailResult.multi_region_trail ? "Yes" : "No"}
                      </li>
                      <li>
                        Trail count: {cloudTrailResult.trail_count ?? 0}
                      </li>
                    </ul>
                  </section>
                )}

                {/* Config */}
                {configResult && (
                  <section>
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">
                      AWS Config
                    </h3>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-400">
                        Recorder configured
                      </span>
                      {pill(configResult.recorder_configured)}
                    </div>
                    <ul className="text-xs text-gray-300 list-disc ml-5">
                      <li>
                        Recording enabled:{" "}
                        {configResult.recording_enabled ? "Yes" : "No"}
                      </li>
                      <li>
                        Recorder count: {configResult.recorder_count ?? 0}
                      </li>
                    </ul>
                  </section>
                )}

                {/* EBS */}
                {ebsResult && (
                  <section>
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">
                      EBS encryption
                    </h3>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-400">
                        Default encryption
                      </span>
                      {pill(ebsResult.default_encryption_enabled)}
                    </div>
                    <ul className="text-xs text-gray-300 list-disc ml-5">
                      <li>Total volumes: {ebsResult.total_volumes ?? 0}</li>
                      <li>
                        Unencrypted volumes:{" "}
                        {ebsResult.unencrypted_volume_ids?.length || 0}
                      </li>
                    </ul>
                    {ebsResult.unencrypted_volume_ids &&
                      ebsResult.unencrypted_volume_ids.length > 0 && (
                        <div className="mt-1 text-[11px] text-gray-400">
                          IDs:{" "}
                          {ebsResult.unencrypted_volume_ids.join(", ")}
                        </div>
                      )}
                  </section>
                )}

                {/* IAM password policy */}
                {iamPasswordResult && (
                  <section>
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">
                      IAM password policy
                    </h3>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-gray-400">
                        Policy configured
                      </span>
                      {pill(iamPasswordResult.policy_present)}
                    </div>
                    {!iamPasswordResult.policy_present ? (
                      <p className="text-xs text-gray-300">
                        No account password policy found. Consider configuring
                        a strong password policy in IAM.
                      </p>
                    ) : (
                      <ul className="text-xs text-gray-300 list-disc ml-5">
                        <li>
                          Min length:{" "}
                          {iamPasswordResult.minimum_password_length}
                        </li>
                        <li>
                          Requires symbols:{" "}
                          {iamPasswordResult.require_symbols ? "Yes" : "No"}
                        </li>
                        <li>
                          Requires numbers:{" "}
                          {iamPasswordResult.require_numbers ? "Yes" : "No"}
                        </li>
                        <li>
                          Requires uppercase:{" "}
                          {iamPasswordResult.require_uppercase_characters
                            ? "Yes"
                            : "No"}
                        </li>
                        <li>
                          Requires lowercase:{" "}
                          {iamPasswordResult.require_lowercase_characters
                            ? "Yes"
                            : "No"}
                        </li>
                        {typeof iamPasswordResult.max_password_age ===
                          "number" && (
                          <li>
                            Max password age:{" "}
                            {iamPasswordResult.max_password_age} days
                          </li>
                        )}
                      </ul>
                    )}
                  </section>
                )}

                {!scanResult &&
                  !s3Summary &&
                  !cloudTrailResult &&
                  !configResult &&
                  !ebsResult &&
                  !iamPasswordResult && (
                    <p className="text-xs text-gray-500">
                      No results yet. Run a scan or one of the individual
                      checks on the left to see details here.
                    </p>
                  )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
