import React, { useState, useEffect } from "react";
import { useAuth } from "./AuthContext";
import { apiFetch } from "./apiClient";

export default function App({ user, onLogout }) {
  const { token } = useAuth();

  // --------- Form state ----------
  const [accountId, setAccountId] = useState("");
  const [roleName, setRoleName] = useState("CloudAuditProReadRole");
  const [region, setRegion] = useState("us-east-1");
  const [emailTo, setEmailTo] = useState("");

  // --------- Results / state ----------
  const [scanResult, setScanResult] = useState(null);
  const [s3Summary, setS3Summary] = useState(null);
  const [cloudTrailResult, setCloudTrailResult] = useState(null);
  const [configResult, setConfigResult] = useState(null);
  const [ebsResult, setEbsResult] = useState(null);
  const [iamResult, setIamResult] = useState(null);
  const [complianceSummary, setComplianceSummary] = useState(null);

  // --------- Loading + error ----------
  const [loadingScan, setLoadingScan] = useState(false);
  const [loadingEmail, setLoadingEmail] = useState(false);
  const [loadingS3, setLoadingS3] = useState(false);
  const [loadingCloudTrail, setLoadingCloudTrail] = useState(false);
  const [loadingConfig, setLoadingConfig] = useState(false);
  const [loadingEbs, setLoadingEbs] = useState(false);
  const [loadingIam, setLoadingIam] = useState(false);
  const [loadingCompliance, setLoadingCompliance] = useState(false);
  const [error, setError] = useState("");

  const hasAccountConfig = accountId && roleName && region;

  const commonBody = {
    account_id: accountId,
    role_name: roleName,
    region: region,
  };

  // --------- Helpers ----------
  const refreshComplianceSummary = async () => {
    if (!hasAccountConfig) return;
    try {
      setLoadingCompliance(true);
      const data = await apiFetch("/compliance/summary", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });
      setComplianceSummary(data);
    } catch (err) {
      console.error("Compliance summary error:", err);
    } finally {
      setLoadingCompliance(false);
    }
  };

  // Optionally auto-refresh when account fields change
  useEffect(() => {
    setComplianceSummary(null);
    setScanResult(null);
    setS3Summary(null);
    setCloudTrailResult(null);
    setConfigResult(null);
    setEbsResult(null);
    setIamResult(null);
  }, [accountId, roleName, region]);

  // --------- Action handlers ----------

  const handleScan = async () => {
    setLoadingScan(true);
    setError("");
    setScanResult(null);

    try {
      const data = await apiFetch("/scan", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
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
          ...commonBody,
          email_to: emailTo || undefined,
        }),
      });
      alert(`Report sent to: ${data.sent_to}`);
      await refreshComplianceSummary();
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
        body: JSON.stringify(commonBody),
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
        body: JSON.stringify(commonBody),
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
        body: JSON.stringify(commonBody),
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
        body: JSON.stringify(commonBody),
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

  const handleIam = async () => {
    setLoadingIam(true);
    setError("");
    setIamResult(null);

    try {
      const data = await apiFetch("/checks/iam-password-policy", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });
      setIamResult(data);
      await refreshComplianceSummary();
    } catch (err) {
      console.error("IAM password policy error:", err);
      setError(err.message || "IAM password policy check failed");
    } finally {
      setLoadingIam(false);
    }
  };

  const handleRefreshScore = async () => {
    setError("");
    await refreshComplianceSummary();
  };

  // --------- Compliance helpers ----------
  const score = complianceSummary
    ? complianceSummary.score ?? complianceSummary.total_score ?? 0
    : 0;

  const maxPoints = complianceSummary
    ? complianceSummary.max_points ?? complianceSummary.max_score ?? 100
    : 100;

  const scorePercent = maxPoints ? Math.round((score / maxPoints) * 100) : 0;

  const controls =
    complianceSummary?.controls || complianceSummary?.breakdown || [];

  const statusBadge = (status) => {
    const normalized = (status || "").toLowerCase();
    if (normalized === "pass" || normalized === "ok" || normalized === "good") {
      return (
        <span className="inline-flex items-center text-emerald-400 text-xs">
          <span className="mr-1">✅</span> Passing
        </span>
      );
    }
    if (normalized === "warn" || normalized === "partial") {
      return (
        <span className="inline-flex items-center text-amber-400 text-xs">
          <span className="mr-1">⚠️</span> Needs attention
        </span>
      );
    }
    return (
      <span className="inline-flex items-center text-red-400 text-xs">
        <span className="mr-1">❌</span> Failing
      </span>
    );
  };

  // --------- Fix guidance builder ----------
  const guidanceItems = [];

  // S3 guidance
  if (s3Summary) {
    if (s3Summary.public_buckets > 0 || s3Summary.unencrypted_buckets > 0) {
      guidanceItems.push({
        id: "s3-security",
        title: "Harden S3 bucket security",
        why: "Public or unencrypted S3 buckets can expose sensitive data and are a common source of breaches and compliance findings.",
        how: [
          "Review which buckets truly need to be public. Lock down everything else.",
          "Enable 'Block public access' at the account and bucket level where possible.",
          "Turn on default bucket encryption (SSE-S3 or SSE-KMS) for all buckets that store any non-public data.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/s3/home?region=${region}#`,
        docsUrl:
          "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
        costNote:
          "Costs: Encryption itself is usually negligible; the main cost is S3 storage and requests you are already paying for.",
      });
    }
  }

  // CloudTrail guidance
  if (cloudTrailResult) {
    if (!cloudTrailResult.has_trail) {
      guidanceItems.push({
        id: "cloudtrail-enable",
        title: "Enable AWS CloudTrail (multi-region)",
        why: "CloudTrail records API calls in your account. Without it, you have almost no forensic trail for incidents and will fail most compliance audits.",
        how: [
          "In CloudTrail, create a new multi-region 'Organization' or 'Management account' trail.",
          "Send logs to a dedicated, locked-down S3 bucket (ideally in a log-archive account).",
          "Enable CloudTrail Insights if you want anomaly detection on API usage.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/cloudtrail/home?region=${region}#/trails`,
        docsUrl:
          "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
        costNote:
          "Costs: Typically a few USD/month for small environments (CloudTrail data + S3 storage).",
      });
    } else if (!cloudTrailResult.multi_region_trail) {
      guidanceItems.push({
        id: "cloudtrail-multiregion",
        title: "Upgrade CloudTrail to multi-region",
        why: "Single-region trails can miss activity in other regions, which is a common gap found in security reviews.",
        how: [
          "Edit your existing trail and enable 'Apply trail to all regions'.",
          "Confirm the S3 log bucket is in a centralized/log-archive account.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/cloudtrail/home?region=${region}#/configuration`,
        docsUrl:
          "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html",
        costNote:
          "Costs: Multi-region trails generate more events, but still usually low for personal/small accounts.",
      });
    }
  }

  // Config guidance
  if (configResult) {
    if (
      !configResult.recorder_configured ||
      !configResult.recording_enabled
    ) {
      guidanceItems.push({
        id: "config-enable",
        title: "Enable AWS Config recorder",
        why: "AWS Config tracks configuration changes over time. It is critical for investigations, drift detection, and many compliance controls.",
        how: [
          "In AWS Config, create a configuration recorder that records 'All resources'.",
          "Choose an S3 bucket to store Config snapshots and a delivery channel.",
          "Optionally enable Config rules (managed rules for CIS, PCI, etc.).",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/config/home?region=${region}#/getting-started`,
        docsUrl:
          "https://docs.aws.amazon.com/config/latest/developerguide/setting-up-aws-config.html",
        costNote:
          "Costs: Config charges per recorded configuration item. For small labs it’s usually a few dollars/month, but it can grow with resource count.",
      });
    }
  }

  // EBS encryption guidance
  if (ebsResult) {
    const hasUnencrypted =
      ebsResult.unencrypted_volume_ids &&
      ebsResult.unencrypted_volume_ids.length > 0;
    if (!ebsResult.default_encryption_enabled || hasUnencrypted) {
      guidanceItems.push({
        id: "ebs-encryption",
        title: "Enforce EBS volume encryption",
        why: "Unencrypted EBS volumes make it easier for attackers with snapshot access or stolen disks to read data in cleartext.",
        how: [
          "Enable 'Default encryption' for EBS in the EC2 settings for this region.",
          "Identify unencrypted volumes and plan to snapshot, copy as encrypted, and re-attach or recreate instances.",
          "Update any automation (CloudFormation/Terraform/AMIs) to create encrypted volumes by default.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/ec2/home?region=${region}#EBSEncryption:`,
        docsUrl:
          "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
        costNote:
          "Costs: Encrypted volumes cost the same as unencrypted; minor costs come from snapshot operations and data transfer.",
      });
    }
  }

  // IAM password policy guidance
  if (iamResult) {
    if (!iamResult.policy_present) {
      guidanceItems.push({
        id: "iam-password-policy",
        title: "Configure an IAM password policy",
        why: "Without a password policy, users can pick short or weak passwords, which is a classic compliance violation.",
        how: [
          "Go to IAM → Account settings → Password policy.",
          "Set minimum length (at least 12), and require numbers, symbols, and upper/lowercase characters.",
          "Enable password reuse prevention and a reasonable max password age.",
        ],
        consoleUrl:
          "https://console.aws.amazon.com/iam/home#/account_settings",
        docsUrl:
          "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
        costNote:
          "Costs: No direct cost — just small user friction, which is worth it for security.",
      });
    }
  }

  const anyResultsForGuidance =
    scanResult ||
    s3Summary ||
    cloudTrailResult ||
    configResult ||
    ebsResult ||
    iamResult;

  // --------- UI ----------
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

      <main className="flex-1 flex justify-center p-6">
        <div className="w-full max-w-6xl grid md:grid-cols-2 gap-6">
          {/* LEFT: Account + Actions */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-lg">
            <h2 className="text-lg font-semibold mb-1 text-indigo-300">
              Account &amp; Actions
            </h2>
            <p className="text-gray-400 mb-6 text-sm">
              Configure your AWS account and run checks. Each action updates the
              Compliance Score and Fix guidance.
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

            <h3 className="text-sm font-semibold text-gray-300 mb-2">
              Actions
            </h3>
            <div className="grid grid-cols-2 gap-3 mb-4">
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
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingCloudTrail ? "Checking..." : "CloudTrail"}
              </button>

              <button
                onClick={handleConfig}
                disabled={loadingConfig || !hasAccountConfig}
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingConfig ? "Checking..." : "Config"}
              </button>
              <button
                onClick={handleEbs}
                disabled={loadingEbs || !hasAccountConfig}
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
              >
                {loadingEbs ? "Checking..." : "EBS encryption"}
              </button>

              <button
                onClick={handleIam}
                disabled={loadingIam || !hasAccountConfig}
                className="bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
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

            <p className="text-xs text-gray-500 mt-2">
              Tip: Make sure your IAM role trust policy allows your app account
              and that Security Hub, CloudTrail, and Config are enabled in the
              selected region. Some checks may require additional AWS services
              (which can incur cost).
            </p>
          </div>

          {/* RIGHT: Compliance + Details + Guidance */}
          <div className="space-y-4">
            {/* Compliance Score */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h2 className="text-lg font-semibold text-indigo-300">
                    Compliance Score
                  </h2>
                  <p className="text-xs text-gray-400">
                    Based on latest checks
                  </p>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-bold text-emerald-400">
                    {scorePercent}%
                  </div>
                  <div className="text-xs text-gray-400">
                    ({score.toFixed(1)} / {maxPoints.toFixed(1)} points)
                  </div>
                </div>
              </div>

              <div className="w-full h-2 rounded-full bg-gray-800 overflow-hidden mb-3">
                <div
                  className="h-full bg-emerald-500 transition-all"
                  style={{ width: `${Math.min(scorePercent, 100)}%` }}
                />
              </div>

              {controls.length > 0 ? (
                <div className="space-y-1 text-xs">
                  {controls.map((c) => (
                    <div
                      key={c.id || c.name}
                      className="flex items-center justify-between"
                    >
                      <span className="text-gray-300">
                        {c.label || c.name || "Control"}
                      </span>
                      <div className="flex items-center gap-2">
                        {statusBadge(c.status)}
                        {typeof c.points === "number" &&
                          typeof c.max_points === "number" && (
                            <span className="text-gray-500">
                              {c.points}/{c.max_points}
                            </span>
                          )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-gray-500">
                  Run some checks on the left to populate your control
                  breakdown.
                </p>
              )}
            </div>

            {/* Details & Guidance */}
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 overflow-auto">
              <h2 className="text-lg font-semibold mb-3 text-indigo-300">
                Details
              </h2>

              {!scanResult &&
                !s3Summary &&
                !cloudTrailResult &&
                !configResult &&
                !ebsResult &&
                !iamResult && (
                  <p className="text-gray-400 text-sm mb-4">
                    No results yet. Run a scan or one of the individual checks
                    on the left to see details and remediation guidance here.
                  </p>
                )}

              {/* Security Hub */}
              {scanResult && (
                <section className="mb-5">
                  <h3 className="text-sm font-semibold text-gray-200 mb-1">
                    Security Hub scan
                  </h3>
                  <p className="text-xs text-gray-400 mb-1">
                    Findings:{" "}
                    <span className="text-gray-200 font-mono">
                      {scanResult.count}
                    </span>
                  </p>
                  <div className="text-xs text-gray-300 bg-black/50 rounded p-3 whitespace-pre-wrap font-mono">
                    {scanResult.summary}
                  </div>
                  <p className="text-[11px] text-gray-500 mt-1">
                    Tip: Security Hub aggregates findings from multiple AWS
                    services. Use this as your high-level risk overview.
                  </p>
                </section>
              )}

              {/* S3 Security */}
              {s3Summary && (
                <section className="mb-5">
                  <h3 className="text-sm font-semibold text-gray-200 mb-1">
                    S3 Security
                  </h3>
                  <p className="text-xs text-gray-300 mb-2">
                    Buckets:{" "}
                    <span className="font-mono">
                      {s3Summary.total_buckets}
                    </span>{" "}
                    • Public:{" "}
                    <span className="font-mono">
                      {s3Summary.public_buckets}
                    </span>{" "}
                    • Unencrypted:{" "}
                    <span className="font-mono">
                      {s3Summary.unencrypted_buckets}
                    </span>
                  </p>
                  <ul className="text-xs text-gray-300 space-y-1 max-h-32 overflow-auto">
                    {s3Summary.buckets.map((b) => (
                      <li
                        key={b.bucket}
                        className="flex justify-between border-b border-gray-800/60 pb-1"
                      >
                        <span>{b.bucket}</span>
                        <span className="text-[11px] text-gray-400">
                          {b.public ? "🌐 Public" : "🔒 Private"} •{" "}
                          {b.encryption_enabled
                            ? "🔐 Encrypted"
                            : "⚠️ No encryption"}
                        </span>
                      </li>
                    ))}
                  </ul>
                  {s3Summary.unencrypted_buckets > 0 && (
                    <p className="text-[11px] text-amber-400 mt-2">
                      Fix: Enable default bucket encryption and avoid public
                      access unless strictly required.
                    </p>
                  )}
                </section>
              )}

              {/* CloudTrail */}
              {cloudTrailResult && (
                <section className="mb-5">
                  <h3 className="text-sm font-semibold text-gray-200 mb-1">
                    CloudTrail
                  </h3>
                  {cloudTrailResult.has_trail ? (
                    <>
                      <p className="text-xs text-emerald-400 mb-1">
                        ✅ CloudTrail is enabled.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        Trails configured:{" "}
                        <span className="font-mono">
                          {cloudTrailResult.trail_count}
                        </span>{" "}
                        • Multi-region:{" "}
                        {cloudTrailResult.multi_region_trail ? "Yes" : "No"}
                      </p>
                      <p className="text-[11px] text-gray-500">
                        Best practice: Use a multi-region trail that sends logs
                        to a dedicated security/audit S3 bucket.
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-xs text-red-400 mb-1">
                        ❌ CloudTrail not enabled.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        CloudTrail records API activity in your AWS account.
                        It&apos;s required for most compliance frameworks
                        (SOC2, PCI, CIS, etc.).
                      </p>
                      <p className="text-[11px] text-gray-400 mb-1">
                        Fix: Create a multi-region trail and send logs to an S3
                        bucket in your log-archive account.
                      </p>
                      <a
                        href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html"
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-indigo-400 hover:underline"
                      >
                        Open AWS docs: Create a trail →
                      </a>
                    </>
                  )}
                </section>
              )}

              {/* Config */}
              {configResult && (
                <section className="mb-5">
                  <h3 className="text-sm font-semibold text-gray-200 mb-1">
                    AWS Config
                  </h3>
                  {configResult.recorder_configured &&
                  configResult.recording_enabled ? (
                    <>
                      <p className="text-xs text-emerald-400 mb-1">
                        ✅ AWS Config recorder is enabled.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        Recorders configured:{" "}
                        <span className="font-mono">
                          {configResult.recorder_count}
                        </span>
                      </p>
                      <p className="text-[11px] text-gray-500">
                        Config tracks configuration changes over time. Use it
                        with rules for continuous compliance.
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-xs text-red-400 mb-1">
                        ❌ AWS Config is not fully enabled.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        Config provides a history of resource configuration
                        changes, which is essential for investigations and
                        compliance evidence.
                      </p>
                      <p className="text-[11px] text-gray-400 mb-1">
                        Fix: Create a configuration recorder and enable
                        recording for all resources.
                      </p>
                      <a
                        href="https://docs.aws.amazon.com/config/latest/developerguide/setting-up-aws-config.html"
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-indigo-400 hover:underline"
                      >
                        Open AWS docs: Set up AWS Config →
                      </a>
                    </>
                  )}
                </section>
              )}

              {/* EBS Encryption */}
              {ebsResult && (
                <section className="mb-5">
                  <h3 className="text-sm font-semibold text-gray-200 mb-1">
                    EBS Encryption
                  </h3>
                  {ebsResult.default_encryption_enabled &&
                  (!ebsResult.unencrypted_volume_ids ||
                    ebsResult.unencrypted_volume_ids.length === 0) ? (
                    <>
                      <p className="text-xs text-emerald-400 mb-1">
                        ✅ Default EBS encryption is enabled and no
                        unencrypted volumes were detected.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        Total volumes checked:{" "}
                        <span className="font-mono">
                          {ebsResult.total_volumes}
                        </span>
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-xs text-red-400 mb-1">
                        ❌ EBS encryption is not fully compliant.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        Default encryption enabled:{" "}
                        {ebsResult.default_encryption_enabled ? "Yes" : "No"}
                        <br />
                        Total volumes:{" "}
                        <span className="font-mono">
                          {ebsResult.total_volumes}
                        </span>
                      </p>
                      {ebsResult.unencrypted_volume_ids &&
                        ebsResult.unencrypted_volume_ids.length > 0 && (
                          <p className="text-[11px] text-amber-400 mb-1">
                            Unencrypted volumes:{" "}
                            {ebsResult.unencrypted_volume_ids.join(", ")}
                          </p>
                        )}
                      <p className="text-[11px] text-gray-400 mb-1">
                        Fix: Enable default EBS encryption and migrate or
                        snapshot/restore unencrypted volumes to encrypted
                        ones.
                      </p>
                      <a
                        href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-indigo-400 hover:underline"
                      >
                        Open AWS docs: EBS encryption →
                      </a>
                    </>
                  )}
                </section>
              )}

              {/* IAM Password Policy */}
              {iamResult && (
                <section className="mb-5">
                  <h3 className="text-sm font-semibold text-gray-200 mb-1">
                    IAM Password Policy
                  </h3>
                  {iamResult.policy_present ? (
                    <>
                      <p className="text-xs text-emerald-400 mb-1">
                        ✅ An IAM password policy is configured.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        Min length:{" "}
                          <span className="font-mono">
                            {iamResult.minimum_password_length}
                          </span>
                        {" • "}
                        Requires symbols:{" "}
                        {iamResult.require_symbols ? "Yes" : "No"}
                        {" • "}
                        Requires numbers:{" "}
                        {iamResult.require_numbers ? "Yes" : "No"}
                      </p>
                      <p className="text-[11px] text-gray-500">
                        Best practice: Enforce strong length (≥ 12), require
                        symbols/numbers, and enable password reuse prevention.
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-xs text-red-400 mb-1">
                        ❌ No IAM password policy detected.
                      </p>
                      <p className="text-xs text-gray-300 mb-1">
                        Without a password policy, users can set weak passwords,
                        which is a common compliance failure.
                      </p>
                      <p className="text-[11px] text-gray-400 mb-1">
                        Fix: Configure an IAM password policy with minimum
                        length, complexity requirements, and rotation.
                      </p>
                      <a
                        href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
                        target="_blank"
                        rel="noreferrer"
                        className="text-[11px] text-indigo-400 hover:underline"
                      >
                        Open AWS docs: Set an account password policy →
                      </a>
                    </>
                  )}
                </section>
              )}

              {/* Fix Guidance */}
              {anyResultsForGuidance && (
                <section className="mt-6 border-t border-gray-800 pt-4">
                  <div className="flex items-center justify-between mb-2">
                    <h3 className="text-sm font-semibold text-indigo-300">
                      Fix guidance
                    </h3>
                    <span className="text-[11px] text-gray-500">
                      Human-readable steps + cost notes
                    </span>
                  </div>

                  {guidanceItems.length === 0 ? (
                    <p className="text-xs text-emerald-400">
                      All checks you&apos;ve run so far are passing. 🎉 Keep
                      running additional checks as you expand your environment.
                    </p>
                  ) : (
                    <div className="space-y-3">
                      {guidanceItems.map((item) => (
                        <div
                          key={item.id}
                          className="rounded-lg border border-gray-800 bg-black/40 p-3"
                        >
                          <div className="flex items-center justify-between mb-1">
                            <h4 className="text-xs font-semibold text-gray-100">
                              {item.title}
                            </h4>
                            <span className="text-[10px] text-amber-400">
                              Priority: High
                            </span>
                          </div>
                          <p className="text-[11px] text-gray-300 mb-1">
                            {item.why}
                          </p>
                          <ul className="list-disc list-inside text-[11px] text-gray-300 space-y-0.5 mb-1.5">
                            {item.how.map((step, idx) => (
                              <li key={idx}>{step}</li>
                            ))}
                          </ul>
                          {item.costNote && (
                            <p className="text-[10px] text-gray-400 mb-1">
                              <span className="font-semibold">Cost note: </span>
                              {item.costNote}
                            </p>
                          )}
                          <div className="flex flex-wrap gap-2 mt-1">
                            {item.consoleUrl && (
                              <a
                                href={item.consoleUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[11px] px-2 py-1 rounded border border-gray-700 bg-gray-900 hover:bg-gray-800 text-indigo-300"
                              >
                                View in AWS Console →
                              </a>
                            )}
                            {item.docsUrl && (
                              <a
                                href={item.docsUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[11px] px-2 py-1 rounded border border-gray-700 bg-gray-900 hover:bg-gray-800 text-gray-300"
                              >
                                Open AWS docs →
                              </a>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </section>
              )}

              {/* Optional “simulated environment” hint */}
              {!anyResultsForGuidance && (
                <p className="mt-4 text-[11px] text-gray-500">
                  Not ready to enable CloudTrail or Config in a real account?
                  You can still demo CloudAuditPro using a low-risk test account
                  or by walking through the guidance cards during a screen share.
                </p>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
