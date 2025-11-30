import React, { useState, useEffect } from "react";
import { useAuth } from "./AuthContext";
import { apiFetch } from "./apiClient";
import GlowDot from "./GlowDot";

const APP_VERSION = import.meta.env.VITE_APP_VERSION || "v0.1.0";

const CHECK_LABELS = {
  security_hub: "Security Hub",
  s3: "S3",
  cloudtrail: "CloudTrail",
  config: "Config",
  ebs: "EBS encryption",
  iam: "IAM password policy",
  compliance: "Compliance score",
};

export default function App({ user, onLogout }) {
  const { token } = useAuth();

  // --------- Form state ----------
  const [accountId, setAccountId] = useState("");
  const [roleName, setRoleName] = useState("CloudAuditProReadRole");
  const [region, setRegion] = useState("us-east-1");
  const [emailTo, setEmailTo] = useState("");

  // --------- Saved AWS accounts (multi-account) ----------
  const [awsAccounts, setAwsAccounts] = useState([]);
  const [selectedAwsAccountId, setSelectedAwsAccountId] = useState("");
  const [loadingAwsAccounts, setLoadingAwsAccounts] = useState(false);

  // --------- Results / state ----------
  const [scanResult, setScanResult] = useState(null);
  const [s3Summary, setS3Summary] = useState(null);
  const [cloudTrailResult, setCloudTrailResult] = useState(null);
  const [configResult, setConfigResult] = useState(null);
  const [ebsResult, setEbsResult] = useState(null);
  const [iamResult, setIamResult] = useState(null);
  const [complianceSummary, setComplianceSummary] = useState(null);

  // Run/Refresh compliance
  const [hasRunCompliance, setHasRunCompliance] = useState(false);

  // Recently fixed + check history
  const [recentlyFixed, setRecentlyFixed] = useState([]);
  const [lastCheckStatus, setLastCheckStatus] = useState({}); // { id: { label, passed } }

  // Which checks have been run this session
  const [checksRun, setChecksRun] = useState([]); // ['security_hub', 's3', ...]

  // Toast for new fixes
  const [toast, setToast] = useState(null); // { label, via }

  // AWS inventory
  const [ec2Inventory, setEc2Inventory] = useState(null);
  const [vpcInventory, setVpcInventory] = useState(null);
  const [rdsInventory, setRdsInventory] = useState(null);
  const [sgInventory, setSgInventory] = useState(null);

  const [loadingEc2, setLoadingEc2] = useState(false);
  const [loadingVpc, setLoadingVpc] = useState(false);
  const [loadingRds, setLoadingRds] = useState(false);
  const [loadingSg, setLoadingSg] = useState(false);
  const [selectedSecurityGroup, setSelectedSecurityGroup] = useState(null);
  const [showSgModal, setShowSgModal] = useState(false);  

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

  // Details tabs: overview vs recently-fixed
  const [detailsTab, setDetailsTab] = useState("overview"); // "overview" | "recent"

  const hasAccountConfig = accountId && roleName && region;

  const commonBody = {
    account_id: accountId,
    role_name: roleName,
    region: region,
  };

  const isSyncing =
    loadingScan ||
    loadingS3 ||
    loadingCloudTrail ||
    loadingConfig ||
    loadingEbs ||
    loadingIam ||
    loadingCompliance ||
    loadingEc2 ||
    loadingVpc ||
    loadingRds ||
    loadingSg;

  const markCheckRun = (id) => {
    setChecksRun((prev) => (prev.includes(id) ? prev : [...prev, id]));
  };

  // --------- Toast auto-hide ----------
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(timer);
  }, [toast]);

  // --------- Fetch saved AWS accounts for this user ----------
  useEffect(() => {
    const fetchAwsAccounts = async () => {
      if (!token) {
        setAwsAccounts([]);
        setSelectedAwsAccountId("");
        return;
      }
      try {
        setLoadingAwsAccounts(true);
        const data = await apiFetch("/aws-accounts", {
          token,
          method: "GET",
        });
        setAwsAccounts(data || []);
      } catch (err) {
        console.error("Failed to load AWS accounts:", err);
      } finally {
        setLoadingAwsAccounts(false);
      }
    };

    fetchAwsAccounts();
  }, [token]);

  // --------- Helper: record "recently fixed" from status changes ----------
  const recordFixedChanges = (updates, sourceLabel) => {
    // updates: { id: { label, passed } }
    const now = new Date().toISOString();

    setLastCheckStatus((prevStatus) => {
      const nextStatus = { ...prevStatus };
      const newlyFixed = [];

      Object.entries(updates).forEach(([id, { label, passed }]) => {
        const prevPassed =
          prevStatus[id] && typeof prevStatus[id].passed === "boolean"
            ? prevStatus[id].passed
            : null;

        nextStatus[id] = { label, passed };

        // Only count as "fixed" if it was previously failing (false) and now passes (true)
        if (prevPassed === false && passed === true) {
          newlyFixed.push({
            id,
            label: label || id,
            via: sourceLabel,
            at: now,
          });
        }
      });

      if (newlyFixed.length > 0) {
        setRecentlyFixed((prev) => {
          const existingIds = new Set(prev.map((f) => f.id));
          const dedupAdds = newlyFixed.filter((f) => !existingIds.has(f.id));
          if (dedupAdds.length === 0) return prev;
          const merged = [...dedupAdds, ...prev];
          return merged.slice(0, 10);
        });

        // Show a toast for the first newly fixed item
        setToast({
          label: newlyFixed[0].label,
          via: newlyFixed[0].via,
        });
      }

      return nextStatus;
    });
  };

  // --------- Compliance summary fetch ----------
  const runComplianceSummary = async () => {
    if (!hasAccountConfig) return;
    try {
      setLoadingCompliance(true);
      setError("");

      const data = await apiFetch("/compliance/summary", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });

      setComplianceSummary(data);
      setHasRunCompliance(true);
      markCheckRun("compliance");

      // Build update map for "Recently fixed"
      const updates = {};
      (data.checks || []).forEach((c) => {
        updates[c.id || c.label || "unknown"] = {
          label: c.label || c.id || "Control",
          passed: !!c.passed,
        };
      });

      recordFixedChanges(updates, "Compliance score");
    } catch (err) {
      console.error("Compliance summary error:", err);
      setError(err.message || "Failed to run compliance score");
    } finally {
      setLoadingCompliance(false);
    }
  };

  // --------- Reset results when account config changes ----------
  useEffect(() => {
    setComplianceSummary(null);
    setScanResult(null);
    setS3Summary(null);
    setCloudTrailResult(null);
    setConfigResult(null);
    setEbsResult(null);
    setIamResult(null);
    setHasRunCompliance(false);
    setRecentlyFixed([]);
    setLastCheckStatus({});
    setToast(null);
    setChecksRun([]);
    setEc2Inventory(null);
    setVpcInventory(null);
    setRdsInventory(null);
    setSgInventory(null);
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
      markCheckRun("security_hub");

      // Determine pass/fail for Security Hub
      const passed = data.count === 0;
      recordFixedChanges(
        {
          security_hub: {
            label: "Security Hub findings",
            passed,
          },
        },
        "Security Hub scan"
      );
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
      // Email doesn't change pass/fail, so no recently-fixed update here.
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
      markCheckRun("s3");

      const total = data.total_buckets || 0;
      const publicBuckets = data.public_buckets || 0;
      const unencrypted = data.unencrypted_buckets || 0;
      const passed = total > 0 && publicBuckets === 0 && unencrypted === 0;

      recordFixedChanges(
        {
          s3_baseline: {
            label: "S3 public access & encryption",
            passed,
          },
        },
        "S3 security check"
      );
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
      markCheckRun("cloudtrail");

      const passed = !!(data.has_trail && data.multi_region_trail);
      recordFixedChanges(
        {
          cloudtrail: {
            label: "CloudTrail multi-region trail",
            passed,
          },
        },
        "CloudTrail check"
      );
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
      markCheckRun("config");

      const passed =
        !!data.recorder_configured && !!data.recording_enabled;
      recordFixedChanges(
        {
          config: {
            label: "AWS Config recorder enabled",
            passed,
          },
        },
        "Config check"
      );
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
      markCheckRun("ebs");

      const unencList = data.unencrypted_volume_ids || [];
      const passed =
        !!data.default_encryption_enabled && unencList.length === 0;

      recordFixedChanges(
        {
          ebs_encryption: {
            label: "EBS default encryption",
            passed,
          },
        },
        "EBS encryption check"
      );
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
      markCheckRun("iam");

      const passed = !!data.policy_present;
      recordFixedChanges(
        {
          iam_password_policy: {
            label: "IAM password policy configured",
            passed,
          },
        },
        "IAM password policy check"
      );
    } catch (err) {
      console.error("IAM password policy error:", err);
      setError(err.message || "IAM password policy check failed");
    } finally {
      setLoadingIam(false);
    }
  };

  // --------- AWS Inventory handlers ----------
  const handleEc2Inventory = async () => {
    setLoadingEc2(true);
    setError("");
    setEc2Inventory(null);

    try {
      const data = await apiFetch("/inventory/ec2", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });
      setEc2Inventory(data);
      markCheckRun("ec2_inventory");
    } catch (err) {
      console.error("EC2 inventory error:", err);
      setError(err.message || "Failed to load EC2 inventory");
    } finally {
      setLoadingEc2(false);
    }
  };

  const handleVpcInventory = async () => {
    setLoadingVpc(true);
    setError("");
    setVpcInventory(null);

    try {
      const data = await apiFetch("/inventory/vpc", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });
      setVpcInventory(data);
      markCheckRun("vpc_inventory");
    } catch (err) {
      console.error("VPC inventory error:", err);
      setError(err.message || "Failed to load VPC inventory");
    } finally {
      setLoadingVpc(false);
    }
  };

  const handleRdsInventory = async () => {
    setLoadingRds(true);
    setError("");
    setRdsInventory(null);

    try {
      const data = await apiFetch("/inventory/rds", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });
      setRdsInventory(data);
      markCheckRun("rds_inventory");
    } catch (err) {
      console.error("RDS inventory error:", err);
      setError(err.message || "Failed to load RDS inventory");
    } finally {
      setLoadingRds(false);
    }
  };

  const handleSgInventory = async () => {
    setLoadingSg(true);
    setError("");
    setSgInventory(null);

    try {
      const data = await apiFetch("/inventory/sg", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });
      setSgInventory(data);
      markCheckRun("sg_inventory");
    } catch (err) {
      console.error("Security Group inventory error:", err);
      setError(err.message || "Failed to load Security Group inventory");
    } finally {
      setLoadingSg(false);
    }
  };



  // --------- Saved AWS accounts handlers ----------
  const handleSelectAwsAccount = (e) => {
    const id = e.target.value;
    setSelectedAwsAccountId(id);

    const acc = awsAccounts.find((a) => String(a.id) === String(id));
    if (acc) {
      setAccountId(acc.account_id || "");
      setRoleName(acc.role_name || "CloudAuditProReadRole");
      setRegion(acc.region || "us-east-1");
    }
  };

  const saveCurrentAwsAccount = async () => {
    if (!accountId) {
      alert("Please enter an AWS Account ID before saving.");
      return;
    }
    try {
      const cleanAccountId = accountId.trim();
      const cleanRoleName = (roleName || "CloudAuditProReadRole").trim();
      const cleanRegion = (region || "us-east-1").trim();
      const display_name = `${cleanAccountId} (${cleanRegion})`;

      if (selectedAwsAccountId) {
        // Update existing
        const updated = await apiFetch(`/aws-accounts/${selectedAwsAccountId}`, {
          token,
          method: "PUT",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            display_name,
            account_id: cleanAccountId,
            role_name: cleanRoleName,
            region: cleanRegion,
          }),
        });

        setAwsAccounts((prev) =>
          prev.map((a) =>
            String(a.id) === String(selectedAwsAccountId) ? updated : a
          )
        );
      } else {
        // Create new
        const created = await apiFetch("/aws-accounts", {
          token,
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            display_name,
            account_id: cleanAccountId,
            role_name: cleanRoleName,
            region: cleanRegion,
          }),
        });

        setAwsAccounts((prev) => [created, ...prev]);
        setSelectedAwsAccountId(String(created.id));
      }
    } catch (err) {
      console.error("Failed to save AWS account:", err);
      alert(err.message || "Failed to save AWS account");
    }
  };

  const deleteSelectedAwsAccount = async () => {
    if (!selectedAwsAccountId) return;
    if (!window.confirm("Delete this saved AWS account?")) return;

    try {
      await apiFetch(`/aws-accounts/${selectedAwsAccountId}`, {
        token,
        method: "DELETE",
      });

      setAwsAccounts((prev) =>
        prev.filter((a) => String(a.id) !== String(selectedAwsAccountId))
      );
      setSelectedAwsAccountId("");
    } catch (err) {
      console.error("Failed to delete AWS account:", err);
      alert(err.message || "Failed to delete AWS account");
    }
  };

  // --------- Compliance helpers ----------
  const score = complianceSummary ? complianceSummary.score ?? 0 : 0;
  const scorePercent = Math.round(score); // already 0–100 from backend
  const controls = complianceSummary?.checks || [];

  const statusBadgeFromPassed = (passed) => {
    if (passed === true) {
      return (
        <span className="inline-flex items-center text-emerald-400 text-xs">
          <span className="mr-1">✅</span> Passing
        </span>
      );
    }
    if (passed === false) {
      return (
        <span className="inline-flex items-center text-red-400 text-xs">
          <span className="mr-1">❌</span> Failing
        </span>
      );
    }
    return (
      <span className="inline-flex items-center text-amber-400 text-xs">
        <span className="mr-1">⚠️</span> Unknown
      </span>
    );
  };

  const renderSecurityGroupRisk = (g) => {
    // These booleans should come from your backend payload
    const worldOpen = !!g.world_open;
    const sshOpen = !!g.ssh_22_open;
    const rdpOpen = !!g.rdp_3389_open;
    const webOpen = Array.isArray(g.web_ports) && g.web_ports.length > 0;
  
    if (worldOpen && (sshOpen || rdpOpen || webOpen)) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-red-900/50 border border-red-500/70 text-red-200">
          🔥 <span>High</span>
        </span>
      );
    }
  
    if (worldOpen) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-amber-900/40 border border-amber-500/70 text-amber-200">
          ⚠️ <span>Medium</span>
        </span>
      );
    }
  
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-emerald-900/40 border border-emerald-500/70 text-emerald-200">
        ✅ <span>Low</span>
      </span>
    );
  };

// --------- Derived summary for Security Groups ----------
// Support a few possible shapes from the backend just in case
const sgGroupsRaw =
  (sgInventory &&
    (sgInventory.groups ||
      sgInventory.security_groups ||
      sgInventory.items)) ||
  [];

const sgGroups = Array.isArray(sgGroupsRaw) ? sgGroupsRaw : [];

const sgWorldOpenCount = sgGroups.filter((g) => g.world_open).length;
const sgSshOpenCount = sgGroups.filter((g) => g.ssh_22_open).length;
const sgRdpOpenCount = sgGroups.filter((g) => g.rdp_3389_open).length;
const sgWebOpenCount = sgGroups.filter(
  (g) => Array.isArray(g.web_ports) && g.web_ports.length > 0
).length;


  // Pulse color for overall score
  const scorePulseColor = !hasRunCompliance
    ? "bg-slate-500"
    : scorePercent >= 80
    ? "bg-emerald-400"
    : scorePercent >= 50
    ? "bg-amber-400"
    : "bg-red-500";

  // --------- Fix guidance builder ----------
  const guidanceItems = [];

  // S3 guidance
  if (s3Summary) {
    if (
      s3Summary.public_buckets > 0 ||
      s3Summary.unencrypted_buckets > 0
    ) {
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
          "Encryption cost is usually negligible; primary cost is S3 storage and requests you already pay for.",
      });
    }
  }

  // CloudTrail guidance
  if (cloudTrailResult) {
    if (!cloudTrailResult.has_trail) {
      guidanceItems.push({
        id: "cloudtrail-enable",
        title: "Enable AWS CloudTrail (multi-region)",
        why: "CloudTrail records API calls in your account. Without it, you have almost no forensic trail and will fail most audits.",
        how: [
          "In CloudTrail, create a new multi-region trail.",
          "Send logs to a dedicated, locked-down S3 bucket (ideally in a log-archive account).",
          "Optionally enable CloudTrail Insights for anomaly detection.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/cloudtrail/home?region=${region}#/trails`,
        docsUrl:
          "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html",
        costNote:
          "Typically a few USD/month for small environments (CloudTrail events + S3 storage).",
      });
    } else if (!cloudTrailResult.multi_region_trail) {
      guidanceItems.push({
        id: "cloudtrail-multiregion",
        title: "Upgrade CloudTrail to multi-region",
        why: "Single-region trails can miss activity in other regions, creating blind spots in investigations.",
        how: [
          "Edit your existing trail and enable 'Apply trail to all regions'.",
          "Confirm the S3 log bucket is centralized and secured.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/cloudtrail/home?region=${region}#/configuration`,
        docsUrl:
          "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html",
        costNote:
          "Multi-region trails generate more events, but still low cost for personal/small accounts.",
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
        why: "AWS Config tracks configuration changes over time. It’s critical for investigations, drift detection, and compliance.",
        how: [
          "In AWS Config, create a configuration recorder that records 'All resources'.",
          "Choose an S3 bucket and delivery channel for snapshots.",
          "Optionally enable managed Config rules for CIS/PCI baselines.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/config/home?region=${region}#/getting-started`,
        docsUrl:
          "https://docs.aws.amazon.com/config/latest/developerguide/setting-up-aws-config.html",
        costNote:
          "Config charges per recorded configuration item; for small labs, often a few dollars/month.",
      });
    }
  }

  // EBS guidance
  if (ebsResult) {
    const unencList = ebsResult.unencrypted_volume_ids || [];
    if (
      !ebsResult.default_encryption_enabled ||
      unencList.length > 0
    ) {
      guidanceItems.push({
        id: "ebs-encryption",
        title: "Enforce EBS volume encryption",
        why: "Unencrypted EBS volumes make it easier for attackers to read data from stolen disks or snapshots.",
        how: [
          "Enable 'Default encryption' for EBS in the EC2 settings for this region.",
          "Identify unencrypted volumes and plan to snapshot and restore them as encrypted.",
          "Update your automation (CloudFormation/Terraform) to create encrypted volumes by default.",
        ],
        consoleUrl: `https://${region}.console.aws.amazon.com/ec2/home?region=${region}#EBSEncryption:`,
        docsUrl:
          "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html",
        costNote:
          "Encrypted volumes cost the same as unencrypted; extra costs come from snapshot/restore operations.",
      });
    }
  }

  // IAM guidance
  if (iamResult) {
    if (!iamResult.policy_present) {
      guidanceItems.push({
        id: "iam-password-policy",
        title: "Configure an IAM password policy",
        why: "Without a password policy, users can pick weak passwords, which is a common compliance failure.",
        how: [
          "Go to IAM → Account settings → Password policy.",
          "Set minimum length (≥ 12), and require numbers, symbols, and upper/lowercase characters.",
          "Enable password reuse prevention and configure password expiration if required.",
        ],
        consoleUrl:
          "https://console.aws.amazon.com/iam/home#/account_settings",
        docsUrl:
          "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html",
        costNote:
          "No direct AWS cost — just a bit more friction for users, which is worth it.",
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

  const mostRecentFixed = recentlyFixed[0];

  const checksRunLabels = checksRun.map((id) => CHECK_LABELS[id] || id);
  const checksRunSummary =
    checksRunLabels.length === 0
      ? "—"
      : checksRunLabels.length <= 3
      ? checksRunLabels.join(", ")
      : `${checksRunLabels.slice(0, 3).join(", ")} +${
          checksRunLabels.length - 3
        } more`;

  // --------- UI ----------
  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-br from-indigo-950 via-slate-950 to-gray-950 text-gray-100">
      {/* Toast for recently fixed */}
      {toast && (
        <div className="fixed top-4 right-4 z-50">
          <div className="flex items-start gap-2 rounded-xl border border-emerald-500/60 bg-emerald-950/95 px-4 py-3 shadow-lg shadow-emerald-900/40 text-xs text-emerald-100">
            <span className="mt-0.5">✨</span>
            <div>
              <div className="font-semibold">
                {toast.label} is now passing
              </div>
              <div className="text-[11px] text-emerald-200/80">
                Detected via {toast.via}. Nice fix.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Top bar */}
      <header className="w-full border-b border-indigo-900/60 px-6 py-3 flex items-center justify-between bg-black/40 backdrop-blur">
        <div className="flex items-center gap-3">
          <GlowDot size={16} />
          <div className="flex items-center gap-2">
            <span className="text-xl font-bold tracking-tight text-indigo-300">
              CloudAuditPro
            </span>
            <span className="text-[10px] md:text-xs text-indigo-200/80 border border-indigo-500/40 rounded-full px-2 py-0.5">
              v{APP_VERSION}
            </span>
            <span className="hidden md:inline text-xs text-indigo-200/70">
              • AWS Security &amp; Compliance Dashboard
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4 text-sm">
          {/* Marketing / info links – open in new tab */}
          <a
            href="/about"
            target="_blank"
            rel="noreferrer"
            className="text-xs md:text-sm text-indigo-200 hover:text-white underline-offset-4 hover:underline"
          >
            About
          </a>
          <a
            href="/security"
            target="_blank"
            rel="noreferrer"
            className="text-xs md:text-sm text-indigo-200 hover:text-white underline-offset-4 hover:underline"
          >
            Security
          </a>
          <a
            href="/how-it-works"
            target="_blank"
            rel="noreferrer"
            className="text-xs md:text-sm text-indigo-200 hover:text-white underline-offset-4 hover:underline"
          >
            How it works
          </a>

          {isSyncing && (
            <div className="flex items-center gap-2 text-[11px] text-amber-300">
              <span className="relative flex h-3 w-3">
                <span className="absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75 animate-ping" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-amber-400" />
              </span>
              <span>System syncing checks…</span>
            </div>
          )}

          {user && (
            <span className="text-gray-200 hidden sm:inline">
              {user.email}
            </span>
          )}
          {onLogout && (
            <button
              onClick={onLogout}
              className="px-3 py-1 rounded-lg bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-400/60 text-xs text-indigo-100"
            >
              Log out
            </button>
          )}
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 px-6 py-6">
        <div className="max-w-7xl mx-auto space-y-6">
          {/* SUMMARY STRIP */}
          <section className="grid gap-4 md:grid-cols-3">
            {/* Summary: Compliance Score */}
            <div className="bg-black/40 border border-indigo-900/70 rounded-2xl px-5 py-4 flex flex-col justify-between shadow-lg shadow-indigo-900/40">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 text-[11px] text-indigo-200/80">
                  <GlowDot size={12} />
                  <span className="uppercase tracking-[0.18em] text-indigo-300">
                    Compliance score
                  </span>
                </div>
                <span className="text-[10px] text-indigo-300/80">
                  Based on latest run
                </span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {hasRunCompliance && (
                    <div className="relative flex h-4 w-4">
                      <span
                        className={`absolute inline-flex h-full w-full rounded-full ${scorePulseColor} opacity-75 animate-ping`}
                      ></span>
                      <span
                        className={`relative inline-flex rounded-full h-4 w-4 ${scorePulseColor}`}
                      ></span>
                    </div>
                  )}
                  <div>
                    <div className="text-xs text-gray-400">
                      Overall pass rate
                    </div>
                    <div className="text-[11px] text-gray-500">
                      Run or refresh from Reporting card.
                    </div>
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-2xl font-semibold text-emerald-400">
                    {hasRunCompliance ? `${scorePercent}%` : "--"}
                  </div>
                </div>
              </div>
            </div>

            {/* Summary: Checks run */}
            <div className="bg-black/40 border border-indigo-900/70 rounded-2xl px-5 py-4 flex flex-col justify-between shadow-lg shadow-indigo-900/40">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 text-[11px] text-indigo-200/80">
                  <span className="h-2 w-2 rounded-full bg-sky-400" />
                  <span className="uppercase tracking-[0.18em] text-indigo-300">
                    Checks run this session
                  </span>
                </div>
                <span className="text-[10px] text-indigo-300/80">
                  Security Hub, S3, more
                </span>
              </div>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-2xl font-semibold text-sky-300">
                    {checksRun.length}
                  </div>
                  <div className="text-[11px] text-gray-400 mt-1 line-clamp-2">
                    {checksRunSummary}
                  </div>
                </div>
              </div>
            </div>

            {/* Summary: Recently fixed */}
            <div className="bg-black/40 border border-indigo-900/70 rounded-2xl px-5 py-4 flex flex-col justify-between shadow-lg shadow-indigo-900/40">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2 text-[11px] text-emerald-200/90">
                  <span className="relative flex h-3 w-3">
                    <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400/80 opacity-70 blur-[2px] animate-ping"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-400"></span>
                  </span>
                  <span className="uppercase tracking-[0.18em] text-emerald-300">
                    Recently fixed
                  </span>
                </div>
                <span className="text-[10px] text-emerald-200/80">
                  {recentlyFixed.length > 0
                    ? `${recentlyFixed.length} controls`
                    : "Waiting for first fix"}
                </span>
              </div>
              <div>
                {mostRecentFixed ? (
                  <>
                    <div className="text-xs text-emerald-100 font-semibold">
                      {mostRecentFixed.label}
                    </div>
                    <div className="text-[11px] text-emerald-200/80">
                      Detected via {mostRecentFixed.via}.
                    </div>
                  </>
                ) : (
                  <div className="text-[11px] text-gray-400">
                    When a failing control becomes passing, it will show up
                    here.
                  </div>
                )}
              </div>
            </div>
          </section>

          {/* MAIN GRID */}
          <section className="grid gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1.3fr)]">
            {/* LEFT: Account + Actions + Reporting */}
            <div className="space-y-4">
              {/* Account & Actions card */}
              <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/40">
                <h2 className="text-lg font-semibold mb-1 text-indigo-200">
                  Account &amp; Actions
                </h2>
                <p className="text-gray-400 mb-6 text-sm">
                  Configure your AWS account and run checks. Each action can
                  improve your Compliance Score and Fix guidance.
                </p>

                <label className="block mb-3 text-sm">
                  AWS Account ID
                  <input
                    className="mt-1 w-full bg-slate-950/80 border border-indigo-800 rounded px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
                    value={accountId}
                    onChange={(e) => setAccountId(e.target.value)}
                    placeholder="123456789012"
                  />
                </label>

                <label className="block mb-3 text-sm">
                  IAM Role Name
                  <input
                    className="mt-1 w-full bg-slate-950/80 border border-indigo-800 rounded px-3 py-2 text-sm"
                    value={roleName}
                    onChange={(e) => setRoleName(e.target.value)}
                  />
                  <span className="text-xs text-gray-500">
                    This should match the role from your CloudFormation
                    template.
                  </span>
                </label>

                <label className="block mb-3 text-sm">
                  AWS Region
                  <input
                    className="mt-1 w-full bg-slate-950/80 border border-indigo-800 rounded px-3 py-2 text-sm"
                    value={region}
                    onChange={(e) => setRegion(e.target.value)}
                    placeholder="us-east-1"
                  />
                </label>

                {/* Saved AWS accounts (multi-account support) */}
                <div className="mt-1 mb-5 border border-slate-800 rounded-xl bg-slate-950/70 p-3">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-semibold text-indigo-200">
                      Saved AWS accounts
                    </span>
                    {awsAccounts.length > 0 && (
                      <span className="text-[10px] text-slate-400">
                        {awsAccounts.length} account
                        {awsAccounts.length > 1 ? "s" : ""} stored
                      </span>
                    )}
                  </div>

                  <div className="flex flex-col sm:flex-row gap-2">
                    <select
                      className="flex-1 bg-slate-950/80 border border-indigo-800 rounded px-3 py-1.5 text-xs"
                      value={selectedAwsAccountId}
                      onChange={handleSelectAwsAccount}
                    >
                      <option value="">
                        {loadingAwsAccounts
                          ? "Loading accounts..."
                          : awsAccounts.length === 0
                          ? "No saved accounts yet"
                          : "Select a saved account"}
                      </option>
                      {awsAccounts.map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.display_name || `${a.account_id} (${a.region})`}
                        </option>
                      ))}
                    </select>

                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={saveCurrentAwsAccount}
                        className="px-3 py-1.5 rounded bg-indigo-500 hover:bg-indigo-600 text-[11px] text-white whitespace-nowrap"
                      >
                        Save current
                      </button>
                      <button
                        type="button"
                        onClick={deleteSelectedAwsAccount}
                        disabled={!selectedAwsAccountId}
                        className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-[11px] text-slate-100 whitespace-nowrap"
                      >
                        Delete
                      </button>
                    </div>
                  </div>

                  <p className="mt-2 text-[10px] text-slate-400">
                    Saved AWS accounts are stored in your CloudAuditPro
                    account and follow you across browsers and devices.
                  </p>
                </div>

                {error && (
                  <div className="bg-red-500/10 border border-red-600 text-red-200 text-xs rounded p-3 mb-4">
                    {error}
                  </div>
                )}

                <h3 className="text-sm font-semibold text-gray-200 mb-2">
                  Checks
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mb-4">
                  <button
                    onClick={handleScan}
                    disabled={loadingScan || !hasAccountConfig}
                    className="bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingScan ? "Running scan..." : "Security Hub scan"}
                  </button>
                  <button
                    onClick={handleS3Summary}
                    disabled={loadingS3 || !hasAccountConfig}
                    className="bg-emerald-500 hover:bg-emerald-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingS3 ? "Checking S3..." : "S3 security"}
                  </button>

                  <button
                    onClick={handleCloudTrail}
                    disabled={loadingCloudTrail || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingCloudTrail ? "Checking..." : "CloudTrail"}
                  </button>

                  <button
                    onClick={handleConfig}
                    disabled={loadingConfig || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingConfig ? "Checking..." : "Config"}
                  </button>

                  <button
                    onClick={handleEbs}
                    disabled={loadingEbs || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingEbs ? "Checking..." : "EBS encryption"}
                  </button>

                  <button
                    onClick={handleIam}
                    disabled={loadingIam || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingIam ? "Checking..." : "IAM password policy"}
                  </button>
                </div>

                {/* Inventory buttons */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
                  <button
                    onClick={handleEc2Inventory}
                    disabled={loadingEc2 || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingEc2 ? "Loading..." : "EC2 inventory"}
                  </button>

                  <button
                    onClick={handleVpcInventory}
                    disabled={loadingVpc || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingVpc ? "Loading..." : "VPC / network"}
                  </button>

                  <button
                    onClick={handleRdsInventory}
                    disabled={loadingRds || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingRds ? "Loading..." : "RDS inventory"}
                  </button>

                  <button
                    onClick={handleSgInventory}
                    disabled={loadingSg || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingSg ? "Loading..." : "Security groups"}
                  </button>
                </div>




                <p className="text-xs text-gray-500 mt-2">
                  Tip: Make sure your IAM role trust policy allows your app
                  account and that Security Hub, CloudTrail, and Config are
                  enabled in the selected region. Some checks may require
                  additional AWS services (which can incur cost).
                </p>
              </div>

              {/* Reporting & Score card */}
              <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/40">
                <h2 className="text-lg font-semibold mb-1 text-indigo-200">
                  Reporting &amp; Score
                </h2>
                <p className="text-gray-400 mb-4 text-sm">
                  Email yourself a report and run the overall compliance
                  score.
                </p>

                <label className="block mb-4 text-sm">
                  Report email (optional)
                  <input
                    className="mt-1 w-full bg-slate-950/80 border border-indigo-800 rounded px-3 py-2 text-sm"
                    value={emailTo}
                    onChange={(e) => setEmailTo(e.target.value)}
                    placeholder="you@gmail.com"
                  />
                  <span className="text-xs text-gray-500">
                    Leave blank to use your default recipient (if configured).
                  </span>
                </label>

                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={handleEmailReport}
                    disabled={loadingEmail || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingEmail ? "Sending..." : "Email report"}
                  </button>
                  <button
                    onClick={runComplianceSummary}
                    disabled={loadingCompliance || !hasAccountConfig}
                    className="bg-indigo-500 hover:bg-indigo-600 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingCompliance
                      ? "Calculating..."
                      : hasRunCompliance
                      ? "Refresh score"
                      : "Run compliance score"}
                  </button>
                </div>
              </div>
            </div>

            {/* RIGHT: Compliance + Details + Guidance */}
            <div className="space-y-4">
              {/* Compliance Score */}
              <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/40">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h2 className="text-lg font-semibold text-indigo-200">
                      Compliance Score
                    </h2>
                    <p className="text-xs text-gray-400">
                      Based on latest compliance run
                    </p>
                  </div>
                  <div className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      {hasRunCompliance && (
                        <div className="relative flex h-3 w-3">
                          <span
                            className={`absolute inline-flex h-full w-full rounded-full ${scorePulseColor} opacity-75 animate-ping`}
                          ></span>
                          <span
                            className={`relative inline-flex rounded-full h-3 w-3 ${scorePulseColor}`}
                          ></span>
                        </div>
                      )}
                      <div className="text-2xl font-bold text-emerald-400">
                        {hasRunCompliance ? `${scorePercent}%` : "--"}
                      </div>
                    </div>
                    {hasRunCompliance && (
                      <div className="text-xs text-gray-400">
                        Overall pass rate
                      </div>
                    )}
                  </div>
                </div>

                <div className="w-full h-2 rounded-full bg-slate-900 overflow-hidden mb-3">
                  <div
                    className="h-full bg-emerald-500 transition-all"
                    style={{
                      width: hasRunCompliance
                        ? `${Math.min(scorePercent, 100)}%`
                        : "0%",
                    }}
                  />
                </div>

                {controls.length > 0 ? (
                  <div className="space-y-1 text-xs">
                    {controls.map((c) => (
                      <div
                        key={c.id || c.label}
                        className="flex items-center justify-between"
                      >
                        <span className="text-gray-300">
                          {c.label || c.id || "Control"}
                        </span>
                        <div className="flex items-center gap-2">
                          <div className="relative flex h-2.5 w-2.5">
                            <span
                              className={`absolute inline-flex h-full w-full rounded-full ${
                                c.passed ? "bg-emerald-400" : "bg-red-500"
                              } opacity-75 animate-ping`}
                            ></span>
                            <span
                              className={`relative inline-flex rounded-full h-2.5 w-2.5 ${
                                c.passed ? "bg-emerald-400" : "bg-red-500"
                              }`}
                            ></span>
                          </div>
                          {statusBadgeFromPassed(c.passed)}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-gray-500">
                    Run the compliance score from the left to populate this
                    section.
                  </p>
                )}
              </div>

              {/* Details & Guidance */}
              <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/40">
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-lg font-semibold text-indigo-200">
                    Details &amp; Guidance
                  </h2>
                  <div className="inline-flex rounded-full border border-indigo-700/60 bg-slate-950/60 text-[11px]">
                    <button
                      className={`px-3 py-1 rounded-full ${
                        detailsTab === "overview"
                          ? "bg-indigo-500 text-white"
                          : "text-indigo-200"
                      }`}
                      onClick={() => setDetailsTab("overview")}
                    >
                      Overview
                    </button>
                    <button
                      className={`px-3 py-1 rounded-full flex items-center gap-1 ${
                        detailsTab === "recent"
                          ? "bg-emerald-500 text-white"
                          : "text-emerald-200"
                      }`}
                      onClick={() => setDetailsTab("recent")}
                    >
                      Recently fixed
                      {recentlyFixed.length > 0 && (
                        <span className="inline-flex h-4 min-w-4 items-center justify-center rounded-full bg-emerald-900/90 text-[10px] px-1">
                          {recentlyFixed.length}
                        </span>
                      )}
                    </button>
                  </div>
                </div>

                {/* Overview tab */}
                {detailsTab === "overview" && (
                  <>
                    {mostRecentFixed && (
                      <div className="mb-4 text-xs bg-emerald-500/10 border border-emerald-500/60 text-emerald-100 rounded-lg px-3 py-2 flex items-start gap-2">
                        <span className="mt-0.5">✅</span>
                        <div>
                          <div className="font-semibold">
                            Recently fixed: {mostRecentFixed.label}
                          </div>
                          <div className="text-[11px] text-emerald-200/80">
                            Detected via {mostRecentFixed.via}. Run the
                            compliance score to see your updated overall
                            posture.
                          </div>
                        </div>
                      </div>
                    )}

                    {!scanResult &&
                      !s3Summary &&
                      !cloudTrailResult &&
                      !configResult &&
                      !ebsResult &&
                      !iamResult && (
                        <p className="text-gray-400 text-sm mb-4">
                          No results yet. Run a scan or one of the individual
                          checks on the left to see details and remediation
                          guidance here.
                        </p>
                      )}

                      {/* EC2 Inventory */}
                      {ec2Inventory && (
                        <section className="mb-5">
                          <h3 className="text-sm font-semibold text-gray-200 mb-1">
                            EC2 inventory
                          </h3>
                          <p className="text-xs text-gray-300 mb-2">
                            Instances:{" "}
                            <span className="font-mono">
                              {ec2Inventory.count}
                            </span>
                          </p>

                          <div className="border border-slate-800/60 rounded-md bg-black/40 overflow-hidden">
                            <table className="w-full table-fixed text-[11px]">
                              <thead className="bg-slate-900/80 text-gray-300 text-[11px]">
                                <tr>
                                  <th className="px-2 py-1 text-left">Name</th>
                                  <th className="px-2 py-1 text-left w-[140px]">Instance ID</th>
                                  <th className="px-2 py-1 text-left w-[70px]">Type</th>
                                  <th className="px-2 py-1 text-left w-[80px]">State</th>
                                  <th className="px-2 py-1 text-left w-[120px]">Public IP</th>
                                  <th className="px-2 py-1 text-left w-[110px]">
                                    <span className="block leading-tight">Root volume</span>
                                    <span className="block leading-tight">encryption</span>
                                  </th>
                                </tr>
                              </thead>

                              <tbody>
                                {ec2Inventory.instances.map((i) => (
                                  <tr
                                    key={i.instance_id}
                                    className="border-t border-slate-800/60"
                                  >
                                    {/* Name */}
                                    <td className="px-2 py-1.5 text-xs text-gray-200">
                                      <span
                                        className="block max-w-[200px] truncate"
                                        title={i.name || i.instance_id}
                                      >
                                        {i.name || "—"}
                                      </span>
                                    </td>

                                    {/* Instance ID */}
                                    <td className="px-2 py-1.5 font-mono text-[10px] text-gray-200 whitespace-nowrap">
                                      {i.instance_id}
                                    </td>

                                    {/* Type */}
                                    <td className="px-2 py-1.5 text-xs text-gray-300 whitespace-nowrap">
                                      {i.instance_type}
                                    </td>

                                    {/* State badge */}
                                    <td className="px-2 py-1.5 text-xs">
                                      <span
                                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[10px] ${
                                          i.state === "running"
                                            ? "border-emerald-500/50 bg-emerald-500/10 text-emerald-300"
                                            : "border-slate-600/70 bg-slate-800 text-slate-200"
                                        }`}
                                      >
                                        <span className="h-1.5 w-1.5 rounded-full bg-current" />
                                        {i.state || "unknown"}
                                      </span>
                                    </td>

                                    {/* Public IP → badge + IP */}
                                    <td className="px-2 py-1.5 text-[11px] text-gray-300 whitespace-nowrap">
                                      {i.public_ip ? (
                                        <div className="flex flex-col leading-tight">
                                          <span className="flex items-center gap-1 text-emerald-300 text-[10px]">
                                            🌐 <span>Public</span>
                                          </span>
                                          <span className="font-mono text-[10px] text-gray-400">
                                            {i.public_ip}
                                          </span>
                                        </div>
                                      ) : (
                                        <span className="flex items-center gap-1 text-gray-400 text-[10px]">
                                          🔒 <span>Private-only</span>
                                        </span>
                                      )}
                                    </td>

                                    {/* Root volume encryption */}
                                    <td className="px-2 py-1.5 text-[11px] whitespace-nowrap">
                                      {i.root_volume_encrypted === true ? (
                                        <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
                                          🔐 <span>Yes</span>
                                        </span>
                                      ) : i.root_volume_encrypted === false ? (
                                        <span className="inline-flex items-center gap-1 text-red-400 text-[11px]">
                                          ⚠️ <span>No</span>
                                        </span>
                                      ) : (
                                        <span className="text-gray-400">—</span>
                                      )}
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </section>
                      )}

                {/* Security groups inventory */}
                {sgInventory && (
                  <section className="mb-5">
                    <h3 className="text-sm font-semibold text-gray-200 mb-1">
                      Security groups
                    </h3>

                    <p className="text-xs text-gray-300 mb-1">
                      Groups:{" "}
                      <span className="font-mono">{sgInventory.count}</span>{" "}
                      • World-open SGs:{" "}
                      <span className="font-mono text-red-300">
                        {sgWorldOpenCount}
                      </span>{" "}
                      • SSH 22 world-open:{" "}
                      <span className="font-mono text-amber-300">
                        {sgSshOpenCount}
                      </span>{" "}
                      • RDP 3389 world-open:{" "}
                      <span className="font-mono text-amber-300">
                        {sgRdpOpenCount}
                      </span>{" "}
                      • Web 80/443 world-open:{" "}
                      <span className="font-mono text-amber-300">
                        {sgWebOpenCount}
                      </span>
                    </p>


                    <div className="border border-slate-800/60 rounded-md bg-black/40">
                      <table className="w-full text-[11px]">
                        <thead className="bg-slate-900/80 text-gray-300 text-[10px]">
                          <tr>
                            <th className="px-2 py-1 text-left w-[180px]">Name</th>
                            <th className="px-2 py-1 text-left w-[160px]">Group ID</th>
                            <th className="px-2 py-1 text-left w-[80px]">Inbound</th>
                            <th className="px-2 py-1 text-left w-[70px]">Risk</th>
                          </tr>
                        </thead>

                        <tbody>
                          {sgGroups.map((g) => (
                            <React.Fragment key={g.group_id}>
                              {/* Main row */}
                              <tr className="border-t border-slate-800/60">
                                {/* Name */}
                                <td className="px-2 py-1.5 text-xs text-gray-200 align-top">
                                  <div
                                    className="truncate font-medium"
                                    title={g.name || g.group_id}
                                  >
                                    {g.name || "—"}
                                  </div>
                                  {g.description && (
                                    <div className="text-[10px] text-gray-500 truncate">
                                      {g.description}
                                    </div>
                                  )}
                                </td>

                                {/* Group ID */}
                                <td className="px-2 py-1.5 font-mono text-[10px] text-gray-300 whitespace-nowrap align-top">
                                  {g.group_id}
                                </td>

                                {/* Inbound rules count – opens modal */}
                                <td className="px-2 py-1.5 align-top">
                                  <button
                                    type="button"
                                    onClick={() => {
                                      setSelectedSecurityGroup(g);
                                      setShowSgModal(true);
                                    }}
                                    className="inline-flex items-center justify-center rounded-full border border-slate-600 bg-slate-900/80 px-2 py-0.5 text-[10px] text-slate-100 hover:bg-slate-800"
                                  >
                                    {(g.inbound_count ?? g.inbound_rules?.length ?? 0)} rules
                                  </button>
                                </td>

                                {/* Risk */}
                                <td className="px-2 py-1.5 align-top">
                                  {renderSecurityGroupRisk(g)}
                                </td>
                              </tr>

                              {/* Exposure detail row (full width) */}
                              <tr className="border-t border-slate-900/60">
                                <td
                                  colSpan={4}
                                  className="px-2 py-1.5 text-[10px] text-gray-200 bg-slate-950/40"
                                >
                                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                                    {/* World / restricted */}
                                    {g.world_open ? (
                                      <span className="inline-flex items-center gap-1 text-red-300">
                                        🌐 World-open
                                      </span>
                                    ) : (
                                      <span className="inline-flex items-center gap-1 text-emerald-300">
                                        🛡️ Restricted
                                      </span>
                                    )}

                                    {/* SSH */}
                                    <span
                                      className={
                                        g.ssh_22_open ? "text-red-300" : "text-emerald-300"
                                      }
                                    >
                                      SSH {g.ssh_22_open ? "open" : "closed"}
                                    </span>

                                    {/* RDP */}
                                    <span
                                      className={
                                        g.rdp_3389_open ? "text-red-300" : "text-emerald-300"
                                      }
                                    >
                                      RDP {g.rdp_3389_open ? "open" : "closed"}
                                    </span>

                                    {/* Web */}
                                    <span
                                      className={
                                        Array.isArray(g.web_ports) && g.web_ports.length > 0
                                          ? "text-amber-300"
                                          : "text-gray-400"
                                      }
                                    >
                                      Web{" "}
                                      {Array.isArray(g.web_ports) && g.web_ports.length > 0
                                        ? g.web_ports.join(", ")
                                        : "—"}
                                    </span>
                                  </div>
                                </td>
                              </tr>
                            </React.Fragment>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </section>
                )}





                        {/* VPC / network inventory */}
                        {vpcInventory && (
                          <section className="mb-5">
                            <h3 className="text-sm font-semibold text-gray-200 mb-1">
                              VPC / network
                            </h3>
                            <p className="text-xs text-gray-300 mb-2">
                              VPCs:{" "}
                              <span className="font-mono">
                                {vpcInventory.count}
                              </span>
                            </p>

                            <div className="border border-slate-800/60 rounded-md bg-black/40 overflow-hidden">
                              <table className="w-full table-fixed text-[11px]">
                                <thead className="bg-slate-900/80 text-gray-300 text-[10px]">
                                  <tr>
                                    <th className="px-2 py-1 text-left">Name</th>
                                    <th className="px-2 py-1 text-left w-[150px]">VPC ID</th>
                                    <th className="px-2 py-1 text-left w-[120px]">CIDR</th>
                                    <th className="px-2 py-1 text-left w-[70px]">Subnets</th>
                                    <th className="px-2 py-1 text-left w-[60px]">IGWs</th>
                                    <th className="px-2 py-1 text-left w-[110px]">
                                      <span className="block leading-tight">Route tables</span>
                                      <span className="block leading-tight">with 0.0.0.0/0</span>
                                    </th>
                                  </tr>
                                </thead>

                                <tbody>
                                  {vpcInventory.vpcs.map((v) => {
                                    const openRouteTables =
                                      (v.route_tables || []).filter((rt) => rt.has_0_0_0_0_route)
                                        .length;

                                    return (
                                      <tr
                                        key={v.vpc_id}
                                        className="border-t border-slate-800/60"
                                      >
                                        {/* Name */}
                                        <td className="px-2 py-1.5 text-xs text-gray-200">
                                          <span
                                            className="block max-w-[200px] truncate"
                                            title={v.name || v.vpc_id}
                                          >
                                            {v.name || "—"}
                                          </span>
                                        </td>

                                        {/* VPC ID */}
                                        <td className="px-2 py-1.5 font-mono text-[10px] text-gray-200 whitespace-nowrap">
                                          {v.vpc_id}
                                        </td>

                                        {/* CIDR */}
                                        <td className="px-2 py-1.5 text-xs text-gray-300 whitespace-nowrap">
                                          {v.cidr_block}
                                        </td>

                                        {/* Subnets */}
                                        <td className="px-2 py-1.5 text-xs text-gray-300 whitespace-nowrap">
                                          {v.subnets?.length ?? 0}
                                        </td>

                                        {/* IGWs */}
                                        <td className="px-2 py-1.5 text-xs text-gray-300 whitespace-nowrap">
                                          {v.internet_gateways?.length ?? 0}
                                        </td>

                                        {/* Route tables with 0.0.0.0/0 */}
                                        <td className="px-2 py-1.5 text-xs text-gray-300 whitespace-nowrap">
                                          {openRouteTables}
                                        </td>
                                      </tr>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          </section>
                        )}



                    {/* RDS inventory */}
                    {rdsInventory && (
                      <section className="mb-5">
                        <h3 className="text-sm font-semibold text-gray-200 mb-1">
                          RDS inventory
                        </h3>
                        <p className="text-xs text-gray-300 mb-2">
                          DB instances:{" "}
                          <span className="font-mono">
                            {rdsInventory.count}
                          </span>
                        </p>
                        <div className="border border-slate-800/60 rounded-md bg-black/40">
                          <table className="min-w-full">
                          <thead className="bg-slate-900/80 text-gray-300 text-[11px]">
                              <tr>
                              <th className="px-2 py-1 text-left">Name</th>
                              <th className="px-2 py-1 text-left">Instance ID</th>
                              <th className="px-2 py-1 text-left">Type</th>
                              <th className="px-2 py-1 text-left">State</th>
                              <th className="px-2 py-1 text-left">Public exposure</th>
                              <th className="px-2 py-1 text-left">Root encryption</th>
                              </tr>
                            </thead>
                            <tbody>
                              {rdsInventory.instances.map((db) => (
                                <tr key={db.id} className="border-t border-slate-800/60">
                                  <td className="px-2 py-1 font-mono text-gray-300">
                                    {db.id}
                                  </td>
                                  <td className="px-2 py-1 text-gray-300">
                                    {db.engine} {db.engine_version}
                                  </td>
                                  <td className="px-2 py-1 text-gray-300">
                                    {db.storage_encrypted ? "🔐" : "⚠️"}
                                  </td>
                                  <td className="px-2 py-1 text-gray-300">
                                    {db.publicly_accessible ? "🌐" : "🔒"}
                                  </td>
                                  <td className="px-2 py-1 text-gray-300">
                                    {db.backup_retention_period || 0} days
                                  </td>
                                  <td className="px-2 py-1 text-gray-300">
                                    {db.multi_az ? "✅" : "—"}
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      </section>
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
                        <div className="text-xs text-gray-300 bg-black/60 rounded p-3 whitespace-pre-wrap font-mono">
                          {scanResult.summary}
                        </div>
                        <p className="text-[11px] text-gray-500 mt-1">
                          Tip: Security Hub aggregates findings from multiple
                          AWS services. Use this as your high-level risk
                          overview.
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
                        <ul className="text-xs text-gray-300 space-y-1">
                          {s3Summary.buckets.map((b) => (
                            <li
                              key={b.bucket}
                              className="flex justify-between border-b border-slate-800/60 pb-1"
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
                            Fix: Enable default bucket encryption and avoid
                            public access unless strictly required.
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
                              {cloudTrailResult.multi_region_trail
                                ? "Yes"
                                : "No"}
                            </p>
                            <p className="text-[11px] text-gray-500">
                              Best practice: Use a multi-region trail that
                              sends logs to a dedicated security/audit S3
                              bucket.
                            </p>
                          </>
                        ) : (
                          <>
                            <p className="text-xs text-red-400 mb-1">
                              ❌ CloudTrail not enabled.
                            </p>
                            <p className="text-xs text-gray-300 mb-1">
                              CloudTrail records API activity in your AWS
                              account. It&apos;s required for most compliance
                              frameworks (SOC2, PCI, CIS, etc.).
                            </p>
                            <p className="text-[11px] text-gray-400 mb-1">
                              Fix: Create a multi-region trail and send logs to
                              an S3 bucket in your log-archive account.
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
                              Config tracks configuration changes over time.
                              Use it with rules for continuous compliance.
                            </p>
                          </>
                        ) : (
                          <>
                            <p className="text-xs text-red-400 mb-1">
                              ❌ AWS Config is not fully enabled.
                            </p>
                            <p className="text-xs text-gray-300 mb-1">
                              Config provides a history of resource
                              configuration changes, which is essential for
                              investigations and compliance evidence.
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
                          ebsResult.unencrypted_volume_ids.length ===
                            0) ? (
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
                              {ebsResult.default_encryption_enabled
                                ? "Yes"
                                : "No"}
                              <br />
                              Total volumes:{" "}
                              <span className="font-mono">
                                {ebsResult.total_volumes}
                              </span>
                            </p>
                            {ebsResult.unencrypted_volume_ids &&
                              ebsResult.unencrypted_volume_ids.length >
                                0 && (
                                <p className="text-[11px] text-amber-400 mb-1">
                                  Unencrypted volumes:{" "}
                                  {ebsResult.unencrypted_volume_ids.join(
                                    ", "
                                  )}
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
                              Best practice: Enforce strong length (≥ 12),
                              require symbols/numbers, and enable password
                              reuse prevention.
                            </p>
                          </>
                        ) : (
                          <>
                            <p className="text-xs text-red-400 mb-1">
                              ❌ No IAM password policy detected.
                            </p>
                            <p className="text-xs text-gray-300 mb-1">
                              Without a password policy, users can set weak
                              passwords, which is a common compliance failure.
                            </p>
                            <p className="text-[11px] text-gray-400 mb-1">
                              Fix: Configure an IAM password policy with
                              minimum length, complexity requirements, and
                              rotation.
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
                      <section className="mt-4 border-t border-slate-800 pt-4">
                        <div className="flex items-center justify-between mb-2">
                          <h3 className="text-sm font-semibold text-indigo-200">
                            Fix guidance
                          </h3>
                          <span className="text-[11px] text-gray-500">
                            Human-readable steps + cost notes
                          </span>
                        </div>

                        {guidanceItems.length === 0 ? (
                          <p className="text-xs text-emerald-400">
                            All checks you&apos;ve run so far are passing. 🎉
                            Keep running additional checks as you expand your
                            environment.
                          </p>
                        ) : (
                          <div className="space-y-3">
                            {guidanceItems.map((item) => (
                              <div
                                key={item.id}
                                className="rounded-lg border border-slate-800 bg-slate-950/70 p-3"
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
                                    <span className="font-semibold">
                                      Cost note:{" "}
                                    </span>
                                    {item.costNote}
                                  </p>
                                )}
                                <div className="flex flex-wrap gap-2 mt-1">
                                  {item.consoleUrl && (
                                    <a
                                      href={item.consoleUrl}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-[11px] px-2 py-1 rounded border border-slate-700 bg-slate-900 hover:bg-slate-800 text-indigo-300"
                                    >
                                      View in AWS Console →
                                    </a>
                                  )}
                                  {item.docsUrl && (
                                    <a
                                      href={item.docsUrl}
                                      target="_blank"
                                      rel="noreferrer"
                                      className="text-[11px] px-2 py-1 rounded border border-slate-700 bg-slate-900 hover:bg-slate-800 text-gray-300"
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
                  </>
                )}

                {/* Recently fixed tab */}
                {detailsTab === "recent" && (
                  <div>
                    {recentlyFixed.length === 0 ? (
                      <p className="text-sm text-gray-400">
                        Nothing has been fixed yet. When a failing check
                        becomes passing (either from an individual check or the
                        compliance score), it will show up here.
                      </p>
                    ) : (
                      <div className="space-y-2">
                        {recentlyFixed.map((item) => (
                          <div
                            key={item.id + item.at}
                            className="flex items-start gap-2 rounded-lg border border-emerald-600/40 bg-emerald-500/10 px-3 py-2 text-xs text-emerald-50"
                          >
                            <span className="mt-0.5">✅</span>
                            <div>
                              <div className="font-semibold">
                                {item.label}
                              </div>
                              <div className="text-[11px] text-emerald-100/80">
                                Detected via {item.via} •{" "}
                                {new Date(item.at).toLocaleString()}
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          </section>
        </div>
      </main>

      {/* SG inbound rules modal */}
      {showSgModal && selectedSecurityGroup && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
          <div className="bg-slate-950 border border-slate-700 rounded-2xl max-w-2xl w-full mx-4 p-5 shadow-xl shadow-black/50">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-gray-100">
                Inbound rules –{" "}
                {selectedSecurityGroup.name || selectedSecurityGroup.group_id}
              </h3>
              <button
                onClick={() => {
                  setShowSgModal(false);
                  setSelectedSecurityGroup(null);
                }}
                className="text-xs text-gray-400 hover:text-gray-200"
              >
                Close
              </button>
            </div>

            <p className="text-[11px] text-gray-400 mb-2">
              Showing inbound rules for this security group. Review any entries
              that allow broad access (0.0.0.0/0 or ::/0), especially on SSH,
              RDP, or web ports.
            </p>

            <div className="border border-slate-800 rounded-md bg-black/50 max-h-72 overflow-auto">
              <table className="w-full text-[11px]">
                <thead className="bg-slate-900/80 text-gray-300">
                  <tr>
                    <th className="px-2 py-1 text-left">Protocol</th>
                    <th className="px-2 py-1 text-left">Port(s)</th>
                    <th className="px-2 py-1 text-left">Source</th>
                    <th className="px-2 py-1 text-left">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {(selectedSecurityGroup.inbound_rules || []).length > 0 ? (
                    selectedSecurityGroup.inbound_rules.map((r, idx) => {
                      // Try to normalize fields for display
                      const proto = r.protocol ?? r.IpProtocol ?? "-";
                      const from = r.from_port ?? r.FromPort;
                      const to = r.to_port ?? r.ToPort;
                      const portRange =
                        from === undefined && to === undefined
                          ? "All"
                          : from === to
                          ? from
                          : `${from}–${to}`;
                      const cidr =
                        r.cidr ??
                        r.CidrIp ??
                        r.CidrIpv6 ??
                        r.source ??
                        "-";
                      const desc =
                        r.description ??
                        r.Description ??
                        r.desc ??
                        "";

                      return (
                        <tr
                          key={idx}
                          className="border-t border-slate-800/60"
                        >
                          <td className="px-2 py-1 text-gray-300">
                            {proto}
                          </td>
                          <td className="px-2 py-1 text-gray-300">
                            {portRange}
                          </td>
                          <td className="px-2 py-1 text-gray-300">
                            {cidr}
                          </td>
                          <td className="px-2 py-1 text-gray-400">
                            {desc || "—"}
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td
                        colSpan={4}
                        className="px-2 py-3 text-center text-gray-500 text-[11px]"
                      >
                        No inbound rules found for this security group.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}