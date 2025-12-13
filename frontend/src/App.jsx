import React, { useState, useEffect } from "react";
import { useAuth } from "./AuthContext";
import { apiFetch } from "./apiClient";
import GlowDot from "./GlowDot";

const APP_VERSION = import.meta.env.VITE_APP_VERSION || "v0.1.0";
const CLOUDAUDITPRO_ACCOUNT_ID = "851725210465";

// Optional: S3 URL where you will host the template later
const CLOUDAUDITPRO_CF_TEMPLATE_URL =
  import.meta.env.VITE_CF_TEMPLATE_URL || "";

// Full CloudFormation template
const CLOUDAUDITPRO_CF_TEMPLATE = `AWSTemplateFormatVersion: '2010-09-09'
Description: >
  CloudAuditPro read-only IAM role and policies to allow security/compliance
  scans without write access.

Parameters:
  ExternalAccountId:
    Type: String
    Description: CloudAuditPro management account ID (the account that will assume this role)
    Default: ${CLOUDAUDITPRO_ACCOUNT_ID}
    MinLength: 12
    MaxLength: 12
    AllowedPattern: '^[0-9]{12}$'

  ExternalRoleName:
    Type: String
    Default: CloudAuditProAppRole
    Description: Role in the CloudAuditPro account that will assume this role.

Resources:
  CloudAuditProReadRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: CloudAuditProReadRole
      Description: Read-only role used by CloudAuditPro to scan this AWS account.
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub arn:aws:iam::\${ExternalAccountId}:role/\${ExternalRoleName}
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
        - arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess
        - arn:aws:iam::aws:policy/AWSConfigUserAccess
      Policies:
        - PolicyName: CloudAuditPro-CloudTrailRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - cloudtrail:DescribeTrails
                  - cloudtrail:GetTrailStatus
                  - cloudtrail:ListTrails
                Resource: '*'
        - PolicyName: CloudAuditPro-ConfigRecorderRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - config:DescribeConfigurationRecorders
                  - config:DescribeConfigurationRecorderStatus
                  - config:DescribeDeliveryChannels
                  - config:DescribeDeliveryChannelStatus
                Resource: '*'
        - PolicyName: CloudAuditPro-EBSEncryptionRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ec2:GetEbsEncryptionByDefault
                  - ec2:DescribeVolumes
                Resource: '*'
        - PolicyName: CloudAuditPro-IAMPasswordPolicyRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - iam:GetAccountPasswordPolicy
                Resource: '*'
        - PolicyName: CloudAuditPro-ResourceInventoryRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ec2:DescribeInstances
                  - ec2:DescribeVpcs
                  - ec2:DescribeSubnets
                  - ec2:DescribeRouteTables
                  - ec2:DescribeInternetGateways
                  - ec2:DescribeVolumes
                  - ec2:GetEbsEncryptionByDefault
                  - ec2:DescribeSecurityGroups
                  - ec2:DescribeNetworkInterfaces
                  - rds:DescribeDBInstances
                Resource: '*'

Outputs:
  CloudAuditProReadRoleArn:
    Description: ARN of the read-only role to paste into CloudAuditPro.
    Value: !GetAtt CloudAuditProReadRole.Arn`;

const CHECK_LABELS = {
  security_hub: "Security Hub",
  s3: "S3",
  cloudtrail: "CloudTrail",
  config: "Config",
  ebs: "EBS encryption",
  iam: "IAM password policy",
  compliance: "Compliance score",
};

const FRAMEWORK_LABELS = {
  cis: "CIS AWS Benchmark",
  pci: "PCI DSS",
  soc2: "SOC 2",
};

const FRAMEWORK_CONTROLS = {
  cis: [
    "security_hub",
    "s3_baseline",
    "cloudtrail",
    "config",
    "ebs_encryption",
    "iam_password_policy",
  ],
  pci: [
    "cloudtrail",
    "config",
    "ebs_encryption",
    "iam_password_policy",
    "s3_baseline",
  ],
  soc2: [
    "security_hub",
    "cloudtrail",
    "config",
    "ebs_encryption",
    "iam_password_policy",
  ],
};



// For guidance text per framework + control
const FRAMEWORK_FIX_GUIDANCE = {
  cis: {
    security_hub:
      "Resolve all open Security Hub findings mapped to CIS AWS Foundations checks.",
    s3_baseline:
      "Ensure no S3 buckets are public and that default encryption is enabled (CIS 2.x).",
    cloudtrail:
      "Enable at least one multi-region CloudTrail with log file validation (CIS 2.1).",
    config:
      "Enable AWS Config and configure a recorder for all resources in all regions (CIS 2.5).",
    ebs_encryption:
      "Turn on EBS default encryption and migrate any unencrypted volumes.",
    iam_password_policy:
      "Configure an IAM account password policy meeting CIS complexity/rotation requirements.",
  },
  pci: {
    security_hub:
      "Use Security Hub to continuously monitor PCI-relevant controls and findings.",
    s3_baseline:
      "Ensure cardholder data buckets are not public and are encrypted at rest (PCI DSS 3.x).",
    cloudtrail:
      "Enable CloudTrail logging for all PCI-scoped resources to support PCI DSS 10.x logging.",
    config:
      "Use AWS Config to track configuration drift on PCI-scoped resources.",
    ebs_encryption:
      "Encrypt all volumes that may store cardholder data; enforce default encryption.",
    iam_password_policy:
      "Enforce strong password policies for IAM users with PCI-relevant access.",
  },
  soc2: {
    security_hub:
      "Use Security Hub as a central source of evidence for SOC 2 security controls.",
    s3_baseline:
      "Encrypt S3 data at rest and avoid public buckets that may expose customer data.",
    cloudtrail:
      "Ensure CloudTrail is enabled org-wide to provide audit evidence for SOC 2 CC7.x.",
    config:
      "Use AWS Config to demonstrate ongoing monitoring of changes to in-scope resources.",
    ebs_encryption:
      "Encrypt EBS volumes that may store customer or confidential data.",
    iam_password_policy:
      "Ensure password policies or SSO enforcement meet SOC 2 access control requirements.",
  },
};


export default function App({ user, onLogout }) {
  const { token } = useAuth();

  // --------- Form state ----------
  const [accountId, setAccountId] = useState("");
  const [roleName, setRoleName] = useState("CloudAuditProReadRole");
  const [region, setRegion] = useState("us-east-1");
  const [emailTo, setEmailTo] = useState("");
  const [framework, setFramework] = useState(() => {
    if (typeof window === "undefined") return "cis";
    return localStorage.getItem("cap_framework") || "cis";
  });



  // Use the selected region for console links, with a safe default
  const consoleRegion = region || "us-east-1";

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

  const handleCopyCloudFormationTemplate = async () => {
    try {
      await navigator.clipboard.writeText(CLOUDAUDITPRO_CF_TEMPLATE);
      setToast({
        type: "success",
        message: "CloudFormation template copied to clipboard.",
      });
    } catch (err) {
      console.error("Failed to copy template", err);
      setToast({
        type: "error",
        message:
          "Couldn't copy automatically — you can still select the template text manually.",
      });
    }
  };


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
  const [attackSurface, setAttackSurface] = useState(null);
  const [loadingAttackSurface, setLoadingAttackSurface] = useState(false); 
  const [showSgHelp, setShowSgHelp] = useState(false);
  // Onboarding helpers
  const [showCfnTemplate, setShowCfnTemplate] = useState(false); 

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
    role_name: roleName || "CloudAuditProReadRole",
    region,
    // Optional extras if you have these in state:
    // start_iso: startIso,
    // end_iso: endIso,
    email_to: emailTo || null,
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
    loadingSg ||
    loadingAttackSurface;

  const markCheckRun = (id) => {
    setChecksRun((prev) => (prev.includes(id) ? prev : [...prev, id]));
  };

  // --------- Toast auto-hide ----------
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(timer);
  }, [toast]);

  // --------- Persist framework selection ----------
  useEffect(() => {
    if (typeof window !== "undefined") {
      localStorage.setItem("cap_framework", framework);
    }
  }, [framework]);

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
        body: JSON.stringify({
          ...commonBody,
          framework, // "cis" | "pci" | "soc2"
        }),
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
    setAttackSurface(null);
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

  const handleAttackSurface = async () => {
    setLoadingAttackSurface(true);
    setError("");
    setAttackSurface(null);

    try {
      const data = await apiFetch("/inventory/attack-surface", {
        token,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(commonBody),
      });
      setAttackSurface(data);
      markCheckRun("attack_surface");
    } catch (err) {
      console.error("Attack surface error:", err);
      setError(err.message || "Failed to load attack surface view");
    } finally {
      setLoadingAttackSurface(false);
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
  
      let savedAccount = null;
  
      if (selectedAwsAccountId) {
        // ----- UPDATE EXISTING -----
        savedAccount = await apiFetch(`/aws-accounts/${selectedAwsAccountId}`, {
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
            String(a.id) === String(selectedAwsAccountId) ? savedAccount : a
          )
        );
      } else {
        // ----- CREATE NEW -----
        savedAccount = await apiFetch("/aws-accounts", {
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
  
        setAwsAccounts((prev) => [savedAccount, ...prev]);
        setSelectedAwsAccountId(String(savedAccount.id));
      }
  
      // ------------------------------------------------------------
      // ⭐️ After save: Perform AWS connection test
      // ------------------------------------------------------------
      try {
        const conn = await apiFetch("/aws/connection-check", {
          token,
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            account_id: cleanAccountId,
            role_name: cleanRoleName,
            region: cleanRegion,
          }),
        });
  
        setToast({
          type: "success",
          message: `Connected ✓ CloudAuditPro successfully assumed: ${conn.arn}`,
        });
      } catch (err) {
        console.error("Connection check failed:", err);
  
        setToast({
          type: "error",
          message:
            "Saved the AWS account, but CloudAuditPro could *not* assume the role. Double-check trust policy and permissions.",
        });
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
  const scorePercent = Math.round(score);
  const controls = complianceSummary?.checks || [];
  const activeFramework = complianceSummary?.framework || framework;
  const activeFrameworkLabel =
    FRAMEWORK_LABELS[activeFramework] || activeFramework;
  
  // Map checks by ID for easier lookup
  const controlsById = controls.reduce((acc, c) => {
    acc[c.id] = c;
    return acc;
    // eslint-disable-next-line no-sequences
  }, {});
  
  // The canonical order of all possible controls
  const ALL_CONTROL_ORDER = [
    { id: "security_hub", label: "Security Hub findings" },
    { id: "s3_baseline", label: "S3 public access & encryption" },
    { id: "cloudtrail", label: "CloudTrail multi-region trail" },
    { id: "config", label: "AWS Config recorder enabled" },
    { id: "ebs_encryption", label: "EBS default encryption" },
    { id: "iam_password_policy", label: "IAM password policy configured" },
  ];
  
  

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
    const worldOpen = !!g.world_open;
    const sshWorld = !!g.ssh_open;   // from backend
    const rdpWorld = !!g.rdp_open;   // from backend
    const webWorld =
      Array.isArray(g.world_ports) &&
      g.world_ports.some((p) => p === 80 || p === 443);
  
    if (worldOpen && (sshWorld || rdpWorld || webWorld)) {
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

// SSH 22 world vs any
const sgSshWorldOpenCount = sgGroups.filter((g) => g.ssh_open).length;
const sgSshAnyOpenCount = sgGroups.filter((g) => g.ssh_any_open).length;

// RDP 3389 world
const sgRdpWorldOpenCount = sgGroups.filter((g) => g.rdp_open).length;

// Web 80/443 world
const sgWebWorldOpenCount = sgGroups.filter(
  (g) =>
    Array.isArray(g.world_ports) &&
    g.world_ports.some((p) => p === 80 || p === 443)
).length;

// --------- Derived summary for VPC inventory ----------
const vpcsRaw =
  (vpcInventory &&
    (vpcInventory.vpcs || vpcInventory.items)) ||
  vpcInventory ||
  [];

const vpcList = Array.isArray(vpcsRaw) ? vpcsRaw : [];
const vpcCount =
  vpcInventory && typeof vpcInventory.count === "number"
    ? vpcInventory.count
    : vpcList.length;

// --------- Derived summary for RDS inventory ----------
const rdsRaw =
  (rdsInventory &&
    (rdsInventory.instances || rdsInventory.items)) ||
  rdsInventory ||
  [];

const rdsInstances = Array.isArray(rdsRaw) ? rdsRaw : [];
const rdsCount =
  rdsInventory && typeof rdsInventory.count === "number"
    ? rdsInventory.count
    : rdsInstances.length;





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
{/* Onboarding helper – shown until at least one AWS account is saved */}
{awsAccounts.length === 0 && (
  <section className="rounded-2xl border border-indigo-900/60 bg-black/40 p-5 shadow-lg shadow-indigo-900/40">
    <div className="flex flex-col md:flex-row md:items-start md:justify-between gap-4">
      {/* Left: steps + explanation */}
      <div>
        <div className="inline-flex items-center gap-2 rounded-full bg-indigo-950/70 border border-indigo-700/80 px-3 py-1 mb-2">
          <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-indigo-300">
            Getting started
          </span>
          <span className="text-[10px] text-indigo-200/80">
            Step 1 of 3 · Connect an AWS account
          </span>
        </div>

        <h2 className="text-lg font-semibold text-indigo-100 mb-1">
          Connect your first AWS account to CloudAuditPro
        </h2>

        <p className="text-[13px] text-gray-300 mb-2 max-w-xl">
          CloudAuditPro reads your environment using a{" "}
          <span className="font-semibold text-indigo-200">
            read-only IAM role
          </span>{" "}
          that you create in your AWS account. No long-lived keys, no write
          access — just Security Hub, Config, CloudTrail, S3, EC2, and IAM{" "}
          <span className="font-semibold">read-only</span> permissions.
        </p>

        {/* Show their CloudAuditPro account ID explicitly */}
        <p className="text-[11px] text-indigo-200 mb-3">
          Your CloudAuditPro account ID:{" "}
          <code className="font-mono text-xs bg-slate-900/70 px-1 py-0.5 rounded border border-slate-700">
            {CLOUDAUDITPRO_ACCOUNT_ID}
          </code>
        </p>

        <ol className="space-y-3 text-[12px] text-gray-200">
  {/* Step 1 */}
  <li className="flex gap-2">
    <span className="mt-[2px] flex h-5 w-5 items-center justify-center rounded-full bg-indigo-700/70 text-[10px] font-bold">
      1
    </span>
    <div className="min-w-0">
      <span className="font-semibold text-indigo-100">
        Create the read-only IAM role in your AWS account.
      </span>

      <p className="text-gray-300 mt-1">
        Option A (recommended): deploy the CloudFormation template below. This creates{" "}
        <span className="font-mono">CloudAuditProReadRole</span> with read-only permissions and the correct trust policy.
      </p>

      <div className="mt-2">
        <button
          type="button"
          onClick={() => setShowCfnTemplate((v) => !v)}
          className="text-[11px] text-indigo-300 underline decoration-dotted hover:text-indigo-200"
        >
          {showCfnTemplate ? "Hide CloudFormation template" : "Show CloudFormation template"}
        </button>

        {showCfnTemplate && (
          <div className="mt-2 rounded-lg border border-slate-800 bg-slate-950/80 p-2">
            <div className="flex items-center justify-between mb-1">
              <span className="text-[11px] text-gray-300">
                CloudFormation (deploy in each AWS account you want to scan)
              </span>
              <span className="text-[10px] text-gray-500">Copy &amp; paste</span>
            </div>

            <pre className="text-[10px] text-gray-200 overflow-x-auto whitespace-pre leading-snug">
{CLOUDAUDITPRO_CF_TEMPLATE}
            </pre>
          </div>
        )}
      </div>
    </div>
  </li>

  {/* Step 2 */}
  <li className="flex gap-2">
    <span className="mt-[2px] flex h-5 w-5 items-center justify-center rounded-full bg-indigo-700/70 text-[10px] font-bold">
      2
    </span>
    <div className="min-w-0">
      <span className="font-semibold text-indigo-100">
        Add the AWS account in CloudAuditPro.
      </span>
      <p className="text-gray-300 mt-1">
        In the left panel, enter your <span className="font-mono">AWS Account ID</span>,{" "}
        <span className="font-mono">Role name</span> (usually{" "}
        <span className="font-mono">CloudAuditProReadRole</span>), and{" "}
        <span className="font-mono">Region</span>, then click{" "}
        <span className="font-semibold">Save AWS account</span>.
      </p>
    </div>
  </li>

  {/* Step 3 */}
  <li className="flex gap-2">
    <span className="mt-[2px] flex h-5 w-5 items-center justify-center rounded-full bg-indigo-700/70 text-[10px] font-bold">
      3
    </span>
    <div className="min-w-0">
      <span className="font-semibold text-indigo-100">
        Verify connection, then run your first checks.
      </span>
      <p className="text-gray-300 mt-1">
        After saving, CloudAuditPro should confirm the role is assumable (your{" "}
        <span className="text-emerald-300 font-semibold">Connected ✓</span> state). Then run
        Security Hub / S3 / CloudTrail / Config checks or generate a compliance score.
      </p>
    </div>
  </li>
</ol>

      </div>

      {/* Right-hand “You’re almost there” explainer card stays the same */}
      {/* ... keep your existing right-side card JSX here ... */}
    </div>
  </section>
)}

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
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mt-3">
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

                  {/* 🚀 Attack surface */}
                  <button
                    onClick={handleAttackSurface}
                    disabled={loadingAttackSurface || !hasAccountConfig}
                    className="bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-white px-4 py-2 rounded text-sm"
                  >
                    {loadingAttackSurface ? "Loading..." : "Attack surface"}
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
                <div className="mb-4">
                  <span className="block text-xs font-medium text-indigo-200 mb-1">
                    Framework
                  </span>
                  <select
                    className="mt-1 w-full bg-slate-950/80 border border-indigo-800 rounded px-3 py-2 text-xs text-indigo-50"
                    value={framework}
                    onChange={(e) => setFramework(e.target.value)}
                  >
                    <option value="cis">CIS AWS Benchmark</option>
                    <option value="pci">PCI DSS</option>
                    <option value="soc2">SOC 2</option>
                  </select>
                  <p className="text-[11px] text-slate-400 mt-1">
                    This selection only affects the compliance score, not the raw checks.
                  </p>
                </div>

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
              <div className="bg-black/40 border border-indigo-900/60 rounded-2xl p-6 shadow-lg shadow-indigo-900/40 flex flex-col">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <h2 className="text-lg font-semibold text-indigo-200">
                      Compliance Score
                    </h2>
                    <p className="text-xs text-gray-400">
                      {hasRunCompliance ? (
                        <>
                          Based on latest compliance run ·{" "}
                          <span className="text-indigo-200">
                            {activeFrameworkLabel}
                          </span>
                        </>
                      ) : (
                        "Run a scan to calculate your compliance score."
                      )}
                    </p>
                  </div>

                  {hasRunCompliance && (
                    <div className="text-right">
                      <div className="text-[11px] text-slate-400">
                        Controls in scope:
                      </div>
                      <div className="text-[11px] text-slate-200 font-mono">
                        {FRAMEWORK_CONTROLS[activeFramework]?.length || 0} /{" "}
                        {ALL_CONTROL_ORDER.length}
                      </div>
                    </div>
                  )}
                </div>

                {/* Score bubble */}
                <div className="flex items-center gap-4 mb-3">
                  <div className="relative w-20 h-20">
                    <div
                      className={`w-full h-full rounded-full flex items-center justify-center text-2xl font-semibold ${
                        !hasRunCompliance
                          ? "bg-slate-900 text-slate-500 border border-slate-700"
                          : scorePercent >= 90
                          ? "bg-emerald-900/50 text-emerald-200 border border-emerald-500/70"
                          : scorePercent >= 70
                          ? "bg-amber-900/50 text-amber-200 border border-amber-500/70"
                          : "bg-rose-900/50 text-rose-100 border border-rose-500/70"
                      }`}
                    >
                      {hasRunCompliance ? scorePercent : "--"}
                    </div>
                    <div className="absolute inset-0 rounded-full border border-white/10 animate-pulse pointer-events-none" />
                  </div>

                  <div className="flex-1">
                    <p className="text-xs text-slate-300 mb-1">
                      Overall score based on controls selected by the{" "}
                      <span className="font-semibold text-indigo-200">
                        {activeFrameworkLabel}
                      </span>{" "}
                      framework.
                    </p>
                    {hasRunCompliance && (
                      <p className="text-[11px] text-slate-400">
                        {complianceSummary?.passed_checks ?? 0} of{" "}
                        {complianceSummary?.total_checks ?? 0} in-scope controls are
                        currently passing.
                      </p>
                    )}
                  </div>
                </div>

                      {/* Per-control breakdown */}
                      <div className="mt-1 border-t border-slate-800/70 pt-2 flex-1">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[11px] font-semibold text-slate-300 uppercase tracking-wide">
                            Control breakdown
                          </span>
                          <span className="text-[10px] text-slate-500">
                            Bold = included in current framework
                          </span>
                        </div>

                        <div className="space-y-1 max-h-56 overflow-y-auto pr-1">
                          {ALL_CONTROL_ORDER.map((ctl) => {
                            const inFramework =
                              FRAMEWORK_CONTROLS[activeFramework]?.includes(ctl.id);
                            const control = controlsById[ctl.id];
                            const hasResult =
                              hasRunCompliance && control && typeof control.passed === "boolean";
                            const passed = hasResult ? control.passed : null;
                            const guidance =
                              FRAMEWORK_FIX_GUIDANCE[activeFramework]?.[ctl.id] || "";

                            // Dot color + pulse
                            let dotColor = "bg-slate-500";
                            let dotShouldPing = false;
                            if (hasRunCompliance && inFramework && hasResult) {
                              if (passed) {
                                dotColor = "bg-emerald-400";
                              } else {
                                dotColor = "bg-red-500";
                              }
                              dotShouldPing = true;
                            }

                            // Status badge content
                            let statusNode;
                            if (!hasRunCompliance) {
                              statusNode = (
                                <span className="text-[10px] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 bg-slate-900/70">
                                  Not run yet
                                </span>
                              );
                            } else if (inFramework && hasResult) {
                              statusNode = statusBadgeFromPassed(passed);
                            } else if (!inFramework) {
                              statusNode = (
                                <span className="text-[10px] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 bg-slate-900/70">
                                  Not scored for this framework
                                </span>
                              );
                            } else {
                              statusNode = (
                                <span className="text-[10px] px-2 py-0.5 rounded-full border border-slate-700 text-slate-300 bg-slate-900/70">
                                  No data
                                </span>
                              );
                            }

                            return (
                              <div
                                key={ctl.id}
                                className={`flex flex-col rounded-md px-2 py-1 border ${
                                  !inFramework
                                    ? "border-slate-800/80 bg-slate-950/60 opacity-60"
                                    : passed
                                    ? "border-emerald-700/70 bg-emerald-950/40"
                                    : "border-amber-700/70 bg-amber-950/40"
                                }`}
                              >
                                <div className="flex items-center justify-between gap-2">
                                  <div className="flex items-center gap-2">
                                    <span
                                      className={`text-[11px] ${
                                        inFramework
                                          ? "font-semibold text-slate-100"
                                          : "text-slate-400"
                                      }`}
                                    >
                                      {ctl.label}
                                    </span>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    {/* Blinking status light */}
                                    <div className="relative flex h-2.5 w-2.5">
                                      {dotShouldPing && (
                                        <span
                                          className={`absolute inline-flex h-full w-full rounded-full ${dotColor} opacity-75 animate-ping`}
                                        />
                                      )}
                                      <span
                                        className={`relative inline-flex rounded-full h-2.5 w-2.5 ${dotColor}`}
                                      />
                                    </div>
                                    {statusNode}
                                  </div>
                                </div>

                                {/* Extra text depending on state */}
                                {!hasRunCompliance && (
                                  <p className="mt-1 text-[10px] text-slate-400">
                                    Run the compliance score to evaluate this control.
                                  </p>
                                )}

                                {hasRunCompliance && inFramework && hasResult && !passed && guidance && (
                                  <p className="mt-1 text-[10px] text-slate-200">
                                    <span className="font-semibold">
                                      Fix ({activeFrameworkLabel}):
                                    </span>{" "}
                                    {guidance}
                                  </p>
                                )}

                                {hasRunCompliance && !inFramework && (
                                  <p className="mt-1 text-[10px] text-slate-400">
                                    This control is tracked but not counted toward the{" "}
                                    <span className="text-indigo-200">
                                      {activeFrameworkLabel}
                                    </span>{" "}
                                    score.
                                  </p>
                                )}
                              </div>
                            );
                          })}
                        </div>
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

                    {!anyResultsForGuidance &&
                      !ec2Inventory &&
                      !vpcInventory &&
                      !rdsInventory &&
                      !sgInventory && (
                        <p className="text-gray-400 text-sm mb-4">
                          No results yet. Run a scan, an individual check, or load
                          inventory on the left to see details and remediation guidance here.
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

{/* VPC / network */}
{vpcInventory &&
  (() => {
    const vpcs = Array.isArray(vpcInventory.vpcs)
      ? vpcInventory.vpcs
      : [];

    const vpcsWithDefaultRoute = vpcs.filter((v) =>
      (v.route_tables || []).some((rt) => rt.has_0_0_0_0_route)
    ).length;

    const totalIgws = vpcs.reduce((sum, v) => {
      const igws = Array.isArray(v.internet_gateways)
        ? v.internet_gateways
        : Array.isArray(v.igws)
        ? v.igws
        : [];
      return sum + igws.length;
    }, 0);

    const internetFacingVpcs = vpcs.filter((v) => {
      const igws = Array.isArray(v.internet_gateways)
        ? v.internet_gateways
        : Array.isArray(v.igws)
        ? v.igws
        : [];
      const routeTables = Array.isArray(v.route_tables)
        ? v.route_tables
        : [];
      const openRtCount = routeTables.filter(
        (rt) => rt.has_0_0_0_0_route
      ).length;
      return igws.length > 0 && openRtCount > 0;
    }).length;

    return (
      <section className="mb-5">
        {/* Header row */}
        <div className="flex items-center justify-between gap-2 mb-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-gray-200">
              VPC / network
            </h3>
            <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-slate-900 border border-slate-700 text-[10px] text-slate-200">
              {consoleRegion || region}
            </span>
          </div>

          <a
            href={`https://${consoleRegion}.console.aws.amazon.com/vpc/home?region=${consoleRegion}#vpcs:sort=VpcId`}
            target="_blank"
            rel="noreferrer"
            className="text-[10px] text-sky-300 hover:text-sky-200 underline decoration-dotted"
          >
            View VPCs in AWS Console →
          </a>
        </div>

        {/* Small KPI strip */}
        <p className="text-[11px] text-gray-300 mb-1">
          VPCs:{" "}
          <span className="font-mono">{vpcInventory.count}</span>{" "}
          • With 0.0.0.0/0 routes:{" "}
          <span className="font-mono text-amber-300">
            {vpcsWithDefaultRoute}
          </span>{" "}
          • IGWs:{" "}
          <span className="font-mono">{totalIgws}</span>{" "}
          • Internet-facing VPCs:{" "}
          <span
            className={
              internetFacingVpcs > 0
                ? "font-mono text-amber-300"
                : "font-mono text-emerald-300"
            }
          >
            {internetFacingVpcs}
          </span>
        </p>
        <p className="text-[10px] text-gray-400 mb-2">
          A VPC is considered{" "}
          <span className="text-amber-300 font-semibold">
            internet-facing
          </span>{" "}
          when it has an Internet Gateway and at least one route table with a
          <code className="font-mono mx-1">0.0.0.0/0</code> route.
        </p>

        <div className="border border-slate-800/60 rounded-md bg-black/40">
          <table className="w-full text-[11px]">
            <thead className="bg-slate-900/80 text-gray-300 text-[10px]">
              <tr>
                <th className="px-2 py-1 text-left w-[120px]">Name</th>
                <th className="px-2 py-1 text-left w-[160px]">VPC ID</th>
                <th className="px-2 py-1 text-left w-[130px]">CIDR</th>
                <th className="px-2 py-1 text-left w-[60px]">Subnets</th>
                <th className="px-2 py-1 text-left w-[60px]">IGWs</th>
                <th className="px-2 py-1 text-left w-[110px]">
                  0.0.0.0/0 routes
                </th>
                <th className="px-2 py-1 text-left w-[150px]">
                  Exposure / console
                </th>
              </tr>
            </thead>

            <tbody>
              {vpcs.map((v) => {
                const igws = Array.isArray(v.internet_gateways)
                  ? v.internet_gateways
                  : Array.isArray(v.igws)
                  ? v.igws
                  : [];

                const routeTables = Array.isArray(v.route_tables)
                  ? v.route_tables
                  : [];

                const openRtCount = routeTables.filter(
                  (rt) => rt.has_0_0_0_0_route
                ).length;

                const hasInternetFacing = igws.length > 0 && openRtCount > 0;

                // Exposure badge styling
                let exposureLabel = "Private only";
                let exposureEmoji = "🔒";
                let exposureClasses =
                  "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-emerald-900/40 border border-emerald-500/70 text-emerald-200";

                if (hasInternetFacing) {
                  exposureLabel = "Internet-facing";
                  exposureEmoji = "🌐";
                  exposureClasses =
                    "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-amber-900/40 border border-amber-500/80 text-amber-100";
                } else if (igws.length > 0) {
                  exposureLabel = "IGW, no default route";
                  exposureEmoji = "🧷";
                  exposureClasses =
                    "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-slate-900/60 border border-slate-600/80 text-slate-200";
                }

                return (
                  <tr
                    key={v.vpc_id}
                    className="border-t border-slate-800/60"
                  >
                    {/* Name */}
                    <td className="px-2 py-1.5 text-xs text-gray-200">
                      <span
                        className="block max-w-[110px] truncate"
                        title={v.name || v.vpc_id}
                      >
                        {v.name || "—"}
                      </span>
                    </td>

                    {/* VPC ID */}
                    <td className="px-2 py-1.5 font-mono text-[10px] text-gray-300">
                      {v.vpc_id || "—"}
                    </td>

                    {/* CIDR */}
                    <td className="px-2 py-1.5 text-xs text-gray-300">
                      {v.cidr_block || v.cidr || "—"}
                    </td>

                    {/* Subnets */}
                    <td className="px-2 py-1.5 text-xs text-gray-200">
                      {Array.isArray(v.subnets) ? v.subnets.length : 0}
                    </td>

                    {/* IGWs */}
                    <td className="px-2 py-1.5 text-xs text-gray-200">
                      {igws.length}
                    </td>

                    {/* 0.0.0.0/0 Route Tables */}
                    <td className="px-2 py-1.5 text-xs text-gray-200">
                      {openRtCount}
                    </td>

                    {/* Exposure badge + console link */}
                    <td className="px-2 py-1.5 text-xs">
                      <div className="flex flex-col gap-0.5">
                        <span className={exposureClasses}>
                          <span>{exposureEmoji}</span>
                          <span>{exposureLabel}</span>
                        </span>
                        <a
                          href={`https://${consoleRegion}.console.aws.amazon.com/vpc/home?region=${consoleRegion}#VpcDetails:VpcId=${v.vpc_id}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-[10px] text-sky-300 hover:text-sky-200 underline decoration-dotted"
                          title="Open this VPC in the AWS console"
                        >
                          Open in console →
                        </a>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
    );
  })()}

{/* RDS inventory */}
{rdsInventory &&
  (() => {
    const instances = Array.isArray(rdsInventory.instances)
      ? rdsInventory.instances
      : Array.isArray(rdsInventory.db_instances)
      ? rdsInventory.db_instances
      : [];

    return (
      <section className="mb-5">
        <div className="flex items-center justify-between gap-2 mb-1">
          <h3 className="text-sm font-semibold text-gray-200">
            RDS inventory
          </h3>
          <a
            href={`https://${consoleRegion}.console.aws.amazon.com/rds/home?region=${consoleRegion}#databases:`}
            target="_blank"
            rel="noreferrer"
            className="text-[10px] text-sky-300 hover:text-sky-200 underline decoration-dotted"
          >
            View RDS in AWS Console →
          </a>
        </div>

        <p className="text-[11px] text-gray-300 mb-2">
          DB instances:{" "}
          <span className="font-mono">
            {rdsInventory.count ?? instances.length}
          </span>
        </p>

        {instances.length === 0 ? (
          <div className="rounded-md bg-slate-900/60 px-3 py-2 text-[11px] text-gray-300">
            No RDS instances found in this region.
          </div>
        ) : (
          <div className="border border-slate-800/60 rounded-md bg-black/40">
            <table className="w-full text-[11px]">
              <thead className="bg-slate-900/80 text-gray-300 text-[10px]">
                <tr>
                  <th className="px-2 py-1 text-left w-[170px]">
                    Identifier
                  </th>
                  <th className="px-2 py-1 text-left w-[90px]">Engine</th>
                  <th className="px-2 py-1 text-left w-[70px]">Public</th>
                  <th className="px-2 py-1 text-left w-[90px]">Encryption</th>
                  <th className="px-2 py-1 text-left w-[80px]">Multi-AZ</th>
                </tr>
              </thead>
              <tbody>
                {instances.map((db) => {
                  const isPublic =
                    db.publicly_accessible ?? db.public ?? false;
                  const encrypted =
                    db.storage_encrypted ?? db.encrypted ?? false;
                  const multiAz =
                    db.multi_az ?? db.multi_az_deployment ?? false;

                  return (
                    <tr
                      key={db.db_instance_identifier || db.identifier}
                      className="border-t border-slate-800/60"
                    >
                      {/* Identifier */}
                      <td className="px-2 py-1.5 text-xs text-gray-200">
                        <span
                          className="block max-w-[160px] truncate"
                          title={
                            db.db_instance_identifier ||
                            db.identifier ||
                            ""
                          }
                        >
                          {db.db_instance_identifier ||
                            db.identifier ||
                            "—"}
                        </span>
                      </td>

                      {/* Engine */}
                      <td className="px-2 py-1.5 text-xs text-gray-300">
                        {db.engine || "—"}
                      </td>

                      {/* Public badge */}
                      <td className="px-2 py-1.5 text-xs">
                        {isPublic ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-900/40 border border-amber-500/70 text-[10px] text-amber-100">
                            🌐 Public
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-900/40 border border-emerald-500/70 text-[10px] text-emerald-100">
                            🔒 Private
                          </span>
                        )}
                      </td>

                      {/* Encryption badge */}
                      <td className="px-2 py-1.5 text-xs">
                        {encrypted ? (
                          <span className="inline-flex items-center gap-1 text-emerald-300">
                            🔐 Encrypted
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-red-300">
                            ⚠️ Not encrypted
                          </span>
                        )}
                      </td>

                      {/* Multi-AZ badge */}
                      <td className="px-2 py-1.5 text-xs">
                        {multiAz ? (
                          <span className="inline-flex items-center gap-1 text-emerald-300">
                            ✅ Yes
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-gray-400">
                            — 
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    );
  })()}






                        {/* Security groups inventory */}
                        {sgInventory && (
                          <section className="mb-5">
                            {/* Header + actions + info pill */}
                            <div className="flex items-center justify-between gap-2 mb-1">
                              <div className="flex items-center gap-2">
                                <h3 className="text-sm font-semibold text-gray-200">
                                  Security groups
                                </h3>

                                {/* Small purple info pill */}
                                <button
                                  type="button"
                                  onClick={() => setShowSgHelp((v) => !v)}
                                  className="inline-flex items-center gap-1 rounded-full border border-indigo-600/70 bg-indigo-900/60 px-2 py-0.5 text-[10px] text-indigo-100 hover:bg-indigo-800/80"
                                >
                                  <span className="inline-flex h-3 w-3 items-center justify-center rounded-full bg-indigo-400 text-[9px] font-bold text-slate-950">
                                    i
                                  </span>
                                  <span>
                                    {showSgHelp ? "Hide exposure help" : "What counts as exposure?"}
                                  </span>
                                </button>
                              </div>

                              <div className="flex flex-wrap gap-2 text-[10px]">
                                <a
                                  href={`https://${consoleRegion}.console.aws.amazon.com/ec2/v2/home?region=${consoleRegion}#SecurityGroups:sort=groupId`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-sky-300 hover:text-sky-200 underline decoration-dotted"
                                >
                                  View all in AWS Console
                                </a>
                                <a
                                  href="https://docs.aws.amazon.com/managedservices/latest/userguide/about-security-groups.html"
                                  target="_blank"
                                  rel="noreferrer"
                                  className="text-sky-300 hover:text-sky-200 underline decoration-dotted"
                                >
                                  SG best practices (AWS docs)
                                </a>
                              </div>
                            </div>

                            {/* Tiny summary row */}
                            <p className="text-[11px] text-gray-300 mb-1">
                              Groups:{" "}
                              <span className="font-mono">{sgInventory.count}</span>{" "}
                              • World-open SGs:{" "}
                              <span className="font-mono text-red-300">
                                {sgWorldOpenCount}
                              </span>{" "}
                              • SSH 22 (world):{" "}
                              <span className="font-mono text-red-300">
                                {sgSshWorldOpenCount}
                              </span>{" "}
                              • SSH 22 (any):{" "}
                              <span className="font-mono text-amber-300">
                                {sgSshAnyOpenCount}
                              </span>{" "}
                              • RDP 3389 (world):{" "}
                              <span className="font-mono text-amber-300">
                                {sgRdpWorldOpenCount}
                              </span>{" "}
                              • Web 80/443 (world):{" "}
                              <span className="font-mono text-amber-300">
                                {sgWebWorldOpenCount}
                              </span>
                            </p>

                            {/* Collapsible “what is risky” box */}
                            {showSgHelp && (
                              <div className="mb-2 rounded-md border border-slate-700/70 bg-slate-950/70 px-3 py-2">
                                <p className="text-[11px] text-gray-300 leading-snug">
                                  <strong className="text-red-300">Potential exposure</strong>{" "}
                                  means this security group allows world-open access (
                                  <code className="font-mono">0.0.0.0/0</code> or{" "}
                                  <code className="font-mono">::/0</code>) on at least one port.
                                </p>
                                <p className="text-[10px] text-gray-400 leading-snug mt-1">
                                  Even private instances using this SG can become internet-reachable
                                  if they ever receive a public IP or sit behind a public load balancer.
                                  Lock down SSH/RDP and keep web ports to only what’s required.
                                </p>
                              </div>
                            )}

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
                                  {sgGroups.map((g) => {
                                    // Normalized inbound count for the button
                                    const inboundCount = Array.isArray(g.inbound_rules_detail)
                                      ? g.inbound_rules_detail.length
                                      : Array.isArray(g.inbound_rules)
                                      ? g.inbound_rules.length
                                      : g.inbound_count ??
                                        (Array.isArray(g.rules) ? g.rules.length : 0);

                                    const hasPotentialExposure =
                                      g.world_open ||
                                      g.ssh_open ||
                                      g.rdp_open ||
                                      (Array.isArray(g.world_ports) && g.world_ports.length > 0);

                                    return (
                                      <React.Fragment key={g.group_id}>
                                        {/* Main row */}
                                        <tr className="border-t border-slate-800/60">
                                          {/* Name */}
                                          <td className="px-2 py-1.5 text-xs text-gray-200 align-top">
                                            <div
                                              className="truncate font-medium"
                                              title={g.group_name || g.group_id}
                                            >
                                              {g.group_name || "—"}
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
                                              {inboundCount} rules
                                            </button>
                                          </td>

                                          {/* Risk */}
                                          <td className="px-2 py-1.5 align-top">
                                            <div className="flex flex-col gap-1">
                                              {renderSecurityGroupRisk(g)}

                                              {hasPotentialExposure && (
                                                <span className="inline-flex items-center gap-1 text-amber-300 text-[10px] font-medium">
                                                  ⚠ Potential exposure
                                                </span>
                                              )}
                                            </div>
                                          </td>
                                        </tr>

                                        {/* Exposure detail row (full width) */}
                                        <tr className="border-t border-slate-900/60">
                                          <td
                                            colSpan={4}
                                            className="px-2 py-1.5 text-[10px] text-gray-200 bg-slate-950/40"
                                          >
                                            <div className="flex flex-wrap items-center justify-between gap-y-1 gap-x-4">
                                              {/* Left side: exposure badges */}
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
                                                    g.ssh_any_open ? "text-amber-300" : "text-emerald-300"
                                                  }
                                                >
                                                  SSH 22:{" "}
                                                  {g.ssh_any_open ? "open (restricted CIDRs)" : "closed"}
                                                </span>

                                                {/* RDP */}
                                                <span
                                                  className={
                                                    g.rdp_any_open ? "text-amber-300" : "text-emerald-300"
                                                  }
                                                >
                                                  RDP 3389: {g.rdp_any_open ? "open" : "closed"}
                                                </span>

                                                {/* Web 80/443 world */}
                                                <span
                                                  className={
                                                    Array.isArray(g.world_ports) &&
                                                    g.world_ports.some((p) => p === 80 || p === 443)
                                                      ? "text-amber-300"
                                                      : "text-gray-400"
                                                  }
                                                >
                                                  Web 80/443:{" "}
                                                  {Array.isArray(g.world_ports) &&
                                                  g.world_ports.some((p) => p === 80 || p === 443)
                                                    ? "open"
                                                    : "closed"}
                                                </span>

                                                {/* Ports / CIDR quick glance (optional) */}
                                                {Array.isArray(g.port_ranges) &&
                                                  g.port_ranges.length > 0 && (
                                                    <span className="text-gray-400">
                                                      Ports: {g.port_ranges.join(", ")}
                                                    </span>
                                                  )}
                                                {Array.isArray(g.cidr_list) &&
                                                  g.cidr_list.length > 0 && (
                                                    <span className="text-gray-400">
                                                      CIDRs: {g.cidr_list.length}
                                                    </span>
                                                  )}
                                              </div>

                                              {/* Right side: per-SG console link */}
                                              <div>
                                                <a
                                                  href={`https://${consoleRegion}.console.aws.amazon.com/ec2/v2/home?region=${consoleRegion}#SecurityGroup:groupId=${g.group_id}`}
                                                  target="_blank"
                                                  rel="noreferrer"
                                                  className="text-[10px] text-sky-300 hover:text-sky-200 underline decoration-dotted"
                                                >
                                                  Open in AWS Console →
                                                </a>
                                              </div>
                                            </div>
                                          </td>
                                        </tr>
                                      </React.Fragment>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          </section>
                        )}


{/* Attack surface view */}
{attackSurface &&
  (() => {
    const summary = attackSurface.summary || attackSurface;

    const instances = Array.isArray(attackSurface.instances)
      ? attackSurface.instances
      : Array.isArray(attackSurface.public_instances)
      ? attackSurface.public_instances
      : [];

    const publicCount =
      summary.public_instance_count ??
      summary.public_instances ??
      instances.length;

    const riskySgCount =
      summary.risky_sg_count ??
      summary.world_open_sg_count ??
      summary.world_open_groups ??
      0;

    // Overall exposure badge
    let exposureLabel = "Low external exposure";
    let exposureEmoji = "✅";
    let exposureClasses =
      "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-emerald-900/40 border border-emerald-500/70 text-emerald-200";

    if (publicCount > 0 && riskySgCount > 0) {
      exposureLabel = "High external exposure";
      exposureEmoji = "🔥";
      exposureClasses =
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-red-900/50 border border-red-500/80 text-red-100";
    } else if (publicCount > 0 || riskySgCount > 0) {
      exposureLabel = "Some exposure";
      exposureEmoji = "⚠️";
      exposureClasses =
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-amber-900/40 border border-amber-500/80 text-amber-100";
    }

    return (
      <section className="mb-5">
        {/* Header row */}
        <div className="flex items-center justify-between gap-2 mb-1">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold text-gray-200">
              Attack surface
            </h3>
            <span className={exposureClasses}>
              <span>{exposureEmoji}</span>
              <span>{exposureLabel}</span>
            </span>
          </div>

          <a
            href={`https://${consoleRegion}.console.aws.amazon.com/ec2/v2/home?region=${consoleRegion}#Instances:sort=instanceId`}
            target="_blank"
            rel="noreferrer"
            className="text-[10px] text-sky-300 hover:text-sky-200 underline decoration-dotted"
          >
            View EC2 in AWS Console
          </a>
        </div>

        <p className="text-xs text-gray-300 mb-1">
          Public instances:{" "}
          <span className="font-mono">{publicCount}</span> •
          World-open security groups attached:{" "}
          <span className="font-mono text-red-300">
            {riskySgCount}
          </span>
        </p>

        <p className="text-[10px] text-gray-400 mb-2">
          Focus on instances with a public IP and world-open ports
          like <span className="font-mono">22</span> (SSH) or{" "}
          <span className="font-mono">3389</span> (RDP). These are
          the most common entry points for attackers.
        </p>

        {instances.length === 0 ? (
          <div className="rounded-md bg-slate-900/60 px-3 py-2 text-[11px] text-emerald-300">
            No public instances with risky exposure detected in
            this region.
          </div>
        ) : (
          <div className="border border-slate-800/60 rounded-md bg-black/40 overflow-hidden">
            <table className="w-full table-fixed text-[11px]">
              <thead className="bg-slate-900/80 text-gray-300 text-[10px]">
                <tr>
                  <th className="px-2 py-1 text-left">Name</th>
                  <th className="px-2 py-1 text-left w-[150px]">
                    Instance ID
                  </th>
                  <th className="px-2 py-1 text-left w-[110px]">
                    Public IP
                  </th>
                  <th className="px-2 py-1 text-left w-[120px]">
                    World-open ports
                  </th>
                  <th className="px-2 py-1 text-left w-[160px]">
                    Security groups
                  </th>
                  <th className="px-2 py-1 text-left w-[80px]">
                    Risk
                  </th>
                </tr>
              </thead>
              <tbody>
                {instances.map((inst) => {
                  const worldPorts = Array.isArray(
                    inst.world_open_ports || inst.risky_ports
                  )
                    ? inst.world_open_ports || inst.risky_ports
                    : [];

                  const sgsRaw =
                    inst.security_groups ||
                    inst.attached_security_groups ||
                    [];
                  const sgs = Array.isArray(sgsRaw) ? sgsRaw : [];

                  const hasSsh = worldPorts.includes(22);
                  const hasRdp = worldPorts.includes(3389);
                  const hasWeb = worldPorts.some(
                    (p) => p === 80 || p === 443
                  );

                  let riskLabel = "Low";
                  let riskEmoji = "✅";
                  let riskClasses =
                    "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-emerald-900/40 border border-emerald-500/70 text-emerald-200";

                  if (hasSsh || hasRdp) {
                    riskLabel = "High";
                    riskEmoji = "🔥";
                    riskClasses =
                      "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-red-900/50 border border-red-500/80 text-red-100";
                  } else if (hasWeb || worldPorts.length > 0) {
                    riskLabel = "Medium";
                    riskEmoji = "⚠️";
                    riskClasses =
                      "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] bg-amber-900/40 border border-amber-500/80 text-amber-100";
                  }

                  return (
                    <tr
                      key={inst.instance_id}
                      className="border-t border-slate-800/60"
                    >
                      {/* Name */}
                      <td className="px-2 py-1.5 text-xs text-gray-200">
                        <span
                          className="block max-w-[200px] truncate"
                          title={inst.name || inst.instance_id}
                        >
                          {inst.name || "—"}
                        </span>
                      </td>

                      {/* Instance ID + console link */}
                      <td className="px-2 py-1.5 text-[10px] text-gray-300 align-top">
                        <div className="flex flex-col gap-0.5">
                          <span className="font-mono whitespace-nowrap">
                            {inst.instance_id}
                          </span>
                          <a
                            href={`https://${consoleRegion}.console.aws.amazon.com/ec2/v2/home?region=${consoleRegion}#InstanceDetails:instanceId=${inst.instance_id}`}
                            target="_blank"
                            rel="noreferrer"
                            className="text-[10px] text-sky-300 hover:text-sky-200 underline decoration-dotted"
                          >
                            Open in console →
                          </a>
                        </div>
                      </td>

                      {/* Public IP */}
                      <td className="px-2 py-1.5 font-mono text-[10px] text-gray-300 whitespace-nowrap">
                        {inst.public_ip || "—"}
                      </td>

                      {/* World-open ports */}
                      <td className="px-2 py-1.5 text-[10px] text-gray-200 whitespace-nowrap">
                        {worldPorts.length > 0 ? (
                          <span className="text-amber-300">
                            {worldPorts.join(", ")}
                          </span>
                        ) : (
                          <span className="text-gray-400">—</span>
                        )}
                      </td>

                      {/* SG list */}
                      <td className="px-2 py-1.5 text-[10px] text-gray-200">
                        {sgs.length === 0 ? (
                          <span className="text-gray-400">—</span>
                        ) : (
                          <span className="block max-w-[220px] truncate">
                            {sgs
                              .map((g) => g.group_name || g.group_id)
                              .join(", ")}
                          </span>
                        )}
                      </td>

                      {/* Risk badge */}
                      <td className="px-2 py-1.5 text-[10px]">
                        <span className={riskClasses}>
                          <span>{riskEmoji}</span>
                          <span>{riskLabel}</span>
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    );
  })()}



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
          </div>
          </section>
        </div>
      </main>

            {/* SG inbound rules modal */}
            {showSgModal &&
              selectedSecurityGroup &&
              (() => {
                const rawRules =
                  selectedSecurityGroup.inbound_rules_detail ||
                  selectedSecurityGroup.inbound_rules ||
                  [];

                const rules = Array.isArray(rawRules) ? rawRules : [];

                const hasWorldOpen = !!selectedSecurityGroup.world_open;
                const hasSshWorld = !!selectedSecurityGroup.ssh_open;
                const hasSshAny = !!selectedSecurityGroup.ssh_any_open;
                const hasWebWorld =
                  !!selectedSecurityGroup.http_open || !!selectedSecurityGroup.https_open;

                return (
                    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
                    <div className="w-full max-w-3xl max-h-[80vh] overflow-hidden rounded-lg border border-slate-700 bg-slate-950 shadow-xl">
                      {/* Header */}
                      <div className="flex items-start justify-between border-b border-slate-800 px-4 py-3">
                        <div>
                          <h3 className="text-sm font-semibold text-gray-100">
                            Security group:{" "}
                            {selectedSecurityGroup.group_name ||
                              selectedSecurityGroup.group_id}
                          </h3>
                          <p className="text-[11px] text-gray-400 font-mono">
                            {selectedSecurityGroup.group_id}
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => {
                            setShowSgModal(false);
                            setSelectedSecurityGroup(null);
                          }}
                          className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1 text-[11px] text-gray-200 hover:bg-slate-800"
                        >
                          Close
                        </button>
                      </div>

                      {/* Badges row */}
                      <div className="flex flex-wrap items-center gap-2 px-4 py-2 text-[11px]">
                        <span className="inline-flex items-center rounded-full bg-slate-900 px-2 py-0.5 text-gray-300">
                          Inbound rules:{" "}
                          <span className="ml-1 font-mono text-gray-100">
                            {rules.length}
                          </span>
                        </span>

                        {hasWorldOpen ? (
                          <span className="inline-flex items-center rounded-full bg-red-900/40 px-2 py-0.5 text-red-200">
                            🌐 World-open
                          </span>
                        ) : (
                          <span className="inline-flex items-center rounded-full bg-emerald-900/40 px-2 py-0.5 text-emerald-200">
                            🛡️ No world-open CIDRs
                          </span>
                        )}

                        {hasSshWorld && (
                          <span className="inline-flex items-center rounded-full bg-red-900/40 px-2 py-0.5 text-red-200">
                            SSH 22 world-open
                          </span>
                        )}

                        {hasSshAny && !hasSshWorld && (
                          <span className="inline-flex items-center rounded-full bg-amber-900/40 px-2 py-0.5 text-amber-200">
                            SSH 22 open (restricted CIDRs)
                          </span>
                        )}

                        {hasWebWorld && (
                          <span className="inline-flex items-center rounded-full bg-amber-900/40 px-2 py-0.5 text-amber-200">
                            Web 80/443 open
                          </span>
                        )}
                      </div>

                      {/* Rules table */}
                      <div className="px-4 pb-4">
                        {rules.length === 0 ? (
                          <div className="rounded-md bg-slate-900/60 px-3 py-2 text-[11px] text-gray-400">
                            No inbound rules found for this security group.
                          </div>
                        ) : (
                          <div className="overflow-x-auto rounded-md border border-slate-800">
                            <table className="w-full text-[11px]">
                              <thead className="bg-slate-900 text-gray-300">
                                <tr>
                                  <th className="px-2 py-1 text-left w-[80px]">Protocol</th>
                                  <th className="px-2 py-1 text-left w-[80px]">Ports</th>
                                  <th className="px-2 py-1 text-left">Source</th>
                                  <th className="px-2 py-1 text-left w-[160px]">
                                    Description
                                  </th>
                                </tr>
                              </thead>
                              <tbody>
                                {rules.map((rule, idx) => {
                                  const proto =
                                    rule.protocol === "-1" || rule.protocol == null
                                      ? "all"
                                      : rule.protocol;

                                  let portsLabel = "All";
                                  if (
                                    rule.from_port != null &&
                                    rule.to_port != null
                                  ) {
                                    if (rule.from_port === rule.to_port) {
                                      portsLabel = String(rule.from_port);
                                    } else {
                                      portsLabel = `${rule.from_port}-${rule.to_port}`;
                                    }
                                  }

                                  const source =
                                    rule.source ||
                                    (Array.isArray(rule.sources) &&
                                      rule.sources.join(", ")) ||
                                    "—";

                                  return (
                                    <tr
                                      key={idx}
                                      className="border-t border-slate-800/70 text-gray-200"
                                    >
                                      <td className="px-2 py-1 font-mono text-[10px]">
                                        {proto}
                                      </td>
                                      <td className="px-2 py-1 font-mono text-[10px]">
                                        {portsLabel}
                                      </td>
                                      <td className="px-2 py-1 font-mono text-[10px]">
                                        {source}
                                      </td>
                                      <td className="px-2 py-1 text-[10px] text-gray-300">
                                        {rule.description || "—"}
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })()}


    </div>
  );
}