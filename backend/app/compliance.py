# backend/app/compliance.py

import boto3
from typing import List, Tuple
from .schemas import ComplianceCheckResult, ComplianceSummary

# If you have a DEFAULT_REGION constant somewhere, reuse that.
DEFAULT_REGION = "us-east-1"


def _build_client(service: str, creds: dict, region: str = DEFAULT_REGION):
    """
    Helper: build a boto3 client from temporary creds.
    Adapt this to use your existing assume-role/session helper if you have one.
    """
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def check_s3_encryption_and_public_access(creds: dict) -> ComplianceCheckResult:
    """
    PASS if:
      - All buckets have default encryption enabled
      - No bucket is publicly accessible (rough heuristic)
    """
    s3 = _build_client("s3", creds)

    buckets = s3.list_buckets().get("Buckets", [])
    total = len(buckets)
    if total == 0:
        return ComplianceCheckResult(
            id="s3_encryption_public",
            title="S3 encryption & public access",
            description="No S3 buckets found in this account.",
            status="WARN",
            score_weight=20,
            score_earned=10,
            details={"buckets": []},
        )

    non_encrypted = []
    public_buckets = []

    for b in buckets:
        name = b["Name"]

        # Encryption check
        encrypted = False
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                encrypted = True
        except s3.exceptions.ClientError as e:
            # No encryption configuration
            if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                encrypted = False
            else:
                # Other errors – treat as not encrypted for safety
                encrypted = False

        if not encrypted:
            non_encrypted.append(name)

        # Public access check via Public Access Block
        is_public = False
        try:
            pab = s3.get_public_access_block(Bucket=name)
            cfg = pab["PublicAccessBlockConfiguration"]
            # If *all* these are True, bucket is effectively protected
            protected = all(
                cfg.get(k, False)
                for k in [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ]
            )
            if not protected:
                is_public = True
        except s3.exceptions.ClientError:
            # No public access block config – treat as potentially public
            is_public = True

        if is_public:
            public_buckets.append(name)

    status = "PASS"
    score_weight = 20
    score_earned = score_weight

    if non_encrypted or public_buckets:
        status = "FAIL"
        score_earned = 0

    return ComplianceCheckResult(
        id="s3_encryption_public",
        title="S3 encryption & public access",
        description="Checks whether S3 buckets are encrypted and not publicly accessible.",
        status=status,
        score_weight=score_weight,
        score_earned=score_earned,
        details={
            "total_buckets": total,
            "non_encrypted": non_encrypted,
            "public_buckets": public_buckets,
        },
    )


def check_ebs_encryption(creds: dict) -> ComplianceCheckResult:
    """
    PASS if all EBS volumes are encrypted.
    """
    ec2 = _build_client("ec2", creds)
    paginator = ec2.get_paginator("describe_volumes")

    unencrypted = []
    total = 0

    for page in paginator.paginate():
        for vol in page.get("Volumes", []):
            total += 1
            if not vol.get("Encrypted", False):
                unencrypted.append(vol["VolumeId"])

    if total == 0:
        return ComplianceCheckResult(
            id="ebs_encryption",
            title="EBS volume encryption",
            description="No EBS volumes found in this account.",
            status="WARN",
            score_weight=15,
            score_earned=8,
            details={"unencrypted_volumes": []},
        )

    status = "PASS"
    score_weight = 15
    score_earned = score_weight

    if unencrypted:
        status = "FAIL"
        score_earned = 0

    return ComplianceCheckResult(
        id="ebs_encryption",
        title="EBS volume encryption",
        description="Checks whether all EBS volumes are encrypted.",
        status=status,
        score_weight=score_weight,
        score_earned=score_earned,
        details={"total_volumes": total, "unencrypted_volumes": unencrypted},
    )


def check_cloudtrail_and_config(creds: dict) -> List[ComplianceCheckResult]:
    """
    Check:
      - At least one CloudTrail trail is logging
      - At least one AWS Config recorder is recording
    """
    results: List[ComplianceCheckResult] = []

    cloudtrail = _build_client("cloudtrail", creds)
    config = _build_client("config", creds)

    # CloudTrail
    trails_resp = cloudtrail.describe_trails(includeShadowTrails=False)
    trails = trails_resp.get("trailList", [])

    logging_trails = []
    for t in trails:
        name = t.get("Name") or t.get("TrailARN")
        try:
            status = cloudtrail.get_trail_status(Name=name)
            if status.get("IsLogging"):
                logging_trails.append(name)
        except cloudtrail.exceptions.TrailNotFoundException:
            continue

    if not trails:
        ct_status = "FAIL"
        ct_score = 0
        desc = "No CloudTrail trails configured."
    elif not logging_trails:
        ct_status = "FAIL"
        ct_score = 0
        desc = "CloudTrail trails exist but none are currently logging."
    else:
        ct_status = "PASS"
        ct_score = 10
        desc = "At least one CloudTrail trail is logging."

    results.append(
        ComplianceCheckResult(
            id="cloudtrail_enabled",
            title="CloudTrail logging",
            description=desc,
            status=ct_status,
            score_weight=10,
            score_earned=ct_score,
            details={
                "total_trails": len(trails),
                "logging_trails": logging_trails,
            },
        )
    )

    # AWS Config
    recorders = config.describe_configuration_recorders().get(
        "ConfigurationRecorders", []
    )
    recorder_statuses = config.describe_configuration_recorder_status().get(
        "ConfigurationRecordersStatus", []
    )

    active_recorders = [
        r["name"]
        for r in recorder_statuses
        if r.get("recording") and r.get("lastStatus") == "SUCCESS"
    ]

    if not recorders:
        cfg_status = "FAIL"
        cfg_score = 0
        desc = "No AWS Config recorders are configured."
    elif not active_recorders:
        cfg_status = "FAIL"
        cfg_score = 0
        desc = "AWS Config recorders exist but none are actively recording."
    else:
        cfg_status = "PASS"
        cfg_score = 10
        desc = "At least one AWS Config recorder is actively recording."

    results.append(
        ComplianceCheckResult(
            id="config_enabled",
            title="AWS Config recording",
            description=desc,
            status=cfg_status,
            score_weight=10,
            score_earned=cfg_score,
            details={
                "total_recorders": len(recorders),
                "active_recorders": active_recorders,
            },
        )
    )

    return results


def check_iam_password_policy(creds: dict) -> ComplianceCheckResult:
    """
    PASS if an account password policy exists and meets some basic standards.
    You can tighten this over time.
    """
    iam = _build_client("iam", creds)

    score_weight = 15
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return ComplianceCheckResult(
            id="iam_password_policy",
            title="IAM password policy",
            description="No account password policy is configured.",
            status="FAIL",
            score_weight=score_weight,
            score_earned=0,
            details={},
        )

    # Simple baseline
    min_length_ok = policy.get("MinimumPasswordLength", 0) >= 12
    requires_complexity = all(
        [
            policy.get("RequireSymbols", False),
            policy.get("RequireNumbers", False),
            policy.get("RequireUppercaseCharacters", False),
            policy.get("RequireLowercaseCharacters", False),
        ]
    )
    max_age_ok = policy.get("MaxPasswordAge", 0) <= 90 if "MaxPasswordAge" in policy else False

    all_ok = min_length_ok and requires_complexity and max_age_ok

    if all_ok:
        status = "PASS"
        score_earned = score_weight
    else:
        status = "WARN"
        # You can get fancy and award partial points, but for now:
        score_earned = int(score_weight / 2)

    return ComplianceCheckResult(
        id="iam_password_policy",
        title="IAM password policy",
        description="Checks for a strong IAM password policy (length, complexity, max age).",
        status=status,
        score_weight=score_weight,
        score_earned=score_earned,
        details={
            "policy": policy,
            "min_length_ok": min_length_ok,
            "requires_complexity": requires_complexity,
            "max_age_ok": max_age_ok,
        },
    )


def run_compliance_scan(creds: dict) -> ComplianceSummary:
    """
    Main orchestrator: run all checks and compute a total score.
    """
    checks: List[ComplianceCheckResult] = []

    checks.append(check_s3_encryption_and_public_access(creds))
    checks.append(check_ebs_encryption(creds))
    checks.extend(check_cloudtrail_and_config(creds))
    checks.append(check_iam_password_policy(creds))

    max_score = sum(c.score_weight for c in checks)
    total_score = sum(c.score_earned for c in checks)
    percentage = round((total_score / max_score) * 100, 1) if max_score else 0.0

    return ComplianceSummary(
        total_score=total_score,
        max_score=max_score,
        percentage=percentage,
        checks=checks,
    )

