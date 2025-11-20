import os
import boto3
from datetime import datetime
from typing import Dict, List, Optional

EXTERNAL_ID = os.getenv("EXTERNAL_ID", "cloudauditpro")
DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")




def assume_customer_role(account_id: str, role_name: str = "CloudAuditProReadRole") -> Dict:
    sts = boto3.client("sts", region_name=DEFAULT_REGION)
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    creds = sts.assume_role(
    RoleArn=role_arn,
    RoleSessionName="cloudauditpro",
    ExternalId=EXTERNAL_ID,
    )["Credentials"]
    return creds




def securityhub_client_from_creds(creds: Dict, region: str = DEFAULT_REGION):
    return boto3.client(
        "securityhub",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        )




def list_findings(sh, start_iso: Optional[str] = None, end_iso: Optional[str] = None) -> List[Dict]:
    filters = None
    if start_iso and end_iso:
        filters = {"CreatedAt": [{"Start": start_iso, "End": end_iso}]}

    findings: List[Dict] = []
    kwargs: Dict = {"MaxResults": 100}
    if filters:
        kwargs["Filters"] = filters

    while True:
        resp = sh.get_findings(**kwargs)
        findings.extend(resp.get("Findings", []))
        if "NextToken" not in resp:
            break  # ✅ this line is now correctly inside the while loop
        kwargs["NextToken"] = resp["NextToken"]

    return findings



def s3_client_from_creds(creds: dict, region: str = DEFAULT_REGION):
    return boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_s3_security_summary(creds: dict, region: str = DEFAULT_REGION):
    s3 = s3_client_from_creds(creds, region)
    buckets_resp = s3.list_buckets()
    results = []

    for b in buckets_resp.get("Buckets", []):
        name = b["Name"]
        # defaults
        is_public = False
        encryption_enabled = False

        # 1) check public access via ACL (best-effort)
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI") == "http://acs.amazonaws.com/groups/global/AllUsers":
                    is_public = True
        except Exception:
            pass  # some buckets may block ACL reads

        # 2) check bucket encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            if rules:
                encryption_enabled = True
        except Exception:
            # no encryption config
            encryption_enabled = False

        results.append(
            {
                "bucket": name,
                "public": is_public,
                "encryption_enabled": encryption_enabled,
            }
        )

    return results

# ---------- NEW HELPERS FOR COMPLIANCE CHECKS ----------

def cloudtrail_client_from_creds(creds: dict, region: str = DEFAULT_REGION):
    return boto3.client(
        "cloudtrail",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_cloudtrail_status(creds: dict, region: str = DEFAULT_REGION) -> dict:
    """
    Basic signal:
      - has_trail: any trail exists
      - multi_region_trail: any trail is multi-region
    """
    ct = cloudtrail_client_from_creds(creds, region)
    try:
        resp = ct.describe_trails(includeShadowTrails=False)
        trails = resp.get("trailList", [])
        has_trail = len(trails) > 0
        multi_region_trail = any(t.get("IsMultiRegionTrail", False) for t in trails)
        return {
            "has_trail": has_trail,
            "multi_region_trail": multi_region_trail,
            "trail_count": len(trails),
        }
    except Exception as e:
        # If we can't read CloudTrail, treat as not configured but return error
        return {
            "has_trail": False,
            "multi_region_trail": False,
            "trail_count": 0,
            "error": str(e),
        }


def config_client_from_creds(creds: dict, region: str = DEFAULT_REGION):
    return boto3.client(
        "config",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_config_status(creds: dict, region: str = DEFAULT_REGION) -> dict:
    """
    Basic signal:
      - recorder_configured: any configuration recorder exists
      - recording_enabled: any recorder status has recording=True
    """
    cfg = config_client_from_creds(creds, region)
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        statuses = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecorderStatuses", []
        )
        recorder_configured = len(recs) > 0
        recording_enabled = any(s.get("recording", False) for s in statuses)
        return {
            "recorder_configured": recorder_configured,
            "recording_enabled": recording_enabled,
            "recorder_count": len(recs),
        }
    except Exception as e:
        return {
            "recorder_configured": False,
            "recording_enabled": False,
            "recorder_count": 0,
            "error": str(e),
        }


def iam_client_from_creds(creds: dict):
    # IAM is global; region doesn't really matter but we pass DEFAULT_REGION
    return boto3.client(
        "iam",
        region_name=DEFAULT_REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_iam_password_policy_status(creds: dict, region: str = DEFAULT_REGION) -> dict:
    """
    Basic signal:
      - policy_present: whether a password policy is configured
      plus common fields if present.
    """
    iam = iam_client_from_creds(creds)
    try:
        resp = iam.get_account_password_policy()
        policy = resp.get("PasswordPolicy", {})
        return {
            "policy_present": True,
            "minimum_password_length": policy.get("MinimumPasswordLength"),
            "require_symbols": policy.get("RequireSymbols"),
            "require_numbers": policy.get("RequireNumbers"),
            "require_uppercase_characters": policy.get("RequireUppercaseCharacters"),
            "require_lowercase_characters": policy.get("RequireLowercaseCharacters"),
            "allow_users_to_change_password": policy.get("AllowUsersToChangePassword"),
            "expire_passwords": policy.get("ExpirePasswords"),
            "max_password_age": policy.get("MaxPasswordAge"),
            "password_reuse_prevention": policy.get("PasswordReusePrevention"),
        }
    except iam.exceptions.NoSuchEntityException:
        # No password policy set on the account
        return {
            "policy_present": False,
        }
    except Exception as e:
        return {
            "policy_present": False,
            "error": str(e),
        }



def ec2_client_from_creds(creds: dict, region: str = DEFAULT_REGION):
    return boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_ebs_encryption_status(creds: dict, region: str = DEFAULT_REGION) -> dict:
    """
    Basic signal:
      - default_encryption_enabled: account-level EBS default encryption
      - total_volumes: number of EBS volumes
      - unencrypted_volume_ids: list of volume IDs that are not encrypted
    """
    ec2 = ec2_client_from_creds(creds, region)
    default_encryption_enabled = False
    try:
        resp = ec2.get_ebs_encryption_by_default()
        default_encryption_enabled = resp.get("EbsEncryptionByDefault", False)
    except Exception:
        # If call fails, we just treat default as False but don't explode
        default_encryption_enabled = False

    volumes = []
    kwargs: Dict = {}
    try:
        while True:
            resp = ec2.describe_volumes(**kwargs)
            volumes.extend(resp.get("Volumes", []))
            token = resp.get("NextToken")
            if not token:
                break
            kwargs["NextToken"] = token
    except Exception as e:
        # If we can't list volumes, return what we know
        return {
            "default_encryption_enabled": default_encryption_enabled,
            "total_volumes": 0,
            "unencrypted_volume_ids": [],
            "error": str(e),
        }

    unencrypted_volume_ids = [
        v["VolumeId"] for v in volumes if not v.get("Encrypted", False)
    ]

    return {
        "default_encryption_enabled": default_encryption_enabled,
        "total_volumes": len(volumes),
        "unencrypted_volume_ids": unencrypted_volume_ids,
    }