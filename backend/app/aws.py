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

