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

def _get_tag_value(tags: List[dict], key: str) -> Optional[str]:
    if not tags:
        return None
    for t in tags:
        if t.get("Key") == key:
            return t.get("Value")
    return None


def get_ec2_inventory(creds: dict, region: str = DEFAULT_REGION) -> dict:
    """
    Simple EC2 inventory:
      - instance_id
      - name tag
      - public / private IP
      - instance_type
      - state
      - security groups
      - root volume encryption flag (via DescribeVolumes)
    """
    ec2 = ec2_client_from_creds(creds, region)

    raw_instances: List[dict] = []
    root_volume_ids: set[str] = set()
    kwargs: Dict = {}

    # 1) Collect instances + their root volume IDs
    while True:
        resp = ec2.describe_instances(**kwargs)

        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                instance_id = inst.get("InstanceId")
                name = _get_tag_value(inst.get("Tags", []), "Name")
                public_ip = inst.get("PublicIpAddress")
                private_ip = inst.get("PrivateIpAddress")
                state = (inst.get("State") or {}).get("Name")
                instance_type = inst.get("InstanceType")
                sg_ids = [sg.get("GroupId") for sg in inst.get("SecurityGroups", [])]

                root_device = inst.get("RootDeviceName")
                root_volume_id = None

                for bdm in inst.get("BlockDeviceMappings", []):
                    ebs = bdm.get("Ebs")
                    if not ebs:
                        continue

                    # Prefer an exact match to the root device, but fall back
                    # to the first EBS mapping if we can't match by name.
                    if root_device is None or bdm.get("DeviceName") == root_device:
                        root_volume_id = ebs.get("VolumeId")
                        break

                if root_volume_id:
                    root_volume_ids.add(root_volume_id)

                raw_instances.append(
                    {
                        "instance_id": instance_id,
                        "name": name,
                        "public_ip": public_ip,
                        "private_ip": private_ip,
                        "state": state,
                        "instance_type": instance_type,
                        "security_groups": sg_ids,
                        "root_volume_id": root_volume_id,
                    }
                )

        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token

    # 2) Describe volumes to get encryption flags
    volume_encryption: dict[str, bool] = {}

    if root_volume_ids:
        vol_kwargs: Dict = {"VolumeIds": list(root_volume_ids)}
        while True:
            vol_resp = ec2.describe_volumes(**vol_kwargs)
            for v in vol_resp.get("Volumes", []):
                vid = v.get("VolumeId")
                if vid:
                    volume_encryption[vid] = bool(v.get("Encrypted"))
            next_token = vol_resp.get("NextToken")
            if not next_token:
                break
            vol_kwargs["NextToken"] = next_token

    # 3) Build final instance list with root_volume_encrypted filled in
    instances: List[dict] = []
    for inst in raw_instances:
        rid = inst.get("root_volume_id")
        root_enc = volume_encryption.get(rid) if rid else None

        instances.append(
            {
                "instance_id": inst["instance_id"],
                "name": inst["name"],
                "public_ip": inst["public_ip"],
                "private_ip": inst["private_ip"],
                "state": inst["state"],
                "instance_type": inst["instance_type"],
                "security_groups": inst["security_groups"],
                "root_volume_encrypted": root_enc,
            }
        )

    return {"instances": instances, "count": len(instances)}



def get_vpc_inventory(creds: dict, region: str = DEFAULT_REGION) -> dict:
    """
    Basic network view:
      - VPCs with CIDR + name
      - Subnets per VPC
      - Internet gateways per VPC
      - Route tables with 0.0.0.0/0 detection
    """
    ec2 = ec2_client_from_creds(creds, region)

    vpcs = ec2.describe_vpcs().get("Vpcs", [])
    subnets = ec2.describe_subnets().get("Subnets", [])
    igws = ec2.describe_internet_gateways().get("InternetGateways", [])
    route_tables = ec2.describe_route_tables().get("RouteTables", [])

    # Index helpers
    subnets_by_vpc: Dict[str, List[dict]] = {}
    for s in subnets:
        vid = s.get("VpcId")
        subnets_by_vpc.setdefault(vid, []).append(
            {
                "subnet_id": s.get("SubnetId"),
                "cidr_block": s.get("CidrBlock"),
                "az": s.get("AvailabilityZone"),
                "name": _get_tag_value(s.get("Tags", []), "Name"),
            }
        )

    igws_by_vpc: Dict[str, List[dict]] = {}
    for igw in igws:
        igw_id = igw.get("InternetGatewayId")
        for att in igw.get("Attachments", []):
            vid = att.get("VpcId")
            igws_by_vpc.setdefault(vid, []).append(
                {
                    "internet_gateway_id": igw_id,
                    "state": att.get("State"),
                }
            )

    rts_by_vpc: Dict[str, List[dict]] = {}
    for rt in route_tables:
        vid = rt.get("VpcId")
        if not vid:
            continue
        routes = rt.get("Routes", [])
        has_0_0_0_0 = any(
            r.get("DestinationCidrBlock") == "0.0.0.0/0" for r in routes
        )
        rts_by_vpc.setdefault(vid, []).append(
            {
                "route_table_id": rt.get("RouteTableId"),
                "has_0_0_0_0_route": has_0_0_0_0,
            }
        )

    vpc_items: List[dict] = []
    for v in vpcs:
        vid = v.get("VpcId")
        vpc_items.append(
            {
                "vpc_id": vid,
                "cidr_block": v.get("CidrBlock"),
                "name": _get_tag_value(v.get("Tags", []), "Name"),
                "subnets": subnets_by_vpc.get(vid, []),
                "internet_gateways": igws_by_vpc.get(vid, []),
                "route_tables": rts_by_vpc.get(vid, []),
            }
        )

    return {"vpcs": vpc_items, "count": len(vpc_items)}


def rds_client_from_creds(creds: dict, region: str = DEFAULT_REGION):
    return boto3.client(
        "rds",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_rds_inventory(creds: dict, region: str = DEFAULT_REGION) -> dict:
    """
    Basic RDS inventory:
      - id, engine, encrypted?, public?, backups?, multi-AZ
    """
    rds = rds_client_from_creds(creds, region)
    instances: List[dict] = []
    marker: Optional[str] = None

    while True:
        kwargs: Dict = {}
        if marker:
            kwargs["Marker"] = marker
        resp = rds.describe_db_instances(**kwargs)
        for db in resp.get("DBInstances", []):
            instances.append(
                {
                    "id": db.get("DBInstanceIdentifier"),
                    "arn": db.get("DBInstanceArn"),
                    "engine": db.get("Engine"),
                    "engine_version": db.get("EngineVersion"),
                    "storage_encrypted": db.get("StorageEncrypted"),
                    "publicly_accessible": db.get("PubliclyAccessible"),
                    "backup_retention_period": db.get("BackupRetentionPeriod"),
                    "multi_az": db.get("MultiAZ"),
                }
            )
        marker = resp.get("Marker")
        if not marker:
            break

    return {"instances": instances, "count": len(instances)}
