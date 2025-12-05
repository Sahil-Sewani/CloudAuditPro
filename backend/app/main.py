import os
import stripe
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from .db import Base, engine
from .routers import auth, onboarding, aws_accounts
from typing import Any, Dict, List
from .auth_utils import get_current_user
from . import models
import boto3
from html import escape

from .aws import (
    assume_customer_role,
    securityhub_client_from_creds,
    list_findings,
    get_s3_security_summary,
    get_cloudtrail_status,
    get_config_status,
    get_iam_password_policy_status,
    get_ebs_encryption_status,
    get_ec2_inventory,
    get_vpc_inventory,
    get_rds_inventory,
    get_sg_inventory,
    build_attack_surface,  # ✅ NEW
)
from .frameworks import FRAMEWORK_CONTROLS
from .report import build_summary, render_s3_section

load_dotenv()

APP_ENV = os.getenv("APP_ENV", "dev")
REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
SES_FROM = os.getenv("SES_FROM_ADDRESS")
TEST_TO = os.getenv("TEST_REPORT_RECIPIENT")
START = os.getenv("REPORT_WINDOW_START")
END = os.getenv("REPORT_WINDOW_END")

stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PRICE_ID = os.getenv("STRIPE_PRICE_ID")
SUCCESS_URL = os.getenv("CHECKOUT_SUCCESS_URL", "https://example.com/success")
CANCEL_URL = os.getenv("CHECKOUT_CANCEL_URL", "https://example.com/cancel")

app = FastAPI(title="CloudAuditPro API", version="0.1.0")

frontend_origin = os.getenv("FRONTEND_ORIGIN", "https://app.cloudauditpro.app")

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    frontend_origin,
]

# Create DB tables on startup (for SQLite / dev)
Base.metadata.create_all(bind=engine)

# Register routers
app.include_router(auth.router)
app.include_router(onboarding.router)
app.include_router(aws_accounts.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # allow POST, GET, OPTIONS, etc.
    allow_headers=["*"],
)


class ScanInput(BaseModel):
    account_id: str
    role_name: str = "CloudAuditProReadRole"
    region: str = REGION
    start_iso: str | None = START
    end_iso: str | None = END
    email_to: str | None = None


class ComplianceSummary(BaseModel):
    account_id: str
    region: str
    compliance_score: int
    checks: dict


class ComplianceInput(ScanInput):
    # Which framework to score against: "cis", "pci", "soc2"
    framework: str = "cis"


@app.get("/")
def health():
    return {"status": "ok", "env": APP_ENV}


@app.post("/scan")
def scan(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        sh = securityhub_client_from_creds(creds, inp.region)
        findings = list_findings(sh, inp.start_iso, inp.end_iso)
        summary = build_summary(findings)
        return {"count": len(findings), "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/report/email")
def email_report(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    Send an HTML email that includes:
      - Security Hub summary
      - S3 security summary
      - CloudTrail, Config, EBS, IAM status
      - Helpful links & a 'View in CloudAuditPro' button
    """
    try:
        # Assume role & clients
        creds = assume_customer_role(inp.account_id, inp.role_name)
        region = inp.region

        # --- Security Hub ---
        sh = securityhub_client_from_creds(creds, region)
        findings = list_findings(sh, inp.start_iso, inp.end_iso)
        sec_hub_text = build_summary(findings)

        # --- S3 summary ---
        s3_list = get_s3_security_summary(creds, region)
        s3_total = len(s3_list)
        s3_public = sum(1 for b in s3_list if b["public"])
        s3_unenc = sum(1 for b in s3_list if not b["encryption_enabled"])

        # --- CloudTrail ---
        ct = get_cloudtrail_status(creds, region)
        ct_ok = bool(ct.get("has_trail")) and bool(ct.get("multi_region_trail"))

        # --- Config ---
        cfg = get_config_status(creds, region)
        cfg_ok = bool(cfg.get("recorder_configured")) and bool(
            cfg.get("recording_enabled")
        )

        # --- EBS encryption ---
        ebs = get_ebs_encryption_status(creds, region)
        ebs_ok = bool(ebs.get("default_encryption_enabled")) and len(
            ebs.get("unencrypted_volume_ids", [])
        ) == 0

        # --- IAM password policy ---
        iam_policy = get_iam_password_policy_status(creds, region)
        iam_ok = bool(iam_policy.get("policy_present"))

        # ---------- Plain-text fallback ----------
        s3_text = (
            f"=== S3 Security Summary ===\n"
            f"Buckets: {s3_total}  |  Public: {s3_public}  |  Unencrypted: {s3_unenc}\n"
        )
        ct_text = (
            "=== CloudTrail ===\n"
            f"Status: {'PASS' if ct_ok else 'FAIL'}; "
            f"has_trail={ct.get('has_trail')}, "
            f"multi_region={ct.get('multi_region_trail')}, "
            f"trail_count={ct.get('trail_count')}\n"
        )
        cfg_text = (
            "=== AWS Config ===\n"
            f"Status: {'PASS' if cfg_ok else 'FAIL'}; "
            f"recorder_configured={cfg.get('recorder_configured')}, "
            f"recording_enabled={cfg.get('recording_enabled')}\n"
        )
        ebs_text = (
            "=== EBS Encryption ===\n"
            f"Status: {'PASS' if ebs_ok else 'FAIL'}; "
            f"default_encryption_enabled={ebs.get('default_encryption_enabled')}, "
            f"total_volumes={ebs.get('total_volumes')}, "
            f"unencrypted_volume_ids={ebs.get('unencrypted_volume_ids')}\n"
        )
        iam_text = (
            "=== IAM Password Policy ===\n"
            f"Status: {'PASS' if iam_ok else 'FAIL'}; "
            f"policy_present={iam_policy.get('policy_present')}\n"
        )

        body_text = (
            f"{sec_hub_text}\n\n"
            f"{s3_text}\n"
            f"{ct_text}\n"
            f"{cfg_text}\n"
            f"{ebs_text}\n"
            f"{iam_text}"
        )

        # ---------- HTML body omitted for brevity (unchanged) ----------
        # Use your existing HTML template here:
        # body_html = f"""<!DOCTYPE html> ... """
        body_html = body_text  # placeholder if you don't have HTML

        # ---------- Send with SES ----------
        to_addr = inp.email_to or TEST_TO
        if not (SES_FROM and to_addr):
            raise HTTPException(
                status_code=400, detail="SES_FROM_ADDRESS or recipient missing"
            )

        ses = boto3.client("ses", region_name=REGION)
        ses.send_email(
            Source=SES_FROM,
            Destination={"ToAddresses": [to_addr]},
            Message={
                "Subject": {"Data": "Weekly AWS Security Report", "Charset": "UTF-8"},
                "Body": {
                    "Text": {"Data": body_text, "Charset": "UTF-8"},
                    "Html": {"Data": body_html, "Charset": "UTF-8"},
                },
            },
        )

        return {"sent_to": to_addr, "length": len(body_html)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/aws/s3-summary")
def s3_summary(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        s3_summary = get_s3_security_summary(creds, inp.region)
        # add a tiny rollup
        total = len(s3_summary)
        public = sum(1 for b in s3_summary if b["public"])
        unencrypted = sum(1 for b in s3_summary if not b["encryption_enabled"])
        return {
            "total_buckets": total,
            "public_buckets": public,
            "unencrypted_buckets": unencrypted,
            "buckets": s3_summary,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/inventory/ec2")
def inventory_ec2(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    EC2 inventory for a single AWS account / region.
    """
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        data = get_ec2_inventory(creds, inp.region)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/inventory/vpc")
def inventory_vpc(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    VPC / network inventory (VPCs, subnets, IGWs, route tables with 0.0.0.0/0).
    """
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        data = get_vpc_inventory(creds, inp.region)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/inventory/rds")
def inventory_rds(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    RDS inventory (encryption, public accessibility, backups, multi-AZ).
    """
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        data = get_rds_inventory(creds, inp.region)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/inventory/sg")
def inventory_sg(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    Security Group inventory for a single AWS account / region.
    """
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        data = get_sg_inventory(creds, inp.region)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/inventory/attack-surface")
def inventory_attack_surface(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    Attack surface view:
    - Public-running EC2 instances
    - World-open ports from attached security groups (0.0.0.0/0 or ::/0)
    """
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        data = build_attack_surface(creds, inp.region)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/checks/cloudtrail")
def check_cloudtrail(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        status = get_cloudtrail_status(creds, inp.region)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/checks/config")
def check_config(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        status = get_config_status(creds, inp.region)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/checks/iam-password-policy")
def check_iam_password_policy(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        status = get_iam_password_policy_status(creds, inp.region)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/checks/ebs-encryption")
def check_ebs_encryption(
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        status = get_ebs_encryption_status(creds, inp.region)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/compliance/summary")
def compliance_summary(
    inp: ComplianceInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    Aggregate multiple controls into a single compliance score.

    Controls (calculated once here):
      - Security Hub: pass if 0 findings
      - S3: pass if no public + no unencrypted buckets
      - CloudTrail: pass if at least 1 multi-region trail
      - Config: pass if recorder exists AND recording enabled
      - EBS: pass if default encryption on AND no unencrypted volumes
      - IAM password policy: pass if a policy is present

    The active framework (cis / pci / soc2) decides which of these
    controls count toward the score.
    """
    try:
        # Assume role once and reuse creds
        creds = assume_customer_role(inp.account_id, inp.role_name)
        region = inp.region

        # --- 1) Security Hub ---
        sh_client = securityhub_client_from_creds(creds, region)
        findings = list_findings(sh_client, inp.start_iso, inp.end_iso)
        sh_count = len(findings)
        sec_hub_ok = sh_count == 0

        # --- 2) S3 baseline ---
        s3_list = get_s3_security_summary(creds, region)
        s3_total = len(s3_list)
        s3_public = sum(1 for b in s3_list if b["public"])
        s3_unenc = sum(1 for b in s3_list if not b["encryption_enabled"])
        s3_ok = (s3_total > 0) and (s3_public == 0) and (s3_unenc == 0)

        # --- 3) CloudTrail ---
        ct = get_cloudtrail_status(creds, region)
        ct_ok = bool(ct.get("has_trail")) and bool(ct.get("multi_region_trail"))

        # --- 4) Config ---
        cfg = get_config_status(creds, region)
        cfg_ok = bool(cfg.get("recorder_configured")) and bool(
            cfg.get("recording_enabled")
        )

        # --- 5) EBS default encryption ---
        ebs = get_ebs_encryption_status(creds, region)
        ebs_ok = bool(ebs.get("default_encryption_enabled")) and len(
            ebs.get("unencrypted_volume_ids", [])
        ) == 0

        # --- 6) IAM password policy ---
        iam_policy = get_iam_password_policy_status(creds, region)
        iam_ok = bool(iam_policy.get("policy_present"))

        # --- Scoring with frameworks ---
        framework = getattr(inp, "framework", "cis")

        all_checks: Dict[str, Dict[str, Any]] = {
            "security_hub": {
                "id": "security_hub",
                "label": "Security Hub findings",
                "passed": sec_hub_ok,
                "details": {"finding_count": sh_count},
            },
            "s3_baseline": {
                "id": "s3_baseline",
                "label": "S3 public access & encryption",
                "passed": s3_ok,
                "details": {
                    "total_buckets": s3_total,
                    "public_buckets": s3_public,
                    "unencrypted_buckets": s3_unenc,
                },
            },
            "cloudtrail": {
                "id": "cloudtrail",
                "label": "CloudTrail multi-region trail",
                "passed": ct_ok,
                "details": ct,
            },
            "config": {
                "id": "config",
                "label": "AWS Config recorder enabled",
                "passed": cfg_ok,
                "details": cfg,
            },
            "ebs_encryption": {
                "id": "ebs_encryption",
                "label": "EBS default encryption",
                "passed": ebs_ok,
                "details": ebs,
            },
            "iam_password_policy": {
                "id": "iam_password_policy",
                "label": "IAM password policy configured",
                "passed": iam_ok,
                "details": iam_policy,
            },
        }

        control_ids = FRAMEWORK_CONTROLS.get(
            framework, FRAMEWORK_CONTROLS["cis"]
        )
        checks = [all_checks[cid] for cid in control_ids if cid in all_checks]

        total_checks = len(checks)
        passed_checks = sum(1 for c in checks if c["passed"])
        score = round((passed_checks / total_checks) * 100, 1) if total_checks else 0.0

        return {
            "framework": framework,
            "score": score,
            "passed_checks": passed_checks,
            "total_checks": total_checks,
            "checks": checks,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
