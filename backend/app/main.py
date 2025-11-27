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
)
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
    allow_methods=["*"],     # allow POST, GET, OPTIONS, etc.
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

        # ---------- HTML body with purple / dark design ----------
        def status_label(ok: bool) -> str:
            return "✅ Pass" if ok else "❌ Failing"

        view_url = f"{frontend_origin}/?account_id={inp.account_id}&region={region}"

        s3_console_url = (
            f"https://{region}.console.aws.amazon.com/s3/home?region={region}#"
        )
        ct_console_url = (
            f"https://{region}.console.aws.amazon.com/cloudtrail/home?region={region}#/trails"
        )
        cfg_console_url = (
            f"https://{region}.console.aws.amazon.com/config/home?region={region}#/getting-started"
        )
        ebs_console_url = (
            f"https://{region}.console.aws.amazon.com/ec2/home?region={region}#EBSEncryption:"
        )
        iam_console_url = "https://console.aws.amazon.com/iam/home#/account_settings"

        body_html = f"""\
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>CloudAuditPro – Weekly AWS Security Report</title>
  </head>
  <body style="margin:0;padding:0;background-color:#020617;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="padding:24px 0;">
      <tr>
        <td align="center">
          <table role="presentation" width="600" cellspacing="0" cellpadding="0" style="width:100%;max-width:600px;border-radius:16px;background:linear-gradient(135deg,#1e1b4b,#020617);color:#e5e7eb;padding:24px;box-shadow:0 10px 40px rgba(15,23,42,0.9);">
            <tr>
              <td align="center" style="padding-bottom:16px;">
                <div style="font-size:20px;font-weight:700;color:#a855f7;">CloudAuditPro</div>
                <div style="font-size:12px;color:#c4b5fd;">AWS Security &amp; Compliance Snapshot</div>
              </td>
            </tr>
            <tr>
              <td align="center" style="padding-bottom:20px;">
                <a href="{view_url}" style="display:inline-block;padding:10px 18px;border-radius:999px;background-color:#4f46e5;color:#f9fafb;font-size:12px;font-weight:600;text-decoration:none;">
                  View in CloudAuditPro
                </a>
              </td>
            </tr>

            <tr>
              <td style="background-color:rgba(15,23,42,0.9);border-radius:12px;padding:16px;margin-bottom:12px;">
                <div style="font-size:14px;font-weight:600;margin-bottom:4px;">Weekly AWS Security Summary</div>
                <div style="font-size:12px;color:#cbd5f5;">
                  Total findings: <strong>{len(findings)}</strong>
                </div>
              </td>
            </tr>

            <tr>
              <td style="height:8px;"></td>
            </tr>

            <tr>
              <td style="background-color:rgba(15,23,42,0.95);border-radius:12px;padding:16px;">
                <div style="font-size:13px;font-weight:600;margin-bottom:6px;">Security Hub details</div>
                <pre style="font-size:11px;line-height:1.5;color:#e5e7eb;white-space:pre-wrap;margin:0;">{escape(sec_hub_text)}</pre>
              </td>
            </tr>

            <tr><td style="height:12px;"></td></tr>

            <tr>
              <td style="background-color:rgba(15,23,42,0.95);border-radius:12px;padding:16px;">
                <div style="font-size:13px;font-weight:600;margin-bottom:4px;">S3 Security</div>
                <div style="font-size:12px;color:#e5e7eb;margin-bottom:4px;">
                  Buckets: <strong>{s3_total}</strong> • Public: <strong>{s3_public}</strong> • Unencrypted: <strong>{s3_unenc}</strong>
                </div>
                <div style="font-size:11px;color:#cbd5f5;margin-bottom:8px;">
                  {escape("No obviously risky buckets detected." if s3_public == 0 and s3_unenc == 0 else "Review public or unencrypted buckets and lock them down.")}
                </div>
                <a href="{s3_console_url}" style="font-size:11px;color:#a5b4fc;text-decoration:none;">Open S3 console →</a>
              </td>
            </tr>

            <tr><td style="height:12px;"></td></tr>

            <tr>
              <td style="background-color:rgba(15,23,42,0.95);border-radius:12px;padding:16px;">
                <div style="font-size:13px;font-weight:600;margin-bottom:4px;">
                  CloudTrail <span style="margin-left:8px;font-size:11px;">{status_label(ct_ok)}</span>
                </div>
                <div style="font-size:11px;color:#e5e7eb;margin-bottom:6px;">
                  has_trail: <strong>{ct.get("has_trail")}</strong> • multi_region_trail: <strong>{ct.get("multi_region_trail")}</strong> • trail_count: <strong>{ct.get("trail_count")}</strong>
                </div>
                <div style="font-size:11px;color:#cbd5f5;margin-bottom:6px;">
                  {escape("Best practice: Use a multi-region trail that logs to a dedicated security/audit bucket.")}
                </div>
                <div style="font-size:11px;">
                  <a href="{ct_console_url}" style="color:#a5b4fc;text-decoration:none;margin-right:12px;">View in CloudTrail console →</a>
                  <a href="https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html" style="color:#e5e7eb;text-decoration:none;">CloudTrail docs →</a>
                </div>
              </td>
            </tr>

            <tr><td style="height:12px;"></td></tr>

            <tr>
              <td style="background-color:rgba(15,23,42,0.95);border-radius:12px;padding:16px;">
                <div style="font-size:13px;font-weight:600;margin-bottom:4px;">
                  AWS Config <span style="margin-left:8px;font-size:11px;">{status_label(cfg_ok)}</span>
                </div>
                <div style="font-size:11px;color:#e5e7eb;margin-bottom:6px;">
                  recorder_configured: <strong>{cfg.get("recorder_configured")}</strong> • recording_enabled: <strong>{cfg.get("recording_enabled")}</strong>
                </div>
                <div style="font-size:11px;color:#cbd5f5;margin-bottom:6px;">
                  {escape("Enable a configuration recorder for all resources and send data to a central bucket.")}
                </div>
                <div style="font-size:11px;">
                  <a href="{cfg_console_url}" style="color:#a5b4fc;text-decoration:none;margin-right:12px;">View in Config console →</a>
                  <a href="https://docs.aws.amazon.com/config/latest/developerguide/setting-up-aws-config.html" style="color:#e5e7eb;text-decoration:none;">AWS Config docs →</a>
                </div>
              </td>
            </tr>

            <tr><td style="height:12px;"></td></tr>

            <tr>
              <td style="background-color:rgba(15,23,42,0.95);border-radius:12px;padding:16px;">
                <div style="font-size:13px;font-weight:600;margin-bottom:4px;">
                  EBS Encryption <span style="margin-left:8px;font-size:11px;">{status_label(ebs_ok)}</span>
                </div>
                <div style="font-size:11px;color:#e5e7eb;margin-bottom:6px;">
                  default_encryption_enabled: <strong>{ebs.get("default_encryption_enabled")}</strong> • total_volumes: <strong>{ebs.get("total_volumes")}</strong> • unencrypted_volume_ids: <strong>{", ".join(ebs.get("unencrypted_volume_ids") or [])}</strong>
                </div>
                <div style="font-size:11px;color:#cbd5f5;margin-bottom:6px;">
                  {escape("Turn on default EBS encryption and migrate any unencrypted volumes via snapshot/restore.")}
                </div>
                <div style="font-size:11px;">
                  <a href="{ebs_console_url}" style="color:#a5b4fc;text-decoration:none;margin-right:12px;">View EBS settings →</a>
                  <a href="https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html" style="color:#e5e7eb;text-decoration:none;">EBS encryption docs →</a>
                </div>
              </td>
            </tr>

            <tr><td style="height:12px;"></td></tr>

            <tr>
              <td style="background-color:rgba(15,23,42,0.95);border-radius:12px;padding:16px;">
                <div style="font-size:13px;font-weight:600;margin-bottom:4px;">
                  IAM Password Policy <span style="margin-left:8px;font-size:11px;">{status_label(iam_ok)}</span>
                </div>
                <div style="font-size:11px;color:#e5e7eb;margin-bottom:6px;">
                  policy_present: <strong>{iam_policy.get("policy_present")}</strong>
                </div>
                <div style="font-size:11px;color:#cbd5f5;margin-bottom:6px;">
                  {escape("Enforce a strong password policy (length ≥ 12, complexity, reuse prevention).")}
                </div>
                <div style="font-size:11px;">
                  <a href="{iam_console_url}" style="color:#a5b4fc;text-decoration:none;margin-right:12px;">View IAM account settings →</a>
                  <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html" style="color:#e5e7eb;text-decoration:none;">IAM password policy docs →</a>
                </div>
              </td>
            </tr>

            <tr><td style="height:16px;"></td></tr>

            <tr>
              <td align="center" style="font-size:10px;color:#6b7280;">
                Generated by CloudAuditPro • Account {escape(inp.account_id)} • Region {escape(region)}
              </td>
            </tr>

          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""

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
    inp: ScanInput,
    current_user: models.User = Depends(get_current_user),
):
    """
    Aggregate multiple controls into a single compliance score.
    Controls (equal weight):
      - Security Hub: pass if 0 findings
      - S3: pass if no public + no unencrypted buckets
      - CloudTrail: pass if at least 1 multi-region trail
      - Config: pass if recorder exists AND recording enabled
      - EBS: pass if default encryption on AND no unencrypted volumes
      - IAM password policy: pass if a policy is present
    """
    try:
        # Assume role once and reuse creds
        creds = assume_customer_role(inp.account_id, inp.role_name)
        region = inp.region

        # --- 1) Security Hub ---
        sh_client = securityhub_client_from_creds(creds, region)
        findings = list_findings(sh_client, inp.start_iso, inp.end_iso)
        sh_count = len(findings)
        sec_hub_ok = (sh_count == 0)

        # --- 2) S3 baseline ---
        s3_list = get_s3_security_summary(creds, region)
        s3_total = len(s3_list)
        s3_public = sum(1 for b in s3_list if b["public"])
        s3_unenc = sum(1 for b in s3_list if not b["encryption_enabled"])
        s3_ok = (s3_total > 0) and (s3_public == 0) and (s3_unenc == 0)

        # --- 3) CloudTrail ---
        ct = get_cloudtrail_status(creds, region)
        # From your sample:
        # { "has_trail": false, "multi_region_trail": false, "trail_count": 0 }
        ct_ok = bool(ct.get("has_trail")) and bool(ct.get("multi_region_trail"))

        # --- 4) Config ---
        cfg = get_config_status(creds, region)
        # From your sample:
        # { "recorder_configured": false, "recording_enabled": false, "recorder_count": 0 }
        cfg_ok = bool(cfg.get("recorder_configured")) and bool(cfg.get("recording_enabled"))

        # --- 5) EBS default encryption ---
        ebs = get_ebs_encryption_status(creds, region)
        # From your sample:
        # {
        #   "default_encryption_enabled": false,
        #   "total_volumes": 1,
        #   "unencrypted_volume_ids": ["vol-..."]
        # }
        ebs_ok = bool(ebs.get("default_encryption_enabled")) and len(
            ebs.get("unencrypted_volume_ids", [])
        ) == 0

        # --- 6) IAM password policy ---
        iam_policy = get_iam_password_policy_status(creds)
        # From your sample:
        # { "policy_present": false }  (pass only if True)
        iam_ok = bool(iam_policy.get("policy_present"))

        # --- Scoring ---
        checks = [
            {
                "id": "security_hub",
                "label": "Security Hub findings",
                "passed": sec_hub_ok,
                "details": {"finding_count": sh_count},
            },
            {
                "id": "s3_baseline",
                "label": "S3 public access & encryption",
                "passed": s3_ok,
                "details": {
                    "total_buckets": s3_total,
                    "public_buckets": s3_public,
                    "unencrypted_buckets": s3_unenc,
                },
            },
            {
                "id": "cloudtrail",
                "label": "CloudTrail multi-region trail",
                "passed": ct_ok,
                "details": ct,
            },
            {
                "id": "config",
                "label": "AWS Config recorder enabled",
                "passed": cfg_ok,
                "details": cfg,
            },
            {
                "id": "ebs_encryption",
                "label": "EBS default encryption",
                "passed": ebs_ok,
                "details": ebs,
            },
            {
                "id": "iam_password_policy",
                "label": "IAM password policy configured",
                "passed": iam_ok,
                "details": iam_policy,
            },
        ]

        total_checks = len(checks)
        passed_checks = sum(1 for c in checks if c["passed"])
        score = round((passed_checks / total_checks) * 100, 1) if total_checks else 0.0

        return {
            "score": score,
            "passed_checks": passed_checks,
            "total_checks": total_checks,
            "checks": checks,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
