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
from botocore.exceptions import ClientError
from app.bedrock import generate_remediation

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

# ✅ Links used in email reports
APP_URL = os.getenv("APP_URL", frontend_origin)          # dashboard/app link
WEBSITE_URL = os.getenv("WEBSITE_URL", "https://app.cloudauditpro.app")  # marketing site

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

class ConnectionCheckInput(BaseModel):
    account_id: str
    role_name: str
    region: str


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
        securityhub_enabled = True
        try:
            findings = list_findings(sh, inp.start_iso, inp.end_iso)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("InvalidAccessException", "AccessDeniedException"):
                # Not subscribed / not enabled / or blocked
                securityhub_enabled = False
                findings = []
            else:
                raise

        summary = (
            build_summary(findings)
            if securityhub_enabled
            else "Security Hub is not enabled in this AWS account/region. Enable Security Hub to view findings."
        )

        return {
            "count": len(findings),
            "summary": summary,
            "securityhub_enabled": securityhub_enabled,
        }

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


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
      - Compliance score (based on these checks)
      - Inventory rollups: EC2, VPC, RDS, SG
      - Attack surface rollup
    """
    try:
        # Assume role & clients
        creds = assume_customer_role(inp.account_id, inp.role_name)
        region = inp.region

        # ---------- helpers ----------
        def yesno(v: bool) -> str:
            return "PASS" if v else "FAIL"

        def badge(ok: bool) -> str:
            bg = "#064e3b" if ok else "#7f1d1d"
            fg = "#d1fae5" if ok else "#fee2e2"
            txt = "PASS" if ok else "FAIL"
            return (
                '<span style="display:inline-block;padding:2px 8px;border-radius:999px;'
                f'background:{bg};color:{fg};font-size:12px;font-weight:600">{txt}</span>'
            )

        def h(s: str) -> str:
            return escape(str(s or ""))

        # ---------- Security Hub ----------
        sec_hub_enabled = True
        sec_hub_error_msg = ""
        findings = []
        finding_count = 0
        top_titles = []

        try:
            sh = securityhub_client_from_creds(creds, region)
            findings = list_findings(sh, inp.start_iso, inp.end_iso)
            finding_count = len(findings)

            # Top finding titles (bounded)
            title_counts: Dict[str, int] = {}
            for f in findings:
                t = f.get("Title") or "Unknown"
                title_counts[t] = title_counts.get(t, 0) + 1
            top_titles = sorted(title_counts.items(), key=lambda x: x[1], reverse=True)[:8]

        except ClientError as e:
            # When Security Hub isn't enabled/subscribed in the target account+region
            if e.response.get("Error", {}).get("Code") in ("InvalidAccessException", "AccessDeniedException"):
                sec_hub_enabled = False
                sec_hub_error_msg = "Security Hub is not enabled in this account/region."
            else:
                raise
        except Exception as e:
            # Fallback (handles string-based errors from wrappers)
            msg = str(e)
            if "not subscribed to AWS Security Hub" in msg or "InvalidAccessException" in msg:
                sec_hub_enabled = False
                sec_hub_error_msg = "Security Hub is not enabled in this account/region."
            else:
                raise

        # If SH isn't enabled, treat this check as "not passing" (but don't crash)
        sec_hub_ok = (finding_count == 0) if sec_hub_enabled else False

        # Precompute display helpers for HTML
        sec_hub_badge = (
            badge(sec_hub_ok)
            if sec_hub_enabled
            else '<span style="display:inline-block;padding:2px 8px;border-radius:999px;background:#1f2937;color:#e5e7eb;border:1px solid rgba(148,163,184,.25);font-size:11px;">NOT ENABLED</span>'
        )
        sec_hub_note_html = (
            f'<div style="margin-top:6px;font-size:12px;color:#fbbf24;">{h(sec_hub_error_msg)}</div>'
            if (not sec_hub_enabled and sec_hub_error_msg)
            else ""
        )


        # ---------- S3 ----------
        s3_list = get_s3_security_summary(creds, region)
        s3_total = len(s3_list)
        s3_public = sum(1 for b in s3_list if b.get("public"))
        s3_unenc = sum(1 for b in s3_list if not b.get("encryption_enabled"))

        # If you have no buckets, keep it as FAIL only if you want to enforce presence.
        s3_ok = (s3_public == 0) and (s3_unenc == 0)

        risky_buckets = []
        for b in s3_list:
            if b.get("public") or not b.get("encryption_enabled"):
                risky_buckets.append(b)
        risky_buckets = risky_buckets[:10]

        # ---------- Core checks ----------
        ct = get_cloudtrail_status(creds, region)
        ct_ok = bool(ct.get("has_trail")) and bool(ct.get("multi_region_trail"))

        cfg = get_config_status(creds, region)
        cfg_ok = bool(cfg.get("recorder_configured")) and bool(cfg.get("recording_enabled"))

        ebs = get_ebs_encryption_status(creds, region)
        ebs_ok = bool(ebs.get("default_encryption_enabled")) and len(ebs.get("unencrypted_volume_ids", [])) == 0

        iam_policy = get_iam_password_policy_status(creds, region)
        iam_ok = bool(iam_policy.get("policy_present"))

        # Compliance score (simple: these 6 controls)
        checks = [
            ("Security Hub findings", sec_hub_ok),
            ("S3 public access & encryption", s3_ok),
            ("CloudTrail multi-region trail", ct_ok),
            ("AWS Config recorder enabled", cfg_ok),
            ("EBS default encryption", ebs_ok),
            ("IAM password policy configured", iam_ok),
        ]
        passed = sum(1 for _, ok in checks if ok)
        total = len(checks)
        score = round((passed / total) * 100) if total else 0

        # ---------- Inventory / Attack surface ----------
        ec2_inv = get_ec2_inventory(creds, region)
        vpc_inv = get_vpc_inventory(creds, region)
        rds_inv = get_rds_inventory(creds, region)
        sg_inv = get_sg_inventory(creds, region)
        attack = build_attack_surface(creds, region)

        ec2_count = int(ec2_inv.get("count", 0) or 0) if isinstance(ec2_inv, dict) else 0
        vpc_count = int(vpc_inv.get("count", 0) or 0) if isinstance(vpc_inv, dict) else 0
        rds_count = 0
        if isinstance(rds_inv, dict):
            rds_count = int(rds_inv.get("count", rds_inv.get("instance_count", 0)) or 0)
        sg_count = int(sg_inv.get("count", 0) or 0) if isinstance(sg_inv, dict) else 0

        # Attack surface keys can vary; keep it resilient
        public_instance_count = int(attack.get("count", 0) or 0) if isinstance(attack, dict) else 0

        # World-open SGs from SG inventory
        sgs = sg_inv.get("security_groups", []) if isinstance(sg_inv, dict) else []
        world_open_sgs = [g for g in sgs if g.get("world_open")]
        world_open_sgs = world_open_sgs[:10]

        # Public RDS list (bounded)
        rds_instances = rds_inv.get("instances", []) if isinstance(rds_inv, dict) else []
        public_rds = [db for db in rds_instances if db.get("publicly_accessible")]
        public_rds = public_rds[:10]

        # ---------- Plain-text fallback ----------
        body_text = build_summary(findings)
        body_text += "\n\n" + render_s3_section(
            {
                "total_buckets": s3_total,
                "public_buckets": s3_public,
                "unencrypted_buckets": s3_unenc,
                "buckets": s3_list,
            }
        )
        body_text += (
            f"\n\n=== Checks ===\n"
            f"Security Hub: {'NOT ENABLED' if not sec_hub_enabled else yesno(sec_hub_ok)} (findings={finding_count})\n"            f"S3: {yesno(s3_ok)} (total={s3_total}, public={s3_public}, unencrypted={s3_unenc})\n"
            f"CloudTrail: {yesno(ct_ok)} (trails={ct.get('trail_count')}, multi_region={ct.get('multi_region_trail')})\n"
            f"AWS Config: {yesno(cfg_ok)} (recorders={cfg.get('recorder_count')}, recording={cfg.get('recording_enabled')})\n"
            f"EBS: {yesno(ebs_ok)} (default={ebs.get('default_encryption_enabled')}, unencrypted={len(ebs.get('unencrypted_volume_ids', []))})\n"
            f"IAM Password Policy: {yesno(iam_ok)}\n"
            f"\n=== Inventory ===\nEC2={ec2_count}, VPC={vpc_count}, RDS={rds_count}, SG={sg_count}\n"
            f"\n=== Attack Surface ===\nPublic-running EC2 instances={public_instance_count}, World-open SGs={len(world_open_sgs)}\n"
        )

        # ---------- Links ----------
        body_text += (
            f"\n\nOpen dashboard: {APP_URL}"
            f"\nWebsite: {WEBSITE_URL}\n"
        )


        # ---------- HTML email ----------
        bar_color = "#10b981" if score >= 80 else ("#f59e0b" if score >= 50 else "#ef4444")
        body_html = f"""<!doctype html>
<html>
  <body style="margin:0;background:#0b1020;color:#e5e7eb;font-family:Arial,Helvetica,sans-serif;">
    <div style="max-width:900px;margin:0 auto;padding:24px;">
      <div style="padding:18px 18px;border:1px solid rgba(99,102,241,.35);border-radius:16px;background:rgba(0,0,0,.35);">
        <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;">
          <div>
            <div style="font-size:14px;letter-spacing:.18em;text-transform:uppercase;color:#a5b4fc;">CloudAuditPro</div>
            <div style="font-size:20px;font-weight:700;margin-top:4px;">AWS Security Report</div>

            <div style="margin-top:6px;font-size:13px;">
            <a href="{APP_URL}" style="color:#93c5fd;text-decoration:none;font-weight:600;">
                Open dashboard →
            </a>
            <span style="color:#64748b;"> · </span>
            <a href="{WEBSITE_URL}" style="color:#93c5fd;text-decoration:none;">
                Visit website
            </a>
            </div>

            <div style="font-size:12px;color:#9ca3af;margin-top:4px;">
              Account: <b>{h(inp.account_id)}</b> · Region: <b>{h(region)}</b>
            </div>
            <div style="font-size:12px;color:#9ca3af;margin-top:2px;">
              Window: {h(inp.start_iso or "N/A")} → {h(inp.end_iso or "N/A")}
            </div>
          </div>
          <div style="text-align:right;min-width:220px;">
            <div style="font-size:12px;color:#9ca3af;margin-bottom:6px;">Compliance score</div>
            <div style="font-size:28px;font-weight:800;line-height:1;">{score}%</div>
            <div style="height:10px;background:#111827;border-radius:999px;overflow:hidden;margin-top:8px;border:1px solid rgba(148,163,184,.25);">
              <div style="height:10px;width:{score}%;background:{bar_color};"></div>
            </div>
            <div style="font-size:12px;color:#9ca3af;margin-top:6px;">{passed}/{total} checks passing</div>
          </div>
        </div>
      </div>

      <div style="display:flex;flex-wrap:wrap;gap:12px;margin-top:14px;">
        <div style="flex:1;min-width:260px;padding:14px;border-radius:16px;background:rgba(0,0,0,.35);border:1px solid rgba(148,163,184,.2);">
          <div style="font-weight:700;margin-bottom:8px;">Core checks</div>
          <table style="width:100%;border-collapse:collapse;font-size:13px;">
            <tr><td style="padding:6px 0;color:#c7d2fe;">Security Hub findings</td><td style="padding:6px 0;text-align:right;">{sec_hub_badge}</td></tr>
            <tr><td style="padding:6px 0;color:#c7d2fe;">S3 public access &amp; encryption</td><td style="padding:6px 0;text-align:right;">{badge(s3_ok)}</td></tr>
            <tr><td style="padding:6px 0;color:#c7d2fe;">CloudTrail multi-region</td><td style="padding:6px 0;text-align:right;">{badge(ct_ok)}</td></tr>
            <tr><td style="padding:6px 0;color:#c7d2fe;">AWS Config recording</td><td style="padding:6px 0;text-align:right;">{badge(cfg_ok)}</td></tr>
            <tr><td style="padding:6px 0;color:#c7d2fe;">EBS default encryption</td><td style="padding:6px 0;text-align:right;">{badge(ebs_ok)}</td></tr>
            <tr><td style="padding:6px 0;color:#c7d2fe;">IAM password policy</td><td style="padding:6px 0;text-align:right;">{badge(iam_ok)}</td></tr>
          </table>
        </div>

        <div style="flex:1;min-width:260px;padding:14px;border-radius:16px;background:rgba(0,0,0,.35);border:1px solid rgba(148,163,184,.2);">
          <div style="font-weight:700;margin-bottom:8px;">Inventory rollup</div>
          <div style="font-size:13px;color:#e5e7eb;line-height:1.8;">
            EC2 instances: <b>{ec2_count}</b><br/>
            VPCs: <b>{vpc_count}</b><br/>
            RDS instances: <b>{rds_count}</b><br/>
            Security groups: <b>{sg_count}</b><br/>
            Attack surface (public-running EC2): <b>{public_instance_count}</b><br/>
            World-open SGs: <b>{len(world_open_sgs)}</b>
          </div>
        </div>
      </div>

      <div style="margin-top:12px;padding:14px;border-radius:16px;background:rgba(0,0,0,.35);border:1px solid rgba(148,163,184,.2);">
        <div style="font-weight:700;margin-bottom:8px;">Security Hub findings</div>
        <div style="font-size:13px;color:#e5e7eb;">
        Total findings: <b>{finding_count}</b>
        {sec_hub_note_html}
        </div>
        <div style="margin-top:8px;font-size:13px;color:#cbd5e1;">
          {("".join([f"<div>• {h(t)} — {c}</div>" for (t,c) in top_titles]) if top_titles else "<div>No findings detected in this window.</div>")}
        </div>
      </div>

      <div style="margin-top:12px;padding:14px;border-radius:16px;background:rgba(0,0,0,.35);border:1px solid rgba(148,163,184,.2);">
        <div style="font-weight:700;margin-bottom:8px;">S3 summary</div>
        <div style="font-size:13px;color:#e5e7eb;">
          Buckets: <b>{s3_total}</b> · Public: <b>{s3_public}</b> · Unencrypted: <b>{s3_unenc}</b>
        </div>
        <div style="margin-top:8px;font-size:13px;color:#cbd5e1;">
          {("".join([f"<div>• {h(b.get('bucket'))} — {('PUBLIC' if b.get('public') else 'private')}, {('ENCRYPTED' if b.get('encryption_enabled') else 'NO-ENCRYPTION')}</div>" for b in risky_buckets]) if risky_buckets else "<div>No obviously risky buckets detected.</div>")}
        </div>
      </div>

      <div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:12px;">
        <div style="flex:1;min-width:260px;padding:14px;border-radius:16px;background:rgba(0,0,0,.35);border:1px solid rgba(148,163,184,.2);">
          <div style="font-weight:700;margin-bottom:8px;">World-open security groups (top)</div>
          <div style="font-size:13px;color:#cbd5e1;">
            {("".join([f"<div>• {h(g.get('group_id'))} — {h(g.get('group_name') or '')}</div>" for g in world_open_sgs]) if world_open_sgs else "<div>No world-open SGs detected.</div>")}
          </div>
        </div>

        <div style="flex:1;min-width:260px;padding:14px;border-radius:16px;background:rgba(0,0,0,.35);border:1px solid rgba(148,163,184,.2);">
          <div style="font-weight:700;margin-bottom:8px;">Public RDS instances (top)</div>
          <div style="font-size:13px;color:#cbd5e1;">
            {("".join([f"<div>• {h(db.get('id'))} — {h(db.get('engine'))}</div>" for db in public_rds]) if public_rds else "<div>No publicly accessible RDS instances detected.</div>")}
          </div>
        </div>
      </div>

        <div style="margin-top:14px;font-size:12px;color:#9ca3af;">
        Generated by CloudAuditPro ·
        <a href="{WEBSITE_URL}" style="color:#93c5fd;text-decoration:none;">
            cloudauditpro.app
        </a>
        ·
        <a href="{APP_URL}" style="color:#93c5fd;text-decoration:none;">
            Open dashboard
        </a>
        </div>
    </div>
  </body>
</html>
"""

        # ---------- Send with SES ----------
        to_addr = inp.email_to or TEST_TO
        if not (SES_FROM and to_addr):
            raise HTTPException(status_code=400, detail="SES_FROM_ADDRESS or recipient missing")

        ses = boto3.client("ses", region_name=REGION)
        ses.send_email(
            Source=SES_FROM,
            Destination={"ToAddresses": [to_addr]},
            Message={
                "Subject": {
                    "Data": f"CloudAuditPro Report — {inp.account_id} ({region}) — Score {score}%",
                    "Charset": "UTF-8",
                },
                "Body": {
                    "Text": {"Data": body_text, "Charset": "UTF-8"},
                    "Html": {"Data": body_html, "Charset": "UTF-8"},
                },
            },
        )

        return {"sent_to": to_addr, "score": score, "finding_count": finding_count}
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

        cfg_ok = (
            bool(status.get("recorder_configured"))
            and bool(status.get("recording_enabled"))
        )

        if not cfg_ok:
            if status.get("error"):
                finding = (
                    "CloudAuditPro could not verify AWS Config status because "
                    f"the AWS API returned an error: {status['error']}"
                )
            elif not status.get("recorder_configured"):
                finding = "No AWS Config recorder is configured."
            else:
                finding = (
                    "An AWS Config recorder exists, but none are actively recording."
                )

            status["ai_remediation"] = generate_remediation(
                service="AWS Config",
                status="FAIL",
                finding=finding,
                control_id="CLOUDAUDITPRO-AWS-CONFIG-RECORDER",
            )

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
        securityhub_enabled = True
        try:
            findings = list_findings(sh_client, inp.start_iso, inp.end_iso)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("InvalidAccessException", "AccessDeniedException"):
                securityhub_enabled = False
                findings = []
            else:
                raise

        sh_count = len(findings)

        # If Security Hub isn't enabled, treat as "not passing" (or you could treat as "N/A")
        sec_hub_ok = securityhub_enabled and (sh_count == 0)

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
                "details": {
                    "finding_count": sh_count,
                    "enabled": securityhub_enabled,
                    "note": None if securityhub_enabled else "Security Hub is not enabled in this account/region.",
                },
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

@app.post("/aws/connection-check")
def aws_connection_check(
    inp: ConnectionCheckInput,
    current_user: models.User = Depends(get_current_user),
):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        sts = boto3.client(
            "sts",
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=inp.region,
        )
        ident = sts.get_caller_identity()
        return {
          "ok": True,
          "account": ident.get("Account"),
          "arn": ident.get("Arn"),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
