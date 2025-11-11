import os
import stripe
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
import boto3


from .aws import assume_customer_role, securityhub_client_from_creds, list_findings
from .report import build_summary


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

origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]

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




@app.get("/")
def health():
    return {"status": "ok", "env": APP_ENV}




@app.post("/scan")
def scan(inp: ScanInput):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        sh = securityhub_client_from_creds(creds, inp.region)
        findings = list_findings(sh, inp.start_iso, inp.end_iso)
        summary = build_summary(findings)
        return {"count": len(findings), "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@app.post("/report/email")
def email_report(inp: ScanInput):
    try:
        creds = assume_customer_role(inp.account_id, inp.role_name)
        sh = securityhub_client_from_creds(creds, inp.region)
        findings = list_findings(sh, inp.start_iso, inp.end_iso)
        summary = build_summary(findings)

        to_addr = inp.email_to or TEST_TO
        if not (SES_FROM and to_addr):
            raise HTTPException(status_code=400, detail="SES_FROM_ADDRESS or recipient missing")

        ses = boto3.client("ses", region_name=REGION)
        ses.send_email(
            Source=SES_FROM,
            Destination={"ToAddresses": [to_addr]},
            Message={
                "Subject": {"Data": "Weekly AWS Security Report"},
                "Body": {"Text": {"Data": summary}},
            },
        )
        return {"sent_to": to_addr, "length": len(summary)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
