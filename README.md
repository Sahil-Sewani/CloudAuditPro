# ☁️ CloudAuditPro  
**Automated AWS Security & Compliance Reporting**

CloudAuditPro is a lightweight SaaS-style application that automatically scans AWS accounts for security misconfigurations using **AWS Security Hub**, then delivers clear, actionable weekly reports via **email or Slack**.  

It’s designed to give teams **instant visibility** into their AWS security posture — without requiring deep AWS expertise or console access.

---

## 🚀 Why CloudAuditPro

| Problem with Security Hub | CloudAuditPro Advantage |
|----------------------------|--------------------------|
| Raw, technical findings that require AWS expertise | Summarized reports in plain English with clear “how-to-fix” steps |
| Results locked inside AWS Console | Weekly automated email & Slack reports for all stakeholders |
| Multi-account data requires manual aggregation | Unified, cross-account view using AssumeRole |
| No compliance context | Findings mapped to CIS / NIST controls (coming soon) |
| No trend visibility | Weekly history & improvement tracking (planned) |

> **In short:**  
> Security Hub tells you what’s wrong — **CloudAuditPro tells you what to fix, when, and how.**

---

## 🧠 How It Works

1. **User connects AWS account**  
   - Deploys a simple, read-only IAM role using the provided CloudFormation template.  
   - Grants CloudAuditPro permission to assume the role securely with an External ID.

2. **Automated scan**  
   - CloudAuditPro uses the AWS SDK (boto3) to assume the role and query **Security Hub** findings.  
   - Findings are summarized, prioritized, and mapped to known compliance frameworks.

3. **Report generation & delivery**  
   - A scheduled Lambda job (via EventBridge) generates weekly reports.  
   - Reports are emailed via **Amazon SES** or sent to a Slack channel.

4. **Dashboard (optional)**  
   - A React-based frontend displays aggregated risk scores, recent findings, and account summaries.

---

## 🧩 Architecture Overview


**Tech Stack:**
- **Backend:** Python + FastAPI  
- **Infrastructure:** AWS Lambda (Zappa), EventBridge, SES  
- **Auth:** AWS Cognito (optional)  
- **Payments:** Stripe Checkout  
- **Frontend:** React + Tailwind CSS (optional for MVP)  

---

## ⚙️ Setup (Developer Quickstart)

```bash
# Clone repo
git clone https://github.com/YOURUSERNAME/CloudAuditPro.git
cd CloudAuditPro/backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp ../.env.example ../.env
# then edit .env with your AWS + Stripe credentials

# Run locally
python -m uvicorn app.main:app --reload
