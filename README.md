# CloudAuditPro — MVP


## 0) Prereqs
- Python 3.11, AWS CLI configured, an S3 bucket for Zappa deploys
- SES verified sender email (and recipient if in sandbox)
- Stripe account (price ID ready)


## 1) Setup
```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp ../.env.example ../.env # then edit values