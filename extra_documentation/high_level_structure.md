```vbnet
                       ┌─────────────────────────┐
                       │     User's Browser       │
                       │  (Chrome / Safari / etc) │
                       └───────────┬─────────────┘
                                   │ HTTPS
                     PUBLIC WEB    ▼
┌──────────────────────────────────────────────────────────────┐
│                       CloudFront CDN                          │
│        (serves React app from S3, handles HTTPS certs)        │
└───────────┬──────────────────────────────────────────────────┘
            │
            ▼
┌──────────────────────────────────────────────────────────────┐
│                         S3 Bucket (Frontend)                  │
│     Contains built React app (static HTML/CSS/JS bundle)      │
└───────────┬──────────────────────────────────────────────────┘
            │ App JS calls API over HTTPS
            ▼
┌──────────────────────────────────────────────────────────────┐
│                          EC2 Backend                          │
│                 FastAPI + Uvicorn + Systemd                  │
│                                                              │
│  ┌───────────────────────────┐   ┌─────────────────────────┐ │
│  │  Authentication Service   │   │      Scan Service       │ │
│  │ (JWT, login, signup, etc)│   │ (AWS Security Hub, S3)  │ │
│  └───────────────────────────┘   └─────────────────────────┘ │
│               │                        │                     │
│               ▼                        ▼                     │
│      SQLite Database            AWS AssumeRole API           │
└───────────┬──────────────────────┬───────────────────────────┘
            │                      │
            ▼                      ▼
  ┌─────────────────┐   ┌─────────────────────────────────────┐
  │Password Reset DB│   │  Customer AWS Accounts (External)  │
  └─────────────────┘   │    - SecurityHub:ListFindings      │
                        │    - S3:GetBucket*                 │
                        │    - Only via IAM Role            │
                        └─────────────────────────────────────┘

```