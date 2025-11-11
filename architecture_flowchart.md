flowchart LR
    subgraph User["User / Security Team"]
        U1["Web UI (React + Tailwind)"]
    end

    subgraph Backend["CloudAuditPro API (FastAPI)"]
        A1["Auth / Users (Cognito or JWT)"]
        A2["AWS Scanner (Security Hub, Config, S3 checks)"]
        A3["Network Scanner (ASA / Nagios / TACACS)"]
        A4["Reporting Engine (HTML/PDF)"]
        A5["Scheduler Hook (EventBridge / Cron)"]
        A6["Storage (DynamoDB / Postgres)"]
    end

    subgraph AWS["Customer AWS Accounts"]
        C1["IAM Role (AssumeRole + ExternalId)"]
        C2["AWS Security Hub"]
        C3["AWS Config / CloudTrail"]
    end

    subgraph Integrations["External Integrations"]
        I1["Slack Webhook"]
        I2["SES (Email Reports)"]
        I3["Stripe (Billing)"]
        I4["Ticketing (Jira/ServiceNow)"]
    end

    subgraph Network["On-Prem / Edge"]
        N1["Cisco ASA / Firewalls"]
        N2["Nagios / Monitoring"]
        N3["TACACS / LDAP"]
    end

    U1 -->|HTTPS| Backend
    Backend -->|AssumeRole| C1
    Backend -->|GetFindings| C2
    Backend -->|Describe*| C3

    Backend -->|SSH/API Poll| Network
    Backend -->|Send report| I2
    Backend -->|Post alert| I1
    Backend -->|Store scans| A6
    Backend -->|Create invoices| I3
    Backend -->|Optional create tickets| I4

    A5 --> Backend
