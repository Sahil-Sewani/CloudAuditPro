# CloudAuditPro

## Live Demo

**Application:** https://app.cloudauditpro.app

CloudAuditPro is deployed on AWS as a demo application.

> Access is restricted to authorized users. If you're evaluating the platform, I'd be happy to provide a walkthrough or demonstration.

---

CloudAuditPro is an AWS security posture and compliance intelligence
platform. It connects to customer AWS accounts through a read-only IAM
role, evaluates security controls, inventories exposed resources, and
presents actionable findings in a React dashboard.

> CloudAuditPro supports compliance readiness and continuous monitoring.
> It does not provide certification, legal advice, or an audit opinion.

## Why CloudAuditPro?

CloudAuditPro helps organizations continuously monitor and understand
the security posture of their AWS environments without requiring
long-lived AWS credentials.

By leveraging **cross-account IAM role assumption (AWS STS)**, the
platform performs automated security analysis while allowing customers
to maintain complete ownership and control of their AWS accounts.

CloudAuditPro was designed around three core engineering principles:

-   **Security by Design** -- Customer credentials are never stored.
    Access is performed using temporary AWS STS credentials and
    least-privilege IAM policies.
-   **Least-Privilege Access** -- Every AWS interaction is executed
    through a customer-managed read-only IAM role.
-   **Cloud-Native Architecture** -- Built using modern AWS services and
    scalable backend technologies suitable for production deployments.

## Key Technical Accomplishments

-   Designed a secure multi-account AWS architecture using cross-account
    IAM role assumption (AWS STS).
-   Built a modular FastAPI backend exposing REST APIs for security
    scanning, compliance analysis, infrastructure inventory,
    authentication, and reporting.
-   Implemented Infrastructure as Code (AWS CloudFormation) for
    automated customer onboarding.
-   Developed a React dashboard for real-time security posture
    visualization and compliance reporting.
-   Integrated Amazon SES for automated reporting workflows.
-   Implemented JWT authentication, bcrypt password hashing, and secure
    onboarding.
-   Designed separate development and production environments using
    SQLite and Amazon RDS PostgreSQL.
-   Built reusable AWS service integrations using Boto3 for Security
    Hub, CloudTrail, AWS Config, EC2, VPC, EBS, RDS, IAM, S3, and
    Security Groups.

## Features

-   Read-only, cross-account AWS access with AWS STS
-   Security Hub finding summaries
-   Security checks for S3, CloudTrail, AWS Config, EBS, and IAM
-   EC2, VPC, RDS, and security group inventory
-   Attack-surface visibility
-   Control mapping for CIS AWS Foundations, PCI DSS, and SOC 2
-   Multi-account management
-   JWT-based user authentication and password reset
-   HTML email reports through Amazon SES
-   Stripe checkout integration

## Architecture

``` mermaid
flowchart LR
    U["React dashboard"] -->|HTTPS + JWT| API["FastAPI API"]
    API --> DB[("SQLite (Development)\nAmazon RDS PostgreSQL (Production)")]
    API -->|AssumeRole| IAM["Customer read-only IAM role"]
    IAM --> AWS["AWS APIs"]
    AWS --> SH["Security Hub"]
    AWS --> S3["S3"]
    AWS --> OBS["CloudTrail + Config"]
    AWS --> INV["EC2 + EBS + VPC + RDS"]
    API --> SES["Amazon SES"]
    API --> STRIPE["Stripe"]
```

## Technology Stack

  -----------------------------------------------------------------------
  Category                      Technologies
  ----------------------------- -----------------------------------------
  **Frontend**                  React 19, Vite, Tailwind CSS, JavaScript
                                (ES6+)

  **Backend**                   Python 3, FastAPI, Uvicorn

  **Database**                  SQLite (Development), Amazon RDS
                                PostgreSQL (Production), SQLAlchemy

  **AWS Services**              IAM, AWS STS, Security Hub, AWS Config,
                                CloudTrail, EC2, VPC, EBS, RDS, S3, SES

  **AWS SDK**                   Boto3

  **Authentication**            JWT, bcrypt

  **Infrastructure as Code**    AWS CloudFormation

  **API Documentation**         OpenAPI / Swagger

  **Billing**                   Stripe

  **Version Control**           Git, GitHub

  **Development Tools**         Python venv, npm, Vite
  -----------------------------------------------------------------------

## Repository Layout

``` text
CloudAuditPro/
├── backend/
│   ├── app/
│   ├── migrations/
│   ├── requirements.txt
│   └── zappa_settings.json
├── frontend/
│   ├── src/
│   └── package.json
├── infra/
│   └── iam/
├── extra_documentation/
├── run.sh
└── LICENSE
```

## Local Development

Keep your existing installation, environment variable, startup, API
overview, AWS account onboarding, and security sections from the
original README below this point.

## Production Deployment

  Environment   Database
  ------------- ---------------------------
  Development   SQLite
  Production    Amazon RDS for PostgreSQL

Set `DATABASE_URL` to the appropriate database connection string for
each environment. SQLite is used by default for local development;
production deployments should use an Amazon RDS PostgreSQL instance.

## AWS account onboarding

CloudAuditPro scans customer accounts by assuming a customer-controlled read-only IAM role. A starter CloudFormation template is available at [`infra/iam/cloudauditpro_role.yml`](infra/iam/cloudauditpro_role.yml).

1. Deploy the template in the AWS account to scan.
2. Supply the AWS account ID where CloudAuditPro runs.
3. Keep the template's external ID aligned with the backend `EXTERNAL_ID`.
4. Confirm that the CloudAuditPro runtime identity can call `sts:AssumeRole`.
5. Add the account ID, role name, and region in the dashboard.
6. Run the connection check before starting a scan.

The default role name is `CloudAuditProReadRole`. Review and tailor the included permissions before production use; required permissions depend on the checks you enable.

## API overview

Most scan and account endpoints require an `Authorization: Bearer <token>` header.

| Area | Representative endpoints |
| --- | --- |
| Authentication | `/auth/register`, `/auth/login`, `/auth/me` |
| AWS accounts | `/aws-accounts/`, `/aws/connections` |
| Scanning | `/scan`, `/aws/connection-check` |
| Security checks | `/aws/s3-summary`, `/checks/cloudtrail`, `/checks/config`, `/checks/iam-password-policy`, `/checks/ebs-encryption` |
| Inventory | `/inventory/ec2`, `/inventory/vpc`, `/inventory/rds`, `/inventory/sg`, `/inventory/attack-surface` |
| Compliance | `/compliance/summary` |
| Reporting | `/report/email` |

Use the generated OpenAPI documentation at `/docs` for current request and response schemas.

## Quality checks

```bash
cd frontend
npm run lint
npm run build
```

The repository does not currently include an automated backend test suite.

## Security model

- Customer AWS access uses temporary STS credentials.
- Customer access keys are not stored by the application.
- The onboarding role is intended to be read-only and customer-controlled.
- API scan routes are protected with JWT authentication.
- Cross-origin access is limited to configured frontend origins.

Please report suspected vulnerabilities privately to [sahil@9o5enterprises.com](mailto:sahil@9o5enterprises.com). Do not open a public issue containing sensitive details.

## Compliance disclaimer

CloudAuditPro performs automated technical assessments using the AWS configuration data available to it. Results may be incomplete or require human interpretation. CloudAuditPro does not guarantee compliance and does not replace a qualified assessor, formal audit, certification, or legal advice.

## License

CloudAuditPro™ is proprietary software owned by 9o5 Enterprises, LLC. It is not open source. Unauthorized copying, modification, distribution, sublicensing, or use is prohibited. See [`LICENSE`](LICENSE).

## Contact

Questions, access requests, and partnership inquiries: [sahil@9o5enterprises.com](mailto:sahil@9o5enterprises.com)

© 2026 9o5 Enterprises, LLC. All rights reserved.

