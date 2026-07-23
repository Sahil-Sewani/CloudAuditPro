# CloudAuditPro

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

> **Note:** Continue using the remainder of your original README (setup
> instructions, API overview, onboarding guide, compliance disclaimer,
> license, and contact information). Only remove the sentence stating
> that there is no automated backend test suite.
