# app/frameworks.py (or wherever main.py lives)

"""
Framework → control mapping for CloudAuditPro compliance scoring.

Control IDs correspond to the IDs produced in main.compliance_summary:

- security_hub
- s3_baseline
- cloudtrail
- config
- ebs_encryption
- iam_password_policy
"""

FRAMEWORK_CONTROLS = {
    # CIS AWS Foundations Benchmark (simplified baseline)
    "cis": [
        "security_hub",
        "s3_baseline",
        "cloudtrail",
        "config",
        "ebs_encryption",
        "iam_password_policy",
    ],
    # PCI DSS - focuses on logging, configuration, encryption, and auth
    "pci": [
        "cloudtrail",
        "config",
        "ebs_encryption",
        "iam_password_policy",
        "s3_baseline",
    ],
    # SOC 2 - emphasizes monitoring, logging, and encryption
    "soc2": [
        "security_hub",
        "cloudtrail",
        "config",
        "ebs_encryption",
        "iam_password_policy",
    ],
}

