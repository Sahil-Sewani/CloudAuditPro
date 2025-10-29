from collections import Counter
from typing import Dict, List

FIX_HINTS = {
    "S3 bucket should not allow public read access": "Review bucket ACL/Policy. Ex: aws s3api put-bucket-acl --acl private --bucket <name>",
    "Security group allows unrestricted access": "Restrict CIDR. Ex: aws ec2 revoke-security-group-ingress --group-id <sg> --protocol tcp --port 22 --cidr 0.0.0.0/0",
}


def build_summary(findings: List[Dict]) -> str:
    sev_counts = Counter(f.get("Severity", {}).get("Label", "UNKNOWN") for f in findings)
    title_counts = Counter(f.get("Title", "Unknown") for f in findings)

    lines = []
    lines.append("=== Weekly AWS Security Summary ===")
    lines.append(f"Total findings: {len(findings)}")

    for sev, cnt in sev_counts.most_common():
        lines.append(f"- {sev}: {cnt}")

    lines.append("\nTop issues and example remediations:\n")
    for title, cnt in title_counts.most_common(8):
        hint = FIX_HINTS.get(title, "Open the finding in Security Hub for remediation guidance.")
        lines.append(f"* {title} — occurrences: {cnt}")
        lines.append(f"  Fix: {hint}")

    return "\n".join(lines)
