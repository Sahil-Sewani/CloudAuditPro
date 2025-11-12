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

def render_s3_section(s3_summary: dict) -> str:
    if not s3_summary:
        return "\n=== S3 Security Summary ===\n(No S3 data gathered)\n"

    lines = []
    lines.append("\n=== S3 Security Summary ===")
    lines.append(
        f"Buckets: {s3_summary.get('total_buckets', 0)}  |  "
        f"Public: {s3_summary.get('public_buckets', 0)}  |  "
        f"Unencrypted: {s3_summary.get('unencrypted_buckets', 0)}"
    )

    # List a few risky buckets (top 10)
    risky = []
    for b in s3_summary.get("buckets", []):
        if b.get("public") or not b.get("encryption_enabled"):
            risky.append(
                f"- {b['bucket']}  "
                f"[{'PUBLIC' if b.get('public') else 'private'}; "
                f"{'ENCRYPTED' if b.get('encryption_enabled') else 'NO-ENCRYPTION'}]"
            )
    if risky:
        lines.append("\nBuckets needing attention:")
        lines.extend(risky[:10])
    else:
        lines.append("No obviously risky buckets detected.")

    return "\n".join(lines)
