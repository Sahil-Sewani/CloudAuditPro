import json

import boto3


MODEL_ID = "us.amazon.nova-2-lite-v1:0"

bedrock = boto3.client(
    "bedrock-runtime",
    region_name="us-east-1",
)


def generate_remediation(service: str, status: str, finding: str) -> dict:
    """
    Generate remediation guidance for an existing CloudAuditPro finding.

    Bedrock does NOT determine whether the control passes or fails.
    CloudAuditPro's deterministic checks make that decision.
    """

    prompt = f"""
Service: {service}
Status: {status}
Finding: {finding}

Explain this AWS security finding.

Return valid JSON only using this structure:

{{
    "summary": "Brief explanation of why this finding matters",
    "risk": "Brief explanation of the security risk",
    "remediation_steps": [
        "Step 1",
        "Step 2",
        "Step 3"
    ]
}}

Do not claim formal compliance certification.
"""

    response = bedrock.converse(
        modelId=MODEL_ID,
        system=[
            {
                "text": (
                    "You are an AWS security remediation assistant. "
                    "Provide clear and practical AWS security guidance. "
                    "Do not determine whether a security control passes or fails. "
                    "Only explain findings already identified by CloudAuditPro."
                )
            }
        ],
        messages=[
            {
                "role": "user",
                "content": [{"text": prompt}],
            }
        ],
        inferenceConfig={
            "maxTokens": 800,
            "temperature": 0.2,
        },
    )

    text = response["output"]["message"]["content"][0]["text"]

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "summary": text,
            "risk": "",
            "remediation_steps": [],
        }
