# backend/app/routers/onboarding.py
import os
import boto3
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import get_db
from .. import models, schemas
from ..auth_utils import get_current_user

router = APIRouter(prefix="/aws", tags=["aws-onboarding"])

CFN_BUCKET = os.getenv("CFN_TEMPLATE_BUCKET", "cloudauditpro-onboarding-templates")
CFN_KEY = os.getenv("CFN_TEMPLATE_KEY", "cloudauditpro-read-role.yaml")
CFN_REGION = os.getenv("CFN_TEMPLATE_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))
CFN_EXPIRES = int(os.getenv("CFN_TEMPLATE_EXPIRES", "900"))  # 15 minutes


@router.get("/cfn-template-url")
def get_cfn_template_url(current_user: models.User = Depends(get_current_user)):
    """
    Returns a short-lived presigned S3 URL for the CloudFormation template.
    We require auth just to avoid leaking internal template URLs.
    """
    try:
        s3 = boto3.client("s3", region_name=CFN_REGION)
        url = s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={"Bucket": CFN_BUCKET, "Key": CFN_KEY},
            ExpiresIn=CFN_EXPIRES,
        )
        return {"template_url": url, "expires_in": CFN_EXPIRES}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate template URL: {e}")



def get_or_create_org_for_user(db: Session, user: models.User) -> models.Organization:
    if user.organization:
        return user.organization

    org = models.Organization(
        name=f"{user.name}'s Org",
        owner_user_id=user.id,
    )
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@router.post("/connections", response_model=schemas.AwsConnectionRead)
def create_aws_connection(
    payload: schemas.AwsConnectionCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    org = get_or_create_org_for_user(db, current_user)

    conn = models.AwsConnection(
        org_id=org.id,
        display_name=payload.display_name,
        account_id=payload.account_id,
        role_arn=payload.role_arn,
        external_id=payload.external_id,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return conn


@router.get("/connections", response_model=schemas.AwsConnectionList)
def list_aws_connections(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    org = get_or_create_org_for_user(db, current_user)
    conns = (
        db.query(models.AwsConnection)
        .filter(models.AwsConnection.org_id == org.id)
        .order_by(models.AwsConnection.created_at.desc())
        .all()
    )
    return schemas.AwsConnectionList(connections=conns)
