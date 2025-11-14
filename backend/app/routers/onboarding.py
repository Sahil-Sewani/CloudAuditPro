# backend/app/routers/onboarding.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import get_db
from .. import models, schemas
from ..auth_utils import get_current_user

router = APIRouter(prefix="/aws", tags=["aws-onboarding"])


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
