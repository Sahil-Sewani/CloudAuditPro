# backend/app/routes/aws_accounts.py
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from .. import models
from .auth import get_current_user  # <- use the same get_current_user as /scan, etc.

router = APIRouter(
    prefix="/aws-accounts",
    tags=["aws-accounts"],
)


def aws_account_to_dict(a: models.AwsAccount) -> dict:
    return {
        "id": a.id,
        "display_name": a.display_name,
        "account_id": a.account_id,
        "role_name": a.role_name,
        "region": a.region,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


@router.get("/", response_model=List[dict])
def list_aws_accounts(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    accounts = (
        db.query(models.AwsAccount)
        .filter(models.AwsAccount.user_id == current_user.id)
        .order_by(models.AwsAccount.created_at.desc())
        .all()
    )
    return [aws_account_to_dict(a) for a in accounts]


@router.post("/", response_model=dict, status_code=status.HTTP_201_CREATED)
def create_aws_account(
    payload: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    display_name = payload.get("display_name")
    account_id = payload.get("account_id")
    role_name = payload.get("role_name") or "CloudAuditProReadRole"
    region = payload.get("region") or "us-east-1"

    if not display_name or not account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="display_name and account_id are required",
        )

    new_acc = models.AwsAccount(
        user_id=current_user.id,
        display_name=display_name,
        account_id=account_id.strip(),
        role_name=role_name.strip(),
        region=region.strip(),
    )
    db.add(new_acc)
    db.commit()
    db.refresh(new_acc)
    return aws_account_to_dict(new_acc)


@router.put("/{account_id}", response_model=dict)
def update_aws_account(
    account_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    acc = (
        db.query(models.AwsAccount)
        .filter(
            models.AwsAccount.id == account_id,
            models.AwsAccount.user_id == current_user.id,
        )
        .first()
    )
    if not acc:
        raise HTTPException(status_code=404, detail="AWS account not found")

    if "display_name" in payload:
        acc.display_name = payload["display_name"]
    if "account_id" in payload:
        acc.account_id = payload["account_id"].strip()
    if "role_name" in payload:
        acc.role_name = payload["role_name"].strip()
    if "region" in payload:
        acc.region = payload["region"].strip()

    db.commit()
    db.refresh(acc)
    return aws_account_to_dict(acc)


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_aws_account(
    account_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    acc = (
        db.query(models.AwsAccount)
        .filter(
            models.AwsAccount.id == account_id,
            models.AwsAccount.user_id == current_user.id,
        )
        .first()
    )
    if not acc:
        raise HTTPException(status_code=404, detail="AWS account not found")

    db.delete(acc)
    db.commit()
    return
