# backend/app/routers/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
from ..db import get_db
from .. import models, schemas
from ..auth_utils import (
    hash_password,
    verify_password,
    create_password_reset_token,
    send_password_reset_email,
    create_access_token,
    get_current_user,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=schemas.TokenResponse)
def register_user(payload: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    user = models.User(
        email=payload.email,
        name=payload.name,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # create organization for this user
    org = models.Organization(
        name=f"{user.name}'s Org",
        owner_user_id=user.id,
    )
    db.add(org)
    db.commit()

    token = create_access_token({"sub": user.id})
    return schemas.TokenResponse(access_token=token)


@router.post("/login", response_model=schemas.TokenResponse)
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    # form_data.username is the email
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect email or password",
        )

    token = create_access_token({"sub": user.id})
    return schemas.TokenResponse(access_token=token)


@router.get("/me", response_model=schemas.UserRead)
def me(current_user=Depends(get_current_user)):
    return current_user


@router.post("/request-password-reset")
def request_password_reset(
    payload: schemas.PasswordResetRequest,
    db: Session = Depends(get_db),
):
    """
    Request a password reset.

    Always returns 200 even if the email doesn't exist,
    so we don't leak which emails are registered.
    """
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if user:
        reset = create_password_reset_token(db, user)
        try:
            send_password_reset_email(user.email, reset.token)
        except Exception as e:
            # In dev, we just log the error and don't break the API
            print("Error sending reset email:", e)

    return {"message": "If that email exists, a reset link has been sent."}


@router.post("/reset-password")
def reset_password(
    payload: schemas.PasswordResetConfirm,
    db: Session = Depends(get_db),
):
    """
    Use a reset token to set a new password.
    """
    reset = (
        db.query(models.PasswordResetToken)
        .filter(models.PasswordResetToken.token == payload.token)
        .first()
    )

    if (
        not reset
        or reset.used
        or reset.expires_at < datetime.utcnow()
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    user = db.query(models.User).filter(models.User.id == reset.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token",
        )

    # Update password
    user.password_hash = hash_password(payload.new_password)
    reset.used = True

    db.add(user)
    db.add(reset)
    db.commit()

    return {"message": "Password updated successfully"}