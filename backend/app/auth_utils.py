# backend/app/auth_utils.py
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

import boto3
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .db import get_db
from . import models

# Load environment variables from .env
load_dotenv()

# ----------------- Config -----------------

JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_ME_IN_PROD")
APP_ENV = os.getenv("APP_ENV", "dev")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours
RESET_TOKEN_TTL_HOURS = 1

AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
SES_FROM = os.getenv("SES_FROM_ADDRESS")
FRONTEND_BASE_URL = os.getenv(
    "FRONTEND_ORIGIN", "https://app.cloudauditpro.app"
)

RESET_EMAIL_TEMPLATE = """
You requested a password reset.

Use this token to reset your password:

{token}

If you did not request this, you can ignore this email.
"""

# ----------------- Clients / security contexts -----------------

ses_client = boto3.client("ses", region_name=AWS_REGION)
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ----------------- Password hashing -----------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    return pwd_context.verify(plain_password, password_hash)


# ----------------- JWT helpers -----------------

def create_access_token(
    data: dict, expires_delta: Optional[timedelta] = None
) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


# ----------------- Password reset helpers -----------------

def create_password_reset_token(
    db: Session, user: models.User
) -> models.PasswordResetToken:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=RESET_TOKEN_TTL_HOURS)

    reset = models.PasswordResetToken(
        user_id=user.id,
        token=token,
        expires_at=expires_at,
    )
    db.add(reset)
    db.commit()
    db.refresh(reset)
    return reset


def send_password_reset_email(email: str, token: str):
    if not SES_FROM:
        # In dev, just log and don't blow up the app
        print("SES_FROM_ADDRESS not set, skipping password reset email")
        print(f"Reset token for {email}: {token}")
        return

    reset_url = f"{FRONTEND_BASE_URL}/reset-password?token={token}"

    subject = "Reset your CloudAuditPro password"
    body_text = (
        f"Click the link below to reset your password:\n\n"
        f"{reset_url}\n\n"
        "This link expires in 1 hour."
    )

    ses_client.send_email(
        Source=SES_FROM,
        Destination={"ToAddresses": [email]},
        Message={
            "Subject": {"Data": subject},
            "Body": {"Text": {"Data": body_text}},
        },
    )


# ----------------- Current user dependency -----------------

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    # DEV MODE: skip JWT validation entirely, just return the first user
    if APP_ENV == "dev":
        print("DEBUG get_current_user: DEV mode – skipping JWT validation")
        user = db.query(models.User).first()
        if not user:
            # In dev, if there is somehow no user, we still error
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="No users found in dev DB",
            )
        return user

    # PROD/STAGE: real JWT validation
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        from jose import JWTError  # in case of circular imports, keep local
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id: str | None = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError as e:
        print("DEBUG get_current_user: JWTError while decoding:", repr(e))
        raise credentials_exception

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None:
        raise credentials_exception

    return user
