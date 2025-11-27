# backend/app/models.py
import uuid
from datetime import datetime
from datetime import datetime, timedelta
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import relationship
from .db import Base
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from .db import Base


def uuid_str() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=uuid_str)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    name = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # One org per user (for now)
    organization = relationship("Organization", back_populates="owner", uselist=False)

    aws_accounts = relationship(
        "AwsAccount",
        back_populates="user",
        cascade="all, delete-orphan",
    )


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True, default=uuid_str)
    name = Column(String, nullable=False)
    owner_user_id = Column(String, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    owner = relationship("User", back_populates="organization")
    aws_connections = relationship("AwsConnection", back_populates="organization")


class AwsConnection(Base):
    __tablename__ = "aws_connections"

    id = Column(String, primary_key=True, default=uuid_str)
    org_id = Column(String, ForeignKey("organizations.id"), nullable=False)
    display_name = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    role_arn = Column(String, nullable=False)
    external_id = Column(String, nullable=False)
    region = Column(String, nullable=False, default="us-east-1")  # 👈 NEW
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    organization = relationship("Organization", back_populates="aws_connections")



class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token = Column(String, unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", backref="password_reset_tokens")


class AwsAccount(Base):
    __tablename__ = "aws_accounts"

    id = Column(String, primary_key=True, default=uuid_str)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)

    display_name = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    role_name = Column(String, nullable=False)
    region = Column(String, nullable=False, default="us-east-1")

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="aws_accounts")