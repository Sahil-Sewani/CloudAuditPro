# backend/app/schemas.py
from datetime import datetime
from typing import List, Literal, Optional
from pydantic import BaseModel, EmailStr

ComplianceStatus = Literal["PASS", "FAIL", "WARN"]


# -------- User / Auth --------

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str


class UserRead(BaseModel):
    id: str
    email: EmailStr
    name: str
    created_at: datetime

    class Config:
        orm_mode = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# -------- AWS Connections --------

class AwsConnectionCreate(BaseModel):
    display_name: str
    account_id: str
    role_arn: str
    external_id: str


class AwsConnectionRead(BaseModel):
    id: str
    display_name: str
    account_id: str
    role_arn: str
    external_id: str
    created_at: datetime

    class Config:
        orm_mode = True


class AwsConnectionList(BaseModel):
    connections: List[AwsConnectionRead]


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str

# -------- Compliance Scan Response --------

class ComplianceCheckResult(BaseModel):
    id: str
    title: str
    description: str
    status: ComplianceStatus
    score_weight: int  # how many points this check contributes
    score_earned: int  # 0..score_weight
    details: Optional[dict] = None

class ComplianceSummary(BaseModel):
    total_score: int
    max_score: int
    percentage: float
    checks: List[ComplianceCheckResult]