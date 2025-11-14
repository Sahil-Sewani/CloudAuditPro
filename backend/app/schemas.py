# backend/app/schemas.py
from datetime import datetime
from typing import List

from pydantic import BaseModel, EmailStr


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
