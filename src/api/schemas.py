from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

# --- Shared validators ---


def validate_password_strength(v: str) -> str:
    """Enforce password strength: uppercase, lowercase, and digit required."""
    if not any(c.isupper() for c in v):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.islower() for c in v):
        raise ValueError("Password must contain at least one lowercase letter")
    if not any(c.isdigit() for c in v):
        raise ValueError("Password must contain at least one digit")
    return v


# --- Auth request/response schemas ---


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    display_name: str = Field(..., min_length=1, max_length=100)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshRequest(BaseModel):
    refresh_token: str


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return validate_password_strength(v)


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


class ChangeEmailRequest(BaseModel):
    new_email: EmailStr
    current_password: str


class MessageResponse(BaseModel):
    message: str


# --- Entity response schemas ---


class EntityResponse(BaseModel):
    id: uuid.UUID
    type: str
    email: str | None = None
    display_name: str
    bio_markdown: str
    avatar_url: str | None = None
    did_web: str
    is_active: bool
    is_admin: bool = False
    is_admin_viewer: bool = False
    email_verified: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


# --- Agent request/response schemas ---


class CreateAgentRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=100)
    capabilities: list[str] = Field(default_factory=list, max_length=50)
    autonomy_level: int | None = Field(None, ge=1, le=5)
    bio_markdown: str = Field("", max_length=5000)


class UpdateAgentRequest(BaseModel):
    display_name: str | None = Field(None, min_length=1, max_length=100)
    capabilities: list[str] | None = Field(None, max_length=50)
    autonomy_level: int | None = Field(None, ge=1, le=5)
    bio_markdown: str | None = Field(None, max_length=5000)


class AgentResponse(BaseModel):
    id: uuid.UUID
    type: str
    display_name: str
    bio_markdown: str
    avatar_url: str | None = None
    did_web: str
    capabilities: list[str]
    autonomy_level: int | None
    operator_id: uuid.UUID | None
    operator_approved: bool = False
    is_active: bool
    is_provisional: bool = False
    created_at: datetime

    model_config = {"from_attributes": True}


class RegisterAgentRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=100)
    capabilities: list[str] = Field(default_factory=list, max_length=50)
    autonomy_level: int | None = Field(None, ge=1, le=5)
    bio_markdown: str = Field("", max_length=5000)
    framework_source: str | None = Field(
        None,
        description="Framework that created this agent (e.g. 'pydantic_ai', 'crewai').",
    )
    operator_email: str | None = Field(
        None,
        description="Optional operator email to link. Must be a registered human.",
    )


class AgentCreatedResponse(BaseModel):
    agent: AgentResponse
    api_key: str  # plaintext, shown once
    claim_token: str | None = None  # for provisional agents, share with operator


class ApiKeyRotatedResponse(BaseModel):
    api_key: str  # plaintext, shown once
    message: str


class SetOperatorRequest(BaseModel):
    operator_email: str = Field(
        ...,
        description="Email of the human operator to link this agent to.",
    )


class UpdateAutonomyRequest(BaseModel):
    autonomy_level: int = Field(..., ge=1, le=5)


class ClaimAgentRequest(BaseModel):
    claim_token: str = Field(
        ...,
        description="The claim token returned when the agent was provisionally registered.",
    )


class ClaimAgentResponse(BaseModel):
    agent: AgentResponse
    message: str


# --- Agent Discovery schemas ---


class AgentDiscoveryItem(BaseModel):
    id: uuid.UUID
    display_name: str
    type: str
    framework_source: str | None = None
    capabilities: list[str]
    autonomy_level: int | None = None
    trust_score: float | None = None
    is_active: bool
    is_provisional: bool = False
    created_at: datetime
    last_seen_at: datetime | None = None
    bio_markdown: str

    model_config = {"from_attributes": True}


class AgentDiscoveryResponse(BaseModel):
    agents: list[AgentDiscoveryItem]
    next_cursor: str | None = None
