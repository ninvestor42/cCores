from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    status: str
    level: int


class IdentityCreateResponse(BaseModel):
    identity_id: int
    did: str
    public_key: str


class MeshSignRequest(BaseModel):
    identity_id: int
    topic: str = "telemetry.daily"
    ts: int
    nonce: str
    payload: Any


class MeshSignResponse(BaseModel):
    did: str
    pub: str
    ts: int
    nonce: str
    topic: str
    payload: Any
    sig: str
    sig_alg: str = "ed25519"


class AuditLogRequest(BaseModel):
    action: str = Field(min_length=1)
    prev_hash: str = Field(default="0" * 64, min_length=64, max_length=64)


class AuditLogResponse(BaseModel):
    audit_id: int
    ts: int
    prev_hash: str
    chain_hash: str


class ORMBaseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)
