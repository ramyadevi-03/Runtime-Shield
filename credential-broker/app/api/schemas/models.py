import re
from pydantic import BaseModel, Field, field_validator
from app.broker.delegation import Delegation
ALIAS=re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")
def check_alias(v):
    if not ALIAS.fullmatch(v): raise ValueError("Invalid credential alias")
    return v
class ProvisionRequest(BaseModel):
    value: dict[str,str]=Field(min_length=1)
    @field_validator("value")
    @classmethod
    def values_nonempty(cls,v):
        if any(not k or not x for k,x in v.items()): raise ValueError("Credential fields must be non-empty")
        return v
class LeaseRequest(BaseModel):
    credential_alias: str
    tool: str=Field(min_length=1,max_length=200)
    operation: str=Field(min_length=1,max_length=200)
    resource: str=Field(min_length=1,max_length=500)
    manifest_hash: str=Field(pattern=r"^sha256:[0-9a-f]{64}$")
    delegation_context: Delegation | None=None
    lease_seconds: int=Field(default=120,ge=1,le=3600)
    max_uses: int=Field(default=1,ge=1,le=10)
    @field_validator("credential_alias")
    @classmethod
    def alias(cls,v): return check_alias(v)
    @field_validator("credential_alias")
    @classmethod
    def alias(cls,v): return check_alias(v)
class LeaseResponse(BaseModel):
    lease_id: str
    status: str
    credential_alias: str
    expires_at: str
    scope: list[str]
class RedeemResponse(BaseModel):
    credential: dict[str,str]
