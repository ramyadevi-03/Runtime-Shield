from datetime import datetime, timezone
from pydantic import BaseModel, Field
class Delegation(BaseModel):
    parent_agent: str
    child_agent: str
    delegation_id: str
    parent_delegation_id: str | None = None
    permitted_operations: set[str] = Field(min_length=1)
    permitted_resources: set[str] = Field(min_length=1)
    expires_at: datetime
    depth: int = Field(ge=1)

def validate_delegation(d: Delegation, agent: str, operation: str, resource: str, max_depth: int) -> bool:
    # No trusted parent-lease store or signed chain is implemented yet. A
    # caller-supplied parent and attenuation set cannot prove authority.
    return False
