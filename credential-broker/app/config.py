from functools import lru_cache
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from urllib.parse import urlsplit

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    environment: str = "development"
    database_path: str = "/data/leases.db"
    openbao_addr: str = "http://openbao:8200"
    openbao_mount: str = "runtime-shield"
    openbao_token: str | None = None
    openbao_role_id: str | None = None
    openbao_secret_id: str | None = None
    opa_url: str = "http://opa:8181/v1/data/runtime_shield/credential/allow"
    jwt_issuer: str = "runtime-shield"
    jwt_audience_agent: str = "credential-broker-agent"
    jwt_audience_admin: str = "credential-broker-admin"
    jwt_audience_egress: str = "credential-broker-egress"
    jwt_public_key: str | None = None
    jwt_algorithm: str = "RS256"
    dev_auth: bool = True
    dev_agent_secret: str = Field(default="", validation_alias="BROKER_DEV_AGENT_SECRET")
    dev_admin_secret: str = Field(default="", validation_alias="BROKER_DEV_ADMIN_SECRET")
    dev_egress_secret: str = Field(default="", validation_alias="BROKER_DEV_EGRESS_SECRET")
    allow_local_policy: bool = True
    lease_max_seconds: int = Field(default=300, ge=1, le=3600)
    lease_max_uses: int = Field(default=1, ge=1, le=10)
    lease_claim_ttl_seconds: int = Field(default=30, ge=1, le=3600)
    registered_manifest_hashes: str = ""
    delegation_max_depth: int = Field(default=3, ge=0, le=10)
    @model_validator(mode="after")
    def secure_production(self):
        if self.openbao_token:
            raise ValueError("OPENBAO_TOKEN is unsupported; authenticate to OpenBao with AppRole")
        if self.dev_auth and self.environment.lower() != "production":
            if not (self.dev_agent_secret and self.dev_admin_secret and self.dev_egress_secret):
                raise ValueError("development authentication requires distinct agent, admin, and egress secrets")
            if any(len(value) < 32 for value in (self.dev_agent_secret, self.dev_admin_secret, self.dev_egress_secret)):
                raise ValueError("development role secrets must be at least 32 characters")
            if len({self.dev_agent_secret, self.dev_admin_secret, self.dev_egress_secret}) != 3:
                raise ValueError("development role secrets must be distinct")
        if self.environment.lower() == "production":
            if self.dev_auth or self.allow_local_policy:
                raise ValueError("production requires dev_auth=false and allow_local_policy=false")
            if not self.jwt_public_key:
                raise ValueError("production requires JWT_PUBLIC_KEY")
            if not (self.openbao_role_id and self.openbao_secret_id):
                raise ValueError("production requires restricted OpenBao AppRole credentials")
            opa_endpoint = urlsplit(self.opa_url)
            if opa_endpoint.scheme != "https" or opa_endpoint.hostname in {"opa", "localhost", "127.0.0.1", "::1"}:
                raise ValueError("production requires a remote HTTPS OPA endpoint")
        return self
    @property
    def manifest_hashes(self) -> set[str]:
        return {x.strip() for x in self.registered_manifest_hashes.split(",") if x.strip()}

@lru_cache
def get_settings(): return Settings()
