import jwt
import hmac
from fastapi import HTTPException, status
from app.config import Settings

class Identity:
    def __init__(self, claims): self.claims = claims
    @property
    def subject(self): return self.claims["sub"]
    @property
    def workload(self): return self.claims.get("workload_id", "")
    @property
    def roles(self): return self.claims.get("roles", [])
    @property
    def audience(self): return self.claims.get("aud")

def verify_token(token: str, audience: str, settings: Settings) -> Identity:
    if settings.dev_auth and settings.environment.lower() != "production":
        try:
            kind, sub, workload, secret = token.split(":", 3)
            expected = {settings.jwt_audience_agent:"agent", settings.jwt_audience_admin:"admin", settings.jwt_audience_egress:"egress"}[audience]
            expected_secret = {"agent":settings.dev_agent_secret,"admin":settings.dev_admin_secret,"egress":settings.dev_egress_secret}[expected]
            if kind != expected or not sub or not workload or not expected_secret or not hmac.compare_digest(secret, expected_secret): raise ValueError
            return Identity({"sub":sub,"workload_id":workload,"roles":[kind],"aud":audience})
        except Exception: raise HTTPException(401, "Invalid credentials")
    if not settings.jwt_public_key: raise HTTPException(503, "Identity verification unavailable")
    try:
        claims = jwt.decode(token, settings.jwt_public_key, algorithms=[settings.jwt_algorithm], audience=audience, issuer=settings.jwt_issuer, options={"require":["sub","exp","iat","iss","aud","workload_id","roles"]})
        if not isinstance(claims.get("workload_id"), str) or not claims["workload_id"]: raise ValueError
        if not isinstance(claims.get("roles"), list) or not claims["roles"]: raise ValueError
        return Identity(claims)
    except Exception: raise HTTPException(401, "Invalid credentials")
