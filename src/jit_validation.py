"""Claim checks applied after signature/issuer verification of a JIT token."""
import time


def validate_jit_claims(
    claims: dict,
    *,
    expected_issuer: str,
    expected_audience: str,
    required_scope: str,
    expected_workload: str,
    now: float | None = None,
) -> bool:
    if not isinstance(claims, dict):
        return False
    now = time.time() if now is None else now
    audience = claims.get("aud")
    audiences = {audience} if isinstance(audience, str) else set(audience) if isinstance(audience, list) and all(isinstance(x, str) for x in audience) else set()
    raw_scope = claims.get("scope", "")
    scopes = set(raw_scope.split()) if isinstance(raw_scope, str) else set(raw_scope) if isinstance(raw_scope, list) and all(isinstance(x, str) for x in raw_scope) else set()
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    return bool(
        claims.get("iss") == expected_issuer
        and expected_audience in audiences
        and required_scope
        and required_scope in scopes
        and claims.get("workload_id") == expected_workload
        and isinstance(issued_at, (int, float))
        and issued_at <= now
        and isinstance(expires_at, (int, float))
        and expires_at > now
        and expires_at > issued_at
    )
