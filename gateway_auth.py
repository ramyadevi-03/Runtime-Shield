import hmac
import re


def extract_bearer_token(authorization_header: str | None) -> str | None:
    parts = (authorization_header or "").split()
    if len(parts) != 2 or parts[0].casefold() != "bearer":
        return None
    return parts[1]


def is_gateway_api_key_configured(api_key: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{32,}", api_key or ""))


def gateway_api_key_matches(configured_key: str, presented_key: str | None) -> bool:
    if not configured_key or not presented_key:
        return False
    return hmac.compare_digest(
        configured_key.encode("utf-8"),
        presented_key.encode("utf-8"),
    )
