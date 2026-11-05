from app.security.hashing import canonical_manifest_hash

def verify_manifest(request_hash: str, registered: set[str]) -> bool:
    return (
        isinstance(request_hash, str)
        and len(request_hash) == 71
        and request_hash.startswith("sha256:")
        and all(char in "0123456789abcdef" for char in request_hash[7:])
        and request_hash in registered
    )
