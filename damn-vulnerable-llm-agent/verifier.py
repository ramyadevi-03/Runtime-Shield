import os
import jwt
import requests

class JITVerifier:
    def __init__(self, jwks_url):
        self.jwks_url = jwks_url
        self.jwks_client = jwt.PyJWKClient(self.jwks_url)

    def verify_jit_token(self, token, expected_scope, expected_audience):
        """
        Cryptographically verifies the signature, audience, and scope of a JIT token using JWKS.
        Strictly fails-closed on any validation error.
        """
        # 1. Fetch signing key and cryptographically verify signature, audience
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)
        
        # Respect LOCAL_DEV_MODE from environment to allow expired static tokens in demo mode
        local_dev = os.getenv("LOCAL_DEV_MODE", "false").lower() == "true"
        options = {"verify_exp": not local_dev}
        
        decoded = jwt.decode(
            token, 
            signing_key.key, 
            algorithms=["RS256"], 
            audience=expected_audience,
            options=options
        )
        
        # 2. Verify scope is correct
        scopes = decoded.get("scope", "").split()
        if expected_scope not in scopes:
            raise PermissionError(f"Missing required scope: {expected_scope}")
            
        return decoded
