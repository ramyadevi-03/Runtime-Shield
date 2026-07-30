import jwt
import os
from dotenv import set_key

user_info = {
    "sub": "1e9c8d21-fb65-418a-aaee-40e7f0ce735f",
    "name": "Security Admin",
    "preferred_username": "admin",
    "roles": ["admin"],
    "scope": "openid email profile files:list files:read keycloak:admin",
    "allowed_paths": ["./"]
}

mock_token = jwt.encode(user_info, "secret", algorithm="HS256")

dot_env_path = ".env"
set_key(dot_env_path, "KEYCLOAK_TOKEN", mock_token)
set_key(dot_env_path, "RUNTIME_ROLE", "admin")
print("Mock admin token updated successfully.")
