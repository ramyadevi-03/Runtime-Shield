import jwt
import os
from dotenv import set_key

user_info = {
    "iss": "https://external-idp.example.com",
    "sub": "xaa-user-888",
    "name": "Federated Partner User",
    "preferred_username": "external-user",
    "groups": ["External-Users"],
    "scope": "openid email profile",
}

mock_token = jwt.encode(user_info, "secret", algorithm="HS256")

dot_env_path = ".env"
set_key(dot_env_path, "KEYCLOAK_TOKEN", mock_token)
set_key(dot_env_path, "RUNTIME_ROLE", "user")
print("🚀 Mock XAA Federated User token updated successfully in .env!")
print("Restart your services to run the chatbot in XAA Federated User mode.")
