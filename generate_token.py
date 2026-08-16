import jwt, os, base64
from pathlib import Path

payload = {
    "preferred_username": "user",
    "realm_access": {"roles": []},
    "resource_access": {},
    "scope": "openid"
}
# Encode with HS256 secret (doesn't matter, verification disabled)
token = jwt.encode(payload, "secret", algorithm="HS256")

# Write to .env, replacing existing KEYCLOAK_TOKEN line
env_path = Path(r"c:/Users/Lenovo/Desktop/Runtime-shield- login/Runtime-shield-for-agentic-systems/.env")
lines = env_path.read_text().splitlines()
new_lines = []
found = False
for line in lines:
    if line.startswith('KEYCLOAK_TOKEN='):
        new_lines.append(f"KEYCLOAK_TOKEN={token}")
        found = True
    else:
        new_lines.append(line)
if not found:
    new_lines.append(f"KEYCLOAK_TOKEN={token}")

env_path.write_text("\n".join(new_lines))
print('New token written with length', len(token))
