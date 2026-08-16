import os, json, base64, reprlib
from pathlib import Path

def decode_jwt(token: str):
    token = token.strip("'\"")
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Invalid JWT format')
    payload = parts[1]
    payload += '=' * (-len(payload) % 4)
    decoded_bytes = base64.urlsafe_b64decode(payload)
    return json.loads(decoded_bytes)

env_path = Path(r"c:/Users/Lenovo/Desktop/Runtime-shield- login/Runtime-shield-for-agentic-systems/.env")
env_vars = {}
for line in env_path.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    if '=' not in line:
        continue
    key, val = line.split('=', 1)
    env_vars[key] = val.strip('"')

token = env_vars.get('KEYCLOAK_TOKEN')
if not token:
    print('No KEYCLOAK_TOKEN found in .env')
else:
    print('Raw token repr:', repr(token))
    print('Raw token length:', len(token))
    # remove surrounding single quotes if any
    token_clean = token.strip("'\"")
    print('Cleaned token length:', len(token_clean))
    print('Cleaned token first 30:', token_clean[:30])
    # attempt decode
    try:
        payload = decode_jwt(token_clean)
        print('preferred_username:', payload.get('preferred_username'))
        print('realm_roles:', payload.get('realm_access', {}).get('roles'))
    except Exception as e:
        print('Decode error:', e)
