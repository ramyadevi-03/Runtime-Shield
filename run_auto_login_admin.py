import sys
import os
import requests
from dotenv import load_dotenv

PROJECT_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.append(PROJECT_DIR)

import login

def auto_login_admin():
    print("--- Auto Login for admin ---")
    load_dotenv(login.DOTENV_PATH, override=True)
    
    token_url = f"{login.KEYCLOAK_URL}/realms/{login.REALM}/protocol/openid-connect/token"
    data = {
        "grant_type": "password",
        "client_id": login.CLIENT_ID,
        "username": "admin",
        "password": "admin",
        "scope": "openid profile email tool:read_file tool:write_file tool:list_directory tool:keycloak_read tool:keycloak_admin tool:keycloak_report tool:admin_internal"
    }
    
    client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")
    if client_secret:
        data["client_secret"] = client_secret
        
    try:
        response = requests.post(token_url, data=data, timeout=5)
        if response.status_code == 200:
            access_token = response.json().get("access_token")
            print("Successfully retrieved access token from Keycloak.")
            login.save_and_resolve(access_token)
            print("Auto-login complete!")
        else:
            print(f"Login failed: {response.text}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    auto_login_admin()
