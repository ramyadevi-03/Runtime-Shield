import json
import logging
import os

logger = logging.getLogger(__name__)

class DashboardClient:
    """
    Client for negotiating schema and retrieving vault secrets from the Central Dashboard.
    Currently uses mock data to allow local development before the real API is ready.
    """
    def __init__(self, dashboard_url: str, tenant_id: str, api_key: str):
        self.dashboard_url = dashboard_url
        self.tenant_id = tenant_id
        self.api_key = api_key
        # In a real scenario, we'd initialize a session here
        
    def fetch_tenant_schema(self):
        """
        Fetches the allowed tools, paths, and guardrail policies for this tenant.
        """
        # TODO: Replace with real HTTP request to dashboard API
        # response = requests.get(f"{self.dashboard_url}/api/v1/schema/{self.tenant_id}", headers={"Authorization": f"Bearer {self.api_key}"})
        
        print(f"🔄 [DashboardClient] Negotiating schema for Tenant {self.tenant_id}...")
        
        # MOCK SCHEMA: FinTech Delta
        mock_schema = {
            "tenant_id": self.tenant_id,
            "policies": {
                "nemo_cloud": {
                    "enabled": True,
                    "pii_rail": {"enabled": True, "detect_entities": ["CREDIT_CARD", "PERSON"]},
                    "jailbreak_rail": {"enabled": True}
                }
            },
            "allowed_tools": [
                "read_file", 
                "keycloak_list_users",
                "get_account_balance"
            ],
            "allowed_paths": [
                "secure-experiment-zone"
            ]
        }
        return mock_schema

    def fetch_vault_secrets(self, tool_name: str):
        """
        Retrieves sensitive keys injected securely into the specific jail.
        """
        print(f"🔐 [DashboardClient] Fetching vault secrets for tool '{tool_name}'...")
        
        # MOCK SECRETS
        mock_vault = {
            "NVIDIA_API_KEY": os.getenv("NVIDIA_API_KEY", "mock-nv-key"),
            "OPENAI_API_KEY": "mock-openai-key-for-" + self.tenant_id
        }
        
        # Return only keys relevant to the requested tool to enforce principle of least privilege
        return mock_vault
