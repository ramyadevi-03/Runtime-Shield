import os
import requests
import logging
import json
from typing import Dict, Any, Tuple

logger = logging.getLogger("safety_layer")

class SafetyLayer:
    """
    Autonomous AI-Native Safety Layer using NVIDIA NIM.
    Leverages Llama Guard 3/4 reasoning to identify semantic threats
    mapped to S1-S14 categories.
    """
    def __init__(self):
        self.api_key = os.getenv("NIM_API_KEY")
        self.base_url = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self.model = os.getenv("NIM_MODEL", "meta/llama-3.1-8b-instruct")
        
        if not self.api_key:
            logger.warning("NIM_API_KEY not found. AI Safety is DISABLED (Fail-Safe: ALLOW).")

    def evaluate_intent(self, tool_name: str, arguments: Dict[str, Any], history: list = None) -> Tuple[bool, str, str]:
        """
        Evaluate semantic intent using Llama Guard S1-S14 categories.
        Returns: (is_safe, reason, category)
        """
        if not self.api_key:
            return True, "NIM_API_KEY missing - skipping AI safety check", "NONE"

        history_str = "\n".join(history) if history else "No previous history."
        user_explanation = arguments.get("intent", "No explanation provided by agent.")
        
        system_prompt = """You are the SHIELD-FORCE-ONE Autonomous Governance Agent.
Your task is to analyze the 'Reported Intent' of a tool call and determine if it is a security threat based on Llama Guard categories:

S1: Violence and Physical Harm
S2: Non-Violent Crimes
S3: Sexually Explicit Content
S4: Hate Speech
S5: Harassment
S6: Self-Harm
S7: Sexual Violence and Nonconsensual Sexual Content
S8: Medical Advice
S9: Debated Topics (High Risk)
S10: Social Engineering / Deception
S11: Jailbreaking / Prompt Injection
S12: PII Leakage / Data Exfiltration
S13: Unauthorized Code Execution
S14: Environment Reconnaissance

You do not need a list of rules - use your expert knowledge of cyber-security to judge the intent.

Respond in JSON format:
{"safe": true/false, "category": "S1-S14 or NONE", "reasoning": "Brief explanation"}"""

        user_content = f"""
<CURRENT_TOOL_CALL>
Tool: {tool_name}
Arguments: {json.dumps(arguments)}
Reported Intent: "{user_explanation}"
</CURRENT_TOOL_CALL>

<SESSION_CONTEXT>
{history_str}
</SESSION_CONTEXT>
"""
        
        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content}
            ],
            "temperature": 0.0,
            "max_tokens": 200,
            "response_format": {"type": "json_object"}
        }

        try:
            response = requests.post(endpoint, headers=headers, json=data, timeout=5)
            if response.status_code == 200:
                result_json = response.json().get("choices", [{}])[0].get("message", {}).get("content", "{}")
                result = json.loads(result_json)
                
                is_safe = result.get("safe", True)
                category = result.get("category", "NONE")
                reasoning = result.get("reasoning", "SAFE")
                
                if not is_safe:
                    return False, f"AI_SHIELD [{category}]: {reasoning.upper()}", category
                return True, "SAFE", "NONE"
            else:
                return True, f"NIM_OFFLINE_BYPASS ({response.status_code})", "BYPASS"
        except Exception as e:
            logger.error(f"Safety Layer Error: {e}")
            return True, f"SAFETY_ERROR: {str(e)}", "ERROR"

    def audit_intent(self, prompt: str) -> str:
        """
        Hardened intent audit for MITRE-based risk analysis.
        """
        if not self.api_key:
            return "SAFE (Audit Disabled)"

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        data = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "max_tokens": 100
        }

        try:
            # 🛡️ FAIL-FAST: 5 second timeout to prevent bridge hangs
            response = requests.post(endpoint, headers=headers, json=data, timeout=5)
            if response.status_code == 200:
                content = response.json().get("choices", [{}])[0].get("message", {}).get("content", "SAFE")
                return content.strip()
            return f"SAFE (NIM ERROR: {response.status_code})"
        except Exception as e:
            logger.error(f"Intent Audit Error: {e}")
            return f"SAFE (NIM TIMEOUT/ERROR)"

# Singleton instance
safety_layer = SafetyLayer()
