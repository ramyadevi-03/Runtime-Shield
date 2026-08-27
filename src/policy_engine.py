import os
import sys
# Ensure repository root is prioritized in sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

import logging
import requests
from typing import TypedDict, Dict, Any

logger = logging.getLogger(__name__)


class PolicyInput(TypedDict):
    user: Dict[str, Any]
    workload: Dict[str, Any]
    agent: Dict[str, Any]
    mcp: Dict[str, Any]
    resource: Dict[str, Any]
    request: Dict[str, Any]


class PolicyDecision(TypedDict):
    allow: bool
    reason: str
    risk_delta: int
    redact_output: bool
    quarantine: bool
    rule_id: str
    policy_backend: str


class PolicyEngine:
    def evaluate_policy(self, policy_input: PolicyInput) -> PolicyDecision:
        raise NotImplementedError


class OpaPolicyEngine(PolicyEngine):
    """
    OPA-only policy engine. This is the sole policy backend.
    Fails closed on any connection or response error.
    """

    def __init__(self, endpoint_url: str = None):
        self.backend = "opa"
        self.endpoint_url = endpoint_url or os.getenv(
            "OPA_URL", "http://localhost:8182/v1/data/runtime_shield/authz/decision"
        )

    def evaluate_policy(self, policy_input: PolicyInput) -> PolicyDecision:
        try:
            resp = requests.post(
                self.endpoint_url,
                json={"input": policy_input},
                timeout=3.0
            )
            if resp.status_code == 200:
                result = resp.json().get("result", {})
                return {
                    "allow": result.get("allow", False),
                    "reason": result.get("reason", "OPA denied the request (no reason provided)"),
                    "risk_delta": result.get("risk_delta", 0),
                    "redact_output": result.get("redact_output", False),
                    "quarantine": result.get("quarantine", False),
                    "rule_id": result.get("rule_id", "opa_rule"),
                    "policy_backend": "opa"
                }
            else:
                logger.error(f"OPA returned non-200 status: {resp.status_code} - {resp.text}")
                return self._fail_closed(f"OPA endpoint returned error: {resp.status_code}")
        except requests.exceptions.ConnectionError as e:
            logger.error(f"OPA connection error: {e}")
            raise
        except requests.exceptions.RequestException as e:
            logger.error(f"OPA request error: {e}")
            return self._fail_closed("OPA connection failed")

    def _fail_closed(self, reason: str) -> PolicyDecision:
        return {
            "allow": False,
            "reason": reason,
            "risk_delta": 0,
            "redact_output": False,
            "quarantine": False,
            "rule_id": "opa_fail_closed",
            "policy_backend": "opa"
        }


class SemanticCachePolicyEngine(PolicyEngine):
    """
    Wrapper Policy Engine implementing Semantic Caching and Clearance checks.
    Uses spaCy 'en_core_web_sm' to compute vectors for tool intent and arguments,
    caching OPA decisions and invalidating them on user role changes.
    """

    def __init__(self, target_engine: PolicyEngine, threshold: float = 0.92):
        self.target_engine = target_engine
        self.threshold = threshold
        self.backend = getattr(target_engine, "backend", "opa")
        self.cache = []  # List of dicts (cached decisions)
        self.user_roles = {}  # user_id -> role string
        self.nlp = None
        
        try:
            import spacy
            self.nlp = spacy.load("en_core_web_sm")
            logger.info("✅ SemanticCache: Loaded spaCy 'en_core_web_sm' successfully.")
        except Exception as e:
            logger.warning(f"⚠️ SemanticCache: Failed to load spaCy: {e}. Falling back to exact matching.")

    def evaluate_policy(self, policy_input: PolicyInput) -> PolicyDecision:
        user_id = policy_input["user"].get("id", "anonymous_user")
        role = policy_input["user"].get("role", "user")
        tool = policy_input["mcp"].get("tool", "unknown")
        
        # 1. Clearance Filter Check
        # If the user's role (clearance level) changes, invalidate cache entries for this user
        if user_id in self.user_roles and self.user_roles[user_id] != role:
            logger.warning(
                f"⚠️ [Clearance Check] User '{user_id}' clearance changed from '{self.user_roles[user_id]}' to '{role}'. "
                "Evicting user cache entries to trigger a fresh check."
            )
            # Evict entries for this user
            self.cache = [entry for entry in self.cache if entry["user_id"] != user_id]
            
        self.user_roles[user_id] = role

        # 2. Build semantic query description
        req_params = policy_input.get("request", {}) or {}
        param_str = " ".join(f"{k}={v}" for k, v in req_params.items())
        text_repr = f"tool={tool} role={role} {param_str}".strip()

        # 3. Check Cache (Similarity Match)
        cached_decision = self._check_cache(tool, role, user_id, text_repr)
        if cached_decision:
            logger.info(
                f"⚡ [Semantic Cache Hit] Reusing decision for '{tool}' under role '{role}': "
                f"{cached_decision['allow']} (Reason: {cached_decision['reason']})"
            )
            return cached_decision

        # 4. Cache Miss - Evaluate OPA target engine
        decision = self.target_engine.evaluate_policy(policy_input)

        # 5. Store in Cache if valid
        if decision:
            self._store_cache(tool, role, user_id, text_repr, decision)

        return decision

    def _check_cache(self, tool: str, role: str, user_id: str, text: str) -> PolicyDecision | None:
        candidates = [entry for entry in self.cache if entry["tool"] == tool and entry["role"] == role]
        if not candidates:
            return None

        # Try semantic match using spaCy vectors
        if self.nlp:
            try:
                new_vec = self.nlp(text).vector
                for entry in candidates:
                    v = entry["vector"]
                    if v is not None:
                        # Cosine similarity using pure Python list zip to avoid dependency issues
                        dot_product = sum(a * b for a, b in zip(new_vec, v))
                        norm_new = sum(a * a for a in new_vec) ** 0.5
                        norm_v = sum(a * a for a in v) ** 0.5
                        if norm_new > 0 and norm_v > 0:
                            sim = dot_product / (norm_new * norm_v)
                            if sim >= self.threshold:
                                return entry["decision"]
            except Exception as e:
                logger.error(f"⚠️ Error computing semantic similarity: {e}")

        # Exact match fallback
        for entry in candidates:
            if entry["text"] == text:
                return entry["decision"]

        return None

    def _store_cache(self, tool: str, role: str, user_id: str, text: str, decision: PolicyDecision):
        import time
        vector = None
        if self.nlp:
            try:
                vector = self.nlp(text).vector
            except Exception:
                pass

        self.cache.append({
            "tool": tool,
            "role": role,
            "user_id": user_id,
            "text": text,
            "vector": vector,
            "decision": decision,
            "timestamp": time.time()
        })
        
        # Cap cache size at 100 entries
        if len(self.cache) > 100:
            self.cache.pop(0)
