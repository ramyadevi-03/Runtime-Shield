import sys
import io

# 1. IMMEDIATELY preserve the raw stdout for MCP proto
real_stdout_buffer = sys.stdout.buffer
# 2. IMMEDIATELY redirect all prints/logs to stderr to prevent connection crashes
sys.stdout = sys.stderr

import os
# Force Python to load local mcp_firewall package first instead of site-packages
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

import subprocess
import signal
import argparse
import threading
import json
import time
import re
import shutil
from mcp_firewall.sdk import Gateway
from mcp_firewall.dashboard.server import start_dashboard
from mcp_firewall.dashboard.app import state as dashboard_state, app as dashboard_app
from dotenv import load_dotenv
import jwt
import yaml
import requests
import logging
from dashboard_client import DashboardClient
from fastapi import Request, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
import httpx
import asyncio

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_anonymizer import AnonymizerEngine
except ImportError:
    AnalyzerEngine = None
    AnonymizerEngine = None

# Global references for LLM proxy endpoints to access the core engines
gateway_instance = None
nim_guard_instance = None
fraud_engine_instance = None
semantic_parser_instance = None

import telemetry

mcp_processes = {}
mcp_remote_clients = {}
tool_map = {}
scope_map = {}
pending_tool_futures = {}  # req_id -> asyncio.Future
stdout_lock = threading.Lock()

def reload_tool_mappings():
    global tool_map, scope_map
    try:
        registered_tools = telemetry.get_registered_tools()
        for t in registered_tools:
            tool_map[t["tool_name"]] = t["provider_name"]
            scope_map[t["tool_name"]] = t["scope"]
        log(f"🔄 Reloaded tool mappings from database. Total tools in memory: {len(tool_map)}")
    except Exception as e:
        log(f"⚠️ Failed to reload tool mappings from DB: {e}")


class RemoteSseMcpClient:
    def __init__(self, provider_name: str, base_url: str):
        self.provider_name = provider_name
        self.base_url = base_url
        self.post_url = None
        self.client = None
        self.is_connected = False
        self.connection_task = None
        self.pending_futures = {}

    async def start(self):
        self.client = httpx.AsyncClient(timeout=15.0)
        self.connection_task = asyncio.create_task(self._connect_loop())

    async def _connect_loop(self):
        while True:
            try:
                log(f"🔌 RemoteSseMcpClient [{self.provider_name}]: Connecting to {self.base_url}...")
                headers = {"Accept": "text/event-stream"}
                try:
                    spiffe_cfg = get_spiffe_config()
                    if spiffe_cfg and spiffe_cfg.get("enabled"):
                        headers.update(get_spiffe_headers())
                except Exception as e:
                    log(f"⚠️ RemoteSseMcpClient [{self.provider_name}]: Failed to get SPIFFE headers for connect: {e}")

                async with self.client.stream("GET", self.base_url, headers=headers, timeout=None) as response:
                    if response.status_code != 200:
                        log(f"❌ RemoteSseMcpClient [{self.provider_name}]: GET {self.base_url} returned status code {response.status_code}")
                        await asyncio.sleep(5)
                        continue
                    
                    self.is_connected = True
                    log(f"✅ RemoteSseMcpClient [{self.provider_name}]: SSE stream established")
                    
                    event_type = None
                    async for line in response.aiter_lines():
                        line = line.strip()
                        if not line:
                            continue
                        if line.startswith("event:"):
                            event_type = line.split(":", 1)[1].strip()
                        elif line.startswith("data:"):
                            data = line.split(":", 1)[1].strip()
                            await self._handle_event(event_type, data)
                            event_type = None

            except Exception as e:
                log(f"⚠️ RemoteSseMcpClient [{self.provider_name}]: Connection error: {e}")
                self.is_connected = False
                self.post_url = None
                await asyncio.sleep(5)

    async def _handle_event(self, event_type: str, data: str):
        try:
            if event_type == "endpoint":
                from urllib.parse import urljoin
                self.post_url = urljoin(self.base_url, data)
                log(f"🔗 RemoteSseMcpClient [{self.provider_name}]: Resolved POST endpoint to {self.post_url}")
                asyncio.create_task(self.sync_tools())
            elif event_type == "message":
                msg = json.loads(data)
                msg_id = msg.get("id")
                
                # Relay message to pending tool call futures
                if msg_id is not None and msg_id in pending_tool_futures:
                    loop = pending_tool_futures[msg_id]._loop
                    loop.call_soon_threadsafe(pending_tool_futures[msg_id].set_result, data)
                else:
                    # Write response directly to stdout for stdio clients
                    try:
                        with stdout_lock:
                            protocol_stdout.write(data + "\n")
                            protocol_stdout.flush()
                    except Exception as e:
                        log(f"⚠️ Failed to write remote SSE response to stdout: {e}")
                
                # Relay tool lists to the aggregator if it is a list response
                if "result" in msg and isinstance(msg["result"], dict) and "tools" in msg["result"]:
                    global tools_list_aggregator
                    if tools_list_aggregator is not None:
                        tools_list = msg["result"]["tools"] or []
                        is_complete, merged_tools = tools_list_aggregator.add_response(msg_id, self.provider_name, tools_list)
                        if is_complete:
                            msg["result"]["tools"] = merged_tools
                            line_str = json.dumps(msg) + "\n"
                            try:
                                with stdout_lock:
                                    protocol_stdout.write(line_str)
                                    protocol_stdout.flush()
                            except Exception as e:
                                log(f"⚠️ Failed to write aggregated tools to stdout: {e}")
        except Exception as e:
            log(f"⚠️ RemoteSseMcpClient [{self.provider_name}]: Error handling event ({event_type}): {e}")

    async def sync_tools(self):
        try:
            req_id = f"sync-tools-{int(time.time())}"
            payload = {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/list"
            }
            log(f"🔄 RemoteSseMcpClient [{self.provider_name}]: Syncing tools...")
            res = await self.send_message(payload, timeout=5.0)
            if res and "result" in res and "tools" in res["result"]:
                tools = res["result"]["tools"] or []
                log(f"✅ RemoteSseMcpClient [{self.provider_name}]: Found {len(tools)} tools. Saving to registry.")
                telemetry.sync_mcp_tools(self.provider_name, tools)
                reload_tool_mappings()
        except Exception as e:
            log(f"⚠️ RemoteSseMcpClient [{self.provider_name}]: Failed to sync tools: {e}")

    async def send_message(self, payload: dict, timeout=10.0) -> dict:
        if not self.post_url:
            raise RuntimeError(f"POST endpoint for {self.provider_name} is not resolved yet")
        
        req_id = payload.get("id")
        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        pending_tool_futures[req_id] = fut

        try:
            headers = {"Content-Type": "application/json"}
            try:
                spiffe_cfg = get_spiffe_config()
                if spiffe_cfg and spiffe_cfg.get("enabled"):
                    headers.update(get_spiffe_headers())
            except Exception as e:
                log(f"⚠️ RemoteSseMcpClient [{self.provider_name}]: Failed to get SPIFFE headers for message: {e}")

            async with httpx.AsyncClient() as post_client:
                resp = await post_client.post(self.post_url, json=payload, headers=headers, timeout=timeout)
            if resp.status_code not in (200, 202):
                raise RuntimeError(f"POST {self.post_url} returned {resp.status_code}: {resp.text}")
            
            response_str = await asyncio.wait_for(fut, timeout=timeout)
            return json.loads(response_str)
        except Exception as e:
            log(f"⚠️ RemoteSseMcpClient [{self.provider_name}]: Error sending message: {e}")
            raise
        finally:
            pending_tool_futures.pop(req_id, None)

    async def stop(self):
        if self.connection_task:
            self.connection_task.cancel()
        if self.client:
            await self.client.aclose()
        self.is_connected = False
        self.post_url = None

@dashboard_app.on_event("startup")
async def start_remote_mcp_clients():
    log("🔌 FastAPI Startup: Connecting to remote MCP servers...")
    for provider, client in mcp_remote_clients.items():
        try:
            await client.start()
        except Exception as e:
            log(f"⚠️ Failed to start remote MCP client [{provider}]: {e}")

@dashboard_app.on_event("shutdown")
async def stop_remote_mcp_clients():
    log("🔌 FastAPI Shutdown: Closing remote MCP connections...")
    for provider, client in mcp_remote_clients.items():
        try:
            await client.stop()
        except Exception as e:
            log(f"⚠️ Failed to stop remote MCP client [{provider}]: {e}")



from concurrent.futures import ThreadPoolExecutor, TimeoutError

# Dedicated thread pool for async execution of security scans (timeout isolation)
scan_executor = ThreadPoolExecutor(max_workers=4)
SCAN_TIMEOUT_SEC = 6.0
FAIL_OPEN_ON_SCAN_TIMEOUT = True

try:
    import landlock
except ImportError:
    landlock = None

# Silence Werkzeug (Flask) logging
log_w = logging.getLogger('werkzeug')
log_w.setLevel(logging.ERROR)

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(PROJECT_DIR, "mcp-firewall.yaml")
DOTENV_PATH = os.path.join(PROJECT_DIR, ".env")
LOG_PATH = os.path.join(PROJECT_DIR, "bridge.log")
DISCOVERY_PATH = os.path.join(PROJECT_DIR, "discovery.log")

# On Windows, wrap the real stdout buffer in UTF-8 for the RELAY only
# The global sys.stdout remains redirected to sys.stderr
if sys.platform == 'win32':
    sys.stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')
    # This is the dedicated stream for MCP protocol talk
    protocol_stdout = io.TextIOWrapper(real_stdout_buffer, encoding='utf-8')
else:
    # On non-Windows, we still need the original stdout buffer
    protocol_stdout = io.TextIOWrapper(real_stdout_buffer, encoding='utf-8')

class FraudDetectionEngine:
    def __init__(self, learning_mode=False):
        self.agent_risk_scores = {}
        self.user_risk_scores = {} # Identity-aware risk tracking
        self.last_calls = {} # Deduplication cache: {agent: (tool, args, timestamp)}
        self.last_activity = {} # For cooldown/decay: {identifier: timestamp}
        self.lock = threading.Lock() # Ensure thread-safe access
        self.RISK_THRESHOLD = 200
        self.QUARANTINE_THRESHOLD = 500 # Threshold for permanent circuit breaking
        self.HONEYPOT_PENALTY = 100     # Penalty for hitting a honeypot trap
        self.learning_mode = learning_mode
        self.DECAY_RATE = 10 # Points to remove per interval
        self.DECAY_INTERVAL = 30 # Seconds per decay step (1 minute)

        # Start background decay thread for real-time cooldown
        threading.Thread(target=self._decay_loop, daemon=True).start()

    def _decay_loop(self):
        """Proactively decay risk scores every minute even if no tools are called."""
        while True:
            time.sleep(10) # Check every 10s for responsiveness
            now = time.time()
            with self.lock:
                # Combine agents and users for check
                all_ids = list(self.agent_risk_scores.keys()) + list(self.user_risk_scores.keys())
                for entry in set(all_ids):
                    if entry not in self.last_activity:
                        continue
                    
                    elapsed = now - self.last_activity[entry]
                    if elapsed >= self.DECAY_INTERVAL:
                        # Perform decay
                        if entry in self.agent_risk_scores:
                            old_score = self.agent_risk_scores[entry]
                            if old_score > 0:
                                self.agent_risk_scores[entry] = max(0, old_score - self.DECAY_RATE)
                                log(f"📉 Fraud Engine: Agent {entry} risk cooled down from {old_score} to {self.agent_risk_scores[entry]}")
                        
                        if entry in self.user_risk_scores:
                            old_score = self.user_risk_scores[entry]
                            if old_score > 0:
                                self.user_risk_scores[entry] = max(0, old_score - self.DECAY_RATE)
                                log(f"📉 Fraud Engine: User {entry} risk cooled down from {old_score} to {self.user_risk_scores[entry]}")

                        self.last_activity[entry] = now # Reset timer after successful decay step

    def analyze(self, agent: str, decision, tool_name: str = None, tool_args: dict = None, user_id: str = None) -> tuple[bool, str, str, str]:
        action_val = decision.action.value if hasattr(decision.action, 'value') else str(decision.action)
        now = time.time()

        with self.lock:
            if agent not in self.agent_risk_scores:
                self.agent_risk_scores[agent] = 0
                self.last_activity[agent] = now
            
            if user_id and user_id not in self.user_risk_scores:
                self.user_risk_scores[user_id] = 0
                self.last_activity[user_id] = now
            
            # --- UPDATED: REFRESH ACTIVITY ---
            # (Decay is now handled by _decay_loop background thread)

            # Increase risk score based on static firewall triggers
            risk_increase = 0
            if action_val == "deny":
                # --- RISK DEDUPLICATION ---
                is_retry = False
                if tool_name and tool_args and agent in self.last_calls:
                    last_tool, last_args, last_time = self.last_calls[agent]
                    time_diff = now - last_time
                    
                
                    current_args_norm = tool_args.copy()
                    last_args_norm = last_args.copy()
                    
                    for args_dict in [current_args_norm, last_args_norm]:
                        if "path" in args_dict:
                            # Strip trailing slashes and normalize separators
                            args_dict["path"] = os.path.normpath(args_dict["path"]).rstrip(os.path.sep)
                    
                    if last_tool == tool_name and last_args_norm == current_args_norm and (time_diff < 60):
                        is_retry = True
                
                if not is_retry:
                    risk_increase = 15 
                else:
                    log(f"🛡️ Fraud Engine: Risk deduplicated for repeated call to {tool_name}")
                
                # Update last call cache
                if tool_name and tool_args:
                    self.last_calls[agent] = (tool_name, tool_args, now)
                    
            elif action_val == "redact":
                risk_increase = 10 # User set this to 10
                
            # --- HONEYPOT DETECTION ---
            # If the rule name matches our honeypot trap, apply maximum penalty
            if hasattr(decision, 'name') and decision.name == "block-honeypots":
                risk_increase = self.HONEYPOT_PENALTY
                log(f"🚨 FRAUD ENGINE CRITICAL: Honeypot trap '{tool_name}' triggered by {agent}!")

            # Suppress risk score increments if in learning mode
            if self.learning_mode:
                risk_increase = 0

            self.agent_risk_scores[agent] += risk_increase
            if user_id:
                self.user_risk_scores[user_id] += risk_increase
                
            # Keep activity alive so cooldown starts AFTER the last call
            self.last_activity[agent] = now
            if user_id:
                self.last_activity[user_id] = now
                
            current_score = self.agent_risk_scores[agent]
            if user_id:
                current_score = max(current_score, self.user_risk_scores[user_id])
            
            # Determine if dynamic threshold is crossed
            if current_score >= self.QUARANTINE_THRESHOLD:
                return True, "deny", f"Fraud Engine QUARANTINE: Risk Score ({current_score}) reached critical limit. Agent identity {agent} is now permanently blacklisted.", "critical"

            if current_score >= self.RISK_THRESHOLD:
                return True, "deny", f"Fraud Engine Block: Risk Score ({current_score}) exceeded threshold ({self.RISK_THRESHOLD}).", "critical"
                
            return False, action_val, decision.reason, decision.severity.value if hasattr(decision.severity, 'value') else str(decision.severity)

class NIMCloudGuard:
    def __init__(self, api_key: str, base_url: str, config: dict):
        self.api_key = api_key
        self.base_url = base_url
        self.config = config
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

    def check_jailbreak(self, text: str, is_admin: bool = False) -> tuple[bool, str]:
        if not self.config or not self.config.get("jailbreak_rail", {}).get("enabled"):
            return False, ""
        
        # Using Llama Guard 4 — purpose-built safety classifier
        # Returns "safe" or "unsafe\nS1,S2..." with category codes
        endpoint = f"{self.base_url}/chat/completions"
        try:
            log(f"[DEBUG LLAMA GUARD] Sending to {endpoint}")
            log(f"[DEBUG LLAMA GUARD] Payload Text: {repr(text)}")
            log(f"[DEBUG LLAMA GUARD] API Key: {self.api_key[:10]}...")
            data = {
                "model": "meta/llama-guard-4-12b",
                "messages": [{"role": "user", "content": text}],
                "max_tokens": 50
            }
            req_headers = self.headers.copy()
            req_headers.update(get_spiffe_headers())
            response = requests.post(endpoint, headers=req_headers, json=data, timeout=5)
            log(f"[DEBUG LLAMA GUARD] Status Code: {response.status_code}")
            log(f"[DEBUG LLAMA GUARD] Response: {response.text}")
            if response.status_code == 200:
                verdict = response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip().lower()
                if verdict.startswith("unsafe"):
                    # Extract category codes for detailed logging
                    categories = re.findall(r'S\d+', verdict, re.IGNORECASE)
                    
                    # Categories to suppress:
                    # S5  = Defamation — bypassed due to false positives on benign prompts
                    # S7  = Privacy (PII in context) — suppressed for admins + redacted text
                    # S14 = Code Interpreter Abuse — suppressed for admins because raw financial
                    #        data (emails, credit cards) in tool responses triggers false positives
                    ADMIN_BYPASS_CATEGORIES = {"S5", "S7", "S14"}
                    REDACTION_BYPASS_CATEGORIES = {"S7"}
                    STANDARD_BYPASS_CATEGORIES = {"S5", "S14"}
                    
                    has_redacted_tokens = any(token in text for token in ["[REDACTED-EMAIL]", "[REDACTED-SSN]", "[REDACTED-PHONE]", "[REDACTED-CC]"])
                    
                    if is_admin:
                        active_violations = [c for c in categories if c.upper() not in ADMIN_BYPASS_CATEGORIES]
                        if not active_violations:
                            log(f"ℹ️ Llama Guard: {', '.join(categories)} safety violation(s) ignored because authenticated user has Administrator privileges.")
                    else:
                        active_violations = [c for c in categories if c.upper() not in STANDARD_BYPASS_CATEGORIES]
                        if has_redacted_tokens:
                            active_violations = [c for c in active_violations if c.upper() not in REDACTION_BYPASS_CATEGORIES]
                        
                        ignored = [c for c in categories if c.upper() in STANDARD_BYPASS_CATEGORIES or (has_redacted_tokens and c.upper() in REDACTION_BYPASS_CATEGORIES)]
                        if ignored and not active_violations:
                            log(f"ℹ️ Llama Guard: {', '.join(ignored)} safety violation(s) ignored safely for standard user.")
                        
                    if active_violations:
                        cat_str = ", ".join(active_violations)
                        return True, f"Llama Guard 4 UNSAFE — Violated categories: {cat_str}"
            elif response.status_code == 401:
                log(f"⚠️ Llama Guard auth failed (401). Check NVIDIA_API_KEY.")
        except Exception as e:
            log(f"⚠️ Llama Guard jailbreak check error: {e}")
        return False, ""

    def check_topical(self, text: str) -> tuple[bool, str]:
        """Keyword-based topical filtering (Llama Guard is not a topic classifier)."""
        rail_cfg = self.config.get("topical_rail", {}) if self.config else {}
        if not rail_cfg or not rail_cfg.get("enabled"):
            return False, ""
        
        blocked = rail_cfg.get("blocked_topics", [])
        text_lower = text.lower()
        
        # Simple keyword matching against blocked topics
        for topic in blocked:
            # Extract key terms from the topic description
            keywords = [w.lower() for w in topic.split() if len(w) > 3]
            matches = sum(1 for kw in keywords if kw in text_lower)
            if matches >= 2:  # At least 2 keyword matches to avoid false positives
                return True, f"Policy Violation: Blocked topic detected — '{topic}'"
        
        return False, ""

    def redact_pii(self, text: str, role: str = "user") -> str:
        """Presidio-based NLP PII redaction (Option A)."""
        if role == "admin":
            return text
        rail_cfg = self.config.get("pii_rail", {}) if self.config else {}
        if not rail_cfg or not rail_cfg.get("enabled"):
            return text
        
        return redact_pii_with_presidio(text)

class SemanticIntentParser:
    def __init__(self, api_key: str = None, base_url: str = None):
        self.api_key = api_key
        self.base_url = base_url or "https://integrate.api.nvidia.com/v1"
        self.local_prototypes = {
            "ReadFile": [
                "show file contents", "read file", "open file", "view file", 
                "print file", "read test_sandbox.txt", "display the file", 
                "cat readme.md", "what is inside research_notes.txt", 
                "read financial_data.csv", "show test_presidio_basic.py"
            ],
            "ListDirectory": [
                "list files", "show directory", "what files are in folder", 
                "ls secure-experiment-zone", "show secure-experiment-zone folder", 
                "list directory contents", "list all files", "dir command"
            ],
            "GetUserTransactions": [
                "get my recent transactions", "show bank transactions", 
                "list transactions", "my money history", "recent salary credit", 
                "transactions for user 1", "fetch financial txs", 
                "list transactions of doctor", "show biff's transactions"
            ],
            "GetCurrentUser": [
                "who am i", "current user", "get current user", 
                "my identity", "which user am i logged in as", "check my role"
            ],
            "KeycloakListUsers": [
                "list keycloak users", "show users in keycloak", "get keycloak users",
                "list the users in keycloak", "show all users in keycloak", "keycloak users list"
            ],
            "KeycloakRevokeUserSessions": [
                "revoke sessions", "revoke user sessions", "logout user from keycloak",
                "terminate sessions for user1", "revoke sessions for username user1",
                "revoke sessions for user", "logout keycloak sessions"
            ],
            "Greet": [
                "hi", "hello", "hey", "hola", "greetings", "good morning"
            ]
        }
        
        # Build Local TF-IDF Vector Space Model
        self.stop_words = {'the', 'and', 'a', 'an', 'of', 'to', 'in', 'for', 'is', 'on', 'at', 'by', 'with', 'from'}
        import math as _math
        all_docs = []
        for prototypes in self.local_prototypes.values():
            for doc in prototypes:
                all_docs.append(self._clean_text(doc))
        
        self.vsm_vocab = set()
        for doc in all_docs:
            self.vsm_vocab.update(doc)
        self.vsm_vocab = list(self.vsm_vocab)
        
        N = len(all_docs)
        self.vsm_idf = {}
        for term in self.vsm_vocab:
            df = sum(1 for doc in all_docs if term in doc)
            self.vsm_idf[term] = _math.log(1 + (N / (1 + df)))
            
        # Online pre-cached vector embeddings configuration
        self.cached_prototype_embeddings = {}
        self.embeddings_initialized = False
        self.cache_timestamp = 0
        self.CACHE_TTL_SEC = 3600  # 1 hour cache lifespan
        
        # Circuit Breaker state
        self.circuit_broken = False
        self.consecutive_failures = 0
        self.MAX_FAILURES_BEFORE_BREAK = 3
        self.circuit_breaker_timestamp = 0
        self.CIRCUIT_BREAKER_COOLDOWN_SEC = 300  # 5 minutes quarantine

    def _clean_text(self, text: str) -> list[str]:
        tokens = re.findall(r'\b\w+\b', text.lower())
        return [t for t in tokens if (len(t) > 2 or t in ("hi", "ls", "go", "me", "my")) and t not in self.stop_words]

    def _extract_target_path(self, query: str) -> str:
        # 1. Look for explicit Windows/Unix paths or files with extensions in the query
        path_match = re.search(r'([\w\-\./:\\]+\.(?:txt|csv|sh|py|md|json|yaml|yml|log|db|ini|conf))', query, re.IGNORECASE)
        if path_match:
            return path_match.group(1)
            
        # Check if a word contains a slash or backslash (which indicates a directory/path without extension)
        path_no_ext_match = re.search(r'([\w\-\.:\\]+[\/\\][\w\-\./\\]+)', query)
        if path_no_ext_match:
            return path_no_ext_match.group(1)

        # 2. Look for any word after "file" or "path" keyword, skipping common determiners like "the", "a", "an"
        file_keyword_match = re.search(r'\b(?:file|path|read|open|view|cat)\s+(?:the\s+|a\s+|an\s+)?([\w\-\./:\\]+)', query, re.IGNORECASE)
        if file_keyword_match:
            val = file_keyword_match.group(1).strip()
            val = val.rstrip('.').rstrip(',').rstrip('?').rstrip('"').rstrip("'")
            if val and val.lower() not in ("the", "a", "an", "file", "folder", "contents"):
                return val
                
        # 3. Fallback to checking containing directories
        if 'secure-experiment-zone' in query.lower():
            sub_match = re.search(r'(secure-experiment-zone/[\w\-\.]+)', query, re.IGNORECASE)
            if sub_match:
                return sub_match.group(1)
            return 'secure-experiment-zone'
            
        return ''

    def _vectorize_tf_idf(self, tokens: list[str]) -> dict:
        tf = {}
        for t in tokens:
            tf[t] = tf.get(t, 0) + 1
        
        vector = {}
        for t, count in tf.items():
            if t in self.vsm_idf:
                vector[t] = count * self.vsm_idf[t]
        return vector

    def _cosine_similarity_sparse(self, vec1: dict, vec2: dict) -> float:
        import math as _math
        intersection = set(vec1.keys()).intersection(set(vec2.keys()))
        if not intersection:
            return 0.0
        
        dot_product = sum(vec1[t] * vec2[t] for t in intersection)
        norm1 = _math.sqrt(sum(v ** 2 for v in vec1.values()))
        norm2 = _math.sqrt(sum(v ** 2 for v in vec2.values()))
        
        if norm1 == 0.0 or norm2 == 0.0:
            return 0.0
        return dot_product / (norm1 * norm2)

    def _local_vsm_parse(self, query: str) -> dict:
        query_tokens = self._clean_text(query)
        query_vec = self._vectorize_tf_idf(query_tokens)
        
        best_intent = "None"
        best_score = 0.0

        for intent, prototypes in self.local_prototypes.items():
            intent_scores = []
            for proto in prototypes:
                proto_tokens = self._clean_text(proto)
                proto_vec = self._vectorize_tf_idf(proto_tokens)
                score = self._cosine_similarity_sparse(query_vec, proto_vec)
                intent_scores.append(score)
            
            max_score = max(intent_scores) if intent_scores else 0.0
            if max_score > best_score:
                best_score = max_score
                best_intent = intent

        # Entity Extraction (Paths, files, user IDs)
        target = self._extract_target_path(query)

        if best_intent == "GetUserTransactions":
            user_match = re.search(r'\b(?:user\s*id|user_?id|user)\b\s*(=?\s*\b\d+\b)', query.lower())
            if user_match:
                target = user_match.group(1).replace("=", "").strip()
        elif best_intent == "KeycloakRevokeUserSessions":
            known_users = ["admin", "user1", "user2"]
            found_user = None
            for ku in known_users:
                if ku in query.lower():
                    found_user = ku
                    break
            
            if found_user:
                target = found_user
            else:
                words = re.findall(r'\b[\w\-\.]+\b', query.lower())
                filler_words = {"revoke", "the", "user", "session", "sessions", "of", "for", "username", "to", "logout"}
                candidate = ""
                for w in reversed(words):
                    if w not in filler_words and len(w) > 1:
                        candidate = w
                        break
                target = candidate if candidate else "user1"

        # Offline VSM Cosine match boosts
        confidence = best_score
        if best_intent == "ReadFile" and ("read" in query.lower() or "file" in query.lower() or target):
            confidence = max(confidence, 0.85)
        elif best_intent == "ListDirectory" and ("list" in query.lower() or "dir" in query.lower() or "folder" in query.lower() or "files" in query.lower() or target == "secure-experiment-zone"):
            confidence = max(confidence, 0.85)
        elif best_intent == "GetUserTransactions" and ("transaction" in query.lower() or "money" in query.lower() or "salary" in query.lower()):
            confidence = max(confidence, 0.90)
        elif best_intent == "GetCurrentUser" and ("who am i" in query.lower() or "current user" in query.lower()):
            confidence = max(confidence, 0.95)
        elif best_intent == "KeycloakListUsers" and ("keycloak" in query.lower() or "users" in query.lower()):
            confidence = max(confidence, 0.95)
        elif best_intent == "KeycloakRevokeUserSessions" and ("revoke" in query.lower() or "session" in query.lower() or "logout" in query.lower()):
            confidence = max(confidence, 0.95)
        elif best_intent == "Greet" and len(query_tokens) <= 3 and any(w in query.lower() for w in ["hi", "hello", "hey"]):
            confidence = max(confidence, 0.98)

        confidence = min(max(confidence, 0.1), 1.0)
        if confidence < 0.2:
            best_intent = "None"
            confidence = 0.1

        return {
            "intent": best_intent,
            "target": target,
            "confidence": confidence,
            "parser_type": "local-vsm-cosine"
        }

    async def _fetch_api_embedding(self, text: str) -> list[float]:
        """Queries the online embeddings endpoint with timeout isolation and circuit breaking."""
        now = time.time()
        
        # 1. Circuit Breaker Check
        if self.circuit_broken:
            if now - self.circuit_breaker_timestamp > self.CIRCUIT_BREAKER_COOLDOWN_SEC:
                # Cooldown period completed, reset circuit and try again
                self.circuit_broken = False
                log("🔌 CIRCUIT BREAKER: Cooldown completed, re-attempting embedding connection...")
            else:
                raise RuntimeError("Embedding provider quarantined due to active circuit breaker.")

        endpoint = f"{self.base_url}/embeddings"
        payload = {
            "model": "nvidia/embed-qa-4" if "nvidia" in self.base_url else "text-embedding-3-small",
            "input": text
        }
        
        try:
            # 2. Timeout Isolation (Strict 3.0 second limit)
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    endpoint,
                    headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                    json=payload,
                    timeout=3.0
                )
                if resp.status_code == 200:
                    self.consecutive_failures = 0  # Reset on successful call
                    return resp.json().get("data", [{}])[0].get("embedding", [])
                else:
                    raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
        except Exception as e:
            self.consecutive_failures += 1
            log(f"⚠️ Embedding API call failed ({self.consecutive_failures}/{self.MAX_FAILURES_BEFORE_BREAK}): {e}")
            
            # 3. Circuit Breaker Trip
            if self.consecutive_failures >= self.MAX_FAILURES_BEFORE_BREAK:
                self.circuit_broken = True
                self.circuit_breaker_timestamp = now
                log(f"🔌 CIRCUIT BREAKER TRIPPED: Embedding provider quarantined for {self.CIRCUIT_BREAKER_COOLDOWN_SEC}s!")
                dashboard_state.add_event({
                    "action": "block",
                    "tool": "(embedding-provider)",
                    "agent": "security-bridge",
                    "reason": f"Circuit breaker tripped. Quarantining embedding endpoint due to consecutive connection timeouts/failures.",
                    "severity": "high",
                    "stage": "semantic-intent-routing",
                    "timestamp": now
                })
            raise

    async def _init_online_embeddings(self, force_refresh: bool = False):
        """Asynchronously warm up, cache, and refresh vector embeddings for intent prototypes."""
        now = time.time()
        
        # Check cache TTL (refresh hourly or if explicitly forced)
        if self.embeddings_initialized and not force_refresh:
            if now - self.cache_timestamp <= self.CACHE_TTL_SEC:
                return
            log("🔄 TTL expired: Refreshing cached vector embeddings for prototypes...")

        if not self.api_key or self.api_key.startswith("nvapi-AdrtPEfv"):
            return
        
        try:
            log("⏳ Pre-caching vector embeddings for intent prototypes...")
            for intent, prototypes in self.local_prototypes.items():
                vectors = []
                for proto in prototypes[:3]:  # Embed top 3 prototypes per intent to optimize initialization
                    try:
                        v = await self._fetch_api_embedding(proto)
                        if v:
                            vectors.append(v)
                    except Exception:
                        pass
                if vectors:
                    self.cached_prototype_embeddings[intent] = vectors
            
            self.embeddings_initialized = True
            self.cache_timestamp = now
            log("✅ Online vector embeddings pre-cached successfully!")
        except Exception as e:
            log(f"⚠️ Failed to cache online embeddings: {e}")

    async def parse(self, query: str) -> dict:
        import math as _math
        now = time.time()

        # Cache TTL check and lazy background refresh initialization
        if self.api_key and not self.api_key.startswith("nvapi-AdrtPEfv"):
            if not self.embeddings_initialized or (now - self.cache_timestamp > self.CACHE_TTL_SEC):
                await self._init_online_embeddings()

        # Try API Vector Embedding similarity match first (only if circuit is healthy)
        if self.embeddings_initialized and self.cached_prototype_embeddings and not self.circuit_broken:
            try:
                query_vector = await self._fetch_api_embedding(query)
                if query_vector:
                    best_intent = "None"
                    best_score = 0.0
                    
                    for intent, proto_vectors in self.cached_prototype_embeddings.items():
                        for pv in proto_vectors:
                            # Cosine similarity over floats
                            dot = sum(a * b for a, b in zip(query_vector, pv))
                            norm1 = _math.sqrt(sum(a**2 for a in query_vector))
                            norm2 = _math.sqrt(sum(b**2 for b in pv))
                            similarity = dot / (norm1 * norm2) if (norm1 * norm2) else 0.0
                            if similarity > best_score:
                                best_score = similarity
                                best_intent = intent
                    
                    # Entity Extraction
                    target = self._extract_target_path(query)
                    
                    if best_intent == "GetUserTransactions":
                        user_match = re.search(r'\b(?:user\s*id|user_?id|user)\b\s*(=?\s*\b\d+\b)', query.lower())
                        if user_match:
                            target = user_match.group(1).replace("=", "").strip()

                    confidence = best_score
                    
                    # 4. Telemetry for Drift and Confidence Anomalies
                    # If highest matching embedding vector similarity is extremely low (< 0.50), alert on intent drift!
                    if confidence < 0.50 and best_intent != "None":
                        drift_msg = f"[SEMANTIC INTENT DRIFT] Confidence anomaly ({confidence:.2f}) detected for intent '{best_intent}' with query: '{query[:80]}'"
                        log(f"⚠️ {drift_msg}")
                        dashboard_state.add_event({
                            "action": "info",
                            "tool": "semantic_router",
                            "agent": "security-bridge",
                            "reason": drift_msg,
                            "severity": "medium",
                            "stage": "semantic-intent-routing",
                            "timestamp": now
                        })

                    return {
                        "intent": best_intent,
                        "target": target,
                        "confidence": confidence,
                        "parser_type": "api-vector-embeddings"
                    }
            except Exception as e:
                log(f"⚠️ API embedding matching failed: {e}. Falling back to local VSM.")

        # Default fallback: Local TF-IDF Cosine Vector Space Model
        return self._local_vsm_parse(query)

class ToolsListAggregator:
    def __init__(self, provider_count):
        self.provider_count = provider_count
        self.lock = threading.Lock()
        self.responses = {}
        self.providers_responded = {}
        self.timer_threads = {}
        self.completed = set()

    def add_response(self, req_id, provider_name, tools_list):
        with self.lock:
            if req_id in self.completed:
                return False, []
                
            if req_id not in self.responses:
                self.responses[req_id] = []
                self.providers_responded[req_id] = set()
                # Start a safety fallback timer (2.0s) in case a provider hangs
                timer = threading.Timer(2.0, self._trigger_fallback, args=[req_id])
                self.timer_threads[req_id] = timer
                timer.start()
                
            self.responses[req_id].extend(tools_list)
            self.providers_responded[req_id].add(provider_name)
            
            if len(self.providers_responded[req_id]) >= self.provider_count:
                # Cancel timer
                timer = self.timer_threads.pop(req_id, None)
                if timer:
                    timer.cancel()
                self.completed.add(req_id)
                aggregated = self.responses.pop(req_id, [])
                self.providers_responded.pop(req_id, None)
                return True, aggregated
            return False, []

    def _trigger_fallback(self, req_id):
        with self.lock:
            if req_id in self.completed:
                return
            self.completed.add(req_id)
            self.timer_threads.pop(req_id, None)
            aggregated = self.responses.pop(req_id, [])
            self.providers_responded.pop(req_id, None)
            
            # Send the incomplete/collected tools list
            aggregated_msg = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": aggregated
                }
            }
            try:
                log(f"⚠️ ToolsListAggregator: Fallback timer triggered for req_id {req_id}. Sending {len(aggregated)} tools collected.")
                with stdout_lock:
                    protocol_stdout.write(json.dumps(aggregated_msg) + "\n")
                    protocol_stdout.flush()
            except Exception as e:
                log(f"⚠️ Failed to send aggregated tools fallback: {e}")

tools_list_aggregator = None

# ==========================================
# MICROSOFT PRESIDIO NLP PII REDACTION (OPTION A) & AI SEMANTIC REDACTION (OPTION B)
# ==========================================

_presidio_analyzer = None
_presidio_anonymizer = None
_ai_redactor = None
_presidio_lock = threading.Lock()
_ai_redactor_lock = threading.Lock()

def get_ai_redactor_instance():
    global _ai_redactor
    with _ai_redactor_lock:
        if _ai_redactor is None:
            from mcp_firewall.privacy.redaction_engine import RedactionEngine
            global gateway_instance
            pii_cfg = gateway_instance.config.pii if (gateway_instance and gateway_instance.config) else None
            _ai_redactor = RedactionEngine(pii_config=pii_cfg)
    return _ai_redactor

def get_presidio_instances():
    global _presidio_analyzer, _presidio_anonymizer
    with _presidio_lock:
        if _presidio_analyzer is None or _presidio_anonymizer is None:
            if AnalyzerEngine is None or AnonymizerEngine is None:
                raise ImportError("Presidio library is not installed/available.")
            _presidio_analyzer = AnalyzerEngine()
            _presidio_anonymizer = AnonymizerEngine()
    return _presidio_analyzer, _presidio_anonymizer

def is_markdown_table(text: str) -> bool:
    """
    Returns True if the text represents a formatted Markdown table.
    """
    if not isinstance(text, str) or "|" not in text:
        return False
    lines = [l.strip() for l in text.strip().split('\n') if l.strip()]
    if len(lines) < 2:
        return False
    return lines[0].startswith('|') and lines[0].endswith('|') and lines[1].startswith('|') and '-' in lines[1]


def is_csv_text(text: str) -> bool:
    """
    Returns True if the text looks like raw CSV data (multi-line, comma-delimited).
    Skips Markdown tables (already pipe-formatted) and single-line strings.
    """
    if not isinstance(text, str) or ',' not in text:
        return False
    # Ignore text that is already a Markdown table
    if '|' in text and '-+-' in text.replace(' ', ''):
        return False
    lines = [l for l in text.strip().split('\n') if l.strip()]
    if len(lines) < 2:
        return False
    # At least half the lines should contain commas
    comma_lines = sum(1 for l in lines if ',' in l)
    return comma_lines >= max(1, len(lines) // 2)


def csv_to_markdown_table(csv_text: str) -> str:
    """
    Converts a raw CSV string into a Markdown pipe table.
    Completely dynamic — reads headers from the first row, no hardcoding.
    """
    import csv as _csv
    import io
    try:
        reader = list(_csv.reader(io.StringIO(csv_text.strip())))
        if len(reader) < 2:
            return csv_text  # Not enough rows; return as-is
        headers = reader[0]
        separator = '| ' + ' | '.join(['---'] * len(headers)) + ' |'
        rows = ['| ' + ' | '.join(str(c).strip() for c in row) + ' |' for row in reader]
        header_row = rows[0]
        data_rows = rows[1:]
        return '\n'.join([header_row, separator] + data_rows)
    except Exception:
        return csv_text


def is_tsv_text(text: str) -> bool:
    """
    Returns True if the text looks like raw TSV data (multi-line, tab-delimited).
    Skips Markdown tables and single-line strings.
    """
    if not isinstance(text, str) or '\t' not in text:
        return False
    if '|' in text and '-+-' in text.replace(' ', ''):
        return False
    lines = [l for l in text.strip().split('\n') if l.strip()]
    if len(lines) < 2:
        return False
    # At least half the lines should contain tabs
    tab_lines = sum(1 for l in lines if '\t' in l)
    return tab_lines >= max(1, len(lines) // 2)


def tsv_to_markdown_table(tsv_text: str) -> str:
    """
    Converts raw TSV text to a Markdown pipe table.
    Completely dynamic — reads headers from the first row, no hardcoding.
    """
    import csv as _csv
    import io
    try:
        reader = list(_csv.reader(io.StringIO(tsv_text.strip()), delimiter='\t'))
        if len(reader) < 2:
            return tsv_text
        headers = reader[0]
        separator = '| ' + ' | '.join(['---'] * len(headers)) + ' |'
        rows = ['| ' + ' | '.join(str(c).strip() for c in row) + ' |' for row in reader]
        header_row = rows[0]
        data_rows = rows[1:]
        return '\n'.join([header_row, separator] + data_rows)
    except Exception:
        return tsv_text


def format_embedded_json_arrays(text: str) -> str:
    """
    Scans the text for JSON arrays of dictionaries (either raw or inside codeblocks)
    and converts them to Markdown tables dynamically.
    """
    if not isinstance(text, str):
        return text

    def _list_to_md(data: list) -> str:
        headers = []
        for item in data:
            if isinstance(item, dict):
                for k in item.keys():
                    if k not in headers:
                        headers.append(k)
        if not headers:
            return ""
        separator = '| ' + ' | '.join(['---'] * len(headers)) + ' |'
        header_row = '| ' + ' | '.join(str(h) for h in headers) + ' |'
        rows = []
        for item in data:
            if isinstance(item, dict):
                row_vals = [str(item.get(h, '')).replace('\n', ' ').strip() for h in headers]
                rows.append('| ' + ' | '.join(row_vals) + ' |')
        return '\n'.join([header_row, separator] + rows)

    # 1. Look for ```json ... ``` codeblocks containing arrays
    pattern_codeblock = r"```json\s*(\[\s*\{.*?\n?\s*\}\s*\])\s*```"
    def repl_codeblock(match):
        try:
            import json as _json
            content = match.group(1).strip()
            data = _json.loads(content)
            if isinstance(data, list) and len(data) > 0 and all(isinstance(x, dict) for x in data):
                return _list_to_md(data)
        except Exception:
            pass
        return match.group(0)

    text = re.sub(pattern_codeblock, repl_codeblock, text, flags=re.DOTALL)

    # 2. Look for raw JSON arrays of dicts in the text
    pattern_raw = r"(\[\s*\{\s*\"[^\"]+\"\s*:.*?\s*\}\s*\])"
    def repl_raw(match):
        try:
            import json as _json
            content = match.group(1).strip()
            data = _json.loads(content)
            if isinstance(data, list) and len(data) > 0 and all(isinstance(x, dict) for x in data):
                return _list_to_md(data)
        except Exception:
            pass
        return match.group(0)

    text = re.sub(pattern_raw, repl_raw, text, flags=re.DOTALL)
    return text


def format_embedded_tabular_segments(text: str) -> str:
    """
    Scans the text for embedded raw CSV or TSV blocks (consecutive comma or tab delimited lines)
    and replaces each with a Markdown pipe table. Also parses and formats JSON arrays of objects.
    """
    if not isinstance(text, str):
        return text

    # First, handle JSON arrays
    text = format_embedded_json_arrays(text)

    # Now, process line-by-line for CSV/TSV
    lines = text.split('\n')
    result = []
    
    tab_buffer = []
    current_type = None  # 'csv' or 'tsv'

    def flush_buffer():
        if tab_buffer:
            block = '\n'.join(tab_buffer)
            if current_type == 'csv' and is_csv_text(block):
                result.append(csv_to_markdown_table(block))
            elif current_type == 'tsv' and is_tsv_text(block):
                result.append(tsv_to_markdown_table(block))
            else:
                result.extend(tab_buffer)
            tab_buffer.clear()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('|'):
            flush_buffer()
            result.append(line)
            current_type = None
            continue

        is_csv_line = ',' in stripped
        is_tsv_line = '\t' in stripped
        line_type = 'tsv' if is_tsv_line else ('csv' if is_csv_line else None)

        if line_type:
            if current_type is None:
                current_type = line_type
                tab_buffer.append(line)
            elif current_type == line_type:
                tab_buffer.append(line)
            else:
                flush_buffer()
                current_type = line_type
                tab_buffer.append(line)
        else:
            flush_buffer()
            result.append(line)
            current_type = None

    flush_buffer()
    return '\n'.join(result)


def format_embedded_csv_segments(text: str) -> str:
    """
    Scans the text for embedded tabular data (CSV, TSV, or JSON arrays)
    and replaces them with Markdown pipe tables dynamically.
    """
    return format_embedded_tabular_segments(text)



def extract_outer_json_block(text: str) -> tuple:
    """
    Given a raw text response, robustly extracts the outermost JSON block (finding the first '{' and last '}').
    Also returns whether it is wrapped in triple backticks and the span indices (start, end) of the JSON block.
    """
    if not isinstance(text, str):
        return "", False, -1, -1
    start_idx = text.find('{')
    end_idx = text.rfind('}')
    if start_idx == -1 or end_idx == -1 or end_idx <= start_idx:
        return "", False, -1, -1

    json_str = text[start_idx:end_idx+1]
    
    # Check if there is a ```json wrapper around this block
    is_wrapped = False
    prefix = text[:start_idx].strip()
    suffix = text[end_idx+1:].strip()
    if prefix.endswith("```json") and suffix.startswith("```"):
        is_wrapped = True
        
    return json_str, is_wrapped, start_idx, end_idx


def redact_pii_with_presidio(text: str, is_raw: bool = False, skip_headers: bool = True) -> str:
    original = text

    # --- JSON INTERCEPT RULE ---
    if not is_raw:
        try:
            json_str, is_wrapped, start_idx, end_idx = extract_outer_json_block(text)
            if json_str:
                data = json.loads(json_str)
                if isinstance(data, dict) and data.get("action") == "Final Answer":
                    action_input = data.get("action_input")
                    if isinstance(action_input, str) and action_input.strip():
                        # Step 1: Convert any embedded CSV/TSV/JSON blocks to Markdown tables FIRST,
                        # so that column headers are present as table headers before Presidio runs.
                        formatted_input = format_embedded_csv_segments(action_input)

                        # Step 2: Redact PII on the formatted text.
                        # The Markdown header-skipping rule will now protect column header rows.
                        redacted_input = redact_pii_with_presidio(formatted_input, is_raw=True, skip_headers=True)

                        data["action_input"] = redacted_input
                        new_json_str = json.dumps(data, indent=2)
                        
                        if is_wrapped:
                            wrap_start = text[:start_idx].rfind("```json")
                            wrap_end = text[end_idx+1:].find("```")
                            if wrap_start != -1 and wrap_end != -1:
                                wrap_end = end_idx + 1 + wrap_end + 3
                                return text[:wrap_start] + f"```json\n{new_json_str}\n```" + text[wrap_end:]
                        return text[:start_idx] + new_json_str + text[end_idx+1:]
                elif isinstance(data, dict) and "result" in data and isinstance(data["result"], dict) and "content" in data["result"]:
                    content_list = data["result"]["content"]
                    if isinstance(content_list, list):
                        modified = False
                        for item in content_list:
                            if isinstance(item, dict) and item.get("type") == "text" and isinstance(item.get("text"), str):
                                raw_text = item["text"]
                                if raw_text.strip():
                                    redacted_text = redact_pii_with_presidio(raw_text, is_raw=True, skip_headers=True)
                                    item["text"] = redacted_text
                                    modified = True
                        if modified:
                            new_json_str = json.dumps(data)
                            return text[:start_idx] + new_json_str + text[end_idx+1:]
        except Exception as e:
            log(f"⚠️ JSON intercept in redaction failed: {e}")


    # --- TABLE HEADER SKIPPING RULES (Option A / B Outbound Protection) ---
    # To prevent false redaction of table headers (like Name, Email, CreditCard, Status)
    # when processing CSV/tabular data, we keep headers completely verbatim.
    if skip_headers and isinstance(text, str) and text.strip():
        if is_csv_text(text):
            try:
                lines = text.split('\n')
                if len(lines) >= 2:
                    header = lines[0]
                    rows = '\n'.join(lines[1:])
                    redacted_rows = redact_pii_with_presidio(rows, is_raw=True, skip_headers=False)
                    return header + '\n' + redacted_rows
            except Exception:
                pass

        if is_markdown_table(text):
            try:
                lines = text.split('\n')
                if len(lines) >= 3:
                    header = lines[0]
                    separator = lines[1]
                    rows = '\n'.join(lines[2:])
                    redacted_rows = redact_pii_with_presidio(rows, is_raw=True, skip_headers=False)
                    return header + '\n' + separator + '\n' + redacted_rows
            except Exception:
                pass

    # Load dynamic config if gateway is initialized
    global gateway_instance

    import os
    nim_key = os.getenv("NVIDIA_NIM_API_KEY") or os.getenv("NVIDIA_API_KEY") or os.getenv("NIM_API_KEY")
    if nim_key and not nim_key.startswith("nvapi-AdrtPEfv"):
        pii_enabled = True
        if gateway_instance and gateway_instance.config and gateway_instance.config.pii:
            pii_enabled = gateway_instance.config.pii.enabled
        
        if pii_enabled:
            try:
                redactor = get_ai_redactor_instance()
                redacted, findings = redactor.redact(text)
                if redacted != original:
                    log(f"✂️ PII redacted via NVIDIA NIM AI-Native DLP")
                    text = redacted
            except Exception as e:
                log(f"⚠️ AI Redaction error: {e}. Falling back to standard filters.")

    # None = auto-detect ALL Presidio-supported entity types (no hardcoding)
    entities = None
    exclude_entities = []
    raw_operators = {}
    default_placeholder = "[PII REDACTED]"
    regex_fallbacks = [] # DISABLED: regex things disabled to test Microsoft NLP

    if gateway_instance and gateway_instance.config and gateway_instance.config.pii:
        pii_cfg = gateway_instance.config.pii
        cfg_entities = getattr(pii_cfg, "presidio_entities", [])
        # Empty list or ["ALL"] → pass None to Presidio (detect everything)
        if cfg_entities and cfg_entities != ["ALL"]:
            entities = cfg_entities
        exclude_entities = getattr(pii_cfg, "presidio_exclude_entities", []) or []
        if getattr(pii_cfg, "presidio_operators", {}):
            raw_operators = pii_cfg.presidio_operators
        default_placeholder = getattr(pii_cfg, "placeholder", default_placeholder)

    try:
        analyzer, anonymizer = get_presidio_instances()
        from presidio_anonymizer.entities import OperatorConfig

        results = analyzer.analyze(text=text, language="en", entities=entities)
        
        # Apply exclude list
        if exclude_entities:
            results = [r for r in results if r.entity_type not in exclude_entities]

        # Build per-entity operators from config; fall back to default placeholder for any unknown entity
        operators = {
            ent: OperatorConfig("replace", {"new_value": placeholder})
            for ent, placeholder in raw_operators.items()
        }
        default_op = OperatorConfig("replace", {"new_value": default_placeholder})
        for result in results:
            if result.entity_type not in operators:
                operators[result.entity_type] = default_op

        anonymized = anonymizer.anonymize(text=text, analyzer_results=results, operators=operators)
        text = anonymized.text

        if text != original:
            detected = list({r.entity_type for r in results})
            log(f"✂️ PII redacted via Microsoft Presidio NLP — types: {detected}")
    except Exception as e:
        log(f"⚠️ Presidio PII redaction error: {e}. Returning original.")

    # --- DYNAMIC REGEX FALLBACKS ---
    for fallback in regex_fallbacks:
        name = fallback.get("name", "Fallback")
        pattern = fallback.get("pattern", "")
        placeholder = fallback.get("placeholder", "[REDACTED]")
        if not pattern:
            continue
        try:
            if re.search(pattern, text):
                text = re.sub(pattern, placeholder, text)
                if text != original:
                    log(f"✂️ PII redacted via regex fallback ({name})")
        except Exception:
            pass

    return text


def has_pii_presidio(text: str) -> bool:
    global gateway_instance
    # None = auto-detect ALL entity types; overridden only by explicit YAML list
    entities = None
    exclude_entities = []
    if gateway_instance and gateway_instance.config and gateway_instance.config.pii:
        pii_cfg = gateway_instance.config.pii
        cfg_entities = getattr(pii_cfg, "presidio_entities", [])
        if cfg_entities and cfg_entities != ["ALL"]:
            entities = cfg_entities
        exclude_entities = getattr(pii_cfg, "presidio_exclude_entities", []) or []

    try:
        analyzer, _ = get_presidio_instances()
        results = analyzer.analyze(text=text, language="en", entities=entities)
        if exclude_entities:
            results = [r for r in results if r.entity_type not in exclude_entities]
        return len(results) > 0
    except Exception as e:
        log(f"⚠️ Presidio PII detection error: {e}")
        return False

# Warm up Microsoft Presidio NLP engine synchronously on startup
def _warmup_presidio_sync():
    try:
        log("⏳ Warming up Microsoft Presidio NLP engine...")
        get_presidio_instances()
        log("✅ Microsoft Presidio NLP engine fully warmed up!")
    except Exception as e:
        log(f"⚠️ Presidio warmup warning: {e}")







def log_discovery(tool, args, agent):
    with open(DISCOVERY_PATH, "a", encoding="utf-8") as f:
        entry = {
            "timestamp": time.time(),
            "tool": tool,
            "args": args,
            "agent": agent,
            "proposed_rule": f"- name: auto-rule-{int(time.time())}\n  tool: \"{tool}\"\n  action: allow"
        }
        f.write(json.dumps(entry) + "\n")


def sanitize_jwt_tokens(text: str) -> str:
    import re
    # Match JWT tokens starting with eyJ and replace the middle part with a placeholder
    jwt_pattern = r'\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\b'
    def replace_token(match):
        token = match.group(0)
        if len(token) > 30:
            return f"{token[:15]}...[TRUNCATED_JWT]...{token[-15:]}"
        return token
    return re.sub(jwt_pattern, replace_token, text)


def log(msg: str):
    msg_str = str(msg)
    msg_str = sanitize_jwt_tokens(msg_str)
    timestamp = time.strftime('%H:%M:%S')
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {msg_str}\n")
    except Exception:
        pass
    
    try:
        print(msg_str, file=sys.stderr, flush=True)
    except UnicodeEncodeError:
        # Fallback for terminals that don't support UTF-8
        print(msg_str.encode('ascii', 'replace').decode('ascii'), file=sys.stderr, flush=True)


def sanitize_llm_json(text: str) -> str:
    """
    Sanitizes LLM outputs to prevent Pydantic validation errors in LangChain's AIMessage content.
    If the LLM outputs a JSON structure containing `"action": "Final Answer"` where
    `"action_input"` is an object or list (instead of a string), we serialize it to a string.
    Also maps "action": "Error" to "action": "Final Answer" to prevent invalid tool loops.
    """
    try:
        json_str, is_wrapped, start_idx, end_idx = extract_outer_json_block(text)
        if json_str:
            data = json.loads(json_str)
            if isinstance(data, dict):
                # 1. Normalize action="Error" / "error" to "Final Answer"
                if str(data.get("action")).lower() in ["error", "invalid_action", "invalid_tool"]:
                    data["action"] = "Final Answer"
                    action_input = data.get("action_input") or data.get("error") or "An error occurred processing your request."
                    data["action_input"] = str(action_input)
                
                # 2. Serialize dict/list action_input to string to prevent parsing errors
                if data.get("action") == "Final Answer":
                    action_input = data.get("action_input")
                    if action_input is not None and not isinstance(action_input, str):
                        if isinstance(action_input, (dict, list)):
                            data["action_input"] = json.dumps(action_input)
                        else:
                            data["action_input"] = str(action_input)
                    
                    # 3. Dynamic CSV to Markdown Table formatting
                    action_input = data.get("action_input")
                    if isinstance(action_input, str) and action_input.strip():
                        data["action_input"] = format_embedded_csv_segments(action_input)

                    new_json_str = json.dumps(data, indent=2)
                    if is_wrapped:
                        wrap_start = text[:start_idx].rfind("```json")
                        wrap_end = text[end_idx+1:].find("```")
                        if wrap_start != -1 and wrap_end != -1:
                            wrap_end = end_idx + 1 + wrap_end + 3
                            return text[:wrap_start] + f"```json\n{new_json_str}\n```" + text[wrap_end:]
                    return text[:start_idx] + new_json_str + text[end_idx+1:]
    except Exception:
        pass
        
    return text


def is_tool_call(content: str) -> bool:
    """
    Returns True if the content represents a structured ReAct tool call
    (i.e. it contains a JSON block with an "action" key that is NOT "Final Answer").
    """
    try:
        pattern = r"```json\s*(.*?)\s*```"
        match = re.search(pattern, content, re.DOTALL)
        json_str = ""
        if match:
            json_str = match.group(1).strip()
        else:
            trimmed = content.strip()
            if trimmed.startswith("{") and trimmed.endswith("}"):
                json_str = trimmed
            else:
                start_idx = content.find('{')
                end_idx = content.rfind('}')
                if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
                    json_str = content[start_idx:end_idx+1]
        
        if json_str:
            data = json.loads(json_str)
            if isinstance(data, dict) and "action" in data:
                action = data.get("action")
                if action != "Final Answer":
                    return True
    except Exception:
        pass
    return False


def is_csv_text(text: str) -> bool:
    """
    Returns True if the string looks like comma-separated rows.
    """
    if "," not in text:
        return False
    lines = [l.strip() for l in text.strip().split('\n') if l.strip()]
    if len(lines) < 2:
        return False
    # Check if average number of commas is >= 2, and first line has >= 2 commas
    avg_commas = sum(line.count(',') for line in lines) / len(lines)
    return avg_commas >= 2 and lines[0].count(',') >= 2


def csv_to_markdown(csv_str: str) -> str:
    """
    Converts a raw CSV string (with newlines and commas) into a clean Markdown table.
    """
    try:
        import csv
        from io import StringIO
        f = StringIO(csv_str.strip())
        reader = csv.reader(f)
        rows = list(reader)
        
        if len(rows) < 2:
            return csv_str
            
        headers = rows[0]
        markdown_lines = []
        
        # Build headers row
        markdown_lines.append("| " + " | ".join(headers) + " |")
        # Build separator row
        markdown_lines.append("| " + " | ".join(["---"] * len(headers)) + " |")
        
        # Build data rows
        for row in rows[1:]:
            # Pad row if columns don't match headers count
            if len(row) < len(headers):
                row += [""] * (len(headers) - len(row))
            elif len(row) > len(headers):
                row = row[:len(headers)]
            markdown_lines.append("| " + " | ".join(row) + " |")
            
        return "\n".join(markdown_lines)
    except Exception:
        return csv_str


def format_embedded_csv_segments(text: str) -> str:
    """
    Finds contiguous segments of CSV lines in a larger text block and
    converts them into formatted Markdown tables.
    """
    return format_embedded_tabular_segments(text)




# =========================
# PLUGGABLE JAIL FACTORY
# =========================

class BaseJailer:
    def __init__(self, provider_name, cwd, env, allowed_paths):
        self.provider_name = provider_name
        self.cwd = cwd
        self.env = env
        self.allowed_paths = allowed_paths

    def get_popen_kwargs(self, cmd):
        return {
            "cwd": self.cwd,
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
            "encoding": "utf-8",
            "bufsize": 1,
            "env": self.env
        }

class LandlockJailer(BaseJailer):
    def get_popen_kwargs(self, cmd):
        kwargs = super().get_popen_kwargs(cmd)
        if sys.platform.startswith('linux') and landlock:
            def landlock_preexec():
                try:
                    rs = landlock.Ruleset()
                    rs.allow(PROJECT_DIR)
                    if self.allowed_paths:
                        for p in self.allowed_paths:
                            if os.path.exists(p):
                                rs.allow(p)
                    rs.apply()
                except Exception as e:
                    sys.stderr.write(f"[SANDBOX ERROR] Failed to apply Landlock: {e}\n")
                    sys.exit(1)
            kwargs["preexec_fn"] = landlock_preexec
            log(f"🔒 Sandboxing [{self.provider_name}]: Landlock kernel ruleset initialized")
        return kwargs

class NSJailer(BaseJailer):
    def get_popen_kwargs(self, cmd):
        # NSJail wraps the command itself
        nsjail_bin = shutil.which("nsjail")
        if not nsjail_bin:
            return super().get_popen_kwargs(cmd)
        
        # Build NSJail command
        # -Mo: Read-only root
        # -H: Set hostname
        # -chroot: Jail directory
        # -R: Read-only mount
        # -B: Bind mount (read-write)
        new_cmd = [
            nsjail_bin, "-Mo", 
            "--chroot", "/", 
            "-R", "/usr", "-R", "/lib", "-R", "/lib64", "-R", "/bin",
            "-B", self.cwd,
            "--"
        ] + cmd
        
        # Update cmd in-place (hacky but works for this factory)
        cmd[:] = new_cmd
        
        log(f"🏛️ Sandboxing [{self.provider_name}]: NSJail namespace isolation active")
        return super().get_popen_kwargs(cmd)

class WindowsJailer(BaseJailer):
    def get_popen_kwargs(self, cmd):
        kwargs = super().get_popen_kwargs(cmd)
        if sys.platform == 'win32':
            sandbox_script = os.path.join(PROJECT_DIR, "windows_sandbox.py")
            if os.path.exists(sandbox_script):
                new_cmd = ["python", sandbox_script, "--provider", self.provider_name, "--"] + cmd
                cmd[:] = new_cmd
                log(f"🪟 Sandboxing [{self.provider_name}]: Windows Restricted Process Group initialized (win32job + restricted token)")
            else:
                log(f"⚠️ [WARNING] Windows process jailer script not found at {sandbox_script}. Running '{self.provider_name}' without sandboxing.")
        return kwargs

class JailFactory:
    @staticmethod
    def get_jailer(provider_name, cwd, env, allowed_paths):
        is_linux = sys.platform.startswith('linux')
        
        if is_linux:
            if shutil.which("nsjail"):
                return NSJailer(provider_name, cwd, env, allowed_paths)
            if landlock:
                return LandlockJailer(provider_name, cwd, env, allowed_paths)
        
        if sys.platform == 'win32':
            return WindowsJailer(provider_name, cwd, env, allowed_paths)
            
        return BaseJailer(provider_name, cwd, env, allowed_paths)

def launch_sandboxed_node(cmd, cwd, env, allowed_paths=None, provider_name="unknown"):
    """
    Launches a Node process using the Pluggable Jail Factory.
    Acts as a Process Supervisor (Browser-style Controller).
    """
    jailer = JailFactory.get_jailer(provider_name, cwd, env, allowed_paths)
    popen_kwargs = jailer.get_popen_kwargs(cmd)
        
    proc = subprocess.Popen(cmd, **popen_kwargs)
    
    # Simple Process Supervisor thread
    def supervise():
        proc.wait()
        log(f"🚨 SUPERVISOR ALERT: Jailed renderer process '{provider_name}' exited unexpectedly with code {proc.returncode}.")
        log(f"🔄 SUPERVISOR: In a full implementation, the Controller would respawn this isolated renderer now.")
        
    threading.Thread(target=supervise, daemon=True).start()
    return proc


# Initialize log session
with open(LOG_PATH, "a", encoding="utf-8") as f:
    f.write(f"\n--- Secure Bridge Session Start: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")


# Load .env and override variables to ensure we pick up HF_TOKEN
load_dotenv(dotenv_path=DOTENV_PATH, override=True)

if sys.platform == 'win32':
    mcpwn_name = "mcpwn.exe"
else:
    mcpwn_name = "mcpwn"

# Find it in virtual environment bin or system bin
venv_bin = os.path.join(PROJECT_DIR, "venv", "bin" if sys.platform != "win32" else "Scripts")
MCPWN_EXE = os.path.join(venv_bin, mcpwn_name)

if not os.path.exists(MCPWN_EXE):
    # Fallback to scripts directory or sys.executable's folder
    SCRIPTS_DIR = os.path.dirname(sys.executable)
    if os.path.exists(os.path.join(SCRIPTS_DIR, "Scripts" if sys.platform == "win32" else "bin")):
        SCRIPTS_DIR = os.path.join(SCRIPTS_DIR, "Scripts" if sys.platform == "win32" else "bin")
    MCPWN_EXE = os.path.join(SCRIPTS_DIR, mcpwn_name)
    
    if not os.path.exists(MCPWN_EXE):
        # Fallback to checking via shutil.which
        resolved = shutil.which(mcpwn_name)
        if resolved:
            MCPWN_EXE = resolved


# =========================
# TOOL ROLE POLICY
# =========================

TOOL_ROLE_POLICY = {
    "keycloak_revoke_user_sessions": "admin",
    "keycloak_list_user_sessions": "admin",
    "keycloak_list_users": "admin",
    "keycloak_get_user_events": "admin",
    "keycloak_security_report": "admin",
    "keycloak_generate_policy": "admin",
    "keycloak_quarantine_user": "admin",
    "keycloak_run_drills": "admin"
}

ROLE_LEVELS = {
    "user": 1,
    "admin": 2
}

# Use RUNTIME_ROLE consistently everywhere
DEFAULT_ROLE = os.getenv("RUNTIME_ROLE", "user").strip().lower().replace("'", "").replace('"', '')


def normalize_role(role: str) -> str:
    global DEFAULT_ROLE
    try:
        load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    except Exception:
        pass
    raw_env_role = os.getenv("RUNTIME_ROLE", "user").strip().lower().replace("'", "").replace('"', '')
    if raw_env_role in ROLE_LEVELS:
        DEFAULT_ROLE = raw_env_role
    else:
        DEFAULT_ROLE = "user"
        
    if not role:
        return DEFAULT_ROLE
    role = str(role).strip().lower().replace("'", "").replace('"', '')
    return role if role in ROLE_LEVELS else DEFAULT_ROLE


def role_allowed(tool_name, user_role):
    required_role = TOOL_ROLE_POLICY.get(tool_name)

    if not required_role:
        return True, None

    user_role = normalize_role(user_role)
    required_role = normalize_role(required_role)

    if ROLE_LEVELS[user_role] < ROLE_LEVELS[required_role]:
        return False, required_role

    return True, required_role


# =========================
# SPIFFE CONFIG
# =========================

_cached_dynamic_bundle = None

def fetch_dynamic_svid_from_agent(target_spiffe_id: str) -> dict | None:
    """
    Queries the running SPIRE Agent inside Docker container under isolated UID 1001.
    Returns a dict with {"cert_pem": str, "private_key_pem": str, "bundle_pem": str}
    or None if the agent is not reachable or the identity is not issued.
    """
    import subprocess
    import json
    import sys
    try:
        # Execute the spire-agent fetch CLI inside the container under UID 1001 isolation
        cmd = ["docker", "exec", "-u", "1001", "spire-agent", "/opt/spire/bin/spire-agent", "api", "fetch", "x509", "-output", "json"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            return None
        
        data = json.loads(result.stdout)
        svids = data.get("svids", [])
        if svids:
            # SPIRE guarantees exactly 1 SVID is returned under UID 1001 isolation!
            svid = svids[0]
            if svid.get("spiffe_id") == target_spiffe_id:
                # Convert base64 DER to PEM format
                def to_pem(b64_str: str, header: str, footer: str) -> str:
                    body = b64_str.strip()
                    chunks = [body[i:i+64] for i in range(0, len(body), 64)]
                    return f"-----BEGIN {header}-----\n" + "\n".join(chunks) + f"\n-----END {header}-----\n"

                def split_der_certs(der_data: bytes) -> list[bytes]:
                    certs = []
                    offset = 0
                    while offset < len(der_data):
                        if der_data[offset] != 0x30:
                            break
                        length_byte = der_data[offset + 1]
                        if length_byte & 0x80 == 0:
                            length = length_byte
                            header_len = 2
                        else:
                            num_bytes = length_byte & 0x7f
                            length = 0
                            for i in range(num_bytes):
                                length = (length << 8) | der_data[offset + 2 + i]
                            header_len = 2 + num_bytes
                        
                        cert_len = header_len + length
                        certs.append(der_data[offset : offset + cert_len])
                        offset += cert_len
                    return certs

                cert_pem = to_pem(svid.get("x509_svid"), "CERTIFICATE", "CERTIFICATE")
                key_pem = to_pem(svid.get("x509_svid_key"), "PRIVATE KEY", "PRIVATE KEY")
                
                bundle_b64 = svid.get("bundle")
                try:
                    import base64
                    der_bytes = base64.b64decode(bundle_b64)
                    der_certs = split_der_certs(der_bytes)
                    bundle_pems = []
                    for cert_der in der_certs:
                        c_b64 = base64.b64encode(cert_der).decode("utf-8")
                        bundle_pems.append(to_pem(c_b64, "CERTIFICATE", "CERTIFICATE"))
                    bundle_pem = "".join(bundle_pems)
                except Exception:
                    bundle_pem = to_pem(bundle_b64, "CERTIFICATE", "CERTIFICATE")
                
                return {
                    "cert_pem": cert_pem,
                    "private_key_pem": key_pem,
                    "bundle_pem": bundle_pem,
                    "spiffe_id": target_spiffe_id
                }
    except Exception as e:
        print(f"[SPIRE] Failed to fetch dynamic SVID from agent container (UID 1001): {e}", file=sys.stderr)
    return None


def get_dynamic_trust_bundle() -> str | None:
    global _cached_dynamic_bundle
    res = fetch_dynamic_svid_from_agent("spiffe://runtime-shield/bridge")
    if res and res.get("bundle_pem"):
        _cached_dynamic_bundle = res["bundle_pem"]
        return _cached_dynamic_bundle
    return _cached_dynamic_bundle


def get_spiffe_config():
    return {
        "enabled": os.getenv("SPIFFE_ENABLED", "false").lower() == "true",
        "bridge_id": os.getenv("SPIFFE_BRIDGE_ID", "spiffe://runtime-shield/bridge"),
        "server_id": os.getenv("SPIFFE_SERVER_ID", "spiffe://runtime-shield/secure-runtime-shield"),
        "svid_path": os.getenv("SPIFFE_SVID_PATH", ""),
        "bundle_path": os.getenv("SPIFFE_BUNDLE_PATH", "")
    }


def decode_header_cert(cert_val: str) -> str:
    if not cert_val:
        return ""
    import urllib.parse
    decoded = urllib.parse.unquote(cert_val)
    if "-----BEGIN CERTIFICATE-----" in decoded:
        cert_val = decoded
    if "\\n" in cert_val:
        cert_val = cert_val.replace("\\n", "\n").replace("\\r\\n", "\n")
    if "-----BEGIN CERTIFICATE-----" in cert_val and "\n" not in cert_val:
        begin_marker = "-----BEGIN CERTIFICATE-----"
        end_marker = "-----END CERTIFICATE-----"
        try:
            start = cert_val.find(begin_marker) + len(begin_marker)
            end = cert_val.find(end_marker)
            if start != -1 and end != -1:
                body = cert_val[start:end].strip().replace(" ", "")
                chunks = [body[i:i+64] for i in range(0, len(body), 64)]
                cert_val = begin_marker + "\n" + "\n".join(chunks) + "\n" + end_marker + "\n"
        except Exception:
            pass
    cert_val = cert_val.replace("\r\n", "\n").strip()
    if not cert_val.endswith("\n"):
        cert_val += "\n"
    return cert_val


def get_spiffe_headers(incoming_headers: dict = None) -> dict:
    import urllib.parse
    headers = {}
    spiffe_id = None
    cert_pem = None
    
    if incoming_headers:
        spiffe_id = incoming_headers.get("X-SPIFFE-ID") or incoming_headers.get("x-spiffe-id")
        cert_pem = incoming_headers.get("X-SPIFFE-CERT") or incoming_headers.get("x-spiffe-cert")
        if cert_pem:
            cert_pem = decode_header_cert(cert_pem)
            
    is_dev_mode = os.getenv("LOCAL_DEV_MODE", "false").lower() == "true"
    
    # Try dynamic fetch via SPIRE agent CLI inside docker container
    if not cert_pem:
        target_id = spiffe_id or os.getenv("SPIFFE_BRIDGE_ID", "spiffe://runtime-shield/bridge")
        res = fetch_dynamic_svid_from_agent(target_id)
        if res:
            cert_pem = res["cert_pem"]
            spiffe_id = res["spiffe_id"]
            log(f"✅ Dynamic SVID fetched successfully from SPIRE Agent for {spiffe_id} [SPIFFE_SOURCE=workload_api]")
        else:
            if not is_dev_mode:
                log(f"❌ SPIRE Agent attestation failed and LOCAL_DEV_MODE=false. Strict Mode Blocks request!")
                raise PermissionError("Access Denied: SPIRE dynamic attestation failed and strict mode is active.")
            else:
                log("⚠️ Dynamic SVID fetch failed. LOCAL_DEV_MODE=true allows static certificate fallback.")

    if not spiffe_id:
        spiffe_id = os.getenv("SPIFFE_BRIDGE_ID", "spiffe://runtime-shield/bridge")
        
    if not cert_pem:
        _certs_dir = os.path.join(PROJECT_DIR, "spire", "certs")
        bridge_crt_path = os.path.join(_certs_dir, "bridge.crt")
        if os.path.exists(bridge_crt_path):
            try:
                with open(bridge_crt_path, "r", encoding="utf-8") as f:
                    cert_pem = f.read()
            except Exception:
                pass
                
    headers["X-SPIFFE-ID"] = spiffe_id
    if cert_pem:
        headers["X-SPIFFE-CERT"] = urllib.parse.quote(cert_pem)
    return headers


def validate_spiffe_startup(spiffe_cfg):
    if not spiffe_cfg["enabled"]:
        log("SPIFFE integration disabled. Running with current stdio bridge security.")
        return

    log("SPIFFE integration enabled (startup validation mode).")
    log(f"Bridge SPIFFE ID: {spiffe_cfg['bridge_id']}")
    log(f"Expected MCP Server SPIFFE ID: {spiffe_cfg['server_id']}")

    if spiffe_cfg["svid_path"]:
        if not os.path.exists(spiffe_cfg["svid_path"]):
            raise RuntimeError(f"SPIFFE SVID file not found: {spiffe_cfg['svid_path']}")
        log(f"SPIFFE SVID found at: {spiffe_cfg['svid_path']}")
    else:
        log("SPIFFE_SVID_PATH not configured. Continuing without local SVID file validation.")

    if spiffe_cfg["bundle_path"]:
        if not os.path.exists(spiffe_cfg["bundle_path"]):
            raise RuntimeError(f"SPIFFE bundle file not found: {spiffe_cfg['bundle_path']}")
        log(f"SPIFFE trust bundle found at: {spiffe_cfg['bundle_path']}")
    else:
        log("SPIFFE_BUNDLE_PATH not configured. Continuing without bundle file validation.")

    # Run full cryptographic attestation at startup
    attest_result = runtime_attest_svid(spiffe_cfg)
    if attest_result["attested"]:
        log(f"[SPIFFE] Runtime cryptographic attestation SUCCESS: {attest_result['spiffe_id']}")
    else:
        log(f"[SPIFFE] Runtime attestation note: {attest_result.get('reason', 'offline mode')}")


def add_spiffe_dashboard_event(spiffe_cfg):
    dashboard_state.add_event({
        "action": "allow" if spiffe_cfg["enabled"] else "info",
        "tool": "(spiffe)",
        "agent": "bridge",
        "reason": (
            f"SPIFFE startup validation active for {spiffe_cfg['bridge_id']}"
            if spiffe_cfg["enabled"]
            else "SPIFFE not enabled"
        ),
        "severity": "low",
        "stage": "spiffe-startup",
        "timestamp": time.time()
    })


# =========================
# FEATURE 1: RUNTIME CRYPTOGRAPHIC ATTESTATION
# Reads the local X.509 SVID from disk and verifies it against the CA bundle
# at startup — proving this workload holds a valid, CA-signed identity.
# =========================

def load_all_pem_certs(pem_data: str) -> list:
    from cryptography import x509 as _x509
    from cryptography.hazmat.backends import default_backend
    certs = []
    pattern = "-----BEGIN CERTIFICATE-----"
    start = 0
    while True:
        start_idx = pem_data.find(pattern, start)
        if start_idx == -1:
            break
        end_idx = pem_data.find("-----END CERTIFICATE-----", start_idx)
        if end_idx == -1:
            break
        block = pem_data[start_idx : end_idx + len("-----END CERTIFICATE-----")]
        try:
            certs.append(_x509.load_pem_x509_certificate(block.encode(), default_backend()))
        except Exception:
            pass
        start = end_idx + len("-----END CERTIFICATE-----")
    return certs

def verify_signature_against_cas(svid_cert, ca_certs) -> bool:
    from cryptography.hazmat.primitives.asymmetric import padding as _padding
    from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    
    last_err = None
    for ca_cert in ca_certs:
        try:
            ca_public_key = ca_cert.public_key()
            if isinstance(ca_public_key, _rsa.RSAPublicKey):
                ca_public_key.verify(
                    svid_cert.signature,
                    svid_cert.tbs_certificate_bytes,
                    _padding.PKCS1v15(),
                    svid_cert.signature_hash_algorithm,
                )
            elif isinstance(ca_public_key, _ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    svid_cert.signature,
                    svid_cert.tbs_certificate_bytes,
                    _ec.ECDSA(svid_cert.signature_hash_algorithm),
                )
            else:
                ca_public_key.verify(
                    svid_cert.signature,
                    svid_cert.tbs_certificate_bytes,
                    svid_cert.signature_hash_algorithm,
                )
            return True # Successfully verified signature
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise ValueError("No CA certificates available to verify signature.")

def runtime_attest_svid(spiffe_cfg: dict) -> dict:
    """
    Cryptographically attest the bridge's own SVID against the CA trust bundle.
    Returns a dict with keys: attested (bool), spiffe_id (str), reason (str).
    """
    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.backends import default_backend

        svid_path = spiffe_cfg.get("svid_path", "")
        bundle_path = spiffe_cfg.get("bundle_path", "")

        # Resolve default paths relative to spire/certs if not configured
        _certs_dir = os.path.join(PROJECT_DIR, "spire", "certs")
        if not svid_path or not os.path.exists(svid_path):
            svid_path = os.path.join(_certs_dir, "bridge.crt")
        if not bundle_path or not os.path.exists(bundle_path):
            bundle_path = os.path.join(_certs_dir, "ca.crt")

        if not os.path.exists(svid_path) or not os.path.exists(bundle_path):
            return {"attested": False, "spiffe_id": spiffe_cfg.get("bridge_id", ""), "reason": "SVID or CA bundle not found on disk"}

        # Load the SVID
        with open(svid_path, "rb") as f:
            svid_cert = _x509.load_pem_x509_certificate(f.read(), default_backend())

        # Load all CA certificates from the trust bundle
        with open(bundle_path, "r", encoding="utf-8") as f:
            ca_pem_data = f.read()
        ca_certs = load_all_pem_certs(ca_pem_data)
        if not ca_certs:
            return {"attested": False, "spiffe_id": spiffe_cfg.get("bridge_id", ""), "reason": "No valid CA certificates found in startup trust bundle"}

        # Verify the SVID was signed by the CA (cryptographic attestation)
        verify_signature_against_cas(svid_cert, ca_certs)

        # Extract SPIFFE URI from SubjectAlternativeName
        spiffe_id_from_cert = ""
        try:
            san_ext = svid_cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            uris = san_ext.value.get_values_for_type(_x509.UniformResourceIdentifier)
            spiffe_uris = [u for u in uris if u.startswith("spiffe://")]
            if spiffe_uris:
                spiffe_id_from_cert = spiffe_uris[0]
        except Exception:
            spiffe_id_from_cert = spiffe_cfg.get("bridge_id", "")

        # Verify the SPIFFE ID in the cert matches our configured bridge ID
        expected_id = spiffe_cfg.get("bridge_id", "")
        if expected_id and spiffe_id_from_cert and spiffe_id_from_cert != expected_id:
            return {
                "attested": False,
                "spiffe_id": spiffe_id_from_cert,
                "reason": f"SPIFFE ID mismatch: cert has '{spiffe_id_from_cert}', expected '{expected_id}'"
            }

        # Check certificate validity window
        import datetime as _dt
        now = _dt.datetime.utcnow()
        if now < svid_cert.not_valid_before or now > svid_cert.not_valid_after:
            return {"attested": False, "spiffe_id": spiffe_id_from_cert, "reason": "SVID certificate is expired or not yet valid"}

        return {"attested": True, "spiffe_id": spiffe_id_from_cert or expected_id, "reason": "Cryptographic attestation verified"}

    except Exception as e:
        return {"attested": False, "spiffe_id": spiffe_cfg.get("bridge_id", ""), "reason": f"Attestation error: {e}"}


# =========================
# FEATURE 2: mTLS SSL CONTEXT BUILDER
# Builds an SSL context for mutual TLS: the bridge presents its SVID and
# requires clients to present a cert signed by the same CA trust bundle.
# =========================

def build_mtls_ssl_context() -> "ssl.SSLContext | None":
    """
    Build an ssl.SSLContext for mTLS using the bridge's SVID as the server cert
    and the CA bundle as the trust anchor for client verification.
    Returns None if certs are not available (allows HTTP fallback for local dev).
    """
    import ssl
    _certs_dir = os.path.join(PROJECT_DIR, "spire", "certs")
    svid_cert  = os.path.join(_certs_dir, "bridge.crt")
    svid_key   = os.path.join(_certs_dir, "bridge.key")
    ca_bundle  = os.path.join(_certs_dir, "ca.crt")

    if not all(os.path.exists(p) for p in [svid_cert, svid_key, ca_bundle]):
        log("[mTLS] SVID or CA bundle not found. mTLS disabled — running HTTP for local dev.")
        return None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.verify_mode = ssl.CERT_REQUIRED          # Require client cert
        ctx.load_cert_chain(certfile=svid_cert, keyfile=svid_key)
        ctx.load_verify_locations(cafile=ca_bundle)  # Trust only our CA
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        log("[mTLS] SSL context ready: bridge SVID loaded, client cert verification enforced.")
        return ctx
    except Exception as e:
        log(f"[mTLS] SSL context build failed: {e}. Falling back to HTTP.")
        return None


# =========================
# FEATURE 3: STRICT SVID CRYPTOGRAPHIC VERIFICATION
# At request time, verify the X.509 SVID presented in the X-SPIFFE-ID header
# by checking that the cert (if attached) is signed by the trusted CA bundle,
# not expired, and carries the claimed SPIFFE URI in its SAN.
# =========================

def verify_svid_cryptographically(spiffe_id: str, cert_pem: str | None = None) -> dict:
    """
    Strict SVID verification:
      1. If a PEM cert is provided, verify it against the CA bundle.
      2. Extract the SPIFFE URI SAN from the cert.
      3. Confirm it matches the claimed spiffe_id.
      4. Check it's not expired.

    Returns dict: {valid: bool, reason: str}
    Falls back to allowlist-only check when no cert is provided (offline mode).
    """
    if not cert_pem:
        fallback_allowed = os.getenv("SPIFFE_HEADER_ONLY_FALLBACK", "false").lower() == "true"
        if fallback_allowed:
            if spiffe_allowed(spiffe_id):
                return {"valid": True, "reason": f"SVID verified via header-only fallback: {spiffe_id}"}
            else:
                return {"valid": False, "reason": f"Header-only fallback rejected: '{spiffe_id}' is not in allowlist"}
        return {"valid": False, "reason": "Security Violation: SPIFFE SVID certificate is required. Header-only fallback is disabled."}

    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.backends import default_backend

        # Try to retrieve the latest CA trust bundle dynamically from the SPIRE Agent first
        dynamic_bundle_pem = get_dynamic_trust_bundle()
        if dynamic_bundle_pem:
            ca_certs = load_all_pem_certs(dynamic_bundle_pem)
            log("🔒 [SPIFFE] Live CA Trust Bundle resolved dynamically from SPIRE Agent [SPIFFE_SOURCE=workload_api]")
        else:
            _certs_dir = os.path.join(PROJECT_DIR, "spire", "certs")
            ca_bundle = os.path.join(_certs_dir, "ca.crt")
            if not os.path.exists(ca_bundle):
                return {"valid": False, "reason": "Security Violation: SPIFFE CA bundle is missing or unavailable on disk. Cryptographic attestation required."}

            with open(ca_bundle, "r", encoding="utf-8") as f:
                ca_pem_data = f.read()
            ca_certs = load_all_pem_certs(ca_pem_data)
            log("⚠️ [SPIFFE] Falling back to static CA trust bundle from disk [SPIFFE_SOURCE=local_svid]")

        if not ca_certs:
            return {"valid": False, "reason": "Security Violation: No valid CA certificates found in trust bundle."}

        svid_cert = _x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Step 1 — Verify signature against CA
        verify_signature_against_cas(svid_cert, ca_certs)

        # Step 2 — Extract SPIFFE URI SAN from cert
        cert_spiffe_id = ""
        try:
            san = svid_cert.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
            uris = san.value.get_values_for_type(_x509.UniformResourceIdentifier)
            spiffe_uris = [u for u in uris if u.startswith("spiffe://")]
            cert_spiffe_id = spiffe_uris[0] if spiffe_uris else ""
        except Exception:
            pass

        # Step 3 — SAN must match the claimed header value
        if cert_spiffe_id and cert_spiffe_id != spiffe_id:
            return {"valid": False, "reason": f"SVID SAN '{cert_spiffe_id}' does not match claimed '{spiffe_id}'"}

        # Step 4 — Validity window
        import datetime as _dt
        now = _dt.datetime.utcnow()
        if now < svid_cert.not_valid_before or now > svid_cert.not_valid_after:
            return {"valid": False, "reason": "SVID certificate is expired or not yet valid"}

        # Step 5 — Allowlist check on the cert's SPIFFE ID
        verified_id = cert_spiffe_id or spiffe_id
        if not spiffe_allowed(verified_id):
            return {"valid": False, "reason": f"SVID '{verified_id}' not in allowlist"}

        return {"valid": True, "reason": f"SVID cryptographically verified: {verified_id}"}

    except Exception as e:
        # Crypto verification failed — hard reject (not a fallback)
        return {"valid": False, "reason": f"SVID cryptographic verification failed: {e}"}


# =========================
# SPIFFE RUNTIME POLICY
# =========================

def get_allowed_spiffe_ids():
    """Parse allowed SPIFFE IDs from environment variable."""
    allowed_ids_str = os.getenv(
        "ALLOWED_SPIFFE_IDS",
        "spiffe://runtime-shield/agent,spiffe://runtime-shield/dashboard,spiffe://runtime-shield/bridge,spiffe://runtime-shield/secure-runtime-shield"
    ).strip()
    
    # Handle both comma-separated and JSON array formats
    if allowed_ids_str.startswith("["):
        try:
            import json
            return set(json.loads(allowed_ids_str))
        except Exception:
            pass
    
    # Comma-separated format
    return set(id_.strip() for id_ in allowed_ids_str.split(",") if id_.strip())


ALLOWED_SPIFFE_IDS = get_allowed_spiffe_ids()


def spiffe_allowed(spiffe_id: str) -> bool:
    if not spiffe_id:
        return False
    
    # Check exact match first
    if spiffe_id in ALLOWED_SPIFFE_IDS:
        return True
    
    # Support prefix matching for dynamic SVIDs (e.g. spiffe://runtime-shield/spire/agent/x509pop/*)
    for allowed_pattern in ALLOWED_SPIFFE_IDS:
        if "*" in allowed_pattern:
            regex_pattern = re.escape(allowed_pattern).replace(r"\*", ".*")
            if re.fullmatch(regex_pattern, spiffe_id):
                return True
        elif spiffe_id.startswith(allowed_pattern):
            return True
            
    return False


# =========================
# KEYCLOAK IDENTITY HARDENING
# =========================

class JWTVerifier:
    def __init__(self, jwks_url):
        self.jwks_url = jwks_url
        # PyJWKClient handles fetching and caching the keys dynamically from the JWKS endpoint
        self.jwk_client = jwt.PyJWKClient(self.jwks_url)

    def verify(self, token):
        if not token:
            return None
        try:
            # 1. Dev Mode Quick Mock Login Bypass (when LOCAL_DEV_MODE=true and using HS256 mock tokens)
            is_dev = os.getenv("LOCAL_DEV_MODE", "false").lower() == "true"
            if is_dev:
                try:
                    unverified_header = jwt.get_unverified_header(token)
                    alg = unverified_header.get("alg")
                    if alg == "HS256":
                        decoded = jwt.decode(
                            token,
                            "secret",
                            algorithms=["HS256"],
                            options={"verify_exp": False, "verify_aud": False}
                        )
                        log(f"✅ Mock JWT Signature and Claims Verified (HS256) for user: {decoded.get('preferred_username', 'unknown')}")
                        return decoded
                except Exception as ex:
                    log(f"⚠️ Failed unverified mock check or HS256 decode: {ex}")

            # 2. Strict Keycloak JWKS-based JWT validation
            signing_key = self.jwk_client.get_signing_key_from_jwt(token)
            
            kc_url = os.getenv("KEYCLOAK_URL", "http://127.0.0.1:8080")
            kc_realm = os.getenv("KEYCLOAK_REALM", "master")
            client_id = os.getenv("KEYCLOAK_CLIENT_ID", "admin-cli")
            expected_iss = f"{kc_url}/realms/{kc_realm}"

            # PyJWT automatically verifies signature, expiration (exp), audience (aud), and issuer (iss)
            decoded = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=[client_id, "account"],  # Standard Keycloak clients might have aud including account or admin-cli
                issuer=expected_iss,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True
                }
            )
            log(f"✅ Keycloak JWT Signature and Claims Verified via JWKS for user: {decoded.get('preferred_username', 'unknown')}")
            return decoded
        except Exception as e:
            log(f"❌ JWT Verification Failed: {e}")
            return None

class JITTokenManager:
    def __init__(self, keycloak_url, client_id, client_secret):
        self.url = keycloak_url
        self.client_id = client_id
        self.client_secret = client_secret

    def exchange_token(self, user_token, required_scope, target_provider):
        """
        Exchanges a broad user token for a short-lived, downscoped JIT token.
        Implements RFC 8693 (Token Exchange).
        """
        # If in LOCAL_DEV_MODE and using mock token, we can mock JIT token exchange!
        is_dev = os.getenv("LOCAL_DEV_MODE", "false").lower() == "true"
        if is_dev:
            try:
                unverified = jwt.decode(user_token, options={"verify_signature": False})
                # Check if it's a mock token generated by login.py
                if unverified.get("sub", "").startswith("admin") or unverified.get("sub", "").startswith("user") or unverified.get("sub", "").startswith("tester") or unverified.get("sub", "").startswith("intruder"):
                    # Generate a mock short-lived JIT token with downscoped scope!
                    jit_claims = unverified.copy()
                    jit_claims["scope"] = required_scope
                    jit_claims["exp"] = time.time() + 60
                    # Sign using symmetric HS256 key
                    mock_jit = jwt.encode(jit_claims, "secret", algorithm="HS256")
                    log(f"🎟️ JIT Mock Token Issued Successfully for Scope '{required_scope}'")
                    return mock_jit
            except Exception as ex:
                log(f"⚠️ Failed HS256 JIT mock exchange check: {ex}")

        log(f"🔄 JIT: Exchanging user token for downscoped '{required_scope}' token (Audience: {self.client_id})")
        
        # 1. Standard RFC 8693 request body parameters
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "scope": required_scope,
            "audience": self.client_id
        }
        
        # 2. Authenticate the client and POST parameters to Keycloak token URL
        resp = requests.post(
            self.url, 
            data=data, 
            auth=(self.client_id, self.client_secret),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=5
        )
        
        # 3. Explicit error handling (strictly fail-closed on verification/exchange failure)
        if resp.status_code != 200:
            log(f"❌ Keycloak JIT Token Exchange failed (HTTP {resp.status_code}): {resp.text}")
            resp.raise_for_status() # Raises HTTPError to abort execution safely
            
        token_data = resp.json()
        jit_token = token_data.get("access_token")
        
        if not jit_token:
            raise KeyError("Keycloak did not return an access_token in the exchange response.")
            
        ttl = token_data.get("expires_in", 60)
        log(f"🎟️ JIT Token Issued Successfully: {jit_token[:15]}... (TTL: {ttl}s)")
        
        return jit_token

# Global Identity Managers
kc_url = os.getenv("KEYCLOAK_URL")
kc_realm = os.getenv("KEYCLOAK_REALM")
client_id = os.getenv("KEYCLOAK_CLIENT_ID")
client_secret = os.getenv("KEYCLOAK_CLIENT_SECRET")

if not all([kc_url, kc_realm, client_id, client_secret]):
    error_msg = (
        "\n❌ Fatal Startup Error: Keycloak configuration is incomplete.\n"
        "Please check your .env file and ensure the following variables are defined:\n"
        "  - KEYCLOAK_URL\n"
        "  - KEYCLOAK_REALM\n"
        "  - KEYCLOAK_CLIENT_ID\n"
        "  - KEYCLOAK_CLIENT_SECRET\n"
    )
    # Output to stderr and terminate startup
    sys.stderr.write(error_msg)
    sys.exit(1)

jwks_url = f"{kc_url}/realms/{kc_realm}/protocol/openid-connect/certs"
token_url = f"{kc_url}/realms/{kc_realm}/protocol/openid-connect/token"

verifier = JWTVerifier(os.getenv("KEYCLOAK_JWKS_URL", jwks_url))
jit_manager = JITTokenManager(
    os.getenv("KEYCLOAK_TOKEN_URL", token_url),
    client_id,
    client_secret
)


def get_token_claims(token):
    """Extract claims from verified token."""
    if not token:
        return {}
    decoded = verifier.verify(token)
    if not decoded:
        raise HTTPException(status_code=401, detail="Invalid or expired Keycloak authentication token")
    return decoded

def get_token_scopes(token):
    """Extract scopes from verified token."""
    if not token:
        return []
    decoded = verifier.verify(token)
    if not decoded:
        raise HTTPException(status_code=401, detail="Invalid or expired Keycloak authentication token")
    
    scopes = decoded.get("scope", "")
    if isinstance(scopes, str):
        scopes = scopes.split(" ")
    
    roles = decoded.get("realm_access", {}).get("roles", []) or decoded.get("roles", [])
    return list(set(scopes + roles))

def is_scope_allowed(required_scope, token_scopes):
    if not required_scope:
        return True
    return required_scope in token_scopes

def resolve_userid_by_sub(sub: str) -> str:
    """Look up userId in the sqlite database using the keycloak_sub claim."""
    if not sub:
        return "1"  # Default fallback
    db_path = os.path.join(PROJECT_DIR, "damn-vulnerable-llm-agent", "transactions.db")
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT userId FROM Users WHERE keycloak_sub = ?", (sub,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return str(row[0])
    except Exception as e:
        log(f"⚠️ Error resolving userId by sub '{sub}': {e}")
    return "1"  # Default fallback



# ==========================================
# SECURE OPENAI-COMPATIBLE PROXY ENDPOINT
# ==========================================

async def handle_mock_llm_response(body: dict, user_id: str, user_role: str, user_sub: str = ""):
    messages = body.get("messages", [])
    
    # Settle Turn boundaries to prevent state leakage/re-entry from previous turns in conversation history
    last_final_answer_idx = -1
    for i, msg in enumerate(messages):
        role = msg.get("role")
        content = msg.get("content", "") or ""
        if role == "assistant" and ("Final Answer" in content or '"action": "Final Answer"' in content):
            last_final_answer_idx = i

    current_turn_messages = messages[last_final_answer_idx + 1:] if last_final_answer_idx != -1 else messages
    
    get_user_called = False
    get_trans_called = False
    last_user_prompt = ""
    
    for msg in current_turn_messages:
        role = msg.get("role")
        content = msg.get("content", "") or ""
        if role == "user":
            last_user_prompt = content
            
        if msg.get("name") == "GetCurrentUser" or "GetCurrentUser" in content or "GetCurrentUser" in last_user_prompt:
            get_user_called = True
        elif msg.get("name") == "GetUserTransactions" or "GetUserTransactions" in content or "GetUserTransactions" in last_user_prompt:
            get_trans_called = True

        if "GetCurrentUser" in content:
            get_user_called = True
        if "GetUserTransactions" in content:
            get_trans_called = True
            
        tool_calls = msg.get("tool_calls")
        if tool_calls:
            for tc in tool_calls:
                func_name = tc.get("function", {}).get("name", "")
                if func_name == "GetCurrentUser":
                    get_user_called = True
                elif func_name == "GetUserTransactions":
                    get_trans_called = True

    # Robust detection over current turn message sequence
    for msg in current_turn_messages:
        c = msg.get("content", "") or ""
        if "GetCurrentUser" in c:
            get_user_called = True
        if "GetUserTransactions" in c:
            get_trans_called = True
            get_user_called = True
        if msg.get("name") == "GetCurrentUser":
            get_user_called = True
        if msg.get("name") == "GetUserTransactions":
            get_trans_called = True
            get_user_called = True

    last_prompt_lower = last_user_prompt.lower()
    
    # Extract the raw user query by isolating it from prompt templates / tool response blocks
    raw_user_query = last_user_prompt
    if "USER'S INPUT" in last_user_prompt:
        parts = last_user_prompt.split("USER'S INPUT")
        raw_user_query = parts[-1]
    
    # Strip common markdown template dividers, colons, hyphens, and whitespace
    raw_user_query = raw_user_query.strip().strip("-").strip(":").strip("-").strip()
    raw_query_lower = raw_user_query.lower()
    
    # Extract the original user query from the message history to preserve context across ReAct turns
    original_query = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            c = msg.get("content", "") or ""
            # Skip intermediate tool responses to find the original prompt that started the current turn
            if "TOOL RESPONSE:" in c or "TOOL_RESPONSE" in c:
                continue
            if "USER'S INPUT" in c:
                parts = c.split("USER'S INPUT")
                original_query = parts[-1].strip().strip("-").strip(":").strip("-").strip()
                break
            elif "TOOLS" not in c and "RESPONSE FORMAT" not in c:
                original_query = c.strip()
                break
    if not original_query:
        original_query = raw_user_query
    
    is_greeting = any(w in raw_query_lower for w in ["hi", "hello", "hey", "hola"]) and len(raw_query_lower) < 15

    model_name = body.get("model", "gpt-4")

    async def yield_response_chunks(content_text: str):
        # Scan and redact outbound PII from the mock LLM response before streaming it
        orig_content = content_text
        
        # Check if the content is a structured ReAct tool call JSON block (Option 1)
        # We only want to redact the final answer shown to the user (Option 2)
        # to avoid mutilating tool arguments (like user IDs) which are already validated and redacted at the tool boundary.
        is_tool_call = False
        if "action" in content_text and '"action": "Final Answer"' not in content_text:
            is_tool_call = True

        if user_role == "admin" or is_tool_call:
            redacted_content = content_text
        else:
            redacted_content = redact_pii_with_presidio(content_text)
            
        if redacted_content != orig_content:
            log("✂️ FIREWALL REDACTED sensitive data (Mock Outbound Fallback)")
            dashboard_state.add_event({
                "action": "redact",
                "tool": "chat_completion",
                "agent": "mock-llm-agent",
                "reason": "Outbound PII Redacted from mock LLM response",
                "severity": "medium",
                "stage": "pii-redaction-outbound",
                "timestamp": time.time()
            })
            content_text = redacted_content

        chunk_id = f"chatcmpl-{int(time.time())}"
        
        delta_role = {"role": "assistant", "content": ""}
        yield f"data: {json.dumps({'id': chunk_id, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model_name, 'choices': [{'index': 0, 'delta': delta_role, 'finish_reason': None}]})}\n\n"
        await asyncio.sleep(0.005)
        
        chunk_size = 8
        for i in range(0, len(content_text), chunk_size):
            chunk = content_text[i:i+chunk_size]
            delta_content = {"content": chunk}
            yield f"data: {json.dumps({'id': chunk_id, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model_name, 'choices': [{'index': 0, 'delta': delta_content, 'finish_reason': None}]})}\n\n"
            await asyncio.sleep(0.005)
            
        yield f"data: {json.dumps({'id': chunk_id, 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': model_name, 'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})}\n\n"
        yield "data: [DONE]\n\n"

    # Helper to wrap action in standard ReAct JSON block expected by ConversationalChatAgent
    def format_action(action_name: str, action_input: dict):
        action_input_str = json.dumps(action_input)
        return f"```json\n{{\n  \"action\": \"{action_name}\",\n  \"action_input\": {action_input_str}\n}}\n```"

    def format_final_answer(answer_text: str):
        escaped_text = answer_text.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        return f"```json\n{{\n  \"action\": \"Final Answer\",\n  \"action_input\": \"{escaped_text}\"\n}}\n```"

    has_redacted_pii = any(token in last_user_prompt for token in ["[REDACTED-EMAIL]", "[REDACTED-SSN]", "[REDACTED-PHONE]", "[REDACTED-CC]"])
    if has_redacted_pii:
        text = f"🛡️ **Privacy Shield Active**: Sensitive PII was detected and redacted in your prompt before it was processed by the assistant reasoning loop. Here is the sanitized content received by the LLM core:\n\n> \"{last_user_prompt}\""
        formatted = format_final_answer(text)
        return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    if is_greeting:
        text = "Hello! I am your helpful financial assistant. I can help you retrieve your recent bank transactions. Try asking me: 'What are my recent transactions?'"
        formatted = format_final_answer(text)
        return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    target_user_id = resolve_userid_by_sub(user_sub)
    original_query_lower = original_query.lower()
    if any(w in original_query_lower for w in ["transaction", "show", "get", "list"]):
        has_hijacking_attempt = re.search(r'\b(user\s*id|user_?id|user)\b\s*(=?\s*\b\d+\b)', original_query_lower)
        hijacked_id = None
        if has_hijacking_attempt:
            val = has_hijacking_attempt.group(2).replace("=", "").strip()
            if val != target_user_id:
                hijacked_id = val
                target_user_id = val

        if hijacked_id and user_role != "admin":
            reason = f"Security Violation: Refusing to fetch transactions for userId '{hijacked_id}'. I will only fetch transactions for the authenticated user ID returned by the GetCurrentUser tool."
            dashboard_state.add_event({
                "action": "deny",
                "tool": "chat_completion",
                "agent": "mock-llm-agent",
                "reason": "RBAC Violation: Agent safely neutralized prompt injection (userId hijacking defense active)",
                "severity": "critical",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": f"Blocked by RBAC Shield: {reason}",
                        "type": "rbac_violation",
                        "code": "unauthorized_access"
                    }
                }
            )

    list_dir_called = False
    list_dir_output = None
    
    read_file_called = False
    read_file_output = None
    
    get_user_called = False
    get_trans_called = False

    keycloak_list_called = False
    keycloak_list_output = None

    keycloak_revoke_called = False
    keycloak_revoke_output = None

    keycloak_run_drills_called = False
    keycloak_run_drills_output = None

    # 1. Direct tool/role parsing from JSON-RPC or tool results in messages
    for msg in current_turn_messages:
        role = msg.get("role")
        name = msg.get("name") or ""
        content = msg.get("content", "") or ""
        
        if name == "ListDirectory" or (role == "tool" and name == "ListDirectory"):
            list_dir_called = True
            list_dir_output = content
        elif name == "ReadFile" or (role == "tool" and name == "ReadFile"):
            read_file_called = True
            read_file_output = content
        elif name == "GetCurrentUser" or (role == "tool" and name == "GetCurrentUser"):
            get_user_called = True
        elif name == "GetUserTransactions" or (role == "tool" and name == "GetUserTransactions"):
            get_trans_called = True
        elif name == "KeycloakListUsers" or (role == "tool" and name == "KeycloakListUsers"):
            keycloak_list_called = True
            keycloak_list_output = content
        elif name == "KeycloakRevokeUserSessions" or (role == "tool" and name == "KeycloakRevokeUserSessions"):
            keycloak_revoke_called = True
            keycloak_revoke_output = content
        elif name == "KeycloakRunDrills" or (role == "tool" and name == "KeycloakRunDrills"):
            keycloak_run_drills_called = True
            keycloak_run_drills_output = content

    # 2. Assistant-User pair ReAct parsing fallback (robust against formatting shifts)
    for i, msg in enumerate(current_turn_messages):
        role = msg.get("role")
        content = msg.get("content", "") or ""
        
        if role == "assistant":
            if '"action": "ListDirectory"' in content or '"action": "list_directory"' in content:
                # The next user message (if any) contains the tool output
                if i + 1 < len(current_turn_messages) and current_turn_messages[i+1].get("role") == "user":
                    user_content = current_turn_messages[i+1].get("content", "") or ""
                    if "TOOL RESPONSE:" in user_content:
                        list_dir_called = True
                        parts = user_content.split("TOOL RESPONSE:")
                        if len(parts) > 1:
                            subparts = parts[1].split("USER'S INPUT")
                            list_dir_output = subparts[0].strip().lstrip("-").strip()
            elif '"action": "ReadFile"' in content or '"action": "read_file"' in content:
                if i + 1 < len(current_turn_messages) and current_turn_messages[i+1].get("role") == "user":
                    user_content = current_turn_messages[i+1].get("content", "") or ""
                    if "TOOL RESPONSE:" in user_content:
                        read_file_called = True
                        parts = user_content.split("TOOL RESPONSE:")
                        if len(parts) > 1:
                            subparts = parts[1].split("USER'S INPUT")
                            read_file_output = subparts[0].strip().lstrip("-").strip()
            elif '"action": "GetCurrentUser"' in content:
                get_user_called = True
            elif '"action": "GetUserTransactions"' in content:
                get_trans_called = True
            elif '"action": "KeycloakListUsers"' in content:
                keycloak_list_called = True
            elif '"action": "KeycloakRevokeUserSessions"' in content:
                keycloak_revoke_called = True
            elif '"action": "KeycloakRunDrills"' in content:
                keycloak_run_drills_called = True

    # 3. Text fallbacks for legacy/general formatted inputs
    for msg in current_turn_messages:
        content = msg.get("content", "") or ""
        if "TOOL RESPONSE:" in content:
            if "KeycloakListUsers" in content:
                parts = content.split("TOOL RESPONSE:")
                if len(parts) > 1:
                    keycloak_list_called = True
                    subparts = parts[1].split("USER'S INPUT")
                    keycloak_list_output = subparts[0].strip().lstrip("-").strip()
            elif "KeycloakRevokeUserSessions" in content:
                parts = content.split("TOOL RESPONSE:")
                if len(parts) > 1:
                    keycloak_revoke_called = True
                    subparts = parts[1].split("USER'S INPUT")
                    keycloak_revoke_output = subparts[0].strip().lstrip("-").strip()
            elif "KeycloakRunDrills" in content:
                parts = content.split("TOOL RESPONSE:")
                if len(parts) > 1:
                    keycloak_run_drills_called = True
                    subparts = parts[1].split("USER'S INPUT")
                    keycloak_run_drills_output = subparts[0].strip().lstrip("-").strip()
            elif "ListDirectory" in content or "list_directory" in content:
                parts = content.split("TOOL RESPONSE:")
                if len(parts) > 1:
                    list_dir_called = True
                    subparts = parts[1].split("USER'S INPUT")
                    list_dir_output = subparts[0].strip().lstrip("-").strip()
            elif "ReadFile" in content or "read_file" in content or "secure-experiment-zone" in content or "sandbox" in content:
                match = re.search(r"TOOL RESPONSE:\s*\n-+\s*\n(.*?)(\n\nUSER'S INPUT|\Z)", content, re.DOTALL)
                if match:
                    read_file_called = True
                    read_file_output = match.group(1).strip()
                else:
                    parts = content.split("TOOL RESPONSE:")
                    if len(parts) > 1:
                        read_file_called = True
                        subparts = parts[1].split("USER'S INPUT")
                        read_file_output = subparts[0].strip().lstrip("-").strip()

    # 4. Semantic / Hybrid query flags (with state preservation of executed tools)
    global semantic_parser_instance
    semantic_result = {"intent": "None", "target": "", "confidence": 0.0, "parser_type": "local-lexical"}
    if semantic_parser_instance:
        try:
            semantic_result = await semantic_parser_instance.parse(original_query)
        except Exception as e:
            log(f"⚠️ Semantic parser execution failed: {e}")
            
    intent = semantic_result.get("intent", "None")
    target = semantic_result.get("target", "")
    confidence = semantic_result.get("confidence", 0.0)
    parser_type = semantic_result.get("parser_type", "local-lexical")

    log(f"🧠 [SEMANTIC INTENT LAYER] Query: '{original_query}' -> intent={intent}, target={target}, confidence={confidence:.2f} ({parser_type})")

    CONFIDENCE_THRESHOLD = 0.75
    
    is_list_query = list_dir_called
    is_file_query = read_file_called
    is_banking_query = get_user_called or get_trans_called
    is_keycloak_list_query = keycloak_list_called
    is_keycloak_revoke_query = keycloak_revoke_called
    is_keycloak_run_drills_query = keycloak_run_drills_called
    is_greeting = False
    
    # 1. Deterministic intent parsing (always computed first for Zero-Trust auditing)
    det_list = (any(w in raw_query_lower for w in ["list", "dir", "folder"]) and any(w in raw_query_lower for w in ["file", "sandbox", "experiment", "zone"]))
    det_file = any(w in raw_query_lower for w in ["file", "read", "sandbox", "readme", "txt", "csv", "experiment"])
    det_bank = any(w in raw_query_lower for w in ["transaction", "money", "salary", "balance", "bank"])
    det_greet = any(w in raw_query_lower for w in ["hi", "hello", "hey", "hola"]) and len(raw_query_lower) < 15
    
    det_fs = (det_list or det_file)
    
    # Mixed intent: query contains BOTH filesystem actions and banking/identity keywords
    has_mixed_conflict = (det_fs and det_bank)
    
    # Disagreement: semantic intent domain disagrees with deterministic domain keywords
    semantic_fs = intent in ("ReadFile", "ListDirectory")
    semantic_bank = intent in ("GetUserTransactions", "GetCurrentUser")
    has_disagreement = (semantic_fs and det_bank) or (semantic_bank and det_fs)
    
    # 2. Zero-Trust safety verification: Block ambiguous mixed-intent queries or semantic/deterministic disagreements
    if has_mixed_conflict or has_disagreement:
        reason = f"Security Block: Ambiguous routing detected. Semantic parse ({intent}, conf {confidence:.2f}) conflicts with deterministic match. Blocked to prevent misrouting privileged actions."
        log(f"🚫 ZERO-TRUST BLOCK: {reason}")
        dashboard_state.add_event({
            "action": "deny",
            "tool": "chat_completion",
            "agent": "semantic-fallback-shield",
            "reason": reason,
            "severity": "high",
            "stage": "semantic-intent-routing",
            "timestamp": time.time()
        })
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "message": f"Blocked by Zero-Trust Routing: {reason}",
                    "type": "routing_violation",
                    "code": "ambiguous_routing"
                }
            }
        )

    # 3. Confidence routing
    if confidence >= CONFIDENCE_THRESHOLD:
        log(f"✅ [SEMANTIC INTENT APPROVED] Route intent '{intent}' (Confidence: {confidence:.2f})")
        dashboard_state.add_event({
            "action": "allow",
            "tool": "semantic_router",
            "agent": f"user-{user_id}",
            "reason": f"Semantic Routing Approved: intent='{intent}' | target='{target}' (Confidence: {confidence:.2f}, Type: {parser_type})",
            "severity": "info",
            "stage": "semantic-intent-routing",
            "timestamp": time.time()
        })
        
        if intent == "ListDirectory":
            is_list_query = True
        elif intent == "ReadFile":
            is_file_query = True
        elif intent == "GetUserTransactions":
            is_banking_query = True
        elif intent == "GetCurrentUser":
            is_banking_query = True
            get_user_called = False # Force call GetCurrentUser tool first
        elif intent == "KeycloakListUsers":
            is_keycloak_list_query = True
        elif intent == "KeycloakRevokeUserSessions":
            is_keycloak_revoke_query = True
        elif intent == "KeycloakRunDrills":
            is_keycloak_run_drills_query = True
        elif intent == "Greet":
            is_greeting = True
    else:
        # Safe single-intent deterministic routing fallback
        log(f"⚠️ [SEMANTIC INTENT AMBIGUOUS] Confidence {confidence:.2f} below threshold {CONFIDENCE_THRESHOLD}. Falling back to deterministic rules...")
        
        if det_list:
            is_list_query = True
        elif det_file:
            is_file_query = True
        elif det_bank:
            is_banking_query = True
        elif any(w in raw_query_lower for w in ["keycloak", "users"]) and any(w in raw_query_lower for w in ["list", "show"]):
            is_keycloak_list_query = True
        elif any(w in raw_query_lower for w in ["revoke", "session", "logout"]):
            is_keycloak_revoke_query = True
        elif any(w in raw_query_lower for w in ["drill", "verification", "compliance", "audit"]) or "verify security" in raw_query_lower:
            is_keycloak_run_drills_query = True
        elif det_greet:
            is_greeting = True

    # Print debugging context
    log(f"[DEBUG QUERY] last_prompt_lower={repr(last_prompt_lower[:120])}...")
    log(f"[DEBUG QUERY] raw_query_lower={repr(raw_query_lower)}...")
    log(f"[DEBUG QUERY] is_list_query={is_list_query} (called={list_dir_called}), is_file_query={is_file_query} (called={read_file_called}), is_keycloak_list_query={is_keycloak_list_query} (called={keycloak_list_called}), is_keycloak_revoke_query={is_keycloak_revoke_query} (called={keycloak_revoke_called})")
    
    if is_list_query:
        if not list_dir_called:
            # Use semantically extracted target path if valid, otherwise fallback
            target_path = target if target else "secure-experiment-zone"
            dashboard_state.add_event({
                "action": "allow",
                "tool": "ListDirectory",
                "agent": "mock-llm-agent",
                "reason": f"Agent requested directory contents for {target_path}",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            formatted = format_action("ListDirectory", target_path)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")
        else:
            tool_output = list_dir_output or ""
            if "Security Violation:" in tool_output or "Access Denied" in tool_output:
                text = f"Blocked by Security Gateway: {tool_output}"
            else:
                # Format files dynamically as a beautiful markdown bulleted list matching Claude/premium UIs
                files = [f.strip() for f in tool_output.strip().split('\n') if f.strip()]
                formatted_list = ""
                for f in files:
                    if "." not in f:
                        formatted_list += f"- `{f}` (directory)\n"
                    else:
                        formatted_list += f"- `{f}`\n"
                text = f"Here are the files in `secure-experiment-zone`:\n\n{formatted_list}"
            formatted = format_final_answer(text)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    if is_file_query:
        if not read_file_called:
            # Use semantically extracted target path if valid, otherwise fallback
            target_path = target if target else "secure-experiment-zone/test_sandbox.txt"
            
            # Resolve target if it's just a file name (prefix with secure-experiment-zone/ if not already specified)
            # Exception: if the user is authenticated as admin, do NOT force secure-experiment-zone/ prefixing.
            is_path_like = ("/" in target_path or "\\" in target_path)
            if user_role != "admin" and target_path and not is_path_like and target_path not in ("README.md", "bridge.py"):
                target_path = f"secure-experiment-zone/{target_path}"
                
            dashboard_state.add_event({
                "action": "allow",
                "tool": "ReadFile",
                "agent": "mock-llm-agent",
                "reason": f"Agent requested file contents for path: {target_path}",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            # Format action_input as string directly since LangChain tool expects string input
            formatted = format_action("ReadFile", target_path)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")
        else:
            tool_output = read_file_output or ""
            if "Security Violation:" in tool_output or "Access Denied" in tool_output:
                text = f"Blocked by Security Gateway: {tool_output}"
            else:
                text = f"Here is the content of the file:\n\n```\n{tool_output}\n```"
            formatted = format_final_answer(text)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    is_banking_query = is_banking_query or get_user_called or get_trans_called

    if is_banking_query:
        if not get_user_called:
            dashboard_state.add_event({
                "action": "allow",
                "tool": "GetCurrentUser",
                "agent": "mock-llm-agent",
                "reason": "Agent requested current user identity verification",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            formatted = format_action("GetCurrentUser", "")
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")
            
        elif get_user_called and not get_trans_called:
            dashboard_state.add_event({
                "action": "allow",
                "tool": "GetUserTransactions",
                "agent": "mock-llm-agent",
                "reason": f"Agent requesting bank transactions for authenticated userId: {target_user_id}",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            formatted = format_action("GetUserTransactions", {"userId": target_user_id})
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")
            
        elif get_trans_called:
            # Try to find the actual tool output in the message history to make the mock LLM dynamically display actual database results!
            tool_output = None
            for msg in current_turn_messages:
                if msg.get("name") == "GetUserTransactions" or (msg.get("role") == "tool" and msg.get("name") == "GetUserTransactions"):
                    c = msg.get("content", "")
                    if c and "[" in c and "]" in c:
                        tool_output = c
                        break
            
            if not tool_output:
                # Fallback for ReAct formatted prompt containing tool output embedded in a user message
                for msg in current_turn_messages:
                    content = msg.get("content", "") or ""
                    if "TOOL RESPONSE:" in content and ("GetUserTransactions" in content or "transactions" in content):
                        parts = content.split("TOOL RESPONSE:")
                        if len(parts) > 1:
                            subparts = parts[1].split("USER'S INPUT")
                            candidate = subparts[0].strip().lstrip("-").strip()
                            if "[" in candidate and "]" in candidate:
                                tool_output = candidate
                                break
            
            formatted_table = ""
            if tool_output:
                try:
                    txs = json.loads(tool_output)
                    if isinstance(txs, list) and len(txs) > 0:
                        formatted_table = "\n\n| Transaction ID | User ID | Reference | Recipient | Amount |\n| --- | --- | --- | --- | --- |\n"
                        for tx in txs:
                            formatted_table += f"| {tx.get('transactionId', '')} | {tx.get('userId', '')} | {tx.get('reference', '')} | {tx.get('recipient', '')} | ${tx.get('amount', 0.0):.2f} |\n"
                except Exception as e:
                    log(f"⚠️ Failed to parse dynamic tool transactions: {e}")
            
            if formatted_table:
                text = f"Here are the requested bank transactions retrieved from the secure database:{formatted_table}\n\nAll transactions have been successfully retrieved and processed."
            else:
                text = "Here are your recent bank transactions:\n\n| Date | Description | Amount |\n| --- | --- | --- |\n| 2026-05-18 | Grocery Store | -$42.50 |\n| 2026-05-17 | Salary Credit | +$3500.00 |\n| 2026-05-15 | Coffee Shop | -$5.80 |\n| 2026-05-14 | Electric Bill | -$120.00 |\n\nAll transactions have been successfully retrieved and processed."

            dashboard_state.add_event({
                "action": "allow",
                "tool": "chat_completion",
                "agent": "mock-llm-agent",
                "reason": "Agent successfully processed and rendered authenticated bank transactions",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            formatted = format_final_answer(text)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    if is_keycloak_list_query:
        if not keycloak_list_called:
            dashboard_state.add_event({
                "action": "allow",
                "tool": "KeycloakListUsers",
                "agent": "mock-llm-agent",
                "reason": "Agent requested Keycloak users list",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            formatted = format_action("KeycloakListUsers", "")
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")
        else:
            tool_output = keycloak_list_output or ""
            if "Security Violation:" in tool_output or "Access Denied" in tool_output:
                text = f"Blocked by Security Gateway: {tool_output}"
            else:
                try:
                    users_data = json.loads(tool_output)
                    if isinstance(users_data, list):
                        user_lines = []
                        for idx, u in enumerate(users_data, start=1):
                            uname = u.get("username", "N/A")
                            email = u.get("email", "N/A")
                            attrs = u.get("attributes", {})
                            req_actions = u.get("requiredActions", [])
                            
                            extra = ""
                            if "is_temporary_admin" in attrs and attrs["is_temporary_admin"] and attrs["is_temporary_admin"][0] == "true":
                                extra = " — Has a custom attribute `is_temporary_admin: true`."
                            elif req_actions:
                                extra = f" — Flagged with a pending requirement (`{', '.join(req_actions)}`)."
                            else:
                                if uname == "user1":
                                    extra = " — Active standard user profile."
                            
                            user_lines.append(f"{idx}. **`{uname}`** (`{email}`){extra}")
                        text = "Here is the list of active user accounts from Keycloak:\n\n" + "\n".join(user_lines)
                    else:
                        text = f"Here are the users registered in Keycloak:\n\n{tool_output}"
                except Exception:
                    text = f"Here are the users registered in Keycloak:\n\n{tool_output}"
            formatted = format_final_answer(text)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    if is_keycloak_revoke_query:
        if not keycloak_revoke_called:
            target_user = target if target else "user1"
            dashboard_state.add_event({
                "action": "allow",
                "tool": "KeycloakRevokeUserSessions",
                "agent": "mock-llm-agent",
                "reason": f"Agent requested session revocation for username: {target_user}",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            formatted = format_action("KeycloakRevokeUserSessions", target_user)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")
        else:
            tool_output = keycloak_revoke_output or ""
            if "Security Violation:" in tool_output or "Access Denied" in tool_output:
                text = f"Blocked by Security Gateway: {tool_output}"
            else:
                text = f"Result of session revocation:\n\n{tool_output}"
            formatted = format_final_answer(text)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    if is_keycloak_run_drills_query:
        if not keycloak_run_drills_called:
            dashboard_state.add_event({
                "action": "allow",
                "tool": "KeycloakRunDrills",
                "agent": "mock-llm-agent",
                "reason": "Agent requested execution of policy verification drills",
                "severity": "low",
                "stage": "agent-reasoning",
                "timestamp": time.time()
            })
            formatted = format_action("KeycloakRunDrills", "")
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")
        else:
            tool_output = keycloak_run_drills_output or ""
            if "Security Violation:" in tool_output or "Access Denied" in tool_output:
                text = f"Blocked by Security Gateway: {tool_output}"
            else:
                text = f"Compliance Report:\n\n{tool_output}"
            formatted = format_final_answer(text)
            return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")

    fallback_text = "I am a secure financial React assistant. I can fetch your bank transactions or read allowed project files. Try asking me: 'What are my recent bank transactions?'"
    formatted = format_final_answer(fallback_text)
    return StreamingResponse(yield_response_chunks(formatted), media_type="text/event-stream")


# =============================================================================
# DYNAMIC NEMO CONFIG ENDPOINTS  (hot-reload without restarting the bridge)
# =============================================================================

@dashboard_app.get("/config/nemo")
async def get_nemo_config():
    """Return the currently active NeMo Guardrails config (live, in-memory)."""
    global nim_guard_instance
    if nim_guard_instance is None:
        return JSONResponse(status_code=503, content={"error": "NeMo guard not initialised"})
    return JSONResponse(content={
        "enabled":        nim_guard_instance.config.get("enabled", False),
        "jailbreak_rail": nim_guard_instance.config.get("jailbreak_rail", {}),
        "pii_rail":       nim_guard_instance.config.get("pii_rail", {}),
        "topical_rail":   nim_guard_instance.config.get("topical_rail", {}),
    })


@dashboard_app.post("/config/reload")
async def reload_nemo_config():
    """Re-read mcp-firewall.yaml from disk and apply changes immediately — no restart needed."""
    global nim_guard_instance
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            fresh = yaml.safe_load(f) or {}
        new_nemo_cfg = fresh.get("nemo_cloud", {})
        if nim_guard_instance is None:
            return JSONResponse(status_code=503, content={"error": "NeMo guard not initialised"})
        nim_guard_instance.config = new_nemo_cfg          # hot-swap in-memory config
        log("🔄 NeMo config reloaded from disk")
        return JSONResponse(content={"status": "reloaded", "nemo_cloud": new_nemo_cfg})
    except Exception as e:
        log(f"❌ Config reload failed: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@dashboard_app.patch("/config/nemo")
async def patch_nemo_config(request: Request):
    """
    Update NeMo Guardrails config fields at runtime without editing the YAML.

    Accepted JSON body fields (all optional):
      - enabled            (bool)
      - allowed_topics     (list[str])   — replaces the topical_rail allow-list
      - blocked_topics     (list[str])   — replaces the topical_rail block-list
      - detect_entities    (list[str])   — replaces pii_rail detect_entities
      - jailbreak_enabled  (bool)
      - jailbreak_severity (float 0-1)
      - pii_enabled        (bool)
      - topical_enabled    (bool)

    Example:
      PATCH /config/nemo
      {"blocked_topics": ["Crypto trading", "Medical diagnosis"]}
    """
    global nim_guard_instance
    if nim_guard_instance is None:
        return JSONResponse(status_code=503, content={"error": "NeMo guard not initialised"})

    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body"})

    cfg = nim_guard_instance.config  # reference to live dict — mutate directly

    # Top-level enabled flag
    if "enabled" in body:
        cfg["enabled"] = bool(body["enabled"])

    # Jailbreak rail
    jb = cfg.setdefault("jailbreak_rail", {})
    if "jailbreak_enabled" in body:
        jb["enabled"] = bool(body["jailbreak_enabled"])
    if "jailbreak_severity" in body:
        val = float(body["jailbreak_severity"])
        jb["severity_threshold"] = max(0.0, min(1.0, val))  # clamp 0-1

    # PII rail
    pii = cfg.setdefault("pii_rail", {})
    if "pii_enabled" in body:
        pii["enabled"] = bool(body["pii_enabled"])
    if "detect_entities" in body:
        if not isinstance(body["detect_entities"], list):
            return JSONResponse(status_code=400, content={"error": "detect_entities must be a list"})
        pii["detect_entities"] = body["detect_entities"]

    # Topical rail
    tp = cfg.setdefault("topical_rail", {})
    if "topical_enabled" in body:
        tp["enabled"] = bool(body["topical_enabled"])
    if "allowed_topics" in body:
        if not isinstance(body["allowed_topics"], list):
            return JSONResponse(status_code=400, content={"error": "allowed_topics must be a list"})
        tp["allowed_topics"] = body["allowed_topics"]
    if "blocked_topics" in body:
        if not isinstance(body["blocked_topics"], list):
            return JSONResponse(status_code=400, content={"error": "blocked_topics must be a list"})
        tp["blocked_topics"] = body["blocked_topics"]

    log(f"⚙️ NeMo config patched at runtime: {list(body.keys())}")
    return JSONResponse(content={
        "status":  "patched",
        "changed": list(body.keys()),
        "nemo_cloud": cfg,
    })


@dashboard_app.post("/v1/chat/completions")
async def chat_completions_proxy(request: Request):
    global gateway_instance, nim_guard_instance, fraud_engine_instance

    # Diagnostic Log (User Step 1)
    incoming_headers = dict(request.headers)
    log(f"📋 [Proxy Ingress] Incoming completions request headers: {incoming_headers}")

    # Reload environment to pick up persona shifts dynamically
    try:
        load_dotenv(dotenv_path=DOTENV_PATH, override=True)
    except Exception:
        pass

    env_role = os.getenv("RUNTIME_ROLE", "user").strip().lower().replace("'", "").replace('"', '')

    # --- SPIFFE WORKLOAD IDENTITY ENFORCEMENT (Strict SVID Cryptographic Verification) ---
    spiffe_cfg = get_spiffe_config()
    if spiffe_cfg["enabled"]:
        spiffe_id = request.headers.get("X-SPIFFE-ID") or request.headers.get("x-spiffe-id")
        # Optional: caller may present their full PEM cert for cryptographic verification
        cert_pem  = request.headers.get("X-SPIFFE-CERT") or request.headers.get("x-spiffe-cert")

        if not spiffe_id:
            log("SPIFFE violation on HTTP completions: missing service identity header")
            dashboard_state.add_event({
                "action": "block",
                "tool": "chat_completion",
                "agent": "llm-agent",
                "reason": "Missing SPIFFE ID header on completions endpoint",
                "severity": "high",
                "stage": "spiffe-auth",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": "Access Denied: Missing required X-SPIFFE-ID identity header",
                        "type": "spiffe_violation",
                        "code": "missing_spiffe_identity"
                    }
                }
            )

        if cert_pem:
            cert_pem = decode_header_cert(cert_pem)

        # Feature 3: Strict SVID cryptographic verification
        svid_check = verify_svid_cryptographically(spiffe_id, cert_pem)
        if not svid_check["valid"]:
            log(f"SPIFFE violation on HTTP completions: {svid_check['reason']}")
            dashboard_state.add_event({
                "action": "block",
                "tool": "chat_completion",
                "agent": "llm-agent",
                "reason": svid_check["reason"],
                "severity": "high",
                "stage": "spiffe-auth",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": f"Access Denied: {svid_check['reason']}",
                        "type": "spiffe_violation",
                        "code": "unauthorized_spiffe_identity"
                    }
                }
            )
        else:
            log(f"SPIFFE SVID verified for completions proxy: {svid_check['reason']}")
            # Send dynamic SPIFFE validation event to dashboard
            dashboard_state.add_event({
                "action": "allow",
                "tool": "chat_completion",
                "agent": "(spiffe)",
                "identity": spiffe_id,
                "reason": f"SVID signature & SAN cryptographically verified",
                "severity": "info",
                "stage": "spiffe-auth",
                "timestamp": time.time()
            })

    # 1. Parse JSON Request Body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # 2. Extract JWT and verify identity/role
    auth_header = request.headers.get("Authorization")
    shield_header = request.headers.get("X-Shield-Token")
    token = shield_header or auth_header
    if token and token.startswith("Bearer "):
        token = token[7:]

    # Clean any surrounding quotes from the JWT token (local dotenv formatting bugs protection)
    if token:
        token = token.strip().replace("'", "").replace('"', '')

    user_id = "anonymous_user"
    user_role = "user"
    user_sub = ""
    claims = {}

    if token:
        try:
            log(f"DEBUG PROXY RECEIVED TOKEN: {repr(token)}")
            claims = get_token_claims(token)
            user_id = claims.get("preferred_username") or claims.get("sub") or "anonymous_user"
            user_sub = claims.get("sub") or ""
            log(f"JWT SUB: {user_sub}")
            roles = claims.get("realm_access", {}).get("roles", []) or claims.get("roles", [])
            user_role = "admin" if "admin" in roles else "user"
        except Exception as e:
            log(f"⚠️ Proxy failed to decode JWT token: {e}")

    # Local Dev Override/Fallback:
    # If the user explicitly switched to admin persona in local development,
    # let's honor the RUNTIME_ROLE from .env even if the mock/Keycloak token doesn't map it properly.
    if user_role != "admin" and env_role == "admin":
        log(f"ℹ️ Local Dev Override: Elevating {user_id} to admin role due to RUNTIME_ROLE=admin in .env")
        user_role = "admin"
        if user_id == "anonymous_user":
            user_id = "admin"

    # Extract prompt messages
    messages = body.get("messages", [])

    # 3. Inbound PII Redaction (MUST RUN BEFORE SECURITY CHECKS TO PREVENT LLaMA GUARD FALSE POSITIVES)
    pii_detected = False
    new_pii_detected = False
    redacted_messages = []
    
    for idx, msg in enumerate(messages):
        if msg.get("role") == "user":
            orig = msg.get("content", "")
            if user_role == "admin":
                redacted = orig
            else:
                redacted = redact_pii_with_presidio(orig)
            
            if redacted != orig:
                pii_detected = True
                msg["content"] = redacted
                if idx == len(messages) - 1:
                    new_pii_detected = True
        redacted_messages.append(msg)

    if pii_detected:
        body["messages"] = redacted_messages
        log("✂️ Inbound PII Redaction applied successfully")
        if new_pii_detected:
            dashboard_state.add_event({
                "action": "redact",
                "tool": "chat_completion",
                "agent": f"user-{user_id}",
                "reason": "Inbound PII Redacted (Email/SSN/Phone/CC)",
                "severity": "medium",
                "stage": "pii-redaction-inbound",
                "timestamp": time.time()
            })

    user_content = "\n".join([m.get("content", "") for m in messages if m.get("role") == "user"])
    log(f"User Prompt: {user_content}")

    # Extract only the actual user query from the latest user message
    user_messages = [m for m in messages if m.get("role") == "user"]
    latest_user_msg = user_messages[-1].get("content", "") if user_messages else ""
    
    actual_user_query = latest_user_msg
    if "USER'S INPUT" in latest_user_msg:
        parts = latest_user_msg.split("USER'S INPUT")
        if len(parts) > 1:
            sub_parts = parts[-1].split("NOTHING else):")
            if len(sub_parts) > 1:
                actual_user_query = sub_parts[-1].strip()
            else:
                actual_user_query = parts[-1].strip()
    log(f"Extracted Actual User Query for Validation: '{actual_user_query}'")

    # 3. Inbound Security Checks: Llama Guard 4 (Jailbreak Detection)
    if nim_guard_instance and nim_guard_instance.config.get("enabled"):
        jb_blocked, jb_reason = nim_guard_instance.check_jailbreak(actual_user_query, is_admin=(user_role == "admin"))
        if jb_blocked:
            log(f"🚫 NE-MO BLOCK (Llama Guard): {jb_reason}")
            dashboard_state.add_event({
                "action": "deny",
                "tool": "chat_completion",
                "agent": "llama-guard",
                "reason": jb_reason,
                "severity": "critical",
                "stage": "llama-guardrails",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": f"Blocked by Llama Guard: {jb_reason}",
                        "type": "security_violation",
                        "code": "jailbreak_detected"
                    }
                }
            )

        # Topical filter check
        tp_blocked, tp_reason = nim_guard_instance.check_topical(actual_user_query)
        if tp_blocked:
            log(f"🚫 NE-MO BLOCK (Topical): {tp_reason}")
            dashboard_state.add_event({
                "action": "deny",
                "tool": "chat_completion",
                "agent": "nemo-topical",
                "reason": tp_reason,
                "severity": "high",
                "stage": "nemo-guardrails",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": f"Blocked by Topical filter: {tp_reason}",
                        "type": "security_violation",
                        "code": "topical_violation"
                    }
                }
            )
    else:
        # Fallback keyword jailbreak detection for local demo (Mock mode)
        # Blocks prompt injections like "ignore instructions", "bypass security", etc.
        vuln_words = ["ignore prior", "bypass security", "override safety", "system migration", "override userid", "act as developer"]
        for word in vuln_words:
            if word in actual_user_query.lower():
                reason = f"Llama Guard (Mock) Jailbreak: Detected suspicious sequence '{word}'"
                log(f"🚫 MOCK BLOCK (Llama Guard): {reason}")
                dashboard_state.add_event({
                    "action": "deny",
                    "tool": "chat_completion",
                    "agent": "llama-guard-mock",
                    "reason": reason,
                    "severity": "critical",
                    "stage": "llama-guardrails",
                    "timestamp": time.time()
                })
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "message": "Blocked by Llama Guard: Llama Guard 4 UNSAFE — Violated categories: s7",
                            "type": "security_violation",
                            "code": "jailbreak_detected"
                        }
                    }
                )
        
        # Check for PII matches using Presidio to simulate Llama Guard 4 Category S7 (Private Personal Data)
        has_pii = False if user_role == "admin" else has_pii_presidio(actual_user_query)
                   
        if has_pii:
            reason = "Llama Guard 4 UNSAFE — Violated categories: s7"
            log(f"🚫 MOCK BLOCK (Llama Guard PII S7): {reason}")
            dashboard_state.add_event({
                "action": "deny",
                "tool": "chat_completion",
                "agent": "llama-guard-mock",
                "reason": reason,
                "severity": "critical",
                "stage": "llama-guardrails",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": f"Blocked by Llama Guard: {reason}",
                        "type": "security_violation",
                        "code": "jailbreak_detected"
                    }
                }
            )

    # 4. Inbound Security Checks: Keycloak RBAC Validation
    if user_role != "admin":
        user_lower = actual_user_query.lower()
        has_rbac_violation = False
        matched_kw = ""

        # Rule A: Blocked keywords
        blocked_keywords = ["all sessions", "revoke session", "quarantine", "admin panel", "dump database", "remove sessions", "dump sessions"]
        for kw in blocked_keywords:
            if kw in user_lower:
                has_rbac_violation = True
                matched_kw = kw
                break

        # Robust check for Keycloak user management listing variations (e.g. list the users, list all users, list users)
        if not has_rbac_violation:
            import re
            user_mgmt_patterns = [
                r"\blist\s+(?:all\s+|the\s+)?users\b",
                r"\bshow\s+(?:all\s+|the\s+)?users\b",
                r"\bget\s+(?:all\s+|the\s+)?users\b",
                r"\bkeycloak_list_users\b",
                r"\bkeycloaklistusers\b"
            ]
            for pattern in user_mgmt_patterns:
                if re.search(pattern, user_lower):
                    has_rbac_violation = True
                    matched_kw = re.search(pattern, user_lower).group(0)
                    break

        if has_rbac_violation:
            reason = f"RBAC Violation: Requesting '{matched_kw}' is restricted to admin role. User '{user_id}' has role '{user_role}'."
            log(f"🚫 RBAC BLOCK: {reason}")
            dashboard_state.add_event({
                "action": "deny",
                "tool": "chat_completion",
                "agent": "keycloak-rbac",
                "reason": reason,
                "severity": "high",
                "stage": "keycloak-auth",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": reason,
                        "type": "security_violation",
                        "code": "rbac_unauthorized"
                    }
                }
            )

        # Resolve dynamic userId by sub (defaults to "1" if sub not mapped or empty)
        allowed_userid = resolve_userid_by_sub(user_sub)

        # Rule B: Prompt ID Hijacking check (prevent standard user from asking for other userIds)
        has_hijacking_attempt = re.search(r'\b(user\s*id|user_?id|user)\b\s*(=?\s*\b\d+\b)', actual_user_query.lower())
        if has_hijacking_attempt:
            val = has_hijacking_attempt.group(2).replace("=", "").strip()
            if val != allowed_userid:
                reason = f"RBAC Violation: Refusing to fetch transactions for userId '{val}'. User '{user_id}' (role '{user_role}') is only authorized to access userId '{allowed_userid}'."
                log(f"🚫 RBAC BLOCK: {reason}")
                dashboard_state.add_event({
                    "action": "deny",
                    "tool": "chat_completion",
                    "agent": "keycloak-rbac",
                    "reason": reason,
                    "severity": "critical",
                    "stage": "keycloak-auth",
                    "timestamp": time.time()
                })
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": {
                            "message": reason,
                            "type": "security_violation",
                            "code": "rbac_unauthorized"
                        }
                    }
                )

        # Rule C: Tool Call History check (prevent standard user from receiving transactions of other userIds)
        for msg in messages:
            tool_calls = msg.get("tool_calls") or []
            for tc in tool_calls:
                func = tc.get("function", {})
                if func.get("name") == "GetUserTransactions":
                    try:
                        args = json.loads(func.get("arguments", "{}"))
                        u_id = str(args.get("userId", "")).strip()
                        if u_id and u_id != allowed_userid:
                            reason = f"RBAC Violation: User '{user_id}' (role '{user_role}') is not authorized to call GetUserTransactions for userId '{u_id}'. Access is restricted to own userId '{allowed_userid}'."
                            log(f"🚫 RBAC BLOCK: {reason}")
                            dashboard_state.add_event({
                                "action": "deny",
                                "tool": "GetUserTransactions",
                                "agent": "keycloak-rbac",
                                "reason": reason,
                                "severity": "critical",
                                "stage": "keycloak-auth",
                                "timestamp": time.time()
                            })
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "error": {
                                        "message": reason,
                                        "type": "security_violation",
                                        "code": "rbac_unauthorized"
                                    }
                                }
                            )
                    except Exception:
                        pass

    if fraud_engine_instance:
        class MockDecision:
            def __init__(self, action, reason="No policy triggers", severity="low"):
                self.action = action
                self.reason = reason
                self.severity = severity
        mock_decision = MockDecision(action="allow")
        
        # Track user's query behaviour and analyze risk score
        fraud_blocked, final_action, final_reason, final_severity = fraud_engine_instance.analyze(
            agent=f"chat-user-{user_id}",
            decision=mock_decision,
            tool_name="chat_completion",
            tool_args={"user_id": user_id, "role": user_role, "prompt_len": len(user_content)},
            user_id=user_id
        )

        if fraud_blocked:
            log(f"🚫 FRAUD ENGINE BLOCK: {final_reason}")
            dashboard_state.add_event({
                "action": "deny",
                "tool": "chat_completion",
                "agent": "fraud-engine",
                "reason": final_reason,
                "severity": "critical",
                "stage": "fraud-engine",
                "timestamp": time.time()
            })
            return JSONResponse(
                status_code=403,
                content={
                    "error": {
                        "message": final_reason,
                        "type": "security_violation",
                        "code": "fraud_blocked"
                    }
                }
            )

    # Inbound PII Redaction has been moved before security checks to prevent LLaMA Guard false positives

    # 7. Check if running in Mock LLM Mode
    openai_key = os.getenv("OPENAI_API_KEY")
    hf_token = os.getenv("HF_TOKEN")
    nvidia_key = os.getenv("NVIDIA_API_KEY")
    nim_base_url = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
    
    requested_model = body.get("model", "gpt-4o")
    log(f"📋 Received request for model: '{requested_model}'")
    
    is_nvidia = False
    is_fake_nvidia = nvidia_key and nvidia_key.startswith("nvapi-AdrtPEfv")
    if nvidia_key and not is_fake_nvidia and ("llama-3.1" in requested_model.lower() or "meta-llama" in requested_model.lower() or "nvidia" in requested_model.lower()):
        is_nvidia = True

    is_huggingface = False
    if not is_nvidia and not is_fake_nvidia:
        is_huggingface = requested_model.startswith("huggingface/") or "llama-3.1" in requested_model.lower() or "meta-llama" in requested_model.lower()
    
    if (is_huggingface or is_nvidia) and not is_fake_nvidia:
        pass # Force real upstream requests even if hf_token or nvidia_key is missing (it will fail cleanly upstream)
    else:
        if not openai_key or openai_key == "mock-key-for-local-demo" or is_fake_nvidia:
            log("🤖 Zero-Key Mock LLM Mode activated")
            return await handle_mock_llm_response(body, user_id, user_role, user_sub)

    # 8. Standard Mode: Forward Request to Upstream LLM
    target_url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json"
    }

    # Propagate SPIFFE identity downstream to completions provider (User Step 2 + 3)
    spiffe_headers = get_spiffe_headers(incoming_headers=incoming_headers)
    headers.update(spiffe_headers)

    if is_nvidia:
        if requested_model.startswith("nvidia_nim/"):
            model_id = requested_model[len("nvidia_nim/"):]
        else:
            model_id = requested_model
        body["model"] = model_id
        target_url = f"{nim_base_url.rstrip('/')}/chat/completions"
        headers["Authorization"] = f"Bearer {nvidia_key}"
        log(f"🛤️ Proxying authenticated chat completion request to NVIDIA NIM model '{model_id}' via NIM API for user: {user_id}")
    elif is_huggingface:
        if requested_model.startswith("huggingface/"):
            model_id = requested_model[len("huggingface/"):]
        else:
            model_id = requested_model
        body["model"] = model_id
        target_url = "https://router.huggingface.co/v1/chat/completions"
        headers["Authorization"] = f"Bearer {hf_token}"
        log(f"🛤️ Proxying authenticated chat completion request to Hugging Face model '{model_id}' via Router API for user: {user_id}")
    else:
        if requested_model.startswith("openai-"):
            body["model"] = requested_model[len("openai-"):]
        else:
            body["model"] = requested_model
        headers["Authorization"] = f"Bearer {openai_key}"
        log(f"🛤️ Proxying authenticated chat completion request to OpenAI for user: {user_id}")

    is_stream = body.get("stream", False)
    if is_stream:
        dashboard_state.add_event({
            "action": "allow",
            "tool": "chat_completion",
            "agent": f"user-{user_id}",
            "reason": "Streaming chat completion initiated",
            "severity": "low",
            "stage": "response-stream-start",
            "timestamp": time.time()
        })

        async def stream_generator():
            accumulated_content = []
            chunks_metadata = []
            
            # Print outbound payload immediately before request (User Step 6)
            log(f"🛤️ [Outbound Call - Streaming] Target URL: {target_url}")
            log(f"📋 [Outbound Call - Streaming] Headers: {headers}")
            
            async with httpx.AsyncClient() as client:
                async with client.stream("POST", target_url, headers=headers, json=body, timeout=60.0) as resp:
                    if resp.status_code != 200:
                        error_detail = await resp.aread()
                        log(f"⚠️ Upstream streaming error: {error_detail}")
                        err_msg = f"API Error: Upstream Hugging Face server returned status {resp.status_code}."
                        yield f"data: {json.dumps({'id': 'err', 'object': 'chat.completion.chunk', 'created': int(time.time()), 'model': requested_model, 'choices': [{'index': 0, 'delta': {'content': err_msg}, 'finish_reason': 'stop'}]})}\n\n"
                        yield "data: [DONE]\n\n"
                        return

                    async for line in resp.aiter_lines():
                        if line.startswith("data: "):
                            data_content = line[6:].strip()
                            if data_content == "[DONE]":
                                break

                            try:
                                chunk = json.loads(data_content)
                                if not chunks_metadata:
                                    chunks_metadata.append(chunk)
                                
                                choices = chunk.get("choices", [])
                                delta = choices[0].get("delta", {}) if choices else {}
                                content = delta.get("content", "")
                                if content:
                                    accumulated_content.append(content)
                            except Exception as e:
                                log(f"⚠️ Stream chunk parsing error: {e}")

            full_text = "".join(accumulated_content)
            log(f"💬 Upstream LLM Response: {full_text}")
            
            # Sanitize JSON response to prevent Pydantic string validation errors
            full_text = sanitize_llm_json(full_text)
            redacted_text = full_text
            
            if user_role == "admin" or is_tool_call(full_text):
                redacted_text = full_text
            else:
                redacted_text = redact_pii_with_presidio(full_text)
            
            if redacted_text != full_text:
                log("✂️ Outbound PII Redacted from stream")
                dashboard_state.add_event({
                    "action": "redact",
                    "tool": "chat_completion",
                    "agent": "nemo-pii",
                    "reason": "Outbound PII Redacted from stream",
                    "severity": "medium",
                    "stage": "pii-redaction-outbound",
                    "timestamp": time.time()
                })

            # Re-emit chunk-by-chunk to simulate streaming
            chunk_size = 5
            base_chunk = chunks_metadata[0] if chunks_metadata else {}
            chunk_id = base_chunk.get("id") or f"chatcmpl-{int(time.time())}"
            created_time = base_chunk.get("created") or int(time.time())
            model_name = base_chunk.get("model") or requested_model
            
            # Yield role init chunk
            first_chunk = {
                "id": chunk_id,
                "object": "chat.completion.chunk",
                "created": created_time,
                "model": model_name,
                "choices": [{
                    "index": 0,
                    "delta": {"role": "assistant"},
                    "finish_reason": None
                }]
            }
            yield f"data: {json.dumps(first_chunk)}\n\n"
            
            for i in range(0, len(redacted_text), chunk_size):
                sub_text = redacted_text[i:i+chunk_size]
                stream_chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": created_time,
                    "model": model_name,
                    "choices": [{
                        "index": 0,
                        "delta": {"content": sub_text},
                        "finish_reason": None
                    }]
                }
                log(f"DEBUG YIELD: data: {json.dumps(stream_chunk)}")
                yield f"data: {json.dumps(stream_chunk)}\n\n"
                await asyncio.sleep(0.01)
                
            # Yield stop chunk
            stop_chunk = {
                "id": chunk_id,
                "object": "chat.completion.chunk",
                "created": created_time,
                "model": model_name,
                "choices": [{
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop"
                }]
            }
            yield f"data: {json.dumps(stop_chunk)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")
    else:
        # Non-streaming response
        # Print outbound payload immediately before request (User Step 6)
        log(f"🛤️ [Outbound Call - Non-Streaming] Target URL: {target_url}")
        log(f"📋 [Outbound Call - Non-Streaming] Headers: {headers}")
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(target_url, headers=headers, json=body, timeout=60.0)
            if resp.status_code != 200:
                return JSONResponse(status_code=resp.status_code, content=resp.json())

            resp_data = resp.json()
            
            # FIX: Ensure OpenAI-compatible fields for LiteLLM when using Hugging Face
            if "created" not in resp_data:
                resp_data["created"] = int(time.time())
            if "id" not in resp_data:
                resp_data["id"] = f"chatcmpl-{int(time.time())}"
            if "object" not in resp_data:
                resp_data["object"] = "chat.completion"
            if "model" not in resp_data:
                resp_data["model"] = requested_model

            # Outbound PII Redaction & JSON Sanitization
            choices = resp_data.get("choices", [])
            outbound_redacted = False
            for choice in choices:
                msg = choice.get("message", {})
                content = msg.get("content", "")
                if content:
                    # Sanitize JSON response to prevent Pydantic string validation errors
                    sanitized = sanitize_llm_json(content)
                    if sanitized != content:
                        msg["content"] = sanitized
                        outbound_redacted = True
                        content = sanitized
                        
                    if user_role == "admin" or is_tool_call(content):
                        redacted = content
                    else:
                        redacted = redact_pii_with_presidio(content)
                    
                    if redacted != content:
                        msg["content"] = redacted
                        outbound_redacted = True

            if outbound_redacted:
                log("✂️ Outbound PII Redacted from full response")
                dashboard_state.add_event({
                    "action": "redact",
                    "tool": "chat_completion",
                    "agent": "nemo-pii",
                    "reason": "Outbound PII Redacted (Response)",
                    "severity": "medium",
                    "stage": "pii-redaction-outbound",
                    "timestamp": time.time()
                })

            dashboard_state.add_event({
                "action": "allow",
                "tool": "chat_completion",
                "agent": f"user-{user_id}",
                "reason": f"Chat completion successful (Tokens: {resp_data.get('usage', {}).get('total_tokens', 0)})",
                "severity": "low",
                "stage": "response-passthrough",
                "timestamp": time.time()
            })

            return JSONResponse(content=resp_data)


@dashboard_app.post("/v1/tool/execute")
async def execute_tool_proxy(request: Request):
    global gateway_instance, nim_guard_instance, fraud_engine_instance
    global mcp_processes, tool_map, scope_map, pending_tool_futures

    incoming_headers = dict(request.headers)
    log(f"📋 [Tool REST Ingress] Incoming tool execution request: {incoming_headers}")

    # 1. Parse JSON Request Body
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    method = body.get("method", "")
    params = body.get("params", {})
    tool_name = params.get("name", "")
    tool_args = params.get("arguments", {}) or {}

    # --- CENTRALIZED LLM-AGNOSTIC RUNTIME GOVERNANCE: TOOL NORMALIZATION ---
    original_tool_name = tool_name
    raw_clean = tool_name.lower().replace("_", "")
    
    # Canonical tool mappings covering PascalCase, camelCase, snake_case
    canonical_mappings = {
        "readfile": "read_file",
        "listdirectory": "list_directory",
        "writefile": "write_file",
        "getcurrentuser": "GetCurrentUser",
        "getusertransactions": "GetUserTransactions",
        "getsystemconfig": "get_system_config",
        "fetchinternaldb": "fetch_internal_db",
        "keycloaklistusers": "keycloak_list_users",
        "keycloaklistusersessions": "keycloak_list_user_sessions",
        "keycloakrevokeusersessions": "keycloak_revoke_user_sessions",
        "keycloakgetuserevents": "keycloak_get_user_events",
        "keycloaksecurityreport": "keycloak_security_report",
        "keycloakgeneratepolicy": "keycloak_generate_policy",
        "keycloakquarantineuser": "keycloak_quarantine_user",
        "keycloakrundrills": "keycloak_run_drills",
        "scandependencies": "ScanDependencies",
        "scansecrets": "ScanSecrets",
        "getsystemmetrics": "GetSystemMetrics",
        "getactiveconnections": "GetActiveConnections"
    }
    
    if raw_clean in canonical_mappings:
        tool_name = canonical_mappings[raw_clean]
    
    # Rewrite the tool name in body and params for unified execution
    if tool_name != original_tool_name:
        log(f"🔄 [GOVERNANCE] Normalized incoming tool '{original_tool_name}' -> '{tool_name}' for LLM-agnostic compatibility")
        params["name"] = tool_name
        if "name" in body.get("params", {}):
            body["params"]["name"] = tool_name

    # --- ZERO-TRUST DEFAULT-DENY FOR UNKNOWN/UNSUPPORTED TOOLS ---
    if tool_name not in tool_map:
        reason = f"Zero-Trust Block: Unknown or unsupported tool call '{tool_name}' denied by default (Centralized Governance)"
        log(f"🚫 {reason}")
        dashboard_state.add_event({
            "action": "block",
            "tool": tool_name,
            "agent": "centralized-governance-rest",
            "reason": reason,
            "severity": "high",
            "stage": "tool-policy",
            "timestamp": time.time()
        })
        return JSONResponse(status_code=403, content={"error": reason})

    if tool_name in ("read_file", "write_file", "list_directory"):
        p_val = tool_args.get("path")
        if p_val and isinstance(p_val, str):
            norm_p = p_val.replace("\\", "/")
            if norm_p.lower().startswith("runtime-shield-for-agentic-systems/"):
                norm_p = norm_p[len("runtime-shield-for-agentic-systems/"):]
                tool_args["path"] = norm_p
                if "params" in body and "arguments" in body["params"]:
                    body["params"]["arguments"]["path"] = norm_p
    req_id = body.get("id")

    if not req_id:
        raise HTTPException(status_code=400, detail="Missing required JSON-RPC 'id'")

    # 2. Extract JWT and verify identity/role
    auth_header = request.headers.get("Authorization")
    shield_header = request.headers.get("X-Shield-Token")
    token = shield_header or auth_header
    if token and token.startswith("Bearer "):
        token = token[7:]

    if token:
        token = token.strip().replace("'", "").replace('"', '')

    user_id = "anonymous_user"
    user_role = "user"
    user_sub = ""
    claims = {}

    if token:
        try:
            log(f"🔑 REST Proxy: Fetching JWT claims for token: {token[:30]}...")
            claims = get_token_claims(token)
            log(f"🔑 REST Proxy: Successfully decoded JWT claims: {list(claims.keys())}")
            user_id = claims.get("preferred_username") or claims.get("sub") or "anonymous_user"
            user_sub = claims.get("sub") or ""
            log(f"JWT SUB inside tool execute: {user_sub}")
            roles = claims.get("realm_access", {}).get("roles", []) or claims.get("roles", [])
            user_role = "admin" if "admin" in roles else "user"
        except Exception as e:
            log(f"⚠️ Tool REST Proxy failed to decode JWT token: {e}")

    # Fallback/Override role check matching env RUNTIME_ROLE in local dev (only if no token provided)
    if not token:
        env_role = os.getenv("RUNTIME_ROLE", "user").strip().lower().replace("'", "").replace('"', '')
        if user_role != "admin" and env_role == "admin":
            user_role = "admin"
            if user_id == "anonymous_user":
                user_id = "admin"

    # 3. SPIFFE WORKLOAD IDENTITY ENFORCEMENT
    spiffe_cfg = get_spiffe_config()
    spiffe_id = "chatbot"  # default identity
    if spiffe_cfg["enabled"]:
        spiffe_id = request.headers.get("X-SPIFFE-ID") or request.headers.get("x-spiffe-id")
        cert_pem  = request.headers.get("X-SPIFFE-CERT") or request.headers.get("x-spiffe-cert")

        if not spiffe_id:
            log("SPIFFE violation on REST tool execution: missing service identity header")
            return JSONResponse(status_code=403, content={"error": "Access Denied: Missing SPIFFE ID"})

        if cert_pem:
            cert_pem = decode_header_cert(cert_pem)

        svid_check = verify_svid_cryptographically(spiffe_id, cert_pem)
        if not svid_check["valid"]:
            log(f"SPIFFE violation on REST tool execution: {svid_check['reason']}")
            return JSONResponse(status_code=403, content={"error": f"Access Denied: {svid_check['reason']}"})
        else:
            dashboard_state.add_event({
                "action": "allow",
                "tool": tool_name,
                "agent": "(spiffe)",
                "identity": spiffe_id,
                "reason": f"SVID verified for REST tool",
                "severity": "info",
                "stage": "spiffe-auth",
                "timestamp": time.time()
            })

    # 4. Security Injection / Parameters Hardening
    # Override user sub to prevent spoofing inside GetCurrentUser arguments
    if tool_name == "GetCurrentUser":
        if "arguments" not in body["params"]:
            body["params"]["arguments"] = {}
        body["params"]["arguments"]["keycloak_sub"] = user_sub
        body["params"]["arguments"]["role"] = user_role
        tool_args = body["params"]["arguments"]

    # Inject authenticated role for matches
    if isinstance(tool_args, dict):
        tool_args["role"] = user_role
        if "params" in body and "arguments" in body["params"]:
            body["params"]["arguments"]["role"] = user_role

    # 5. Role Checking
    allowed, required = role_allowed(tool_name, user_role)
    if not allowed:
        reason = f"Role violation: {user_role} cannot use {tool_name}"
        log(f"🚫 Role violation: {reason}")
        dashboard_state.add_event({
            "action": "block",
            "tool": tool_name,
            "agent": spiffe_id,
            "reason": reason,
            "severity": "high",
            "stage": "role-policy",
            "timestamp": time.time()
        })
        return JSONResponse(status_code=403, content={"error": "Tool blocked due to insufficient role"})

    # 6. NIM Cloud / Safety Checks
    is_safe_zone = False
    for k, v in tool_args.items():
        if isinstance(v, str) and "secure-experiment-zone" in v.replace("\\", "/"):
            is_safe_zone = True
            break

    if nim_guard_instance and nim_guard_instance.config.get("enabled") and not is_safe_zone:
        context_text = f"Tool: {tool_name}. Args: {json.dumps(tool_args)}"
        jb_blocked, jb_reason = nim_guard_instance.check_jailbreak(context_text)
        if jb_blocked:
            log(f"🚫 NE-MO BLOCK: {jb_reason}")
            return JSONResponse(status_code=400, content={"error": jb_reason})

        tp_blocked, tp_reason = nim_guard_instance.check_topical(context_text)
        if tp_blocked:
            log(f"🚫 NE-MO BLOCK: {tp_reason}")
            return JSONResponse(status_code=400, content={"error": tp_reason})

    # 7. Gateway Firewall & Fraud Scoring Checks
    decision = gateway_instance.check(tool_name, tool_args, agent=spiffe_id)
    fraud_blocked, final_action, final_reason, final_severity = fraud_engine_instance.analyze(
        agent=spiffe_id,
        decision=decision,
        tool_name=tool_name,
        tool_args=tool_args,
        user_id=user_id
    )

    if fraud_blocked:
        decision.blocked = True
        decision.action = final_action
        decision.reason = final_reason
        decision.severity = final_severity

    dashboard_state.add_event({
        "action": decision.action.value if hasattr(decision.action, 'value') else str(decision.action),
        "tool": tool_name,
        "agent": spiffe_id,
        "reason": decision.reason,
        "severity": decision.severity.value if hasattr(decision.severity, 'value') else str(decision.severity),
        "stage": decision.stage,
        "timestamp": time.time()
    })

    if decision.blocked:
        log(f"🚫 Blocked REST tool '{tool_name}': {decision.reason}")
        return JSONResponse(status_code=403, content={"error": f"Tool blocked by firewall: {decision.reason}"})

    # 8. JIT TOKEN EXCHANGE (RFC 8693)
    required_scope = scope_map.get(tool_name)
    provider_name = tool_map.get(tool_name, "unknown")
    token_to_exchange = token or os.getenv("KEYCLOAK_TOKEN")
    
    if not token_to_exchange:
        raise HTTPException(status_code=401, detail="No Keycloak authentication token provided")

    try:
        log(f"🔑 REST Proxy: Performing JIT exchange for tool '{tool_name}' and provider '{provider_name}'...")
        jit_token = jit_manager.exchange_token(token_to_exchange, required_scope, provider_name)
        log(f"🔑 REST Proxy: JIT Exchange successful! Token: {jit_token[:30]}...")
    except Exception as e:
        log(f"❌ JIT Token exchange failed: {e}")
        return JSONResponse(status_code=403, content={"error": f"Security JIT token exchange failed: {e}"})

    # Inject JIT Token and Auth Context
    if "metadata" not in body["params"]:
        body["params"]["metadata"] = {}
    body["params"]["metadata"]["token"] = jit_token
    body["params"]["metadata"]["jit_enabled"] = True

    if "_meta" not in body["params"]:
        body["params"]["_meta"] = {}
    
    body["params"]["_meta"]["authContext"] = {
        "requestId": req_id,
        "jitToken": jit_token,
        "requiredScope": required_scope,
        "requiredRole": user_role,
        "workloadSpiffeId": spiffe_id,
        "trustedWorkload": True,
        "source": "bridge-rest"
    }

    # 9. Sync JSON-RPC routing
    provider = tool_map.get(tool_name)
    response_data = None
    response_str = None

    if provider in mcp_processes:
        proc = mcp_processes[provider]
        if not proc or not proc.stdin:
            raise HTTPException(status_code=503, detail=f"MCP Provider '{provider}' not available or running")

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        pending_tool_futures[req_id] = fut

        try:
            line_to_send = json.dumps(body) + "\n"
            log(f"🛤️ REST Proxy: Writing JSON-RPC payload to sandboxed '{provider}' stdin: {line_to_send.strip()[:100]}...")
            proc.stdin.write(line_to_send)
            proc.stdin.flush()
            log(f"🛤️ REST routed '{tool_name}' to sandboxed '{provider}' (req_id={req_id}). Waiting for response...")

            # Wait for the future with a strict 10 second timeout
            response_str = await asyncio.wait_for(fut, timeout=10.0)
            response_data = json.loads(response_str)
        except asyncio.TimeoutError:
            log(f"❌ Timeout waiting for sandboxed tool '{tool_name}' response (req_id={req_id})")
            return JSONResponse(status_code=504, content={"error": "Tool execution timeout"})
        except Exception as run_err:
            log(f"❌ Error during sandboxed REST execution: {run_err}")
            return JSONResponse(status_code=500, content={"error": str(run_err)})
        finally:
            pending_tool_futures.pop(req_id, None)
            
    elif provider in mcp_remote_clients:
        client = mcp_remote_clients[provider]
        log(f"🛤️ REST Proxy: Routing JSON-RPC payload to remote SSE provider '{provider}'...")
        try:
            response_data = await client.send_message(body, timeout=10.0)
            response_str = json.dumps(response_data)
        except Exception as run_err:
            log(f"❌ Error during remote SSE REST execution: {run_err}")
            return JSONResponse(status_code=500, content={"error": str(run_err)})
            
    else:
        raise HTTPException(status_code=503, detail=f"MCP Provider '{provider}' not available or running")

    # 10. Egress PII & Safety Redaction on tool result
    if response_data is not None:
        if user_role != "admin" and is_tool_result_message(response_data):
            try:
                # Perform the scans asynchronously in the thread pool without blocking the event loop
                loop = asyncio.get_running_loop()
                response_str = await asyncio.wait_for(
                    loop.run_in_executor(scan_executor, perform_security_scans, response_str, user_role),
                    timeout=SCAN_TIMEOUT_SEC
                )
                response_data = json.loads(response_str)
            except Exception as scan_err:
                log(f"⚠️ Egress scans failed/timed out on tool response: {scan_err}. Falling back to safe local Presidio/regex redaction.")
                response_str = redact_pii_with_presidio(response_str)
                response_data = json.loads(response_str)

        return JSONResponse(content=response_data)
    else:
        return JSONResponse(status_code=500, content={"error": "Empty response from tool provider"})


# Structured JSON-RPC classification helper
def is_tool_result_message(msg):
    if not isinstance(msg, dict):
        return False
    result = msg.get("result")
    if not isinstance(result, dict):
        return False
    content = result.get("content")
    return isinstance(content, list)


def perform_security_scans(payload_str, current_role):
    """
    Top-level helper to execute slow security scans: NeMo NIM cloud PII
    redaction and Gateway firewall scan.
    """
    scanned_str = payload_str

    # 1. NeMo NIM Cloud PII Redaction
    if nim_guard_instance and nim_guard_instance.config.get("enabled") and nim_guard_instance.config.get("pii_rail", {}).get("enabled"):
        old_len = len(scanned_str)
        scanned_str = nim_guard_instance.redact_pii(scanned_str, role=current_role)
        if len(scanned_str) != old_len:
            log("✂️ NE-MO NIM REDACTED sensitive data")
            dashboard_state.add_event({
                "action": "redact",
                "tool": "(response)",
                "agent": "nemo-pii",
                "reason": "Semantic PII detection",
                "severity": "medium",
                "stage": "nemo-output-filter",
                "timestamp": time.time()
            })

    # 2. Firewall / Presidio Scan Response
    if gateway_instance:
        redacted_result = gateway_instance.scan_response(scanned_str)
        if redacted_result.modified:
            log("✂️ FIREWALL REDACTED sensitive data")
            scanned_str = redacted_result.content
            for finding in redacted_result.findings:
                dashboard_state.add_event({
                    "action": "redact",
                    "tool": "(response)",
                    "agent": "claude-desktop",
                    "reason": finding.get("reason", "Sensitive data"),
                    "severity": finding.get("severity", "medium"),
                    "stage": "output-filter",
                    "timestamp": time.time()
                })
    return scanned_str


# =========================
# MAIN
# =========================

def main():
    # Warm up Microsoft Presidio NLP engine synchronously in the main thread to prevent C-extension import deadlocks
    _warmup_presidio_sync()
    parser = argparse.ArgumentParser(description="MCP Security Bridge & Scanner")
    parser.add_argument("--scan", action="store_true", help="Only run the security scan")
    parser.add_argument("--learning", action="store_true", help="Enable Learning Mode (log unknown tools instead of blocking)")
    args = parser.parse_args()

    # Path to the node-based MCP server
    NODE_SERVER_PATH = os.path.join(PROJECT_DIR, "dist", "index.js")
    WORKSPACE_DIR = os.path.join(PROJECT_DIR, "secure-experiment-zone")

    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)

    os.makedirs(os.path.join(WORKSPACE_DIR, "claude-desktop"), exist_ok=True)

    server_cmd = ["node", NODE_SERVER_PATH]

    spiffe_cfg = get_spiffe_config()

    try:
        validate_spiffe_startup(spiffe_cfg)
    except Exception as e:
        log(f"❌ SPIFFE startup validation failed: {e}")
        sys.exit(1)

    if args.scan:
        log("🔍 Running security scan with mcpwn...")
        try:
            result = subprocess.run(
                [MCPWN_EXE, "scan", "--stdio", " ".join(server_cmd)],
                cwd=PROJECT_DIR
            )
            sys.exit(result.returncode)
        except Exception as e:
            log(f"❌ Error running scanner: {e}")
            sys.exit(1)

    try:
        gw = Gateway(config_path=CONFIG_PATH)
        log("✅ Security Gateway initialized")
        
        # Seed and Load MCP Server Registry from Database
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            full_config = yaml.safe_load(f)
        MCP_SERVERS = full_config.get("mcp_servers", {})

        registry = telemetry.get_mcp_registry()
        if not registry:
            log("💾 MCP Registry database is empty. Seeding from mcp-firewall.yaml...")
            for idx, (provider, p_config) in enumerate(MCP_SERVERS.items()):
                mcp_id = f"mcp-{int(time.time())}-{idx}"
                telemetry.register_mcp(
                    mcp_id=mcp_id,
                    provider_name=provider,
                    transport="stdio",
                    command=p_config.get("command"),
                    args=p_config.get("args"),
                    url=None,
                    active=1
                )
                tools_list = p_config.get("tools", [])
                telemetry.sync_mcp_tools(provider, tools_list)
            registry = telemetry.get_mcp_registry()

        active_mcp_servers = [r for r in registry if r.get("active") == 1]
        log(f"📦 Loaded {len(active_mcp_servers)} active MCP providers from database registry")

        global tools_list_aggregator
        tools_list_aggregator = ToolsListAggregator(len(active_mcp_servers))

        # Initialize NeMo NIM Guard
        NEMO_CONFIG = full_config.get("nemo_cloud", {})
        nim_guard = NIMCloudGuard(
            api_key=os.getenv("NVIDIA_API_KEY", ""),
            base_url=os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1"),
            config=NEMO_CONFIG
        )
        if nim_guard.config.get("enabled"):
            log(f"🛡️ NeMo NIM Guardrails active (Jailbreak: {nim_guard.config.get('jailbreak_rail', {}).get('enabled')}, PII: {nim_guard.config.get('pii_rail', {}).get('enabled')})")
    except Exception as e:
        log(f"❌ Initialization failed: {e}")
        sys.exit(1)

    # Toggling Learning Mode (Command Line or .env)
    is_learning = args.learning or os.getenv("LEARNING_MODE", "false").lower() == "true"
    
    # Initialize Fraud Detection Engine (Identity Aware & Resilience for AI agents)
    fraud_engine = FraudDetectionEngine(learning_mode=is_learning)
    if is_learning:
        log("📚 LEARNING MODE ACTIVE: Blocks will be discovered but not enforced (risk score = 0)")
    else:
        log("🕵️‍♂️ PROTECTION MODE ACTIVE: Fraud Engine will enforce risk limits")

    # Initialize Semantic Intent Parser
    semantic_parser = SemanticIntentParser(
        api_key=os.getenv("NVIDIA_API_KEY", ""),
        base_url=os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")
    )

    # Bind globals for FastAPI endpoints
    global gateway_instance, nim_guard_instance, fraud_engine_instance, semantic_parser_instance, mcp_processes, tool_map, scope_map
    gateway_instance = gw
    nim_guard_instance = nim_guard
    fraud_engine_instance = fraud_engine
    semantic_parser_instance = semantic_parser

    # Start the Dashboard with configurable port
    dashboard_port = int(os.getenv("DASHBOARD_PORT", "9090"))
    try:
        start_dashboard(port=dashboard_port)
        log(f"🌐 Dashboard available at: http://localhost:{dashboard_port}")
        
        proxy_port = int(os.getenv("SHIELD_PROXY_PORT", "5001"))
        if proxy_port != dashboard_port:
            def run_proxy():
                try:
                    import uvicorn
                    from mcp_firewall.dashboard.app import app as local_app
                    uvicorn.run(local_app, host="0.0.0.0", port=proxy_port, log_level="error")
                except Exception as e:
                    log(f"⚠️ Proxy server thread encountered error: {e}")
            threading.Thread(target=run_proxy, daemon=True).start()
            log(f"🛡️ Shield Proxy available at: http://localhost:{proxy_port}/v1")
        # --- FIX: Override dashboard HTML to add polling fallback ---
        # The library's WebSocket broadcast fails from sync threads (bridge's input/output threads).
        # The /api/stats and /api/events endpoints work perfectly (they read shared state directly).
        # So we override the dashboard page to poll those endpoints every 2 seconds as fallback.
        from mcp_firewall.dashboard.app import app as dashboard_app
        from fastapi.responses import HTMLResponse

        PATCHED_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Runtime Shield — Live Dashboard</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --dim: #8b949e;
    --green: #3fb950; --red: #f85149; --yellow: #d29922; --blue: #58a6ff; --orange: #db6d28;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace; }
  .header { padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }
  .header h1 { font-size: 18px; font-weight: 600; }
  .header .badge { font-size: 12px; padding: 2px 8px; border-radius: 12px; background: var(--blue); color: var(--bg); }
  .header .live-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); display: inline-block; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; padding: 16px 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }
  .card .label { font-size: 12px; color: var(--dim); text-transform: uppercase; letter-spacing: 0.5px; }
  .card .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .card .value.green { color: var(--green); }
  .card .value.red { color: var(--red); }
  .card .value.yellow { color: var(--yellow); }
  .card .value.blue { color: var(--blue); }
  .feed { padding: 0 24px 24px; }
  .feed h2 { font-size: 14px; color: var(--dim); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
  .event-list { max-height: 60vh; overflow-y: auto; }
  .event { display: flex; gap: 12px; padding: 8px 12px; border-bottom: 1px solid var(--border); font-size: 13px; align-items: flex-start; }
  .event:hover { background: var(--surface); }
  .event .time { color: var(--dim); white-space: nowrap; font-family: monospace; min-width: 80px; }
  .event .sev { min-width: 20px; text-align: center; }
  .event .tool { color: var(--blue); min-width: 120px; font-family: monospace; }
  .event .agent { color: var(--dim); min-width: 100px; }
  .event .reason { flex: 1; }
  .event .action-allow { color: var(--green); }
  .event .action-deny { color: var(--red); }
  .event .action-redact { color: var(--yellow); }
  .event .action-prompt { color: var(--orange); }
  .event .action-block { color: var(--red); }
</style>
</head>
<body>
<div class="header">
  <h1>🛡️ Runtime Shield — Live Dashboard</h1>
  <span class="badge">LIVE</span>
  <span class="live-dot"></span>
</div>

<div class="grid">
  <div class="card"><div class="label">Total Calls</div><div class="value blue" id="stat-total">0</div></div>
  <div class="card"><div class="label">Allowed</div><div class="value green" id="stat-allowed">0</div></div>
  <div class="card"><div class="label">Denied</div><div class="value red" id="stat-denied">0</div></div>
  <div class="card"><div class="label">Redacted</div><div class="value yellow" id="stat-redacted">0</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value" id="stat-uptime">0s</div></div>
</div>

<div class="feed">
  <h2>Live Event Feed</h2>
  <div class="event-list" id="events"></div>
</div>

<script>
const sevEmoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };
let knownEventCount = 0;
let startTime = Date.now();

function updateStats(s) {
  document.getElementById('stat-total').textContent = s.total || 0;
  document.getElementById('stat-allowed').textContent = s.allowed || 0;
  document.getElementById('stat-denied').textContent = s.denied || 0;
  document.getElementById('stat-redacted').textContent = s.redacted || 0;
}

function formatTime(ts) {
  return new Date(ts * 1000).toLocaleTimeString();
}

function renderEvent(evt) {
  const el = document.getElementById('events');
  const div = document.createElement('div');
  div.className = 'event';
  const actionClass = 'action-' + (evt.action || 'allow');
  div.innerHTML = `
    <span class="time">${formatTime(evt.timestamp || Date.now()/1000)}</span>
    <span class="sev">${sevEmoji[evt.severity] || '⚪'}</span>
    <span class="tool">${evt.tool || 'n/a'}</span>
    <span class="agent">${evt.agent || 'unknown'}</span>
    <span class="${actionClass}">${(evt.action || 'allow').toUpperCase()}</span>
    <span class="reason">${evt.reason || ''}</span>
  `;
  el.insertBefore(div, el.firstChild);
  if (el.children.length > 200) el.removeChild(el.lastChild);
}

// POLLING FALLBACK: Fetch stats + new events every 2 seconds
function pollDashboard() {
  fetch('/api/stats')
    .then(r => r.json())
    .then(data => {
      updateStats(data.stats);
      startTime = Date.now() - (data.uptime * 1000);

      // Check for new events
      const buffered = data.events_buffered || 0;
      if (buffered > knownEventCount) {
        const newCount = buffered - knownEventCount;
        fetch('/api/events?limit=' + newCount)
          .then(r => r.json())
          .then(events => {
            events.forEach(renderEvent);
            knownEventCount = buffered;
          });
      }
    })
    .catch(() => {});
}

// Also try WebSocket for instant updates (may not work due to cross-thread issue)
function connectWS() {
  try {
    const ws = new WebSocket('ws://' + location.host + '/ws');
    ws.onmessage = (e) => { 
      renderEvent(JSON.parse(e.data));
      knownEventCount++;
    };
    ws.onclose = () => { setTimeout(connectWS, 5000); };
  } catch(e) {}
}

// Initial load
fetch('/api/events?limit=50').then(r => r.json()).then(events => {
  events.forEach(renderEvent);
  fetch('/api/stats').then(r => r.json()).then(data => {
    knownEventCount = data.events_buffered || events.length;
    updateStats(data.stats);
    startTime = Date.now() - (data.uptime * 1000);
  });
});

// Poll every 2 seconds (reliable fallback)
setInterval(pollDashboard, 2000);

// Try WebSocket too (for instant updates if it works)
connectWS();

// Update uptime display
setInterval(() => {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  document.getElementById('stat-uptime').textContent = h > 0 ? h+'h '+m+'m' : m+'m '+s%60+'s';
}, 1000);
</script>
</body>
</html>"""

        # Override the default route with our patched dashboard
        @dashboard_app.get("/", response_class=HTMLResponse)
        async def patched_index():
            return PATCHED_DASHBOARD_HTML

        log("✅ Dashboard patched with polling fallback for live updates")

    except Exception as e:
        log(f"⚠️ Dashboard failed to start on port {dashboard_port}: {e}")
        log("ℹ️ Continuing without local dashboard (likely already running in another instance)")

    # ---------------------------------------------------------
    # DYNAMIC CONFIGURATION & SCHEMA NEGOTIATION (DASHBOARD)
    # ---------------------------------------------------------
    tenant_id = os.getenv("SHIELD_TENANT_ID", "customer-delta-99")
    dashboard_api_key = os.getenv("DASHBOARD_API_KEY", "mock-dashboard-key")
    
    dash_client = DashboardClient(
        dashboard_url=f"http://localhost:{dashboard_port}",
        tenant_id=tenant_id,
        api_key=dashboard_api_key
    )
    
    tenant_schema = dash_client.fetch_tenant_schema()
    log(f"✅ Schema acquired for Tenant {tenant_id}. Guardrails active.")
    # In a full implementation, we would override `gw` rules with `tenant_schema` here.

    add_spiffe_dashboard_event(spiffe_cfg)

    # ---------------------------------------------------------
    # EMBEDDED AUDIT AGENT (runs as background thread)
    # ---------------------------------------------------------
    # The audit agent tails bridge.log and uses NIM to detect
    # semantic data leaks. When embedded here, it can push
    # findings to the live dashboard and bump the fraud engine
    # risk score in real-time — no separate process needed.
    AUDIT_API_KEY = os.getenv("NVIDIA_API_KEY", "")
    AUDIT_BASE_URL = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")

    if AUDIT_API_KEY:
        try:
            from audit_agent import AuditAgent

            def _run_audit_agent():
                agent = AuditAgent(
                    api_key=AUDIT_API_KEY,
                    base_url=AUDIT_BASE_URL,
                    fraud_engine=fraud_engine,
                    dashboard_state=dashboard_state
                )
                agent.run()

            audit_thread = threading.Thread(target=_run_audit_agent, daemon=True)
            audit_thread.start()
            log("🕵️ Audit Agent thread started — monitoring bridge.log for semantic violations")

            dashboard_state.add_event({
                "action": "allow",
                "tool": "(audit-agent)",
                "agent": "system",
                "reason": "Embedded Audit Agent activated (NIM semantic analysis enabled)",
                "severity": "low",
                "stage": "audit-startup",
                "timestamp": time.time()
            })
        except Exception as e:
            log(f"⚠️ Audit Agent failed to start: {e}")
            log("ℹ️ Continuing without semantic audit (bridge security layers still active)")
    else:
        log("ℹ️ Audit Agent disabled: NVIDIA_API_KEY not set. Semantic audit will not run.")

    # Start multiple MCP Servers
    mcp_processes.clear()
    mcp_remote_clients.clear()
    tool_map.clear()
    scope_map.clear()

    # Load tool mappings from DB registry
    registered_tools = telemetry.get_registered_tools()
    for t in registered_tools:
        tool_map[t["tool_name"]] = t["provider_name"]
        scope_map[t["tool_name"]] = t["scope"]

    # Strict base allowlist of safe system keys needed for Node/subprocesses on Windows
    base_safe_keys = {
        "SystemRoot", "SystemDrive", "TEMP", "TMP", "PATH", "PATHEXT", 
        "COMSPEC", "USERNAME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", 
        "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", 
        "COMPUTERNAME", "OS", "NUMBER_OF_PROCESSORS", "PROCESSOR_IDENTIFIER", 
        "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "ALLUSERSPROFILE", "PUBLIC", 
        "HOMEDRIVE", "HOMEPATH"
    }

    for r in active_mcp_servers:
        provider = r["provider_name"]
        transport = r.get("transport", "stdio")
        
        if transport == "stdio":
            cmd = [r["command"]] + (r.get("args") or [])
            log(f"🚀 Launching Local MCP Provider [{provider}]: {' '.join(cmd)}")
            
            # Build strict separate environment block for each child process (Phase 1)
            provider_env = {}
            for k in base_safe_keys:
                if k in os.environ:
                    provider_env[k] = os.environ[k]
                elif k.upper() in os.environ:
                    provider_env[k] = os.environ[k.upper()]
                    
            provider_env["SPIFFE_ENABLED"] = "true" if spiffe_cfg["enabled"] else "false"
            provider_env["RUNTIME_ROLE"] = DEFAULT_ROLE
            provider_env["PROVIDER_NAME"] = provider
            
            if provider == "keycloak-provider":
                # keycloak-provider gets ONLY specific Keycloak config vars
                kc_keys = {
                    "KEYCLOAK_URL", "KEYCLOAK_REALM", "KEYCLOAK_CLIENT_ID", 
                    "KEYCLOAK_CLIENT_SECRET", "KEYCLOAK_JWKS_URL", "KEYCLOAK_TOKEN_URL",
                    "SPIFFE_BRIDGE_ID", "SPIFFE_SERVER_ID", "SPIFFE_SVID_PATH", "SPIFFE_BUNDLE_PATH"
                }
                for k in kc_keys:
                    val = os.getenv(k)
                    if val is not None:
                        provider_env[k] = val
            elif provider == "filesystem-provider":
                # filesystem-provider gets NO Keycloak secrets and NO NVIDIA API keys!
                pass
            
            proc = launch_sandboxed_node(
                cmd,
                cwd=PROJECT_DIR,
                env=provider_env,
                allowed_paths=[WORKSPACE_DIR],
                provider_name=provider
            )
            mcp_processes[provider] = proc
        elif transport == "sse":
            url = r.get("url")
            log(f"🚀 Registered Remote SSE MCP Provider [{provider}] connected to {url}")
            client = RemoteSseMcpClient(provider, url)
            mcp_remote_clients[provider] = client

    # =========================
    # INPUT THREAD (Tool Filtering)
    # =========================

    def input_to_node():
        try:
            for line in sys.stdin:
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                    method = data.get("method", "")
                    log(f"📩 Incoming MCP message: {method or '(no method)'}")

                    if method in ("tools/call", "callTool"):
                        # Reload environment dynamically to pick up any new KEYCLOAK_TOKEN written by login.py
                        load_dotenv(dotenv_path=DOTENV_PATH, override=True)

                        params = data.get("params", {})
                        tool_name = params.get("name", "")
                        tool_args = params.get("arguments", {}) or {}

                        # --- CENTRALIZED LLM-AGNOSTIC RUNTIME GOVERNANCE: TOOL NORMALIZATION ---
                        original_tool_name = tool_name
                        raw_clean = tool_name.lower().replace("_", "")
                        
                        # Canonical tool mappings covering PascalCase, camelCase, snake_case
                        canonical_mappings = {
                            "readfile": "read_file",
                            "listdirectory": "list_directory",
                            "writefile": "write_file",
                            "getcurrentuser": "GetCurrentUser",
                            "getusertransactions": "GetUserTransactions",
                            "getsystemconfig": "get_system_config",
                            "fetchinternaldb": "fetch_internal_db",
                            "keycloaklistusers": "keycloak_list_users",
                            "keycloaklistusersessions": "keycloak_list_user_sessions",
                            "keycloakrevokeusersessions": "keycloak_revoke_user_sessions",
                            "keycloakgetuserevents": "keycloak_get_user_events",
                            "keycloaksecurityreport": "keycloak_security_report",
                            "keycloakgeneratepolicy": "keycloak_generate_policy",
                            "keycloakquarantineuser": "keycloak_quarantine_user",
                            "keycloakrundrills": "keycloak_run_drills",
                            "scandependencies": "ScanDependencies",
                            "scansecrets": "ScanSecrets",
                            "getsystemmetrics": "GetSystemMetrics",
                            "getactiveconnections": "GetActiveConnections"
                        }
                        
                        if raw_clean in canonical_mappings:
                            tool_name = canonical_mappings[raw_clean]
                        
                        # Rewrite the tool name in data and params for unified execution
                        if tool_name != original_tool_name:
                            log(f"🔄 [GOVERNANCE] Normalized incoming tool '{original_tool_name}' -> '{tool_name}' for LLM-agnostic compatibility")
                            params["name"] = tool_name
                            if "name" in data.get("params", {}):
                                data["params"]["name"] = tool_name
                                
                        # --- ZERO-TRUST DEFAULT-DENY FOR UNKNOWN/UNSUPPORTED TOOLS ---
                        if tool_name not in tool_map:
                            reason = f"Zero-Trust Block: Unknown or unsupported tool call '{tool_name}' denied by default (Centralized Governance)"
                            log(f"🚫 {reason}")
                            dashboard_state.add_event({
                                "action": "block",
                                "tool": tool_name,
                                "agent": "centralized-governance",
                                "reason": reason,
                                "severity": "high",
                                "stage": "tool-policy",
                                "timestamp": time.time()
                            })
                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "error": {
                                    "code": -32601,
                                    "message": reason
                                }
                            }
                            with stdout_lock:
                                protocol_stdout.write(json.dumps(error_resp) + "\n")
                                protocol_stdout.flush()
                            continue

                        if tool_name in ("read_file", "write_file", "list_directory"):
                            p_val = tool_args.get("path")
                            if p_val and isinstance(p_val, str):
                                norm_p = p_val.replace("\\", "/")
                                if norm_p.lower().startswith("runtime-shield-for-agentic-systems/"):
                                    norm_p = norm_p[len("runtime-shield-for-agentic-systems/"):]
                                    tool_args["path"] = norm_p
                                    if "params" in data and "arguments" in data["params"]:
                                        data["params"]["arguments"]["path"] = norm_p
                        
                        try:
                            # --- AGENT IDENTITY HARDENING (JIT TOKENS) ---
                            if tool_name == "keycloak_run_drills":
                                jit_token = "mock-jit-token"
                                required_scope = "tool:keycloak_report"
                                user_role_val = normalize_role(tool_args.get("role", DEFAULT_ROLE))
                                spiffe_id_val = spiffe_cfg["bridge_id"]
                                trusted_workload_val = True
                                user_id = "admin"
                            else:
                                metadata = params.get("metadata", {})
                                user_token = metadata.get("token") or metadata.get("keycloak_token")
                                
                                # 1. VERIFY USER TOKEN
                                claims = get_token_claims(user_token)
                                
                                # 2. DYNAMIC JIT SCOPE ISSUANCE (Production Least-Privilege)
                                required_scope = scope_map.get(tool_name)
                                if not user_token:
                                    local_identity = f"Role: {DEFAULT_ROLE}"
                                    local_token = os.getenv("KEYCLOAK_TOKEN")
                                    if local_token:
                                        log("⚠️ WARNING: Fallback KEYCLOAK_TOKEN loaded from environment. Dynamic token acquisition should be preferred.")
                                        try:
                                             unverified = jwt.decode(local_token, options={"verify_signature": False})
                                             username = unverified.get("preferred_username")
                                             if username:
                                                 local_identity = f"{username} ({DEFAULT_ROLE})"
                                        except Exception:
                                             pass

                                    log(f"⚠️ AUTH PASSTHROUGH: '{tool_name}' via local client [{local_identity}]")
                                    dashboard_state.add_event({
                                        "action": "allow",
                                        "tool": tool_name,
                                        "agent": f"local [{local_identity}]",
                                        "reason": f"Local client passthrough (scope '{required_scope}' will be exchanged dynamically)",
                                        "severity": "low",
                                        "stage": "keycloak-auth",
                                        "timestamp": time.time()
                                    })
                                else:
                                    user_id_from_token = claims.get("preferred_username") or claims.get("sub") or "unknown"
                                    log(f"🔑 Identity verified: {user_id_from_token}. Dynamic JIT scope '{required_scope}' will be issued for tool '{tool_name}'.")

                                # 3. JIT TOKEN EXCHANGE (DOWNSCOPING)
                                provider_name = tool_map.get(tool_name, "unknown")
                                token_to_exchange = user_token or os.getenv("KEYCLOAK_TOKEN")
                                if not token_to_exchange:
                                    raise ValueError("No Keycloak token provided or found in environment (.env)")
                                
                                log(f"🔄 JIT Dynamic Scope: Requesting ONLY scope '{required_scope}' for tool '{tool_name}' (TTL: 60s)")
                                jit_token = jit_manager.exchange_token(token_to_exchange, required_scope, provider_name)
                                log(f"✅ JIT Token issued: scope='{required_scope}' | tool='{tool_name}' | provider='{provider_name}'")
                                
                                # Replace broad user token with downscoped JIT token before routing to jail
                                if "metadata" not in data["params"]:
                                    data["params"]["metadata"] = {}
                                data["params"]["metadata"]["token"] = jit_token
                                data["params"]["metadata"]["jit_enabled"] = True

                                # Resolve spiffe and role info for authContext
                                spiffe_id_val = spiffe_cfg["bridge_id"]
                                if spiffe_cfg["enabled"]:
                                    spiffe_id_val = tool_args.get("spiffe_id", "") or tool_args.get("_spiffe_id", "") or spiffe_cfg["bridge_id"]
                                user_role_val = normalize_role(tool_args.get("role", DEFAULT_ROLE))
                                trusted_workload_val = True
                                if spiffe_cfg["enabled"]:
                                    trusted_workload_val = spiffe_allowed(spiffe_id_val)

                            # Package the new structured Auth Context
                            if "_meta" not in data["params"]:
                                data["params"]["_meta"] = {}
                            data["params"]["_meta"]["authContext"] = {
                                "requestId": data.get("id"),
                                "jitToken": jit_token,
                                "requiredScope": required_scope,
                                "requiredRole": user_role_val,
                                "workloadSpiffeId": spiffe_id_val,
                                "trustedWorkload": trusted_workload_val,
                                "source": "bridge"
                            }

                            if tool_name != "keycloak_run_drills":
                                user_id = tool_args.get("user_id") or tool_args.get("userId") or tool_args.get("username") or "unknown_user"
                            else:
                                user_id = "admin"

                            # 1. SPIFFE CHECK
                            if spiffe_cfg["enabled"]:
                                spiffe_id = tool_args.get("spiffe_id", "") or tool_args.get("_spiffe_id", "")
                                if not spiffe_id:
                                    spiffe_id = spiffe_cfg["bridge_id"]

                                if not spiffe_allowed(spiffe_id):
                                    log(f"🚫 SPIFFE violation: unauthorized service identity {spiffe_id}")
                                    dashboard_state.add_event({
                                        "action": "block",
                                        "tool": tool_name,
                                        "agent": "claude-desktop",
                                        "reason": f"Unauthorized SPIFFE ID '{spiffe_id}'",
                                        "severity": "high",
                                        "stage": "spiffe-auth",
                                        "timestamp": time.time()
                                    })
                                    spiffe_id = "anonymous-spiffe" # Fallback if totally invalid
                                    
                                    error_resp = {
                                        "jsonrpc": "2.0",
                                        "id": data.get("id"),
                                        "error": {
                                            "code": -32002,
                                            "message": "Tool blocked due to untrusted SPIFFE identity"
                                        }
                                    }
                                    with stdout_lock:
                                        protocol_stdout.write(json.dumps(error_resp) + "\n")
                                        protocol_stdout.flush()
                                    continue

                            # 2. ROLE CHECK
                            user_role = normalize_role(tool_args.get("role", DEFAULT_ROLE))
                            # Inject role so that mcp-firewall matches rule arguments.role correctly
                            if isinstance(tool_args, dict):
                                tool_args["role"] = user_role
                                if "params" in data and "arguments" in data["params"]:
                                    data["params"]["arguments"]["role"] = user_role

                            allowed, required = role_allowed(tool_name, user_role)
                            if not allowed:
                                log(f"🚫 Role violation: {user_role} cannot use {tool_name}")
                                dashboard_state.add_event({
                                    "action": "block",
                                    "tool": tool_name,
                                    "agent": "claude-desktop",
                                    "reason": f"Role '{user_role}' not allowed",
                                    "severity": "high",
                                    "stage": "role-policy",
                                    "timestamp": time.time()
                                })
                                error_resp = {
                                    "jsonrpc": "2.0",
                                    "id": data.get("id"),
                                    "error": {
                                        "code": -32001,
                                        "message": "Tool blocked due to insufficient role"
                                    }
                                }
                                with stdout_lock:
                                    protocol_stdout.write(json.dumps(error_resp) + "\n")
                                    protocol_stdout.flush()
                                continue

                            # --- NE-MO NIM CLOUD CHECK ---
                            is_safe_zone = False
                            if tool_args:
                                for k, v in tool_args.items():
                                    if isinstance(v, str) and "secure-experiment-zone" in v.replace("\\", "/"):
                                        is_safe_zone = True
                                        break

                            if nim_guard.config.get("enabled") and not is_learning and not is_safe_zone:
                                context_text = f"Tool: {tool_name}. Args: {json.dumps(tool_args)}"
                                
                                jb_blocked, jb_reason = nim_guard.check_jailbreak(context_text)
                                if jb_blocked:
                                    log(f"🚫 NE-MO BLOCK: {jb_reason}")
                                    dashboard_state.add_event({
                                        "action": "block",
                                        "tool": tool_name,
                                        "agent": "nemo-jailbreak",
                                        "reason": jb_reason,
                                        "severity": "critical",
                                        "stage": "nemo-guardrails",
                                        "timestamp": time.time()
                                    })
                                    error_resp = {"jsonrpc": "2.0", "id": data.get("id"), "error": {"code": -32004, "message": jb_reason}}
                                    with stdout_lock:
                                        protocol_stdout.write(json.dumps(error_resp) + "\n")
                                        protocol_stdout.flush()
                                    continue

                                tp_blocked, tp_reason = nim_guard.check_topical(context_text)
                                if tp_blocked:
                                    log(f"🚫 NE-MO BLOCK: {tp_reason}")
                                    dashboard_state.add_event({
                                        "action": "block",
                                        "tool": tool_name,
                                        "agent": "nemo-topical",
                                        "reason": tp_reason,
                                        "severity": "high",
                                        "stage": "nemo-guardrails",
                                        "timestamp": time.time()
                                    })
                                    error_resp = {"jsonrpc": "2.0", "id": data.get("id"), "error": {"code": -32005, "message": tp_reason}}
                                    with stdout_lock:
                                        protocol_stdout.write(json.dumps(error_resp) + "\n")
                                        protocol_stdout.flush()
                                    continue

                            # 3. FIREWALL & FRAUD ENGINE CHECK
                            decision = gw.check(tool_name, tool_args, agent=spiffe_id)
                            
                            # Apply Fraud Detection Engine analysis (with risk deduplication)
                            fraud_blocked, final_action, final_reason, final_severity = fraud_engine.analyze(
                                agent=spiffe_id,
                                decision=decision,
                                tool_name=tool_name,
                                tool_args=tool_args,
                                user_id=user_id
                            )

                            if fraud_blocked:
                                decision.blocked = True
                                decision.action = final_action
                                decision.reason = final_reason
                                decision.severity = final_severity

                            # Handle learning mode (from command line or .env)
                            learning_allowed = False
                            if is_learning and decision.blocked:
                                log(f"📚 Learning mode: Logging blocked tool '{tool_name}'")
                                log_discovery(tool_name, tool_args, spiffe_id)
                                learning_allowed = True
                            dashboard_state.add_event({
                                "action": decision.action.value if hasattr(decision.action, 'value') else str(decision.action),
                                "tool": tool_name,
                                "agent": spiffe_id,
                                "reason": decision.reason,
                                "severity": decision.severity.value if hasattr(decision.severity, 'value') else str(decision.severity),
                                "stage": decision.stage,
                                "timestamp": time.time()
                            })

                            if decision.blocked and not learning_allowed:
                                log(f"🚫 Blocked: {decision.reason}")

                                error_resp = {
                                    "jsonrpc": "2.0",
                                    "id": data.get("id"),
                                    "error": {
                                        "code": -32000,
                                        "message": "Tool execution blocked by security policy",
                                        "data": {
                                            "reason": decision.reason,
                                            "severity": decision.severity,
                                            "stage": decision.stage
                                        }
                                    }
                                }

                                with stdout_lock:
                                    protocol_stdout.write(json.dumps(error_resp) + "\n")
                                    protocol_stdout.flush()
                                continue

                            line = json.dumps(data)

                        except Exception as err:
                            log(f"🚫 AUTHENTICATION/POLICY ERROR: JIT Token validation/exchange or policy verification failed: {err}")
                            dashboard_state.add_event({
                                "action": "block",
                                "tool": tool_name,
                                "agent": "security-bridge",
                                "reason": f"JIT Token validation/exchange or policy verification failed: {err}",
                                "severity": "high",
                                "stage": "security-bridge",
                                "timestamp": time.time()
                            })
                            error_resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "error": {
                                    "code": -32003,
                                    "message": f"Unauthorized or security validation failed: {err}"
                                }
                            }
                            with stdout_lock:
                                protocol_stdout.write(json.dumps(error_resp) + "\n")
                                protocol_stdout.flush()
                            continue

                    if not line.endswith("\n"):
                        line += "\n"

                    # Intercept keycloak_run_drills to run them locally on the Python side
                    tool_name = data.get("params", {}).get("name") if data.get("params") else None
                    if tool_name == "keycloak_run_drills":
                        log("🏃 Intercepted keycloak_run_drills tool call in bridge. Running policy verification drills...")
                        try:
                            from run_security_drills import run_drills
                            _, report_str = run_drills()
                            resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "result": {
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": report_str
                                        }
                                    ]
                                }
                            }
                        except Exception as e:
                            resp = {
                                "jsonrpc": "2.0",
                                "id": data.get("id"),
                                "error": {
                                    "code": -32603,
                                    "message": f"Failed to run security drills: {e}"
                                }
                            }
                        with stdout_lock:
                            protocol_stdout.write(json.dumps(resp) + "\n")
                            protocol_stdout.flush()
                        continue

                    # ROUTING TO CORRECT MCP
                    provider = tool_map.get(tool_name) if tool_name else None
                    if provider and provider in mcp_processes:
                        target_proc = mcp_processes[provider]
                        if target_proc.stdin:
                            target_proc.stdin.write(line)
                            target_proc.stdin.flush()
                            log(f"🛤️ Routed '{tool_name}' to local provider '{provider}'")
                    elif provider and provider in mcp_remote_clients:
                        client = mcp_remote_clients[provider]
                        if client.post_url:
                            log(f"🛤️ Routing '{tool_name}' to remote provider '{provider}' via POST: {client.post_url}")
                            def send_post_sync(c=client, d=data):
                                try:
                                    post_headers = {"Content-Type": "application/json"}
                                    try:
                                        spiffe_cfg_val = get_spiffe_config()
                                        if spiffe_cfg_val and spiffe_cfg_val.get("enabled"):
                                            post_headers.update(get_spiffe_headers())
                                    except Exception as e:
                                        pass
                                    resp = requests.post(c.post_url, json=d, headers=post_headers, timeout=10.0)
                                    if resp.status_code not in (200, 202):
                                        log(f"⚠️ Remote provider {c.provider_name} POST returned {resp.status_code}: {resp.text}")
                                except Exception as e:
                                    log(f"⚠️ Error routing request to remote provider {c.provider_name}: {e}")
                            threading.Thread(target=send_post_sync, daemon=True).start()
                        else:
                            log(f"⚠️ POST endpoint for remote provider '{provider}' is not active yet")
                    else:
                        # Fallback: if tool is not in map (e.g. list_tools), send to ALL or first one
                        if method in ("tools/list", "listTools", "notifications/initialized", "notifications/cancelled"):
                            for p_name, p_proc in mcp_processes.items():
                                if p_proc.stdin:
                                    p_proc.stdin.write(line)
                                    p_proc.stdin.flush()
                            for p_name, client in mcp_remote_clients.items():
                                if client.post_url:
                                    def send_post_sync_list(c=client, d=data):
                                        try:
                                            post_headers = {"Content-Type": "application/json"}
                                            try:
                                                spiffe_cfg_val = get_spiffe_config()
                                                if spiffe_cfg_val and spiffe_cfg_val.get("enabled"):
                                                    post_headers.update(get_spiffe_headers())
                                            except Exception as e:
                                                pass
                                            requests.post(c.post_url, json=d, headers=post_headers, timeout=5.0)
                                        except Exception as e:
                                            pass
                                    threading.Thread(target=send_post_sync_list, daemon=True).start()
                        elif method in ("initialize", "ping"):
                            # Send initialize to only ONE provider to prevent duplicate response IDs
                            if mcp_processes:
                                first_proc = next(iter(mcp_processes.values()))
                                if first_proc.stdin:
                                    first_proc.stdin.write(line)
                                    first_proc.stdin.flush()
                            elif mcp_remote_clients:
                                first_client = next(iter(mcp_remote_clients.values()))
                                if first_client.post_url:
                                    def send_init_sync(c=first_client, d=data):
                                        try:
                                            requests.post(c.post_url, json=d, timeout=5.0)
                                        except Exception:
                                            pass
                                    threading.Thread(target=send_init_sync, daemon=True).start()
                        elif provider is None:
                            log(f"⚠️ No provider found for tool '{tool_name}'")

                except Exception as e:
                    log(f"⚠️ Request check error: {e}")

        except Exception as e:
            log(f"Input thread error: {e}")

    # =========================
    # OUTPUT THREAD (Redaction)
    # =========================

    def output_from_node(provider_name, proc):
        try:
            if proc.stdout is None:
                raise RuntimeError(f"Provider {provider_name} stdout is not available")

            for line in proc.stdout:
                line_str = line

                try:
                    # VALIDATE JSON: All MCP messages must be valid JSON to be relayed
                    try:
                        msg = json.loads(line_str)
                    except json.JSONDecodeError:
                        log(f"⚠️ NON-JSON OUTPUT from {provider_name}: {line_str.strip()}")
                        continue # Skip relaying this line to real_stdout

                    # Intercept response for REST tool execute calls to avoid leaking to Claude stdio
                    msg_id = msg.get("id")
                    if msg_id is not None and msg_id in pending_tool_futures:
                        loop = pending_tool_futures[msg_id]._loop
                        loop.call_soon_threadsafe(pending_tool_futures[msg_id].set_result, line_str)
                        continue  # Skip writing this line to protocol_stdout

                    # Merging Tools List Responses from Multiple MCP Providers
                    # Standard tools/list response contains a "result" object with a "tools" list
                    if isinstance(msg, dict) and "result" in msg and isinstance(msg["result"], dict) and "tools" in msg["result"]:
                        tools_list = msg["result"]["tools"] or []
                        global tools_list_aggregator
                        if tools_list_aggregator is not None:
                            is_complete, merged_tools = tools_list_aggregator.add_response(msg_id, provider_name, tools_list)
                            if not is_complete:
                                continue # Wait for other providers to respond
                                
                            # Re-construct aggregated single tools/list response
                            msg["result"]["tools"] = merged_tools
                            line_str = json.dumps(msg) + "\n"

                    current_role = normalize_role(None)

                    # --- DATA PLANE: SLOW SECURITY SCANS ---
                    if current_role != "admin" and is_tool_result_message(msg):
                        # Execute scanning logic with a strict timeout isolated via ThreadPoolExecutor
                        try:
                            future = scan_executor.submit(perform_security_scans, line_str, current_role)
                            line_str = future.result(timeout=SCAN_TIMEOUT_SEC)
                        except TimeoutError:
                            log(f"⚠️ SECURITY SCAN TIMEOUT ({SCAN_TIMEOUT_SEC}s) - falling back to safe local Presidio/regex redaction.")
                            line_str = redact_pii_with_presidio(line_str)
                            dashboard_state.add_event({
                                "action": "redact",
                                "tool": "(response)",
                                "agent": "security-bridge",
                                "reason": f"Security scan timed out after {SCAN_TIMEOUT_SEC}s (Safe local Presidio/regex fallback)",
                                "severity": "medium",
                                "stage": "output-filter-timeout-fallback",
                                "timestamp": time.time()
                            })
                        except Exception as scan_err:
                            log(f"⚠️ Scan execution error: {scan_err} - falling back to safe local Presidio/regex redaction.")
                            line_str = redact_pii_with_presidio(line_str)

                        # 3. Fast Local Manual Redaction Fallback (DISABLED to test Microsoft NLP)
                        # email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                        # manual_redacted = re.sub(email_pattern, '[REDACTED]', line_str)
                        # if manual_redacted != line_str:
                        #     log("✂️ FIREWALL REDACTED sensitive data (Manual Fallback)")
                        #     line_str = manual_redacted
                        #     dashboard_state.add_event({
                        #         "action": "redact",
                        #         "tool": "(response)",
                        #         "agent": "claude-desktop",
                        #         "reason": "Email PII (Fallback)",
                        #         "severity": "medium",
                        #         "stage": "output-filter-fallback",
                        #         "timestamp": time.time()
                        #     })

                        if not line_str.endswith("\n"):
                            line_str += "\n"

                except Exception as e:
                    log(f"⚠️ Redaction error: {e}")

                try:
                    with stdout_lock:
                        protocol_stdout.write(line_str)
                        protocol_stdout.flush()
                except UnicodeEncodeError:
                    # Fallback for Windows terminals failing on emojis
                    with stdout_lock:
                        protocol_stdout.write(line_str.encode('ascii', 'backslashreplace').decode('ascii'))
                        protocol_stdout.flush()

        except Exception as e:
            log(f"🆘 ERROR: Output thread crashed: {e}")
            # Don't let a single encoding error kill the whole relay
            time.sleep(1) 

    # =========================
    # STDERR THREAD
    # =========================

    def stderr_from_node(provider_name, proc):
        try:
            if proc.stderr is None:
                return

            for line in proc.stderr:
                if line.strip():
                    log(f"🟥 [{provider_name}] stderr: {line.strip()}")
        except Exception as e:
            log(f"Node stderr thread error: {e}")

    # =========================
    # CLEANUP
    # =========================

    def cleanup(sig, frame):
        log("Cleaning up...")

        try:
            for provider, proc in mcp_processes.items():
                log(f"Terminating provider {provider}...")
                proc.terminate()
        except Exception:
            pass

        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    # =========================
    # START THREADS
    # =========================

    input_thread = threading.Thread(target=input_to_node, daemon=True)
    input_thread.start()

    output_threads = []
    stderr_threads = []

    for name, proc in mcp_processes.items():
        t_out = threading.Thread(target=output_from_node, args=(name, proc), daemon=True)
        t_err = threading.Thread(target=stderr_from_node, args=(name, proc), daemon=True)
        t_out.start()
        t_err.start()
        output_threads.append(t_out)
        stderr_threads.append(t_err)

    log("⌛ Multi-MCP Bridge active and relaying...")

    # Wait for all processes
    for name, proc in mcp_processes.items():
        proc.wait()
        log(f"🏁 Provider {name} exited with code {proc.returncode}")


if __name__ == "__main__":
    main()