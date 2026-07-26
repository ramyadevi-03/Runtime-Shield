import os
import re
import time
import json
import requests
from dotenv import load_dotenv

# Load configuration
load_dotenv()
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(PROJECT_DIR, "bridge.log")
API_KEY = os.getenv("NVIDIA_API_KEY", "")
BASE_URL = os.getenv("NIM_BASE_URL", "https://integrate.api.nvidia.com/v1")

# ── Governance Memory Layer ───────────────────────────────────────
try:
    from governance_memory.writer import MemoryWriter
    from governance_memory.scanner import MemoryScanner
    _memory_writer  = MemoryWriter(base_dir=PROJECT_DIR)
    _memory_scanner = MemoryScanner(base_dir=PROJECT_DIR)
except Exception as _mem_err:
    _memory_writer  = None
    _memory_scanner = None
    print(f"[AuditAgent] ⚠️ Governance Memory not available: {_mem_err}", flush=True)
# ────────────────────────────────────────────────────────────

# Llama Guard 4 safety categories mapping
LLAMA_GUARD_CATEGORIES = {
    "S1": "Violent Crimes",
    "S2": "Non-Violent Crimes (incl. data theft/exfiltration)",
    "S3": "Sex-Related Crimes",
    "S4": "Child Sexual Exploitation",
    "S5": "Defamation",
    "S6": "Specialized Advice (unauthorized)",
    "S7": "Privacy Violations (PII/sensitive data leaks)",
    "S8": "Intellectual Property",
    "S9": "Indiscriminate Weapons",
    "S10": "Hate Speech",
    "S11": "Suicide & Self-Harm",
    "S12": "Sexual Content",
    "S13": "Elections & Political",
    "S14": "Code Interpreter Abuse",
}

def log_audit(msg: str):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    try:
        print(f"[AUDIT][{timestamp}] {msg}")
    except UnicodeEncodeError:
        print(f"[AUDIT][{timestamp}] {msg.encode('ascii', 'replace').decode('ascii')}")


def get_spiffe_headers() -> dict:
    import urllib.parse
    headers = {}
    spiffe_id = os.getenv("SPIFFE_BRIDGE_ID", "spiffe://runtime-shield/bridge")
    _certs_dir = os.path.join(PROJECT_DIR, "spire", "certs")
    bridge_crt_path = os.path.join(_certs_dir, "bridge.crt")
    cert_pem = None
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


class AuditAgent:
    def __init__(self, api_key: str, base_url: str, fraud_engine=None, dashboard_state=None):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        self.last_position = 0
        # Bridge integration hooks (set when running as embedded thread)
        self.fraud_engine = fraud_engine
        self.dashboard_state = dashboard_state
        # Governance Memory references (module-level singletons)
        self.memory_writer  = _memory_writer
        self.memory_scanner = _memory_scanner

    def _parse_guard_response(self, guard_text: str) -> tuple[bool, int, list[str]]:
        """
        Parse Llama Guard 4 response.
        
        Returns:
            (is_unsafe, score, categories)
            - is_unsafe: True if content is flagged
            - score: Mapped safety score 0-10
            - categories: List of violated category codes (e.g. ['S2', 'S7'])
        """
        guard_text = guard_text.strip().lower()
        
        if guard_text.startswith("safe"):
            return False, 0, []
        
        if guard_text.startswith("unsafe"):
            # Extract category codes like S1, S2, S7 from response
            categories = re.findall(r'S\d+', guard_text, re.IGNORECASE)
            categories = [c.upper() for c in categories]
            
            # Map to severity score based on categories
            # Privacy (S7), Crime (S2), Code abuse (S14) are most relevant for our use case
            high_severity = {"S2", "S4", "S7", "S9", "S14"}
            
            if any(c in high_severity for c in categories):
                score = 8  # Critical
            elif len(categories) >= 2:
                score = 7  # Multiple violations
            else:
                score = 5  # Single violation
            
            return True, score, categories
        
        # Fallback: if response is unexpected, treat as safe
        log_audit(f"⚠️ Unexpected Llama Guard response format: {guard_text[:100]}")
        return False, 0, []

    def analyze_conversation_block(self, block: str):
        """Uses Llama Guard 4 to analyze a block of conversation for safety violations."""
        if not self.api_key:
            return
        
        # Clean the block to reconstruct the conversation and remove logs/JSON garbage
        lines = block.split("\n")
        cleaned_conversation = []
        assistant_reply = []
        
        for line in lines:
            if "User Prompt: " in line:
                prompt_text = line.split("User Prompt: ", 1)[1].strip()
                if prompt_text:
                    cleaned_conversation.append(f"User: {prompt_text}")
            elif "DEBUG YIELD: data: " in line:
                try:
                    json_str = line.split("DEBUG YIELD: data: ", 1)[1].strip()
                    if json_str == "[DONE]":
                        continue
                    chunk = json.loads(json_str)
                    content = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                    if content:
                        assistant_reply.append(content)
                except Exception:
                    pass
            elif "🚫 RBAC BLOCK:" in line or "🚫 NE-MO BLOCK:" in line:
                cleaned_conversation.append(f"Security Alert: {line}")
                
        if assistant_reply:
            cleaned_conversation.append(f"Assistant: {''.join(assistant_reply)}")
            
        cleaned_block = "\n".join(cleaned_conversation)
        
        # If there is no active conversation content in the log block, skip auditing.
        # This prevents false positive Llama Guard 4 flags on HTTP debug prints, startup lines, and raw JSON wrappers.
        if not cleaned_block.strip() or (len(cleaned_conversation) == 1 and cleaned_conversation[0].startswith("Security Alert:")):
            log_audit("✅ No active conversation content in log block to audit. Skipping.")
            return

        log_audit(f"🔍 Reconstructed conversation for Llama Guard audit:\n{cleaned_block}")

        # ── 🧠 MEMORY CONTEXT: Read historical context before sending to Llama Guard ──
        mem_context = self._lookup_memory_context(block)
        if mem_context:
            log_audit(f"🧠 Memory context: {mem_context}")
        # ────────────────────────────────────────────────────────────────────────────

        endpoint = f"{self.base_url}/chat/completions"
        try:
            # Format the conversation for Llama Guard 4's expected input
            data = {
                "model": "meta/llama-guard-4-12b",
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            "Review this AI agent conversation log for security violations "
                            "(data exfiltration, PII leaks, unauthorized access, prompt injection):\n\n"
                            + cleaned_block[:3000]
                        )
                    }
                ],
                "max_tokens": 50
            }
            req_headers = self.headers.copy()
            req_headers.update(get_spiffe_headers())
            response = requests.post(endpoint, headers=req_headers, json=data, timeout=30)
            if response.status_code == 200:
                result = response.json().get("choices", [{}])[0].get("message", {}).get("content", "").strip()
                is_unsafe, score, categories = self._parse_guard_response(result)

                # Store mem_context reference for _handle_audit_finding
                self._current_mem_context = mem_context
                self._current_block = block
                
                # --- ROLE-AWARE ADJUSTMENT ---
                # Detect if the log block we just read belongs to an Admin
                is_admin = "Role: admin" in block
                if is_admin and "S14" in categories:
                    log_audit("ℹ️ Admin detected: Downgrading S14 (Code Abuse) severity.")
                    # If it was only S14, make it safe. If it had others, just lower the score.
                    if len(categories) == 1:
                        is_unsafe = False
                        score = 0
                    else:
                        score = 5 # Downgrade from 8 (Critical) to 5 (Warning)
                
                # Build human-readable category description
                cat_descriptions = [
                    f"{c}: {LLAMA_GUARD_CATEGORIES.get(c, 'Unknown')}" 
                    for c in categories
                ]
                cat_str = ", ".join(cat_descriptions) if cat_descriptions else "none"
                
                if is_unsafe:
                    log_audit(f"🚨 Llama Guard UNSAFE (Score {score}/10) — Categories: {cat_str}")
                else:
                    log_audit(f"✅ Llama Guard SAFE — No violations detected")

                # --- BRIDGE INTEGRATION: Push findings to dashboard + fraud engine ---
                self._handle_audit_finding(score, f"{'UNSAFE' if is_unsafe else 'SAFE'} — Categories: {cat_str}", categories)

            else:
                log_audit(f"Error calling Llama Guard: {response.status_code} - {response.text}")
        except requests.exceptions.Timeout:
            log_audit("⚠️ Llama Guard audit timed out. Consider increasing timeout.")
        except Exception as e:
            log_audit(f"Exception during Llama Guard audit: {e}")

    def _handle_audit_finding(self, score: int, description: str, categories: list[str] = None):
        """Push audit findings to the dashboard, fraud engine, AND governance memory."""
        if score < 3:
            # 🧠 MEMORY: Even SAFE findings update agent trust if they have memory context
            if hasattr(self, '_current_mem_context') and self._current_mem_context:
                pass  # Future: log safe audit confirmation to session
            return  # Safe — nothing to report

        # Determine severity based on score
        if score >= 8:
            severity = "critical"
            action = "deny"
        elif score >= 5:
            severity = "high"
            action = "redact"
        else:
            severity = "medium"
            action = "allow"

        # 1. Push event to Live Dashboard
        if self.dashboard_state:
            try:
                cat_str = ", ".join(categories) if categories else ""
                self.dashboard_state.add_event({
                    "action": action,
                    "tool": "(audit-agent)",
                    "agent": "llama-guard-4",
                    "reason": f"Llama Guard Score: {score}/10 — {description[:150]}",
                    "severity": severity,
                    "stage": "post-hoc-audit",
                    "timestamp": time.time()
                })
                log_audit(f"📊 Dashboard event posted (severity: {severity})")
            except Exception as e:
                log_audit(f"⚠️ Failed to post dashboard event: {e}")

        # 2. Bump fraud engine risk score for high-severity findings
        if self.fraud_engine and score >= 5:
            try:
                risk_bump = score * 5  # Score 7 = +35 risk, Score 10 = +50 risk
                with self.fraud_engine.lock:
                    for agent_id in list(self.fraud_engine.agent_risk_scores.keys()):
                        old_score = self.fraud_engine.agent_risk_scores[agent_id]
                        self.fraud_engine.agent_risk_scores[agent_id] += risk_bump
                        log_audit(
                            f"🚨 Fraud engine risk bumped for '{agent_id}': "
                            f"{old_score} → {self.fraud_engine.agent_risk_scores[agent_id]} (+{risk_bump})"
                        )
                log_audit(f"🚨 AUDIT AGENT: Fraud engine risk bumped by {risk_bump} across all agents")
            except Exception as e:
                log_audit(f"⚠️ Failed to bump fraud engine risk: {e}")

        # 3. 🧠 MEMORY: Write Llama Guard finding to governance memory
        self._write_to_memory(score, description, categories or [])

    # ── Governance Memory Methods ───────────────────────────────────────────

    def _lookup_memory_context(self, block: str) -> str | None:
        """
        Before running Llama Guard, scan the memory files for context about
        any agent IDs mentioned in this log block.

        Returns a short human-readable context string, or None if no history.
        """
        if not self.memory_scanner:
            return None

        try:
            # Try to extract an agent/SPIFFE ID from the log block
            agent_match = re.search(r'spiffe://[^\s"\)]+', block)
            agent_id = agent_match.group(0) if agent_match else None

            if not agent_id:
                return None

            # Run a memory scan with a neutral tool name (audit context)
            ctx = self.memory_scanner.scan(
                agent_id=agent_id,
                tool_name="(audit-agent)",
                tool_args={},
            )

            if not ctx.agent_found_in_memory:
                return None

            parts = []
            if ctx.agent_trust_level != "new":
                parts.append(f"Agent trust: {ctx.agent_trust_level}")
            if ctx.historical_blocks > 0:
                parts.append(f"{ctx.historical_blocks} prior blocks")
            if ctx.known_attack_match:
                parts.append(f"known pattern: {ctx.known_attack_match}")

            return " | ".join(parts) if parts else None

        except Exception as e:
            log_audit(f"[GovernanceMemory] ⚠️ Memory context lookup failed: {e}")
            return None

    def _write_to_memory(self, score: int, description: str, categories: list[str]):
        """
        Write every Llama Guard finding (score >= 3) to governance memory.

        Writes to:
          - long_term/incident_history.md  (severity log)
          - long_term/agent_profiles.md    (agent profile update)
          - short_term/active_threats.md   (if high severity)
        """
        if not self.memory_writer:
            return

        try:
            # Determine severity label
            if score >= 8:
                severity = "critical"
                action   = "deny"
            elif score >= 5:
                severity = "high"
                action   = "deny"
            else:
                severity = "medium"
                action   = "allow"

            # Extract agent ID from current block if available
            block = getattr(self, '_current_block', '')
            agent_match = re.search(r'spiffe://[^\s"\)]+', block)
            agent_id  = agent_match.group(0) if agent_match else "llama-guard-audit"

            # Build reason string
            cat_str = ", ".join(categories) if categories else "none"
            reason  = f"Llama Guard Score {score}/10 — Categories: {cat_str} — {description[:120]}"

            # Use a synthetic audit session ID so it shows up in the session log
            session_id = f"audit-{int(time.time())}"

            self.memory_writer.record_decision(
                session_id=session_id,
                agent_id=agent_id,
                user_id="llama-guard-4",
                user_role="audit-agent",
                tool_name="(audit-agent)",
                tool_args={"categories": cat_str, "score": str(score)},
                action=action,
                reason=reason,
                severity=severity,
                risk_score=score * 10,
                memory_context=(
                    {"known_attack_match": getattr(self, '_current_mem_context', None)}
                    if getattr(self, '_current_mem_context', None) else None
                ),
            )

            log_audit(f"🧠 Memory: Llama Guard finding written to governance memory (session: {session_id})")

        except Exception as e:
            log_audit(f"[GovernanceMemory] ⚠️ Non-fatal memory write error: {e}")
    # ────────────────────────────────────────────────────────────────────────────

    def run(self):
        log_audit(f"Audit Agent active (Llama Guard 4). Monitoring {LOG_PATH}...")
        
        # Initialize position to end of file if it exists, or start
        if os.path.exists(LOG_PATH):
            self.last_position = os.path.getsize(LOG_PATH)

        while True:
            try:
                if not os.path.exists(LOG_PATH):
                    time.sleep(5)
                    continue

                current_size = os.path.getsize(LOG_PATH)
                if current_size > self.last_position:
                    with open(LOG_PATH, "r", encoding="utf-8") as f:
                        f.seek(self.last_position)
                        new_data = f.read()
                        self.last_position = current_size
                        
                        if new_data.strip():
                            log_audit("New activity detected. Running Llama Guard 4 audit...")
                            self.analyze_conversation_block(new_data)
                
                time.sleep(10) # Review every 10 seconds
            except KeyboardInterrupt:
                break
            except Exception as e:
                log_audit(f"Loop error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    if not API_KEY:
        print("❌ Error: NVIDIA_API_KEY not found in environment.")
    else:
        agent = AuditAgent(API_KEY, BASE_URL)
        agent.run()
