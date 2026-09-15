import sqlite3
import time
import os
import json
import uuid
import threading
import queue
import logging
import sys
from typing import List, Dict, Any, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "telemetry.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "mcp_firewall", "schema", "schema_v2.sql")
LOG_PATH = os.path.join(BASE_DIR, "telemetry.log")

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding='utf-8'),
        logging.StreamHandler(sys.stderr) # sys.stderr might need wrapping but usually okay if console supports it
    ]
)
logger = logging.getLogger("telemetry")

class SuperloglabsExporter:
    def __init__(self, endpoint: Optional[str] = None):
        self.endpoint = endpoint or os.getenv("SUPERLOGLABS_ENDPOINT")
        self.api_key = os.getenv("SUPERLOGLABS_API_KEY")
        
    def export_event(self, event: Dict[str, Any]):
        """
        Formats event as an OpenTelemetry log record / trace span
        and sends/logs it to Superloglabs.
        """
        # Format as standard OTel Log Record
        otel_log = {
            "timeUnixNano": int(event["timestamp"] * 1e9),
            "severityNumber": self._map_severity_number(event["severity"]),
            "severityText": event["severity"].upper(),
            "body": {
                "stringValue": f"Security Action: {event['action'].upper()} by {event['engine']} on tool {event.get('tool')}"
            },
            "attributes": [
                {"key": "identity", "value": {"stringValue": event["identity"]}},
                {"key": "trace_id", "value": {"stringValue": event["trace_id"]}},
                {"key": "request_id", "value": {"stringValue": event["request_id"]}},
                {"key": "session_id", "value": {"stringValue": event["session_id"]}},
                {"key": "tenant_id", "value": {"stringValue": event["tenant_id"]}},
                {"key": "engine", "value": {"stringValue": event["engine"]}},
                {"key": "action", "value": {"stringValue": event["action"]}},
                {"key": "reason", "value": {"stringValue": event.get("reason", "")}},
                {"key": "tool", "value": {"stringValue": event.get("tool", "")}},
            ],
            "traceId": event["trace_id"],
            "spanId": event["request_id"][:16] # Mock span ID from request ID
        }
        
        # If tool execution failed or blocked, run a root-cause analysis
        if event["action"] == "deny" or event["severity"] == "critical" or "fail" in event.get("reason", "").lower():
            rca_result = self.run_root_cause_analysis(event)
            otel_log["attributes"].append({"key": "superloglabs.rca", "value": {"stringValue": json.dumps(rca_result)}})
            
            # Print the root-cause analysis findings to help debugging
            logger.info(f"🚨 [Superloglabs RCA] Root Cause Analysis performed on tool failure:")
            logger.info(f"   - Trigger Event: {event['event_type']} on {event.get('tool')}")
            logger.info(f"   - Root Cause: {rca_result['root_cause']}")
            logger.info(f"   - Recommendation: {rca_result['recommendation']}")
            if rca_result.get("pr_prepared"):
                logger.info(f"   - [AUTO-FIX] Prepared PR Fix: {rca_result['pr_fix_summary']}")
        
        if self.endpoint:
            try:
                headers = {"Content-Type": "application/json"}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"
                requests.post(self.endpoint, json=otel_log, headers=headers, timeout=2.0)
            except Exception:
                pass
                
    def _map_severity_number(self, sev: str) -> int:
        s = sev.lower()
        if s == "info": return 9
        if s == "warning": return 13
        if s == "critical": return 17
        return 9
        
    def run_root_cause_analysis(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes tool failures/blocks to perform root-cause analysis
        and automatically prepare code fixes (as simulated PRs).
        """
        tool = event.get("tool", "unknown")
        reason = event.get("reason", "")
        
        rca = {
            "analyzed_at": time.time(),
            "event_id": event["event_id"],
            "tool": tool,
            "root_cause": "Unknown tool execution failure.",
            "recommendation": "Check upstream server availability.",
            "pr_prepared": False
        }
        
        # Analyze known failure signatures (e.g. policy violations, path traversals, internal tool bugs)
        if "directory traversal" in reason.lower() or "../" in str(event.get("resource", "")):
            rca["root_cause"] = "Agent attempted to escape sandbox workspace via path traversal (../../)."
            rca["recommendation"] = "Enforce stricter path validation inside the tool wrapper."
            rca["pr_prepared"] = True
            rca["pr_fix_summary"] = "Stricter path sanitization using os.path.realpath and boundary checking."
        elif "rbac_deny" in event["event_type"].lower() or "deny" in event["action"]:
            rca["root_cause"] = f"Insufficient scope/role for tool '{tool}'. Standard user tried to invoke restricted tool."
            rca["recommendation"] = "Assign proper OAuth/Keycloak scopes or map user to the admin group."
            rca["pr_prepared"] = False
        elif "pii" in event["event_type"].lower():
            rca["root_cause"] = "Data loss prevention filter blocked transmission of sensitive PII data."
            rca["recommendation"] = "Enable inline redaction instead of blocking, or strip PII before sending to LLM."
            rca["pr_prepared"] = False
            
        return rca

superloglabs_exporter = SuperloglabsExporter()

class TelemetryEventBus:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.queue = queue.Queue()
        self._init_db()
        self._stop_event = threading.Event()
        self._writer_thread = threading.Thread(target=self._process_queue, daemon=True)
        self._writer_thread.start()

    def _get_conn(self):
        # Increased timeout and added busy_timeout for Windows stability
        conn = sqlite3.connect(self.db_path, timeout=60)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize the database using schema_v2.sql."""
        try:
            with self._get_conn() as conn:
                if os.path.exists(SCHEMA_PATH):
                    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
                        conn.executescript(f.read())
                    logger.info("Database initialized with Schema v2")
                else:
                    logger.warning(f"Schema file not found at {SCHEMA_PATH}. Falling back to basic init.")
                    # Basic fallback if schema file is missing
                    conn.execute("CREATE TABLE IF NOT EXISTS telemetry_events (event_id TEXT PRIMARY KEY, timestamp REAL)")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            # FAIL-CLOSED: Telemetry failure should be logged to disk at least
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"CRITICAL: DB INIT FAILURE: {e}\n")

    def log_event(self, 
                  tenant_id: str, 
                  engine: str, 
                  event_type: str, 
                  severity: str,
                  action: str,
                  identity: Optional[str] = "unknown",
                  trace_id: Optional[str] = None,
                  request_id: Optional[str] = None,
                  session_id: Optional[str] = None,
                  tool: Optional[str] = None,
                  resource: Optional[str] = None,
                  reason: Optional[str] = None,
                  policy_version: str = "1.0.0",
                  details: Dict[str, Any] = None):
        """Standardized event logging. Emits to an internal queue for async processing."""
        event = {
            "event_id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "identity": identity,
            "trace_id": trace_id or str(uuid.uuid4()),
            "request_id": request_id or str(uuid.uuid4()),
            "session_id": session_id or "unknown",
            "tenant_id": tenant_id,
            "engine": engine,
            "event_type": event_type,
            "severity": severity,
            "tool": tool,
            "resource": resource,
            "action": action,
            "reason": reason,
            "policy_version": policy_version,
            "details": json.dumps(details or {})
        }
        self.queue.put(event)

    def _process_queue(self):
        """Background worker to write events to SQLite."""
        while not self._stop_event.is_set() or not self.queue.empty():
            try:
                # Get with timeout to allow checking stop event periodically
                event = self.queue.get(timeout=0.5)
                self._write_to_db(event)
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"❌ Error in telemetry writer thread: {e}")

    def _write_to_db(self, event: Dict[str, Any]):
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                # 1. Log Event
                cursor.execute('''
                    INSERT INTO telemetry_events 
                    (event_id, timestamp, identity, trace_id, request_id, session_id, tenant_id, engine, 
                     event_type, severity, tool, resource, action, reason, policy_version, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event["event_id"], event["timestamp"], event["identity"], event["trace_id"],
                    event["request_id"], event["session_id"], event["tenant_id"], event["engine"],
                    event["event_type"], event["severity"], event["tool"], event["resource"],
                    event["action"], event["reason"], event["policy_version"], event["details"]
                ))

                # 2. Update Tenant Metrics
                is_blocked = 1 if event["action"] in ("deny", "block") else 0
                is_redacted = 1 if event["action"] == "redact" else 0
                
                cursor.execute('''
                    INSERT INTO tenant_registry (tenant_id, last_seen, total_requests, blocked_requests, redacted_requests)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(tenant_id) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        total_requests = total_requests + 1,
                        blocked_requests = blocked_requests + ?,
                        redacted_requests = redacted_requests + ?
                ''', (event["tenant_id"], event["timestamp"], is_blocked, is_redacted, is_blocked, is_redacted))

                # 3. Update Risk State (If event is from risk engine or is a denial)
                if event["engine"] == "risk_engine" or is_blocked:
                    # This will be refined when risk_engine.py is implemented
                    pass

                # 4. Superloglabs: Automatically group repeating alert noise into single "incidents"
                if is_blocked or event["severity"] == "critical":
                    try:
                        self._correlate_incident(cursor, event)
                    except Exception as inc_err:
                        logger.error(f"⚠️ Failed to correlate incident: {inc_err}")

                conn.commit()
                
            # 5. Export to Superloglabs Observability Layer (OTel Format)
            try:
                superloglabs_exporter.export_event(event)
            except Exception as exp_err:
                pass
                
        except Exception as e:
            logger.error(f"❌ Failed to write event to DB: {e}")
            # Fallback to file log on DB failure
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"FALLBACK: {json.dumps(event)}\n")

    def _correlate_incident(self, cursor, event: Dict[str, Any]):
        """
        Automatically group repeating alert noise into single 'incidents'.
        Checks if an open incident exists for the same tenant & engine within the last 5 minutes.
        """
        now = event["timestamp"]
        window = 300 # 5 minutes
        
        # Search for an open incident for the same tenant and severity/engine within the window
        cursor.execute('''
            SELECT incident_id, affected_sessions, description FROM security_incidents
            WHERE tenant_id = ? AND status = 'open' AND start_time >= ?
            LIMIT 1
        ''', (event["tenant_id"], now - window))
        
        row = cursor.fetchone()
        if row:
            # Group into existing incident
            incident_id, affected_sessions, description = row
            sessions = set(affected_sessions.split(",")) if affected_sessions else set()
            sessions.add(event["session_id"])
            new_sessions = ",".join(sessions)
            
            # Update the incident's end time and list of affected sessions
            cursor.execute('''
                UPDATE security_incidents
                SET end_time = ?, affected_sessions = ?
                WHERE incident_id = ?
            ''', (now, new_sessions, incident_id))
            logger.info(f"🚨 [Superloglabs] Grouped event {event['event_id']} into existing Incident {incident_id}")
        else:
            # Create a new aggregated incident
            incident_id = str(uuid.uuid4())
            description = f"Aggregated security alerts from {event['engine']} engine. Reason: {event.get('reason', 'None')}"
            cursor.execute('''
                INSERT INTO security_incidents (incident_id, tenant_id, start_time, end_time, status, severity, description, affected_sessions)
                VALUES (?, ?, ?, ?, 'open', ?, ?, ?)
            ''', (incident_id, event["tenant_id"], now, now, event["severity"], description, event["session_id"]))
            logger.info(f"🚨 [Superloglabs] Created new aggregated security Incident {incident_id} for tenant {event['tenant_id']}")

    def get_recent_events(self, limit: int = 100, tenant_id: str = None) -> List[Dict[str, Any]]:
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                if tenant_id and tenant_id != "all":
                    cursor.execute('SELECT * FROM telemetry_events WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?', (tenant_id, limit))
                else:
                    cursor.execute('SELECT * FROM telemetry_events ORDER BY timestamp DESC LIMIT ?', (limit,))
                return [dict(row) for row in cursor.fetchall()]
        except:
            return []

    def get_metrics(self) -> Dict[str, Any]:
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                metrics = {}
                cursor.execute('SELECT COUNT(*) FROM telemetry_events')
                total = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE action = "deny" OR action = "block"')
                blocked = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE action = "allow"')
                allowed = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE action = "redact"')
                redacted = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE severity = "critical"')
                high_risk = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM tenant_registry WHERE status = "online"')
                active_tenants = cursor.fetchone()[0]
                
                return {
                    "total_requests": total,
                    "blocked_requests": blocked,
                    "allowed_requests": allowed,
                    "redacted_requests": redacted,
                    "high_risk_events": high_risk,
                    "active_tenants": active_tenants,
                    
                    # Add UI expected keys for frontend stats calculation compatibility
                    "total": total,
                    "allowed": allowed,
                    "denied": blocked,
                    "redacted": redacted
                }
        except:
            return {"total_requests": 0, "blocked_requests": 0, "high_risk_events": 0, "active_tenants": 0, "total": 0, "allowed": 0, "denied": 0, "redacted": 0}

    def get_timeline(self, session_id: str) -> List[Dict[str, Any]]:
        """Reconstruct an incident timeline for a session."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM telemetry_events WHERE session_id = ? ORDER BY timestamp ASC', (session_id,))
                return [dict(row) for row in cursor.fetchall()]
        except:
            return []

    def get_analytics(self) -> Dict[str, Any]:
        """Calculate governance analytics."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT tool, COUNT(*) as count FROM telemetry_events WHERE action = "deny" OR action = "block" GROUP BY tool ORDER BY count DESC LIMIT 5')
                top_denied = [dict(row) for row in cursor.fetchall()]
                
                cursor.execute('SELECT strftime("%H:%M", datetime(timestamp, "unixepoch")) as minute, COUNT(*) as count FROM telemetry_events WHERE timestamp > ? GROUP BY minute ORDER BY minute ASC', (time.time() - 3600,))
                trends = [dict(row) for row in cursor.fetchall()]
                
                # Distribution of decisions by Engine
                cursor.execute('SELECT engine, COUNT(*) as count FROM telemetry_events GROUP BY engine')
                engines = [dict(row) for row in cursor.fetchall()]
 
                # Distribution by Severity
                cursor.execute('SELECT severity, COUNT(*) as count FROM telemetry_events GROUP BY severity')
                risk = [dict(row) for row in cursor.fetchall()]
 
                # Top Personas
                cursor.execute('SELECT role, COUNT(*) as count FROM telemetry_events GROUP BY role ORDER BY count DESC LIMIT 5')
                personas = [dict(row) for row in cursor.fetchall()]

                return {
                    "top_denied_tools": top_denied, 
                    "attack_trends": trends,
                    "engine_distribution": engines,
                    "risk_distribution": risk,
                    "top_personas": personas
                }
        except Exception as e:
            logger.error(f"Analytics error: {e}")
            return {
                "top_denied_tools": [], 
                "attack_trends": [],
                "engine_distribution": [],
                "risk_distribution": [],
                "top_personas": []
            }

    def stop(self):
        """Gracefully stop and flush all events."""
        # Process remaining queue items before stopping
        while not self.queue.empty():
            time.sleep(0.1)
        self._stop_event.set()
        self._writer_thread.join(timeout=5)

    def register_mcp(self, mcp_id: str, provider_name: str, transport: str, command: str = None, args: list = None, url: str = None, active: int = 1):
        import json
        import time
        args_str = json.dumps(args or [])
        now = time.time()
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO mcp_registry (mcp_id, provider_name, transport, command, args, url, active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mcp_id) DO UPDATE SET
                    provider_name = excluded.provider_name,
                    transport = excluded.transport,
                    command = excluded.command,
                    args = excluded.args,
                    url = excluded.url,
                    active = excluded.active,
                    updated_at = excluded.updated_at
            ''', (mcp_id, provider_name, transport, command, args_str, url, active, now, now))
            conn.commit()

    def get_mcp_registry(self) -> List[Dict[str, Any]]:
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM mcp_registry')
                result = []
                for row in cursor.fetchall():
                    d = dict(row)
                    if d.get("args"):
                        try:
                            d["args"] = json.loads(d["args"])
                        except:
                            d["args"] = []
                    else:
                        d["args"] = []
                    result.append(d)
                return result
        except Exception as e:
            logger.error(f"Error reading MCP registry: {e}")
            return []

    def delete_mcp(self, mcp_id: str):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT provider_name FROM mcp_registry WHERE mcp_id = ?', (mcp_id,))
            row = cursor.fetchone()
            if row:
                provider_name = row[0]
                cursor.execute('DELETE FROM mcp_registry_tools WHERE provider_name = ?', (provider_name,))
            cursor.execute('DELETE FROM mcp_registry WHERE mcp_id = ?', (mcp_id,))
            conn.commit()

    def sync_mcp_tools(self, provider_name: str, tools_list: List[Dict[str, Any]]):
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM mcp_registry_tools WHERE provider_name = ?', (provider_name,))
            for t in tools_list:
                tool_name = t.get("name")
                scope = t.get("scope")
                role = t.get("required_role") or t.get("role") or "user"
                cursor.execute('''
                    INSERT INTO mcp_registry_tools (tool_name, provider_name, scope, required_role)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(tool_name) DO UPDATE SET
                        provider_name = excluded.provider_name,
                        scope = excluded.scope,
                        required_role = excluded.required_role
                ''', (tool_name, provider_name, scope, role))
            conn.commit()

    def get_registered_tools(self) -> List[Dict[str, Any]]:
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM mcp_registry_tools')
                return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error reading registered tools: {e}")
            return []

    def clear_events(self):
        """Purges all telemetry events and resets metrics in database."""
        try:
            with self._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM telemetry_events')
                cursor.execute('DELETE FROM session_risk')
                cursor.execute('DELETE FROM tenant_registry')
                conn.commit()
            logger.info("🧹 Telemetry events and session risk tables cleared successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to clear telemetry events: {e}")
            return False

# Singleton instance for the system
bus = TelemetryEventBus()

def log_event(**kwargs):
    bus.log_event(**kwargs)

def get_recent_events(**kwargs):
    return bus.get_recent_events(**kwargs)

def get_metrics():
    return bus.get_metrics()

def get_timeline(session_id: str):
    return bus.get_timeline(session_id)

def get_analytics():
    return bus.get_analytics()

def clear_events():
    return bus.clear_events()

def register_mcp(**kwargs):
    bus.register_mcp(**kwargs)

def get_mcp_registry():
    return bus.get_mcp_registry()

def delete_mcp(mcp_id: str):
    bus.delete_mcp(mcp_id)

def sync_mcp_tools(provider_name: str, tools_list: list):
    bus.sync_mcp_tools(provider_name, tools_list)

def get_registered_tools():
    return bus.get_registered_tools()

