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
                is_blocked = 1 if event["action"] == "deny" else 0
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

                conn.commit()
        except Exception as e:
            logger.error(f"❌ Failed to write event to DB: {e}")
            # Fallback to file log on DB failure
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(f"FALLBACK: {json.dumps(event)}\n")

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
                metrics["total_requests"] = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE action = "deny"')
                metrics["blocked_requests"] = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE action = "allow"')
                metrics["allowed_requests"] = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE action = "redact"')
                metrics["redacted_requests"] = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM telemetry_events WHERE severity = "critical"')
                metrics["high_risk_events"] = cursor.fetchone()[0]
                cursor.execute('SELECT COUNT(*) FROM tenant_registry WHERE status = "online"')
                metrics["active_tenants"] = cursor.fetchone()[0]
                return metrics
        except:
            return {"total_requests": 0, "blocked_requests": 0, "high_risk_events": 0, "active_tenants": 0}

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
                cursor.execute('SELECT tool, COUNT(*) as count FROM telemetry_events WHERE action = "deny" GROUP BY tool ORDER BY count DESC LIMIT 5')
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
