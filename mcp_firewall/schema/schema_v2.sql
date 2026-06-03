-- Runtime Shield Security Datastore Schema v2
-- Optimizing for telemetry normalization, correlation, and high-concurrency access.

-- Enable WAL mode for high concurrency (handled in Python connection init)
-- PRAGMA journal_mode=WAL;

-- 🛡️ SECURITY EVENTS (Audit Log)
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id TEXT PRIMARY KEY,
    timestamp REAL NOT NULL,
    trace_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    engine TEXT NOT NULL, -- policy_engine, redaction_engine, risk_engine
    identity TEXT DEFAULT "unknown",
    event_type TEXT NOT NULL, -- rbac_deny, pii_redact, injection_blocked
    severity TEXT NOT NULL, -- info, warning, critical
    tool TEXT,
    resource TEXT,
    action TEXT NOT NULL, -- allow, deny, redact
    reason TEXT,
    policy_version TEXT,
    details TEXT -- JSON blob for engine-specific metadata
);

CREATE INDEX IF NOT EXISTS idx_telemetry_trace ON telemetry_events(trace_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_session ON telemetry_events(session_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_tenant ON telemetry_events(tenant_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry_events(timestamp DESC);

-- 📉 SESSION RISK (Active Reputation)
CREATE TABLE IF NOT EXISTS session_risk (
    session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    risk_score INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active', -- active, terminated, suspicious
    threat_state TEXT DEFAULT 'healthy', -- healthy, suspicious, under_attack
    last_updated REAL NOT NULL,
    violation_count INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_risk_score ON session_risk(risk_score DESC);

-- 🏢 TENANT REGISTRY (Health & Metrics)
CREATE TABLE IF NOT EXISTS tenant_registry (
    tenant_id TEXT PRIMARY KEY,
    last_seen REAL NOT NULL,
    status TEXT DEFAULT 'online', -- online, offline
    current_threat_level TEXT DEFAULT 'low',
    total_requests INTEGER DEFAULT 0,
    blocked_requests INTEGER DEFAULT 0,
    redacted_requests INTEGER DEFAULT 0
);

-- 🛡️ POLICY RULES (Version Tracking)
CREATE TABLE IF NOT EXISTS policy_rules (
    rule_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    version TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    rule_definition TEXT NOT NULL, -- YAML/JSON blob
    active INTEGER DEFAULT 1,
    created_at REAL NOT NULL
);

-- ✂️ PII REDACTION EVENTS (Specific DLP Tracking)
CREATE TABLE IF NOT EXISTS pii_redaction_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT REFERENCES telemetry_events(event_id),
    pattern_name TEXT NOT NULL, -- email, secret_key
    match_count INTEGER DEFAULT 1
);

-- 🚨 SECURITY INCIDENTS (Aggregated Alarms)
CREATE TABLE IF NOT EXISTS security_incidents (
    incident_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    start_time REAL NOT NULL,
    end_time REAL,
    status TEXT DEFAULT 'open', -- open, mitigated, resolved
    severity TEXT NOT NULL,
    description TEXT,
    affected_sessions TEXT -- Comma separated session IDs
);
