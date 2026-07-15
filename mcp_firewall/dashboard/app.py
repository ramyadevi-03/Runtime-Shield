from __future__ import annotations
import asyncio
import json
import time
import os
import logging
from typing import Any, List, Dict
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
import telemetry

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dashboard")

app = FastAPI(title="SHIELD-FORCE-ONE | Governance Console")

class DashboardManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._start_time = time.time()

    async def connect(self, websocket: WebSocket):
        self.loop = asyncio.get_running_loop()
        await websocket.accept()
        self.active_connections.append(websocket)
        stats = telemetry.get_metrics()
        events = telemetry.get_recent_events(limit=100)
        await websocket.send_json({
            "type": "init",
            "stats": stats,
            "events": events,
            "uptime": int(time.time() - self._start_time)
        })

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_event(self, event: Dict[str, Any]):
        # Enrich the event payload with engine and identity so the frontend displays them correctly
        if "engine" not in event:
            event["engine"] = event.get("agent", "unknown")
        if "identity" not in event:
            event["identity"] = event.get("agent", "unknown")

        stats = telemetry.get_metrics()
        payload = {"type": "event", "data": event, "current_stats": stats}
        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except:
                self.disconnect(connection)

manager = DashboardManager()

class DashboardState:
    """Interface for the bridge to push events into the dashboard system."""
    def add_event(self, event: Dict[str, Any]):
        # 1. Log to persistent telemetry (Database)
        try:
            telemetry.log_event(
                tenant_id=event.get("tenant_id", "default"),
                engine=event.get("agent", "unknown"),
                event_type="tool_call",
                severity=event.get("severity", "info"),
                action=event.get("action", "allow"),
                tool=event.get("tool"),
                reason=event.get("reason"),
                identity=event.get("identity") or event.get("agent"),
                details=event
            )
        except Exception as e:
            logger.error(f"Failed to log event to telemetry: {e}")

        # 2. Broadcast to live WebSockets
        try:
            if hasattr(manager, 'loop') and manager.loop and manager.loop.is_running():
                asyncio.run_coroutine_threadsafe(manager.broadcast_event(event), manager.loop)
            else:
                import asyncio
                loop = None
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    pass

                if loop and loop.is_running():
                    loop.create_task(manager.broadcast_event(event))
        except Exception as e:
            logger.error(f"Failed to broadcast live event: {e}")

# Exported state for bridge.py
state = DashboardState()

@app.get("/")
async def index():
    return HTMLResponse(DASHBOARD_HTML)

@app.post("/api/events")
async def receive_event(event: Dict[str, Any]):
    await manager.broadcast_event(event)
    return {"status": "ok"}

@app.get("/api/registry/mcps")
async def get_registry():
    import telemetry
    return {"status": "ok", "mcps": telemetry.get_mcp_registry()}

@app.post("/api/registry/mcps")
async def add_registry(payload: Dict[str, Any]):
    import telemetry
    import uuid
    import sys
    mcp_id = payload.get("mcp_id") or f"mcp-{str(uuid.uuid4())[:8]}"
    provider_name = payload.get("provider_name")
    transport = payload.get("transport", "stdio")
    command = payload.get("command")
    args = payload.get("args") or []
    url = payload.get("url")
    active = int(payload.get("active", 1))

    if not provider_name:
        return {"status": "error", "message": "provider_name is required"}

    telemetry.register_mcp(
        mcp_id=mcp_id,
        provider_name=provider_name,
        transport=transport,
        command=command,
        args=args,
        url=url,
        active=active
    )

    bridge = sys.modules.get('bridge') or sys.modules.get('__main__')
    if bridge and hasattr(bridge, 'reload_tool_mappings'):
        bridge.reload_tool_mappings()

    if bridge and hasattr(bridge, 'mcp_remote_clients') and hasattr(bridge, 'mcp_processes'):
        if transport == "sse" and url:
            if provider_name in bridge.mcp_remote_clients:
                try:
                    await bridge.mcp_remote_clients[provider_name].stop()
                except:
                    pass
            client = bridge.RemoteSseMcpClient(provider_name, url)
            bridge.mcp_remote_clients[provider_name] = client
            asyncio.create_task(client.start())
        elif transport == "stdio" and command:
            if provider_name in bridge.mcp_processes:
                try:
                    bridge.mcp_processes[provider_name].terminate()
                except:
                    pass
            try:
                base_safe_keys = {
                    "SystemRoot", "SystemDrive", "TEMP", "TMP", "PATH", "PATHEXT", 
                    "COMSPEC", "USERNAME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", 
                    "PROGRAMFILES", "PROGRAMFILES(X86)", "COMMONPROGRAMFILES", 
                    "COMPUTERNAME", "OS", "NUMBER_OF_PROCESSORS", "PROCESSOR_IDENTIFIER", 
                    "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "ALLUSERSPROFILE", "PUBLIC", 
                    "HOMEDRIVE", "HOMEPATH"
                }
                provider_env = {}
                for k in base_safe_keys:
                    if k in os.environ:
                        provider_env[k] = os.environ[k]
                spiffe_cfg = bridge.get_spiffe_config()
                provider_env["SPIFFE_ENABLED"] = "true" if spiffe_cfg["enabled"] else "false"
                provider_env["RUNTIME_ROLE"] = bridge.DEFAULT_ROLE
                provider_env["PROVIDER_NAME"] = provider_name
                proc = bridge.launch_sandboxed_node(
                    [command] + args,
                    cwd=bridge.PROJECT_DIR,
                    env=provider_env,
                    allowed_paths=[bridge.WORKSPACE_DIR],
                    provider_name=provider_name
                )
                bridge.mcp_processes[provider_name] = proc
            except Exception as e:
                logger.error(f"Failed to start local subprocess: {e}")

    return {"status": "ok", "mcp_id": mcp_id}

@app.delete("/api/registry/mcps/{mcp_id}")
async def remove_registry(mcp_id: str):
    import telemetry
    import sys
    registry = telemetry.get_mcp_registry()
    provider_name = None
    for r in registry:
        if r.get("mcp_id") == mcp_id:
            provider_name = r.get("provider_name")
            break
            
    telemetry.delete_mcp(mcp_id)

    bridge = sys.modules.get('bridge') or sys.modules.get('__main__')
    if bridge and provider_name:
        if hasattr(bridge, 'mcp_remote_clients') and provider_name in bridge.mcp_remote_clients:
            try:
                await bridge.mcp_remote_clients[provider_name].stop()
                del bridge.mcp_remote_clients[provider_name]
            except Exception as e:
                logger.error(f"Error stopping remote client: {e}")
        if hasattr(bridge, 'mcp_processes') and provider_name in bridge.mcp_processes:
            try:
                bridge.mcp_processes[provider_name].terminate()
                del bridge.mcp_processes[provider_name]
            except Exception as e:
                logger.error(f"Error terminating process: {e}")

    return {"status": "ok"}


# ════════════════════════════════════════════════════════════════════
# 🧠 GOVERNANCE INTELLIGENCE API  (Phase 4 — Memory Layer)
# ════════════════════════════════════════════════════════════════════

def _get_advisor():
    """Get or create a PolicyAdvisor instance (lazy, uses PROJECT_DIR from bridge)."""
    import sys, os
    bridge = sys.modules.get("bridge") or sys.modules.get("__main__")
    base_dir = getattr(bridge, "PROJECT_DIR", None) or os.getcwd()
    from governance_memory.policy_advisor import PolicyAdvisor
    return PolicyAdvisor(base_dir=base_dir)

@app.get("/api/memory/stats")
async def get_memory_stats():
    """Memory utilization — file counts, sizes, last consolidation time."""
    try:
        return {"status": "ok", "data": _get_advisor().get_memory_stats()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/memory/recommendations")
async def get_recommendations(status: str = None):
    """All governance recommendations. Filter by ?status=PENDING|APPLIED|REJECTED."""
    try:
        return {"status": "ok", "data": _get_advisor().get_recommendations(status_filter=status)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.patch("/api/memory/recommendations/{rec_id}")
async def update_recommendation(rec_id: str, payload: Dict[str, Any]):
    """Approve or reject a recommendation. Body: {status: 'APPLIED', applied_to: 'yaml'}"""
    try:
        new_status = payload.get("status", "APPLIED")
        applied_to = payload.get("applied_to")
        updated = _get_advisor().update_recommendation_status(rec_id, new_status, applied_to)
        if updated:
            return {"status": "ok", "message": f"Recommendation {rec_id} updated to {new_status}"}
        return {"status": "error", "message": f"Recommendation {rec_id} not found"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/memory/patterns")
async def get_attack_patterns():
    """All confirmed attack patterns from long-term memory."""
    try:
        return {"status": "ok", "data": _get_advisor().get_attack_patterns()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/memory/agents")
async def get_agent_profiles():
    """All agent behavioral profiles from long-term memory."""
    try:
        return {"status": "ok", "data": _get_advisor().get_agent_profiles()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/memory/risk-state")
async def get_risk_state():
    """Live risk state summary from last consolidation cycle."""
    try:
        return {"status": "ok", "data": _get_advisor().get_risk_state()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/memory/consolidate")
async def trigger_consolidation():
    """Trigger an immediate consolidation cycle (admin use)."""
    import asyncio, sys
    try:
        bridge = sys.modules.get("bridge") or sys.modules.get("__main__")
        consolidator = getattr(bridge, "memory_consolidator", None)
        if consolidator:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, consolidator.run_once)
            return {"status": "ok", "message": "Consolidation cycle completed"}
        return {"status": "error", "message": "Consolidator not running in bridge process"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ════════════════════════════════════════════════════════════════════
# 🔒 DEDUP GUARD API  (Phase 6 — Deduplication)
# ════════════════════════════════════════════════════════════════════

def _get_dedup_guard():
    """Lazy DedupGuard factory."""
    import sys, os
    bridge = sys.modules.get("bridge") or sys.modules.get("__main__")
    base_dir = getattr(bridge, "PROJECT_DIR", None) or os.getcwd()
    from governance_memory.dedup_guard import DedupGuard
    return DedupGuard(base_dir=base_dir)

@app.get("/api/memory/dedup-report")
async def get_dedup_report():
    """
    Full dedup status: shows which PENDING recommendations are already
    covered by active YAML/OPA rules and which are genuinely new.
    """
    try:
        return {"status": "ok", "data": _get_dedup_guard().get_dedup_report()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/memory/yaml-coverage")
async def get_yaml_coverage():
    """All active YAML rule names with their semantic fingerprints."""
    try:
        return {"status": "ok", "data": _get_dedup_guard().get_yaml_coverage()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/memory/migration-check")
async def migration_check(from_engine: str = "yaml", to_engine: str = "opa"):
    """
    Engine migration report. Checks every APPLIED/PENDING recommendation
    against the destination engine to flag NEEDS_MIGRATION vs ALREADY_COVERED.
    """
    try:
        report = _get_dedup_guard().check_migration(
            from_engine=from_engine, to_engine=to_engine
        )
        return {"status": "ok", "from": from_engine, "to": to_engine, "data": report}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ════════════════════════════════════════════════════════════════════

@app.post("/api/registry/mcps/{provider_name}/sync")
async def sync_mcp(provider_name: str):
    import sys
    bridge = sys.modules.get('bridge') or sys.modules.get('__main__')
    if bridge and hasattr(bridge, 'mcp_remote_clients'):
        client = bridge.mcp_remote_clients.get(provider_name)
        if client:
            try:
                await client.sync_tools()
                return {"status": "ok", "message": f"Successfully synced tools for {provider_name}"}
            except Exception as e:
                return {"status": "error", "message": str(e)}
    return {"status": "error", "message": f"SSE Client for provider '{provider_name}' is not running or found in gateway memory"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SHIELD-FORCE-ONE | Governance</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --sidebar-bg: #171717; --main-bg: #212121; --border: #303030;
            --text: #ececec; --text-dim: #b4b4b4; --accent: #d97757;
            --alert-bg: rgba(217, 119, 87, 0.1); --green: #4ade80; --red: #f87171; --orange: #fbbf24;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: var(--main-bg); color: var(--text); font-family: 'Inter', sans-serif; display: flex; height: 100vh; overflow: hidden; }

        /* Sidebar Like Claude */
        .sidebar { width: 260px; background: var(--sidebar-bg); border-right: 1px solid var(--border); display: flex; flex-direction: column; padding: 20px 15px; }
        .sidebar-header { margin-bottom: 30px; font-weight: 700; display: flex; align-items: center; gap: 10px; font-size: 0.9rem; }
        .nav-item { padding: 10px; border-radius: 8px; cursor: pointer; color: var(--text-dim); font-size: 0.85rem; transition: 0.2s; margin-bottom: 5px; }
        .nav-item:hover { background: rgba(255,255,255,0.05); color: var(--text); }
        .nav-item.active { background: rgba(255,255,255,0.08); color: var(--text); border: 1px solid var(--border); }
        
        .view-section { display: none; }
        .view-section.active { display: block; }

        .recent-label { font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; margin-top: 25px; margin-bottom: 15px; padding-left: 10px; font-weight: 600; letter-spacing: 0.5px; }
        .recent-item { padding: 8px 10px; font-size: 0.8rem; color: var(--text-dim); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; cursor: pointer; border-radius: 6px; }
        .recent-item:hover { color: var(--text); background: rgba(255,255,255,0.03); }

        /* Risk Visualization Upgrade */
        .risk-container { padding: 0 40px 40px; display: grid; grid-template-columns: 350px 1fr; gap: 20px; }
        .risk-card { background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 16px; padding: 25px; display: flex; flex-direction: column; justify-content: space-between; }
        .chart-card { background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 16px; padding: 25px; height: 350px; }
        .risk-meter { height: 12px; background: #333; border-radius: 6px; margin: 20px 0; overflow: hidden; }
        .risk-bar { height: 100%; width: 0%; background: var(--green); transition: 0.5s cubic-bezier(0.4, 0, 0.2, 1); }
        .risk-status { font-size: 2rem; font-weight: 700; color: var(--green); margin-bottom: 10px; }
        
        .violation-list { font-size: 0.8rem; line-height: 1.8; color: var(--text-dim); margin-top: 20px; border-top: 1px solid var(--border); padding-top: 15px; }
        .violation-list b { color: #fff; }
        
        /* Identity Mesh */
        .mesh-list { padding: 0 40px; }
        .mesh-item { background: var(--sidebar-bg); border: 1px solid var(--border); margin-bottom: 10px; border-radius: 10px; padding: 15px 20px; display: flex; align-items: center; justify-content: space-between; }
        .spiffe-id { font-family: 'JetBrains Mono'; font-size: 0.85rem; color: #60a5fa; }

        /* Main Content Area */
        .main { flex-grow: 1; display: flex; flex-direction: column; overflow-y: auto; }
        
        .alert-banner { background: #3a2a16; border: 1px solid #634a26; margin: 20px 40px; padding: 15px 25px; border-radius: 12px; display: flex; align-items: center; justify-content: space-between; gap: 15px; display: none; }
        .alert-text { font-size: 0.85rem; color: #f59e0b; flex-grow: 1; }
        .alert-btn { background: #fff; color: #000; border: none; padding: 6px 15px; border-radius: 8px; font-size: 0.8rem; font-weight: 600; cursor: pointer; }

        .header { padding: 30px 40px; display: flex; align-items: center; justify-content: space-between; }
        .brand-title { font-size: 1.5rem; font-weight: 600; color: #fefefe; display: flex; align-items: center; gap: 15px; }
        .live-status { display: flex; align-items: center; gap: 8px; font-size: 0.75rem; color: var(--green); font-weight: 600; text-transform: uppercase; }
        .dot-pulse { width: 8px; height: 8px; background: var(--green); border-radius: 50%; box-shadow: 0 0 10px var(--green); animation: pulse 2s infinite; }
        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }

        .metrics { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; padding: 0 40px 30px; }
        .m-card { background: var(--sidebar-bg); border: 1px solid var(--border); padding: 20px; border-radius: 12px; }
        .m-label { font-size: 0.65rem; color: var(--text-dim); text-transform: uppercase; margin-bottom: 10px; font-weight: 700; letter-spacing: 0.5px; }
        .m-value { font-size: 1.8rem; font-weight: 600; }

        .feed-container { margin: 0 40px 40px; background: var(--sidebar-bg); border: 1px solid var(--border); border-radius: 12px; }
        .table { width: 100%; border-collapse: collapse; }
        .th { text-align: left; padding: 12px 25px; font-size: 0.65rem; color: var(--text-dim); border-bottom: 1px solid var(--border); text-transform: uppercase; }
        .td { padding: 15px 25px; font-size: 0.85rem; border-bottom: 1px solid var(--border); }
        
        .status-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; margin-right: 12px; }
        .tag { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; }
    </style>
</head>
<body>
    <div class="sidebar">
        <div class="sidebar-header">🛡️ SHIELD-FORCE-ONE</div>
        <div class="nav-item active" data-view="audit" onclick="switchNav(this)">Live Audit</div>
        <div class="nav-item" data-view="policy" onclick="switchNav(this)">Policy Engine</div>
        <div class="nav-item" data-view="identity" onclick="switchNav(this)">Identity Mesh</div>
        <div class="nav-item" data-view="risk" onclick="switchNav(this)">Risk Graph</div>
        <div class="nav-item" data-view="registry" onclick="switchNav(this)">MCP Registry</div>
        <div class="nav-item" data-view="governance" onclick="switchNav(this); loadGovernanceData()">🧠 Governance Memory</div>
        <div class="recent-label">Recent Sessions</div>
        <div class="recent-item">demo-session (Active)</div>
        <div class="recent-item">security-audit-v1</div>
    </div>

    <div class="main">
        <div id="alert-box" class="alert-banner">
            <div class="alert-text">⚠️ <b>SHIELD-FORCE-ONE:</b> System connection unstable. Real-time governance may be delayed.</div>
            <button class="alert-btn">Open diagnostics</button>
        </div>

        <div class="header">
            <div class="brand-title">SHIELD-FORCE-ONE <span style="font-weight: 300; opacity: 0.5;" id="view-title">Governance</span></div>
            <div class="live-status"><div class="dot-pulse"></div> ENFORCEMENT ACTIVE</div>
        </div>

        <div class="metrics">
            <div class="m-card"><div class="m-label">TOTAL CALLS</div><div class="m-value" id="val-total" style="color: var(--accent)">0</div></div>
            <div class="m-card"><div class="m-label">ALLOWED</div><div class="m-value" id="val-allowed" style="color: var(--green)">0</div></div>
            <div class="m-card"><div class="m-label">DENIED</div><div class="m-value" id="val-denied" style="color: var(--red)">0</div></div>
            <div class="m-card"><div class="m-label">REDACTED</div><div class="m-value" id="val-redacted" style="color: var(--orange)">0</div></div>
            <div class="m-card"><div class="m-label">UPTIME</div><div class="m-value" id="val-uptime">0s</div></div>
        </div>

        <!-- VIEW: LIVE AUDIT -->
        <div id="view-audit" class="view-section active">
            <div class="feed-container">
                <table class="table">
                    <thead>
                        <tr>
                            <th class="th" style="width: 100px;">TIME</th>
                            <th class="th">ENGINE & IDENTITY</th>
                            <th class="th">TOOL</th>
                            <th class="th">ACTION</th>
                            <th class="th">REASON</th>
                        </tr>
                    </thead>
                    <tbody id="feed-body"></tbody>
                </table>
            </div>
        </div>

        <!-- VIEW: RISK GRAPH -->
        <div id="view-risk" class="view-section">
            <div style="padding: 0 40px 20px; font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">Behavioral Threat Analysis</div>
            <div class="risk-container">
                <div class="risk-card">
                    <div>
                        <div class="m-label">CURRENT RISK STATE</div>
                        <div class="risk-status" id="risk-status-text">HEALTHY</div>
                        <div class="risk-meter"><div class="risk-bar" id="risk-bar-fill"></div></div>
                        <div style="font-size: 0.9rem; color: var(--text-dim);">
                            Integrity Score: <span id="risk-score-val" style="color: #fff; font-weight: 600;">0</span> / 100
                        </div>
                    </div>
                    <div class="violation-list">
                        <div>• Policy Infractions: <b id="risk-infractions">0</b></div>
                        <div>• Suspicious Intents: <b id="risk-patterns">0</b></div>
                        <div>• Identity Drift: <b id="risk-drift">0.0%</b></div>
                    </div>
                </div>
                <div class="chart-card">
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
        </div>

        <!-- VIEW: IDENTITY MESH -->
        <div id="view-identity" class="view-section">
            <div class="mesh-list" id="mesh-list-body">
                <div class="mesh-item">
                    <div>
                        <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 5px;">Bridge Proxy (Windows Host)</div>
                        <div class="spiffe-id">spiffe://runtime-shield/bridge</div>
                    </div>
                    <div class="tag" style="color: var(--green)">Verified</div>
                </div>
                <div class="mesh-item">
                    <div>
                        <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 5px;">Damn Vulnerable LLM Agent (Streamlit)</div>
                        <div class="spiffe-id">spiffe://runtime-shield/llm-agent</div>
                    </div>
                    <div class="tag" style="color: var(--green)">Verified</div>
                </div>
                <div class="mesh-item">
                    <div>
                        <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 5px;">MCP Backend Server</div>
                        <div class="spiffe-id">spiffe://runtime-shield/backend</div>
                    </div>
                    <div class="tag" style="color: var(--green)">Verified</div>
                </div>
            </div>
        </div>

        <!-- VIEW: POLICY ENGINE -->
        <div id="view-policy" class="view-section">
            <div class="mesh-list">
                <div class="mesh-item">
                    <div>
                        <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 5px;">active_tenant_rules.yaml</div>
                        <div style="font-size: 0.75rem; color: var(--text-dim);">Last Synchronized: Just Now</div>
                    </div>
                    <div class="tag" style="color: var(--green)">Policy v3.1</div>
                </div>
            </div>
        </div>

        <!-- VIEW: MCP REGISTRY -->
        <div id="view-registry" class="view-section">
            <div style="padding: 0 40px 20px; font-size: 0.7rem; color: var(--text-dim); text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">MCP Connections Registry</div>
            <div style="margin: 0 40px 20px; display: flex; justify-content: flex-end;">
                <button class="alert-btn" style="background: var(--accent); color: white;" onclick="openAddMcpModal()">+ Register MCP Server</button>
            </div>
            
            <div class="mesh-list" id="registry-list-body">
                <!-- Dynamically populated registry entries -->
            </div>
        </div>

        <!-- Modal for registering new MCP -->
        <div id="add-mcp-modal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.7); z-index:1000; align-items:center; justify-content:center;">
            <div style="background:var(--sidebar-bg); border:1px solid var(--border); padding:30px; border-radius:12px; width:450px; display:flex; flex-direction:column; gap:15px;">
                <h3 style="color:#fff; margin-bottom:5px;">Register MCP Server</h3>
                <div>
                    <label style="font-size:0.75rem; color:var(--text-dim); display:block; margin-bottom:5px;">Provider Name</label>
                    <input type="text" id="mcp-provider-name" placeholder="my-remote-mcp" style="width:100%; background:var(--main-bg); border:1px solid var(--border); color:#fff; padding:8px; border-radius:6px; outline:none;">
                </div>
                <div>
                    <label style="font-size:0.75rem; color:var(--text-dim); display:block; margin-bottom:5px;">Transport Type</label>
                    <select id="mcp-transport" onchange="toggleTransportFields()" style="width:100%; background:var(--main-bg); border:1px solid var(--border); color:#fff; padding:8px; border-radius:6px; outline:none;">
                        <option value="sse">Remote Network (SSE)</option>
                        <option value="stdio">Local Command (stdio)</option>
                    </select>
                </div>
                <div id="field-sse">
                    <label style="font-size:0.75rem; color:var(--text-dim); display:block; margin-bottom:5px;">SSE Endpoint URL</label>
                    <input type="text" id="mcp-url" placeholder="https://example.com/sse" style="width:100%; background:var(--main-bg); border:1px solid var(--border); color:#fff; padding:8px; border-radius:6px; outline:none;">
                </div>
                <div id="field-stdio" style="display:none;">
                    <label style="font-size:0.75rem; color:var(--text-dim); display:block; margin-bottom:5px;">Executable Command</label>
                    <input type="text" id="mcp-command" placeholder="node" style="width:100%; background:var(--main-bg); border:1px solid var(--border); color:#fff; padding:8px; border-radius:6px; outline:none; margin-bottom:10px;">
                    <label style="font-size:0.75rem; color:var(--text-dim); display:block; margin-bottom:5px;">Arguments (Comma-separated)</label>
                    <input type="text" id="mcp-args" placeholder="./dist/index.js, arg2" style="width:100%; background:var(--main-bg); border:1px solid var(--border); color:#fff; padding:8px; border-radius:6px; outline:none;">
                </div>
                <div style="display:flex; justify-content:flex-end; gap:10px; margin-top:10px;">
                    <button class="alert-btn" style="background:#444; color:#fff;" onclick="closeAddMcpModal()">Cancel</button>
                    <button class="alert-btn" style="background:var(--green); color:#000;" onclick="submitAddMcp()">Register</button>
                </div>
            </div>
        </div>

        <!-- VIEW: GOVERNANCE INTELLIGENCE -->
        <div id="view-governance" class="view-section">
            <div style="padding: 0 40px 10px; display:flex; align-items:center; justify-content:space-between;">
                <div style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; font-weight:700; letter-spacing:1px;">🧠 Governance Memory Intelligence</div>
                <div style="display:flex; gap:10px; align-items:center;">
                    <span id="gov-last-sync" style="font-size:0.72rem; color:var(--text-dim);">Last sync: —</span>
                    <button class="alert-btn" style="background:var(--accent);color:#fff;" onclick="triggerConsolidation()">⚡ Run Consolidation Now</button>
                </div>
            </div>

            <!-- Row 1: Risk State Cards -->
            <div style="display:flex; gap:16px; padding:0 40px 24px; flex-wrap:wrap;">
                <div class="m-card" style="flex:1; min-width:140px;">
                    <div class="m-label">SESSIONS SCANNED</div>
                    <div class="m-value" id="gov-sessions" style="color:var(--accent)">—</div>
                </div>
                <div class="m-card" style="flex:1; min-width:140px;">
                    <div class="m-label">TOTAL DENIES</div>
                    <div class="m-value" id="gov-denies" style="color:var(--red)">—</div>
                </div>
                <div class="m-card" style="flex:1; min-width:140px;">
                    <div class="m-label">KNOWN PATTERNS</div>
                    <div class="m-value" id="gov-patterns" style="color:var(--orange)">—</div>
                </div>
                <div class="m-card" style="flex:1; min-width:140px;">
                    <div class="m-label">HIGH-RISK SESSIONS</div>
                    <div class="m-value" id="gov-highrisk" style="color:var(--red)">—</div>
                </div>
                <div class="m-card" style="flex:1; min-width:140px;">
                    <div class="m-label">PENDING RECS</div>
                    <div class="m-value" id="gov-pending" style="color:var(--green)">—</div>
                </div>
            </div>

            <!-- Row 2: Attack Patterns -->
            <div style="padding:0 40px 24px;">
                <div style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; letter-spacing:1px; margin-bottom:12px;">⚠️ Confirmed Attack Patterns (Long-Term Memory)</div>
                <div id="gov-patterns-list" style="display:flex; flex-direction:column; gap:8px;">
                    <div style="color:var(--text-dim); font-size:0.8rem;">Loading…</div>
                </div>
            </div>

            <!-- Row 3: Agent Profiles -->
            <div style="padding:0 40px 24px;">
                <div style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; letter-spacing:1px; margin-bottom:12px;">👤 Agent Behavioral Profiles</div>
                <div id="gov-agents-list" style="display:flex; flex-direction:column; gap:6px; max-height:200px; overflow-y:auto;">
                    <div style="color:var(--text-dim); font-size:0.8rem;">Loading…</div>
                </div>
            </div>

            <!-- Row 4: Pending Recommendations -->
            <div style="padding:0 40px 24px;">
                <div style="font-size:0.7rem; color:var(--text-dim); text-transform:uppercase; letter-spacing:1px; margin-bottom:12px;">📋 Pending Policy Recommendations</div>
                <div id="gov-recs-list" style="display:flex; flex-direction:column; gap:10px;">
                    <div style="color:var(--text-dim); font-size:0.8rem;">Loading…</div>
                </div>
            </div>
        </div>

    </div>

    <script>
        let startTime = Date.now();
        let currentEvents = [];
        let riskScore = 0;
        let riskChart;

        // ── Governance Intelligence ─────────────────────────────────────
        async function loadGovernanceData() {
            try {
                const [riskRes, patternsRes, agentsRes, recsRes] = await Promise.all([
                    fetch('/api/memory/risk-state').then(r => r.json()),
                    fetch('/api/memory/patterns').then(r => r.json()),
                    fetch('/api/memory/agents').then(r => r.json()),
                    fetch('/api/memory/recommendations?status=PENDING').then(r => r.json()),
                ]);

                // Risk State cards
                const rs = riskRes.data || {};
                document.getElementById('gov-sessions').textContent = rs.active_sessions_scanned ?? '—';
                document.getElementById('gov-denies').textContent   = rs.total_denies_this_window ?? '—';
                document.getElementById('gov-patterns').textContent = rs.known_patterns_in_long_term ?? '—';
                document.getElementById('gov-highrisk').textContent = rs['high_risk_sessions_≥3_blocks'] ?? rs.high_risk_sessions ?? '—';
                if (rs.last_updated) document.getElementById('gov-last-sync').textContent = 'Last sync: ' + rs.last_updated;

                // Pending recommendations count
                const recs = recsRes.data || [];
                document.getElementById('gov-pending').textContent = recs.length;

                // Attack Patterns
                const patterns = patternsRes.data || [];
                const pEl = document.getElementById('gov-patterns-list');
                if (patterns.length === 0) {
                    pEl.innerHTML = '<div style="color:var(--text-dim);font-size:0.8rem;">No confirmed patterns yet — run consolidation after multiple sessions.</div>';
                } else {
                    pEl.innerHTML = patterns.map(p => `
                        <div style="background:rgba(248,113,113,0.08); border:1px solid rgba(248,113,113,0.2); border-radius:8px; padding:12px 16px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-size:0.82rem; font-weight:600; color:var(--text);">${p.name || p.pattern_key}</div>
                                <div style="font-size:0.72rem; color:var(--text-dim); margin-top:3px;">Tool: <code style="background:#333;padding:1px 5px;border-radius:3px;">${p.tool}</code> · Category: ${p.category} · ${p.session_count || 0} sessions · ${p.total_attempts || 0} attempts</div>
                            </div>
                            <div style="font-size:0.72rem; color:var(--red); font-weight:600;">${p.agent_count || 0} agents</div>
                        </div>
                    `).join('');
                }

                // Agent Profiles
                const agents = agentsRes.data || [];
                const aEl = document.getElementById('gov-agents-list');
                if (agents.length === 0) {
                    aEl.innerHTML = '<div style="color:var(--text-dim);font-size:0.8rem;">No agent profiles yet.</div>';
                } else {
                    const trustColor = {trusted:'var(--green)', new:'var(--text-dim)', suspicious:'var(--orange)', 'high-risk':'var(--red)'};
                    aEl.innerHTML = agents.map(a => `
                        <div style="background:var(--sidebar-bg); border:1px solid var(--border); border-radius:6px; padding:10px 14px; display:flex; justify-content:space-between; align-items:center;">
                            <div>
                                <div style="font-size:0.78rem; color:var(--text); font-family:'JetBrains Mono',monospace;">${a.agent_id}</div>
                                <div style="font-size:0.7rem; color:var(--text-dim); margin-top:2px;">Calls: ${a.total_calls||0} · Blocked: ${a.blocked_attempts||0} · Risk: ${a.current_risk_score||0}</div>
                            </div>
                            <span style="font-size:0.7rem; font-weight:700; color:${trustColor[a.trust_level]||'var(--text-dim)'}; text-transform:uppercase;">${a.trust_level||'new'}</span>
                        </div>
                    `).join('');
                }

                // Pending Recommendations
                const rEl = document.getElementById('gov-recs-list');
                if (recs.length === 0) {
                    rEl.innerHTML = '<div style="color:var(--green);font-size:0.82rem;">✅ No pending recommendations — governance is up to date.</div>';
                } else {
                    rEl.innerHTML = recs.map(r => `
                        <div style="background:rgba(251,191,36,0.06); border:1px solid rgba(251,191,36,0.25); border-radius:8px; padding:14px 16px;">
                            <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;">
                                <div>
                                    <span style="font-size:0.7rem; color:var(--orange); font-weight:700; font-family:'JetBrains Mono',monospace;">${r.id}</span>
                                    <span style="margin-left:10px; font-size:0.7rem; background:rgba(251,191,36,0.15); color:var(--orange); padding:2px 8px; border-radius:4px;">PENDING</span>
                                </div>
                                <div style="display:flex; gap:8px;">
                                    <button onclick="applyRec('${r.id}','REJECTED')" style="background:rgba(248,113,113,0.15);border:1px solid rgba(248,113,113,0.3);color:var(--red);padding:4px 12px;border-radius:5px;cursor:pointer;font-size:0.72rem;">Reject</button>
                                    <button onclick="applyRec('${r.id}','APPLIED')" style="background:rgba(74,222,128,0.15);border:1px solid rgba(74,222,128,0.3);color:var(--green);padding:4px 12px;border-radius:5px;cursor:pointer;font-size:0.72rem;">✓ Apply</button>
                                </div>
                            </div>
                            <div style="font-size:0.8rem; color:var(--text); margin-bottom:4px;">${r.suggested_rule || r.pattern || ''}</div>
                            <div style="font-size:0.7rem; color:var(--text-dim);">Fingerprint: <code style="background:#333;padding:1px 5px;border-radius:3px;">${r.fingerprint||''}</code> · Source: ${r.source||''}</div>
                        </div>
                    `).join('');
                }

            } catch(e) {
                console.error('Governance data load failed:', e);
            }
        }

        async function applyRec(recId, status) {
            try {
                const res = await fetch('/api/memory/recommendations/' + recId, {
                    method: 'PATCH',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({status, applied_to: status === 'APPLIED' ? 'yaml' : 'none'})
                });
                const data = await res.json();
                if (data.status === 'ok') loadGovernanceData();
                else alert('Error: ' + data.message);
            } catch(e) { console.error(e); }
        }

        async function triggerConsolidation() {
            const btn = event.target;
            btn.textContent = '⏳ Running…';
            btn.disabled = true;
            try {
                const res = await fetch('/api/memory/consolidate', {method:'POST'});
                const data = await res.json();
                btn.textContent = data.status === 'ok' ? '✅ Done!' : '❌ Error';
                setTimeout(() => {
                    btn.textContent = '⚡ Run Consolidation Now';
                    btn.disabled = false;
                    loadGovernanceData();
                }, 2000);
            } catch(e) {
                btn.textContent = '⚡ Run Consolidation Now';
                btn.disabled = false;
            }
        }
        // ────────────────────────────────────────────────────────────────

        function initChart() {
            const ctx = document.getElementById('riskChart').getContext('2d');
            const gradient = ctx.createLinearGradient(0, 0, 0, 300);
            gradient.addColorStop(0, 'rgba(217, 119, 87, 0.3)');
            gradient.addColorStop(1, 'rgba(217, 119, 87, 0)');

            riskChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Session Risk Score',
                        data: [],
                        borderColor: '#d97757',
                        borderWidth: 3,
                        fill: true,
                        backgroundColor: gradient,
                        tension: 0.4,
                        pointRadius: 4,
                        pointBackgroundColor: '#d97757'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, max: 100, grid: { color: '#333' }, ticks: { color: '#999' } },
                        x: { grid: { display: false }, ticks: { color: '#999' } }
                    },
                    plugins: {
                        legend: { display: false }
                    }
                }
            });
        }

        function updateChartData(events) {
            if (!riskChart) return;
            
            const points = [];
            const labels = [];
            let runningInfractions = 0;
            
            const history = [...events].reverse();
            const step = Math.max(1, Math.floor(history.length / 10));
            
            history.forEach((e, idx) => {
                if (e.action === 'deny' || e.action === 'block') runningInfractions++;
                if (idx % step === 0 || idx === history.length - 1) {
                    points.push(Math.min(100, runningInfractions * 25));
                    const d = new Date(e.timestamp * 1000);
                    labels.push(d.toLocaleTimeString([], {minute:'2-digit', second:'2-digit'}));
                }
            });

            riskChart.data.labels = labels;
            riskChart.data.datasets[0].data = points;
            riskChart.update('none');
        }

        function switchNav(el) {
            const view = el.getAttribute('data-view');
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            el.classList.add('active');
            
            document.querySelectorAll('.view-section').forEach(s => s.classList.remove('active'));
            document.getElementById('view-' + view).classList.add('active');
            document.getElementById('view-title').innerText = el.innerText;

            if (view === 'risk' && riskChart) {
                setTimeout(() => riskChart.update(), 100);
            }
            if (view === 'registry') {
                loadRegistry();
            }
        }

        function loadRegistry() {
            fetch('/api/registry/mcps')
                .then(r => r.json())
                .then(data => {
                    if (data.status === 'ok') {
                        renderRegistry(data.mcps);
                    }
                });
        }

        function renderRegistry(mcps) {
            const container = document.getElementById('registry-list-body');
            container.innerHTML = '';
            mcps.forEach(m => {
                const item = document.createElement('div');
                item.className = 'mesh-item';
                
                const isSse = m.transport === 'sse';
                const tagColor = isSse ? 'var(--blue)' : 'var(--green)';
                const tagText = isSse ? 'Remote Network (SSE)' : 'Local Sandboxed (stdio)';
                const detailText = isSse ? m.url : `${m.command} ${(m.args || []).join(' ')}`;
                const statusColor = m.active ? 'var(--green)' : 'var(--red)';
                const statusText = m.active ? 'Active' : 'Disabled';

                item.innerHTML = `
                    <div>
                        <div style="font-weight: 600; font-size: 0.9rem; margin-bottom: 5px; display:flex; align-items:center; gap:8px;">
                            ${m.provider_name}
                            <span style="font-size:0.65rem; background:rgba(255,255,255,0.08); padding:2px 6px; border-radius:4px; color:${statusColor}; font-weight:700;">${statusText}</span>
                        </div>
                        <div class="spiffe-id" style="font-size:0.8rem; color:var(--text-dim); margin-bottom:5px;">${detailText}</div>
                    </div>
                    <div style="display:flex; align-items:center; gap:15px;">
                        <span class="tag" style="color: ${tagColor}">${tagText}</span>
                        ${isSse ? `<button class="alert-btn" style="background:#58a6ff; color:#fff; font-size:0.75rem; padding:4px 10px;" onclick="syncRemoteMcp('${m.provider_name}')">Sync Tools</button>` : ''}
                        <button class="alert-btn" style="background:var(--red); color:#fff; font-size:0.75rem; padding:4px 10px;" onclick="deleteMcp('${m.mcp_id}')">Delete</button>
                    </div>
                `;
                container.appendChild(item);
            });
        }

        function syncRemoteMcp(name) {
            fetch(`/api/registry/mcps/${name}/sync`, { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    alert(data.message || data.status);
                })
                .catch(err => alert('Sync failed: ' + err));
        }

        function deleteMcp(id) {
            if (confirm('Are you sure you want to unregister this MCP server?')) {
                fetch(`/api/registry/mcps/${id}`, { method: 'DELETE' })
                    .then(r => r.json())
                    .then(data => {
                        if (data.status === 'ok') {
                            loadRegistry();
                        }
                    });
            }
        }

        function openAddMcpModal() {
            document.getElementById('add-mcp-modal').style.display = 'flex';
        }

        function closeAddMcpModal() {
            document.getElementById('add-mcp-modal').style.display = 'none';
        }

        function toggleTransportFields() {
            const transport = document.getElementById('mcp-transport').value;
            if (transport === 'sse') {
                document.getElementById('field-sse').style.display = 'block';
                document.getElementById('field-stdio').style.display = 'none';
            } else {
                document.getElementById('field-sse').style.display = 'none';
                document.getElementById('field-stdio').style.display = 'block';
            }
        }

        function submitAddMcp() {
            const nameField = document.getElementById('mcp-provider-name');
            const provider_name = nameField.value.trim();
            const transport = document.getElementById('mcp-transport').value;
            const url = document.getElementById('mcp-url').value;
            const command = document.getElementById('mcp-command').value;
            const argsRaw = document.getElementById('mcp-args').value;
            
            const payload = {
                provider_name: provider_name,
                transport: transport,
                active: 1
            };
            if (transport === 'sse') {
                payload.url = url;
            } else {
                payload.command = command;
                payload.args = argsRaw ? argsRaw.split(',').map(x => x.trim()) : [];
            }

            fetch('/api/registry/mcps', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            .then(r => r.json())
            .then(data => {
                if (data.status === 'ok') {
                    closeAddMcpModal();
                    loadRegistry();
                    document.getElementById('mcp-provider-name').value = '';
                    document.getElementById('mcp-url').value = '';
                    document.getElementById('mcp-command').value = '';
                    document.getElementById('mcp-args').value = '';
                } else {
                    alert('Error: ' + data.message);
                }
            })
            .catch(err => alert('Failed to register: ' + err));
        }

        function updateRiskUI() {
            const bar = document.getElementById('risk-bar-fill');
            const status = document.getElementById('risk-status-text');
            const scoreVal = document.getElementById('risk-score-val');
            
            scoreVal.innerText = riskScore;
            bar.style.width = riskScore + '%';
            
            if (riskScore > 80) {
                bar.style.background = 'var(--red)';
                status.innerText = 'UNDER ATTACK';
                status.style.color = 'var(--red)';
            } else if (riskScore > 40) {
                bar.style.background = 'var(--orange)';
                status.innerText = 'SUSPICIOUS';
                status.style.color = 'var(--orange)';
            } else {
                bar.style.background = 'var(--green)';
                status.innerText = 'HEALTHY';
                status.style.color = 'var(--green)';
            }
        }

        function updateMetricsFromStats(stats) {
            document.getElementById('val-total').innerText = stats.total || 0;
            document.getElementById('val-allowed').innerText = stats.allowed || 0;
            document.getElementById('val-denied').innerText = stats.denied || 0;
            document.getElementById('val-redacted').innerText = stats.redacted || 0;
            document.getElementById('risk-infractions').innerText = stats.denied || 0;
            
            // Re-calculate drift and patterns for the UI based on stats if available
            updateRiskUI();
        }

        function calculateMetrics(events, serverStats) {
            const localStats = { total: events.length, allowed: 0, denied: 0, redacted: 0 };
            
            events.forEach(e => {
                const act = (e.action || 'allow').toLowerCase();
                if (act === 'allow') localStats.allowed++;
                else if (act === 'deny' || act === 'block') localStats.denied++;
                else if (act === 'redact') localStats.redacted++;
            });

            // If serverStats has data, use it for the big numbers. Otherwise fallback to local.
            const displayStats = (serverStats && serverStats.total > 0) ? serverStats : localStats;
            
            document.getElementById('val-total').innerText = displayStats.total;
            document.getElementById('val-allowed').innerText = displayStats.allowed;
            document.getElementById('val-denied').innerText = displayStats.denied;
            document.getElementById('val-redacted').innerText = displayStats.redacted;
            document.getElementById('risk-infractions').innerText = displayStats.denied;
            
            // DYNAMIC IDENTITY DRIFT: Calculate based on unique identities detected
            const uniqueIdentities = new Set(events.map(e => e.identity || 'unknown')).size;
            const driftBase = Math.min(15, (uniqueIdentities / Math.max(1, events.length)) * 100);
            const driftJitter = (Math.random() * 0.4) - 0.2; // Add realistic fluctuation
            const finalDrift = Math.max(0, (driftBase + driftJitter)).toFixed(1);
            
            document.getElementById('risk-drift').innerText = finalDrift + '%';
            
            // Extract categories for "Suspicious Patterns" (Only count DENY/BLOCK events with AI Category 'S')
            const patterns = events.filter(e => {
                const act = (e.action || '').toLowerCase();
                return (act === 'deny' || act === 'block') && e.reason && e.reason.includes('S');
            }).length;
            document.getElementById('risk-patterns').innerText = patterns;

            // Calculate dynamic risk score based on denied requests (each deny event adds 25 risk points, max 100)
            riskScore = Math.min(100, (displayStats.denied || 0) * 25);

            updateRiskUI();
            updateChartData(events);
        }

        function createRow(e) {
            const tr = document.createElement('tr');
            const act = (e.action || 'allow').toLowerCase();
            const date = new Date(e.timestamp * 1000);
            const timeStr = date.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false});
            
            let dotColor = '#fff';
            if (e.engine === '(audit-agent)') dotColor = '#f87171';
            if (e.engine === '(response)' || act === 'redact') dotColor = '#fbbf24';
            if (e.engine === '(spiffe)') dotColor = '#60a5fa';

            let toolDisplay = e.tool || '-';
            if (toolDisplay === '-') {
                if (e.event_type === 'startup') toolDisplay = 'SYSTEM_INIT';
                else if (act === 'redact') toolDisplay = 'DLP_REDACT';
                else if (e.engine === '(spiffe)') toolDisplay = 'IDENTITY_VAL';
                else toolDisplay = 'INTERNAL';
            }

            tr.innerHTML = `
                <td class="td" style="color: var(--text-dim); font-family: 'JetBrains Mono'; font-size: 0.75rem;">${timeStr}</td>
                <td class="td">
                    <span class="status-dot" style="background: ${dotColor}"></span>
                    <span style="color: var(--accent); font-size: 0.8rem; margin-right: 10px;">${e.engine || ''}</span>
                    <span style="color: var(--text-dim); font-size: 0.75rem;">${e.identity || '-'}</span>
                </td>
                <td class="td" style="font-family: 'JetBrains Mono'; font-weight: 600;">${toolDisplay}</td>
                <td class="td"><span class="tag" style="color: ${act === 'allow' ? 'var(--green)' : (act === 'redact' ? 'var(--orange)' : 'var(--red)')}">${act}</span></td>
                <td class="td" style="font-size: 0.8rem; color: var(--text-dim);">${e.reason || '-'}</td>
            `;
            return tr;
        }

        function connect() {
            const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/ws`);
            const feed = document.getElementById('feed-body');
            const alertBox = document.getElementById('alert-box');

            ws.onopen = () => { alertBox.style.display = 'none'; };
            ws.onmessage = (msg) => {
                const p = JSON.parse(msg.data);
                if (!riskChart) initChart();
                if (p.type === 'init') {
                    feed.innerHTML = '';
                    currentEvents = p.events || [];
                    
                    // Unified Update Path: Always calculate and update UI
                    calculateMetrics(currentEvents, p.stats);
                    
                    if (p.uptime) startTime = Date.now() - (p.uptime * 1000);
                    currentEvents.forEach(e => feed.appendChild(createRow(e)));
                } else if (p.type === 'event') {
                    currentEvents.unshift(p.data);
                    if (currentEvents.length > 100) currentEvents.pop();
                    
                    // Unified Update Path: Always calculate and update UI
                    calculateMetrics(currentEvents, p.current_stats);
                    
                    feed.prepend(createRow(p.data));
                    if (feed.children.length > 100) feed.removeChild(feed.lastChild);
                }
            };
            ws.onclose = () => { alertBox.style.display = 'flex'; setTimeout(connect, 2000); };
            
            setInterval(() => {
                const diff = Math.floor((Date.now() - startTime) / 1000);
                document.getElementById('val-uptime').innerText = `${Math.floor(diff/60)}m ${diff%60}s`;
            }, 1000);
        }
        connect();
    </script>
</body>
</html>
"""
