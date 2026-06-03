import sqlite3
from typing import List, Dict

DB_PATH = "telemetry.db"

class AuditReplay:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    def get_session_timeline(self, session_id: str) -> List[Dict]:
        """Fetch all events for a session and format as a timeline."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM telemetry_events 
            WHERE session_id = ? 
            ORDER BY timestamp ASC
        ''', (session_id,))
        
        rows = cursor.fetchall()
        conn.close()
        
        timeline = []
        for row in rows:
            event = dict(row)
            # Reconstruct the "story" of the event
            timeline.append({
                "time": event["timestamp"],
                "type": event["event_type"],
                "user": event["username"],
                "tool": event["tool"],
                "resource": event["resource"],
                "status": event["status"],
                "reason": event["reason"],
                "risk_score": event["risk_score"],
                "severity": event["severity"]
            })
            
        return timeline

    def get_risky_sessions(self, limit: int = 10) -> List[Dict]:
        """Get sessions with the highest risk scores."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('''
            SELECT session_id, tenant_id, user_id, MAX(risk_score) as max_risk, COUNT(*) as event_count
            FROM telemetry_events
            GROUP BY session_id
            HAVING max_risk > 30
            ORDER BY max_risk DESC
            LIMIT ?
        ''', (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]
