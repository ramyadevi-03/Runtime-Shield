import logging
import time
from typing import Dict, Any, Tuple
from enum import Enum

logger = logging.getLogger("risk_engine")

class RiskStatus(Enum):
    HEALTHY = "healthy"
    SUSPICIOUS = "suspicious"
    UNDER_ATTACK = "under_attack"
    TERMINATED = "terminated"

class RiskEngine:
    def __init__(self, 
                 terminate_threshold: int = 85,
                 suspicious_threshold: int = 40,
                 decay_rate: float = 0.1): # points per second
        self.terminate_threshold = terminate_threshold
        self.suspicious_threshold = suspicious_threshold
        self.decay_rate = decay_rate
        self.sessions = {} 

    def _apply_decay(self, session: Dict[str, Any]):
        """Apply temporal risk decay based on inactivity."""
        now = time.time()
        last_update = session.get("last_updated", now)
        elapsed = now - last_update
        if elapsed > 0:
            decay_amount = elapsed * self.decay_rate
            session["score"] = max(0, session["score"] - decay_amount)

    def update_risk(self, 
                    session_id: str, 
                    tenant_id: str, 
                    user_id: str, 
                    increment: int) -> Tuple[int, RiskStatus]:
        """
        Increment risk score with temporal decay and returning new status.
        """
        session = self.sessions.get(session_id, {
            "score": 0,
            "status": RiskStatus.HEALTHY,
            "violation_count": 0,
            "last_updated": time.time(),
            "creation_time": time.time()
        })

        # 1. Apply Decay before adding new risk
        self._apply_decay(session)

        # 2. Update Score
        new_score = min(100, session["score"] + increment)
        session["score"] = new_score
        session["last_updated"] = time.time()
        
        if increment > 0:
            session["violation_count"] += 1

        # 3. Determine Status
        if new_score >= self.terminate_threshold:
            session["status"] = RiskStatus.TERMINATED
        elif new_score >= self.suspicious_threshold:
            session["status"] = RiskStatus.SUSPICIOUS
        else:
            session["status"] = RiskStatus.HEALTHY

        self.sessions[session_id] = session

        return int(new_score), session["status"]

    def get_session_status(self, session_id: str) -> RiskStatus:
        session = self.sessions.get(session_id)
        if not session:
            return RiskStatus.HEALTHY
        return session["status"]

    def reset_session(self, session_id: str):
        if session_id in self.sessions:
            del self.sessions[session_id]
