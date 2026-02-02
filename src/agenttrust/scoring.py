"""Trust score computation engine."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .models import ResponseAction, ThreatDetection, ThreatType


@dataclass
class BehaviorRecord:
    """Record of an agent's behavioral history."""

    total_actions: int = 0
    safe_actions: int = 0
    warned_actions: int = 0
    blocked_actions: int = 0
    isolated_actions: int = 0
    threats_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    last_action_time: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    trust_score_history: List[float] = field(default_factory=list)


class TrustScoreEngine:
    """Computes and manages trust scores for agents."""

    # Weights for different factors
    HISTORY_WEIGHT = 0.4
    RECENT_WEIGHT = 0.35
    THREAT_WEIGHT = 0.25

    # Penalty multipliers per threat type
    THREAT_PENALTIES: Dict[ThreatType, float] = {
        ThreatType.PROMPT_INJECTION: 0.25,
        ThreatType.PRIVILEGE_ESCALATION: 0.30,
        ThreatType.DATA_EXFILTRATION: 0.35,
        ThreatType.BEHAVIORAL_DRIFT: 0.15,
    }

    # Recovery rate per second (trust slowly recovers)
    RECOVERY_RATE = 0.001

    def __init__(self) -> None:
        self._records: Dict[str, BehaviorRecord] = {}

    def get_or_create_record(self, agent_id: str) -> BehaviorRecord:
        """Get or create a behavior record for an agent."""
        if agent_id not in self._records:
            self._records[agent_id] = BehaviorRecord()
        return self._records[agent_id]

    def record_action(
        self,
        agent_id: str,
        response: ResponseAction,
        threats: Optional[List[ThreatDetection]] = None,
    ) -> float:
        """Record an action and return the updated trust score."""
        record = self.get_or_create_record(agent_id)
        record.total_actions += 1
        record.last_action_time = time.time()

        if response == ResponseAction.ALLOW:
            record.safe_actions += 1
        elif response == ResponseAction.WARN:
            record.warned_actions += 1
        elif response == ResponseAction.BLOCK:
            record.blocked_actions += 1
        elif response == ResponseAction.ISOLATE:
            record.isolated_actions += 1

        if threats:
            for threat in threats:
                record.threats_by_type[threat.threat_type.value] += 1

        score = self.compute_score(agent_id)
        record.trust_score_history.append(score)
        # Keep last 1000 scores
        if len(record.trust_score_history) > 1000:
            record.trust_score_history = record.trust_score_history[-1000:]

        return score

    def compute_score(self, agent_id: str) -> float:
        """Compute the current trust score for an agent."""
        record = self.get_or_create_record(agent_id)

        if record.total_actions == 0:
            return 1.0

        # Factor 1: Historical safety ratio
        safety_ratio = record.safe_actions / record.total_actions
        history_score = safety_ratio

        # Factor 2: Recent behavior (weighted toward recent scores)
        if record.trust_score_history:
            recent = record.trust_score_history[-10:]
            recent_score = sum(recent) / len(recent)
        else:
            recent_score = 1.0

        # Factor 3: Threat penalty
        threat_penalty = 0.0
        for threat_type_str, count in record.threats_by_type.items():
            try:
                threat_type = ThreatType(threat_type_str)
                penalty = self.THREAT_PENALTIES.get(threat_type, 0.1)
                threat_penalty += penalty * min(count, 5)  # Cap at 5 per type
            except ValueError:
                threat_penalty += 0.1 * min(count, 5)

        threat_score = max(0.0, 1.0 - threat_penalty)

        # Factor 4: Time-based recovery
        elapsed = time.time() - record.last_action_time
        recovery = min(elapsed * self.RECOVERY_RATE, 0.1)

        # Weighted combination
        raw_score = (
            self.HISTORY_WEIGHT * history_score
            + self.RECENT_WEIGHT * recent_score
            + self.THREAT_WEIGHT * threat_score
            + recovery
        )

        return max(0.0, min(1.0, raw_score))

    def get_score(self, agent_id: str) -> float:
        """Get the current trust score for an agent."""
        return self.compute_score(agent_id)

    def reset(self, agent_id: str) -> None:
        """Reset an agent's behavioral history."""
        if agent_id in self._records:
            del self._records[agent_id]
