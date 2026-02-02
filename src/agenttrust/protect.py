"""Layer 2: AgentProtect — Behavioral firewall for AI agents."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .models import (
    Action,
    ResponseAction,
    ThreatDetection,
    ThreatType,
    TrustDecision,
)
from .patterns import ALL_PATTERNS, ThreatPattern
from .scoring import TrustScoreEngine


class BehavioralFirewall:
    """Behavioral firewall that evaluates agent actions for threats.

    Uses pattern-based threat detection with a graduated response system.
    Maintains per-agent behavioral history for trust score computation.
    """

    # Trust score thresholds for graduated responses
    THRESHOLDS = {
        ResponseAction.ALLOW: 0.8,
        ResponseAction.WARN: 0.6,
        ResponseAction.THROTTLE: 0.4,
        ResponseAction.ISOLATE: 0.2,
        ResponseAction.BLOCK: 0.0,
    }

    def __init__(
        self,
        custom_patterns: Optional[List[ThreatPattern]] = None,
        scoring_engine: Optional[TrustScoreEngine] = None,
    ) -> None:
        """Initialize the behavioral firewall.

        Args:
            custom_patterns: Additional threat patterns to evaluate.
            scoring_engine: Custom scoring engine (uses default if None).
        """
        self._patterns = list(ALL_PATTERNS)
        if custom_patterns:
            self._patterns.extend(custom_patterns)
        self._scoring = scoring_engine or TrustScoreEngine()
        self._rate_limits: Dict[str, List[float]] = defaultdict(list)
        self._alerts: List[ThreatDetection] = []

    def evaluate_action(
        self,
        agent_id: str,
        action: Action,
        context: Optional[Dict[str, Any]] = None,
    ) -> TrustDecision:
        """Evaluate an action through the behavioral firewall.

        Args:
            agent_id: The agent performing the action.
            action: The action to evaluate.
            context: Additional context for evaluation.

        Returns:
            TrustDecision with the response action and reasoning.
        """
        context = context or {}
        threats: List[ThreatDetection] = []

        # Scan input data for threats
        text_to_scan = " ".join(filter(None, [
            action.description,
            action.input_data,
            action.output_data,
            str(action.metadata) if action.metadata else None,
        ]))

        for pattern in self._patterns:
            confidence = pattern.match(text_to_scan)
            if confidence is not None and confidence > 0.0:
                threat = ThreatDetection(
                    threat_type=pattern.threat_type,
                    confidence=confidence,
                    description=pattern.description,
                    evidence=text_to_scan[:200],
                )
                threats.append(threat)

        # Check rate limiting
        if self._is_rate_limited(agent_id):
            threats.append(ThreatDetection(
                threat_type=ThreatType.BEHAVIORAL_DRIFT,
                confidence=0.5,
                description="Agent is making requests at an unusually high rate",
            ))

        # Record the rate
        self._rate_limits[agent_id].append(time.time())
        # Keep only last 60 seconds of timestamps
        cutoff = time.time() - 60
        self._rate_limits[agent_id] = [
            t for t in self._rate_limits[agent_id] if t > cutoff
        ]

        # Determine response action
        if not threats:
            response = ResponseAction.ALLOW
            reasoning = "No threats detected"
        else:
            max_severity = max(t.confidence for t in threats)
            threat_types = [t.threat_type.value for t in threats]

            if max_severity >= 0.8:
                # Check for combined escalation
                if len(set(threat_types)) >= 2:
                    response = ResponseAction.ISOLATE
                    reasoning = f"Multiple threat types detected: {', '.join(threat_types)}"
                else:
                    response = ResponseAction.BLOCK
                    reasoning = f"High-severity threat: {threat_types[0]}"
            elif max_severity >= 0.6:
                response = ResponseAction.THROTTLE
                reasoning = f"Medium-severity threat detected: {', '.join(threat_types)}"
            elif max_severity >= 0.3:
                response = ResponseAction.WARN
                reasoning = f"Low-severity indicators: {', '.join(threat_types)}"
            else:
                response = ResponseAction.ALLOW
                reasoning = "Threat indicators below threshold"

        # Update trust score
        trust_score = self._scoring.record_action(agent_id, response, threats)

        # Store alerts
        if threats:
            self._alerts.extend(threats)

        return TrustDecision(
            action=response,
            trust_score=trust_score,
            threats=threats,
            reasoning=reasoning,
        )

    def get_trust_score(self, agent_id: str) -> float:
        """Get the current trust score for an agent.

        Args:
            agent_id: The agent to query.

        Returns:
            Trust score between 0.0 and 1.0.
        """
        return self._scoring.get_score(agent_id)

    def get_alerts(self, limit: int = 100) -> List[ThreatDetection]:
        """Get recent threat alerts.

        Args:
            limit: Maximum number of alerts to return.

        Returns:
            List of ThreatDetection alerts.
        """
        return sorted(self._alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

    def _is_rate_limited(self, agent_id: str, window: float = 60.0, max_requests: int = 100) -> bool:
        """Check if an agent is making requests too fast.

        Args:
            agent_id: The agent to check.
            window: Time window in seconds.
            max_requests: Maximum requests allowed in window.

        Returns:
            True if rate limited.
        """
        cutoff = time.time() - window
        recent = [t for t in self._rate_limits.get(agent_id, []) if t > cutoff]
        return len(recent) >= max_requests
