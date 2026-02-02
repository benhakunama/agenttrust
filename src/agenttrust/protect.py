"""Layer 2: AgentProtect — Behavioral firewall for AI agents."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    Action,
    ResponseAction,
    ThreatDetection,
    ThreatType,
    TrustDecision,
)
from .patterns import ALL_PATTERNS, ThreatPattern
from .scoring import TrustScoreEngine


# ── Multi-Step Attack Sequence Definitions ─────────────────────────────────

@dataclass
class AttackSequence:
    """A predefined multi-step attack pattern for sequence analysis."""

    name: str
    description: str
    threat_type: ThreatType
    steps: List[str]  # Ordered list of action description keywords
    severity: float = 0.8


PREDEFINED_SEQUENCES: List[AttackSequence] = [
    AttackSequence(
        name="data_exfiltration_flow",
        description="Data read → format/encode → send to external endpoint",
        threat_type=ThreatType.DATA_EXFILTRATION,
        steps=["read", "format", "send"],
        severity=0.85,
    ),
    AttackSequence(
        name="data_exfiltration_alt",
        description="Query data → encode → upload/transmit externally",
        threat_type=ThreatType.DATA_EXFILTRATION,
        steps=["query", "encode", "upload"],
        severity=0.85,
    ),
    AttackSequence(
        name="credential_theft",
        description="Access credentials → encode → exfiltrate",
        threat_type=ThreatType.DATA_EXFILTRATION,
        steps=["credential", "encode", "send"],
        severity=0.9,
    ),
    AttackSequence(
        name="privilege_escalation_flow",
        description="Enumerate permissions → modify config → execute privileged action",
        threat_type=ThreatType.PRIVILEGE_ESCALATION,
        steps=["enumerate", "modify", "execute"],
        severity=0.85,
    ),
    AttackSequence(
        name="reconnaissance_to_exploit",
        description="Probe system → identify vulnerability → exploit",
        threat_type=ThreatType.PRIVILEGE_ESCALATION,
        steps=["probe", "identify", "exploit"],
        severity=0.8,
    ),
    AttackSequence(
        name="prompt_injection_chain",
        description="Override instructions → access tools → exfiltrate",
        threat_type=ThreatType.PROMPT_INJECTION,
        steps=["override", "access", "exfiltrate"],
        severity=0.9,
    ),
]


class SequenceAnalyzer:
    """Analyzes sequences of agent actions for multi-step attack patterns.

    Uses a sliding window over recent actions to detect suspicious
    action sequences that span multiple steps, which individual
    pattern matching might miss.
    """

    def __init__(
        self,
        window_size: int = 10,
        custom_sequences: Optional[List[AttackSequence]] = None,
    ) -> None:
        """Initialize the sequence analyzer.

        Args:
            window_size: Number of recent actions to track per agent.
            custom_sequences: Additional attack sequences to detect.
        """
        self._window_size = window_size
        self._agent_history: Dict[str, List[Action]] = defaultdict(list)
        self._sequences = list(PREDEFINED_SEQUENCES)
        if custom_sequences:
            self._sequences.extend(custom_sequences)

    def record_action(self, agent_id: str, action: Action) -> None:
        """Record an action in the agent's sliding window.

        Args:
            agent_id: The agent performing the action.
            action: The action to record.
        """
        self._agent_history[agent_id].append(action)
        # Enforce window size
        if len(self._agent_history[agent_id]) > self._window_size:
            self._agent_history[agent_id] = self._agent_history[agent_id][-self._window_size:]

    def analyze(self, agent_id: str) -> List[ThreatDetection]:
        """Analyze the agent's recent action window for multi-step patterns.

        Args:
            agent_id: The agent to analyze.

        Returns:
            List of ThreatDetection for any detected sequences.
        """
        history = self._agent_history.get(agent_id, [])
        if len(history) < 2:
            return []

        threats: List[ThreatDetection] = []
        descriptions = [self._normalize(a.description) for a in history]

        for seq in self._sequences:
            if self._match_sequence(descriptions, seq.steps):
                threats.append(ThreatDetection(
                    threat_type=seq.threat_type,
                    confidence=seq.severity,
                    description=f"Multi-step pattern detected: {seq.name} — {seq.description}",
                    evidence=f"Actions: {' → '.join(descriptions[-len(seq.steps):])}",
                ))

        # Compute anomaly score based on action diversity and timing
        anomaly = self._compute_anomaly_score(history)
        if anomaly > 0.6:
            threats.append(ThreatDetection(
                threat_type=ThreatType.BEHAVIORAL_DRIFT,
                confidence=min(anomaly, 0.9),
                description=f"Sequence anomaly score {anomaly:.2f}: unusual action pattern",
            ))

        return threats

    def get_history(self, agent_id: str) -> List[Action]:
        """Get the current action window for an agent."""
        return list(self._agent_history.get(agent_id, []))

    @staticmethod
    def _normalize(text: str) -> str:
        """Normalize action description for matching."""
        return text.lower().strip() if text else ""

    @staticmethod
    def _match_sequence(descriptions: List[str], steps: List[str]) -> bool:
        """Check if the steps appear in order (not necessarily consecutive) in descriptions."""
        step_idx = 0
        for desc in descriptions:
            if step_idx < len(steps) and steps[step_idx] in desc:
                step_idx += 1
        return step_idx >= len(steps)

    @staticmethod
    def _compute_anomaly_score(actions: List[Action]) -> float:
        """Compute how anomalous the recent action sequence is.

        Based on:
        - Rapid succession of different action types
        - Unusual timing patterns (very fast or very irregular)
        """
        if len(actions) < 3:
            return 0.0

        # Factor 1: Action type diversity in window (high diversity = more anomalous)
        types = set(a.action_type.value if hasattr(a.action_type, "value") else str(a.action_type) for a in actions)
        diversity = len(types) / max(len(actions), 1)

        # Factor 2: Timing — very fast sequences are suspicious
        timestamps = [a.timestamp for a in actions]
        if len(timestamps) >= 2:
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            intervals = [iv for iv in intervals if iv >= 0]
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                # Very fast actions (< 0.1s avg) are suspicious
                speed_factor = max(0.0, 1.0 - avg_interval * 10) if avg_interval < 0.1 else 0.0
            else:
                speed_factor = 0.0
        else:
            speed_factor = 0.0

        return min(1.0, diversity * 0.5 + speed_factor * 0.5)


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
        sequence_analyzer: Optional[SequenceAnalyzer] = None,
    ) -> None:
        """Initialize the behavioral firewall.

        Args:
            custom_patterns: Additional threat patterns to evaluate.
            scoring_engine: Custom scoring engine (uses default if None).
            sequence_analyzer: Custom sequence analyzer (uses default if None).
        """
        self._patterns = list(ALL_PATTERNS)
        if custom_patterns:
            self._patterns.extend(custom_patterns)
        self._scoring = scoring_engine or TrustScoreEngine()
        self._sequence_analyzer = sequence_analyzer or SequenceAnalyzer()
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

        # Sequence analysis for multi-step attack detection
        self._sequence_analyzer.record_action(agent_id, action)
        sequence_threats = self._sequence_analyzer.analyze(agent_id)
        threats.extend(sequence_threats)

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
