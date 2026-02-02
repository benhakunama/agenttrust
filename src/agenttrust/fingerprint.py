"""Behavioral fingerprinting for AI agents.

Extracts behavioral features from agent action history and computes
a fingerprint vector that can be used to detect identity drift,
impersonation, or anomalous behavioral changes.
"""

from __future__ import annotations

import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import Action


@dataclass
class FingerprintVector:
    """A behavioral fingerprint vector for an agent.

    Attributes:
        agent_id: The agent this fingerprint belongs to.
        action_distribution: Normalized distribution of action types.
        tool_distribution: Normalized distribution of tools used.
        transition_matrix: Action-type transition probabilities.
        temporal_features: Temporal behavior features (avg interval, burstiness, etc.).
        computed_at: When this fingerprint was computed.
        action_count: Number of actions this fingerprint is based on.
    """

    agent_id: str = ""
    action_distribution: Dict[str, float] = field(default_factory=dict)
    tool_distribution: Dict[str, float] = field(default_factory=dict)
    transition_matrix: Dict[str, Dict[str, float]] = field(default_factory=dict)
    temporal_features: Dict[str, float] = field(default_factory=dict)
    computed_at: float = field(default_factory=time.time)
    action_count: int = 0

    def to_vector(self) -> List[float]:
        """Flatten the fingerprint into a numeric vector for distance calculations.

        Returns:
            List of floats representing the fingerprint.
        """
        vec: List[float] = []
        # Action distribution (sorted for consistency)
        for key in sorted(self.action_distribution.keys()):
            vec.append(self.action_distribution[key])
        # Tool distribution
        for key in sorted(self.tool_distribution.keys()):
            vec.append(self.tool_distribution[key])
        # Temporal features
        for key in sorted(self.temporal_features.keys()):
            vec.append(self.temporal_features[key])
        return vec

    def to_dict(self) -> Dict[str, Any]:
        """Export as JSON-serializable dictionary."""
        return {
            "agent_id": self.agent_id,
            "action_distribution": self.action_distribution,
            "tool_distribution": self.tool_distribution,
            "transition_matrix": self.transition_matrix,
            "temporal_features": self.temporal_features,
            "computed_at": self.computed_at,
            "action_count": self.action_count,
        }


class BehavioralFingerprint:
    """Computes and tracks behavioral fingerprints for agents.

    Extracts features from action history including:
    - Action type distribution (what kinds of actions)
    - Tool usage distribution (which tools)
    - Transition probabilities (what follows what)
    - Temporal patterns (timing, burstiness, periodicity)

    Detects behavioral drift by comparing current fingerprint
    against historical baselines.
    """

    def __init__(
        self,
        window_size: int = 100,
        drift_threshold: float = 0.3,
    ) -> None:
        """Initialize the fingerprinting engine.

        Args:
            window_size: Number of recent actions to use for current fingerprint.
            drift_threshold: Cosine distance threshold above which drift is flagged.
        """
        self._window_size = window_size
        self._drift_threshold = drift_threshold
        self._agent_actions: Dict[str, List[Action]] = defaultdict(list)
        self._baselines: Dict[str, FingerprintVector] = {}
        self._history: Dict[str, List[FingerprintVector]] = defaultdict(list)

    def record_action(self, action: Action) -> None:
        """Record an action for fingerprinting.

        Args:
            action: The action to record.
        """
        self._agent_actions[action.agent_id].append(action)

    def compute_fingerprint(self, agent_id: str) -> FingerprintVector:
        """Compute the current behavioral fingerprint for an agent.

        Args:
            agent_id: The agent to fingerprint.

        Returns:
            FingerprintVector with extracted features.
        """
        actions = self._agent_actions.get(agent_id, [])
        recent = actions[-self._window_size:] if actions else []

        fp = FingerprintVector(
            agent_id=agent_id,
            action_count=len(recent),
        )

        if not recent:
            return fp

        # Action type distribution
        type_counts = Counter(a.action_type.value if hasattr(a.action_type, "value") else str(a.action_type) for a in recent)
        total = sum(type_counts.values())
        fp.action_distribution = {k: v / total for k, v in type_counts.items()}

        # Tool distribution (from description or metadata)
        tool_counts: Counter = Counter()
        for a in recent:
            tool = a.metadata.get("tool", a.description.split()[0] if a.description else "unknown")
            tool_counts[tool] += 1
        tool_total = sum(tool_counts.values())
        fp.tool_distribution = {k: v / tool_total for k, v in tool_counts.items()}

        # Transition matrix
        transitions: Dict[str, Counter] = defaultdict(Counter)
        for i in range(len(recent) - 1):
            from_type = recent[i].action_type.value if hasattr(recent[i].action_type, "value") else str(recent[i].action_type)
            to_type = recent[i + 1].action_type.value if hasattr(recent[i + 1].action_type, "value") else str(recent[i + 1].action_type)
            transitions[from_type][to_type] += 1

        fp.transition_matrix = {}
        for from_type, counts in transitions.items():
            t = sum(counts.values())
            fp.transition_matrix[from_type] = {k: v / t for k, v in counts.items()}

        # Temporal features
        timestamps = [a.timestamp for a in recent]
        if len(timestamps) >= 2:
            intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
            intervals = [iv for iv in intervals if iv >= 0]
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                variance = sum((iv - avg_interval) ** 2 for iv in intervals) / len(intervals)
                std_dev = math.sqrt(variance)
                burstiness = (std_dev - avg_interval) / (std_dev + avg_interval) if (std_dev + avg_interval) > 0 else 0.0

                fp.temporal_features = {
                    "avg_interval": avg_interval,
                    "std_interval": std_dev,
                    "burstiness": burstiness,
                    "min_interval": min(intervals),
                    "max_interval": max(intervals),
                    "total_duration": timestamps[-1] - timestamps[0],
                    "actions_per_second": len(recent) / max(timestamps[-1] - timestamps[0], 0.001),
                }
            else:
                fp.temporal_features = self._default_temporal()
        else:
            fp.temporal_features = self._default_temporal()

        # Store in history
        self._history[agent_id].append(fp)
        # Keep last 50 fingerprints
        if len(self._history[agent_id]) > 50:
            self._history[agent_id] = self._history[agent_id][-50:]

        return fp

    def set_baseline(self, agent_id: str, fingerprint: Optional[FingerprintVector] = None) -> FingerprintVector:
        """Set or compute a baseline fingerprint for drift detection.

        Args:
            agent_id: The agent to baseline.
            fingerprint: Use this fingerprint as baseline (computes fresh if None).

        Returns:
            The baseline FingerprintVector.
        """
        if fingerprint is None:
            fingerprint = self.compute_fingerprint(agent_id)
        self._baselines[agent_id] = fingerprint
        return fingerprint

    def compute_drift_score(self, agent_id: str) -> float:
        """Compute behavioral drift from the baseline.

        Uses cosine distance between current and baseline fingerprint vectors.

        Args:
            agent_id: The agent to check.

        Returns:
            Drift score between 0.0 (identical) and 1.0 (completely different).
            Returns 0.0 if no baseline exists.
        """
        baseline = self._baselines.get(agent_id)
        if baseline is None:
            return 0.0

        current = self.compute_fingerprint(agent_id)
        return self._cosine_distance(baseline, current)

    def is_drifting(self, agent_id: str) -> bool:
        """Check if an agent's behavior has drifted beyond the threshold.

        Args:
            agent_id: The agent to check.

        Returns:
            True if drift exceeds the configured threshold.
        """
        return self.compute_drift_score(agent_id) > self._drift_threshold

    def get_history(self, agent_id: str) -> List[FingerprintVector]:
        """Get fingerprint history for an agent.

        Args:
            agent_id: The agent to query.

        Returns:
            List of historical FingerprintVector objects.
        """
        return list(self._history.get(agent_id, []))

    # ── Internal helpers ───────────────────────────────────────────────

    @staticmethod
    def _cosine_distance(a: FingerprintVector, b: FingerprintVector) -> float:
        """Compute cosine distance between two fingerprint vectors.

        To handle different feature sets, we build a unified key space.
        """
        # Build unified distributions
        all_action_keys = sorted(set(list(a.action_distribution.keys()) + list(b.action_distribution.keys())))
        all_tool_keys = sorted(set(list(a.tool_distribution.keys()) + list(b.tool_distribution.keys())))
        all_temporal_keys = sorted(set(list(a.temporal_features.keys()) + list(b.temporal_features.keys())))

        vec_a: List[float] = []
        vec_b: List[float] = []

        for k in all_action_keys:
            vec_a.append(a.action_distribution.get(k, 0.0))
            vec_b.append(b.action_distribution.get(k, 0.0))

        for k in all_tool_keys:
            vec_a.append(a.tool_distribution.get(k, 0.0))
            vec_b.append(b.tool_distribution.get(k, 0.0))

        for k in all_temporal_keys:
            # Normalize temporal features to [0,1] range roughly
            va = a.temporal_features.get(k, 0.0)
            vb = b.temporal_features.get(k, 0.0)
            max_val = max(abs(va), abs(vb), 1.0)
            vec_a.append(va / max_val)
            vec_b.append(vb / max_val)

        if not vec_a:
            return 0.0

        # Cosine similarity → distance
        dot = sum(x * y for x, y in zip(vec_a, vec_b))
        mag_a = math.sqrt(sum(x * x for x in vec_a))
        mag_b = math.sqrt(sum(x * x for x in vec_b))

        if mag_a == 0 or mag_b == 0:
            return 1.0 if mag_a != mag_b else 0.0

        similarity = dot / (mag_a * mag_b)
        # Clamp to [-1, 1] for numerical stability
        similarity = max(-1.0, min(1.0, similarity))
        return 1.0 - similarity

    @staticmethod
    def _default_temporal() -> Dict[str, float]:
        """Default temporal features when not enough data."""
        return {
            "avg_interval": 0.0,
            "std_interval": 0.0,
            "burstiness": 0.0,
            "min_interval": 0.0,
            "max_interval": 0.0,
            "total_duration": 0.0,
            "actions_per_second": 0.0,
        }
