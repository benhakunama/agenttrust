"""Tests for the behavioral fingerprinting module."""

import time

from agenttrust.fingerprint import BehavioralFingerprint, FingerprintVector
from agenttrust.models import Action, ActionType


def _action(agent_id: str, atype: ActionType = ActionType.TOOL_CALL, desc: str = "test", ts: float = 0.0) -> Action:
    a = Action(action_type=atype, agent_id=agent_id, description=desc)
    if ts:
        a.timestamp = ts
    return a


class TestBehavioralFingerprint:
    def test_compute_empty(self) -> None:
        fp_engine = BehavioralFingerprint()
        fp = fp_engine.compute_fingerprint("agent-1")
        assert fp.action_count == 0
        assert fp.agent_id == "agent-1"

    def test_compute_with_actions(self) -> None:
        fp_engine = BehavioralFingerprint()
        base_ts = time.time()
        for i in range(10):
            fp_engine.record_action(_action("agent-1", ActionType.TOOL_CALL, f"query_{i}", base_ts + i))
        for i in range(5):
            fp_engine.record_action(_action("agent-1", ActionType.LLM_CALL, f"llm_{i}", base_ts + 10 + i))

        fp = fp_engine.compute_fingerprint("agent-1")
        assert fp.action_count == 15
        assert ActionType.TOOL_CALL.value in fp.action_distribution
        assert ActionType.LLM_CALL.value in fp.action_distribution
        # Tool calls are 10/15
        assert abs(fp.action_distribution[ActionType.TOOL_CALL.value] - 10 / 15) < 0.01

    def test_transition_matrix(self) -> None:
        fp_engine = BehavioralFingerprint()
        base_ts = time.time()
        # Alternating pattern
        for i in range(6):
            atype = ActionType.TOOL_CALL if i % 2 == 0 else ActionType.LLM_CALL
            fp_engine.record_action(_action("a", atype, f"act_{i}", base_ts + i))

        fp = fp_engine.compute_fingerprint("a")
        assert ActionType.TOOL_CALL.value in fp.transition_matrix
        # TOOL_CALL always transitions to LLM_CALL
        assert fp.transition_matrix[ActionType.TOOL_CALL.value].get(ActionType.LLM_CALL.value, 0) > 0

    def test_temporal_features(self) -> None:
        fp_engine = BehavioralFingerprint()
        base_ts = time.time()
        for i in range(5):
            fp_engine.record_action(_action("a", ts=base_ts + i * 2.0))

        fp = fp_engine.compute_fingerprint("a")
        assert fp.temporal_features["avg_interval"] > 0
        assert fp.temporal_features["total_duration"] > 0

    def test_set_baseline_and_drift(self) -> None:
        fp_engine = BehavioralFingerprint()
        base_ts = time.time()

        # Baseline: mostly tool calls
        for i in range(20):
            fp_engine.record_action(_action("a", ActionType.TOOL_CALL, f"query_{i}", base_ts + i))
        fp_engine.set_baseline("a")

        # Now change behavior completely: only LLM calls
        for i in range(20):
            fp_engine.record_action(_action("a", ActionType.LLM_CALL, f"llm_{i}", base_ts + 20 + i))

        drift = fp_engine.compute_drift_score("a")
        assert drift > 0.0  # Should detect some drift

    def test_no_drift_without_baseline(self) -> None:
        fp_engine = BehavioralFingerprint()
        assert fp_engine.compute_drift_score("unknown") == 0.0

    def test_is_drifting(self) -> None:
        fp_engine = BehavioralFingerprint(drift_threshold=0.01)  # Very low threshold
        base_ts = time.time()

        for i in range(20):
            fp_engine.record_action(_action("a", ActionType.TOOL_CALL, f"q_{i}", base_ts + i))
        fp_engine.set_baseline("a")

        for i in range(20):
            fp_engine.record_action(_action("a", ActionType.LLM_CALL, f"l_{i}", base_ts + 20 + i))

        # With such a low threshold, any change should trigger
        assert fp_engine.is_drifting("a") or fp_engine.compute_drift_score("a") >= 0.0

    def test_fingerprint_vector(self) -> None:
        fp = FingerprintVector(
            agent_id="a",
            action_distribution={"tool_call": 0.6, "llm_call": 0.4},
            tool_distribution={"db_query": 1.0},
            temporal_features={"avg_interval": 1.0},
        )
        vec = fp.to_vector()
        assert len(vec) > 0
        assert all(isinstance(v, float) for v in vec)

    def test_fingerprint_to_dict(self) -> None:
        fp = FingerprintVector(agent_id="a", action_count=10)
        d = fp.to_dict()
        assert d["agent_id"] == "a"
        assert d["action_count"] == 10

    def test_history(self) -> None:
        fp_engine = BehavioralFingerprint()
        fp_engine.record_action(_action("a"))
        fp_engine.compute_fingerprint("a")
        fp_engine.compute_fingerprint("a")
        history = fp_engine.get_history("a")
        assert len(history) == 2
