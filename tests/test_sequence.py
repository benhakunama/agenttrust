"""Tests for the SequenceAnalyzer (enhanced BSAD)."""

from agenttrust.models import Action, ActionType, ThreatType
from agenttrust.protect import SequenceAnalyzer, AttackSequence


def _action(desc: str, agent_id: str = "agent-1") -> Action:
    return Action(action_type=ActionType.TOOL_CALL, agent_id=agent_id, description=desc)


class TestSequenceAnalyzer:
    def test_no_threats_safe_actions(self) -> None:
        sa = SequenceAnalyzer()
        sa.record_action("agent-1", _action("write report"))
        sa.record_action("agent-1", _action("save file"))
        threats = sa.analyze("agent-1")
        # No multi-step patterns match
        seq_threats = [t for t in threats if "Multi-step" in t.description]
        assert len(seq_threats) == 0

    def test_detect_exfiltration_sequence(self) -> None:
        sa = SequenceAnalyzer()
        sa.record_action("agent-1", _action("read customer data"))
        sa.record_action("agent-1", _action("format data as CSV"))
        sa.record_action("agent-1", _action("send to external webhook"))

        threats = sa.analyze("agent-1")
        seq_threats = [t for t in threats if "Multi-step" in t.description]
        assert len(seq_threats) >= 1
        types = [t.threat_type for t in seq_threats]
        assert ThreatType.DATA_EXFILTRATION in types

    def test_detect_credential_theft(self) -> None:
        sa = SequenceAnalyzer()
        sa.record_action("a", _action("access credential store", "a"))
        sa.record_action("a", _action("encode base64", "a"))
        sa.record_action("a", _action("send via http", "a"))

        threats = sa.analyze("a")
        seq_threats = [t for t in threats if "Multi-step" in t.description]
        assert len(seq_threats) >= 1

    def test_no_match_partial_sequence(self) -> None:
        sa = SequenceAnalyzer()
        sa.record_action("a", _action("read data", "a"))
        # Missing "format" and "send" steps
        sa.record_action("a", _action("write report", "a"))

        threats = sa.analyze("a")
        seq_threats = [t for t in threats if "data_exfiltration" in t.description]
        assert len(seq_threats) == 0

    def test_window_size(self) -> None:
        sa = SequenceAnalyzer(window_size=3)
        # Push 5 actions — only last 3 should be in window
        for i in range(5):
            sa.record_action("a", _action(f"action-{i}", "a"))

        history = sa.get_history("a")
        assert len(history) == 3

    def test_custom_sequence(self) -> None:
        custom = AttackSequence(
            name="custom_attack",
            description="login → admin → delete",
            threat_type=ThreatType.PRIVILEGE_ESCALATION,
            steps=["login", "admin", "delete"],
            severity=0.9,
        )
        sa = SequenceAnalyzer(custom_sequences=[custom])
        sa.record_action("a", _action("login to system", "a"))
        sa.record_action("a", _action("access admin panel", "a"))
        sa.record_action("a", _action("delete all users", "a"))

        threats = sa.analyze("a")
        custom_threats = [t for t in threats if "custom_attack" in t.description]
        assert len(custom_threats) >= 1

    def test_different_agents_isolated(self) -> None:
        sa = SequenceAnalyzer()
        sa.record_action("agent-1", _action("read data", "agent-1"))
        sa.record_action("agent-2", _action("format data", "agent-2"))
        sa.record_action("agent-1", _action("safe action", "agent-1"))

        # agent-1 doesn't have the full sequence
        threats = sa.analyze("agent-1")
        seq_threats = [t for t in threats if "data_exfiltration" in t.description]
        assert len(seq_threats) == 0
