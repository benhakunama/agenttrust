"""Tests for ABG integration in ObserveTracer."""

from agenttrust.models import ActionType
from agenttrust.observe import ObserveTracer


class TestObserveABG:
    def test_abg_built_from_actions(self) -> None:
        tracer = ObserveTracer()
        tracer.record_action("agent-1", ActionType.TOOL_CALL, "query db", metadata={"tool": "db", "data_pattern": "read"})
        tracer.record_action("agent-1", ActionType.LLM_CALL, "process data")
        tracer.record_action("agent-1", ActionType.TOOL_CALL, "send email", metadata={"tool": "email", "data_pattern": "send_external"})

        abg = tracer.get_abg()
        assert abg.node_count == 3
        assert abg.edge_count == 2

    def test_abg_cleared(self) -> None:
        tracer = ObserveTracer()
        tracer.record_action("a", ActionType.TOOL_CALL, "test")
        tracer.clear()
        abg = tracer.get_abg()
        assert abg.node_count == 0

    def test_abg_multi_agent(self) -> None:
        tracer = ObserveTracer()
        tracer.record_action("a1", ActionType.TOOL_CALL, "x")
        tracer.record_action("a2", ActionType.TOOL_CALL, "y")
        tracer.record_action("a1", ActionType.LLM_CALL, "z")

        abg = tracer.get_abg()
        assert abg.node_count == 3

        sub = abg.get_subgraph("a1")
        assert sub.node_count == 2
