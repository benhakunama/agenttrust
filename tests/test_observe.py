"""Tests for the ObserveTracer module."""

import time

from agenttrust.models import ActionType
from agenttrust.observe import ObserveTracer


class TestObserveTracer:
    def test_record_action(self) -> None:
        tracer = ObserveTracer()
        action = tracer.record_action(
            agent_id="test-agent",
            action_type=ActionType.TOOL_CALL,
            description="Testing tool call",
            input_data="test input",
        )
        assert action.agent_id == "test-agent"
        assert action.action_type == ActionType.TOOL_CALL
        assert action.description == "Testing tool call"
        assert action.input_data == "test input"

    def test_get_actions(self) -> None:
        tracer = ObserveTracer()
        for i in range(5):
            tracer.record_action(
                agent_id="agent-1",
                action_type=ActionType.LLM_CALL,
                description=f"Action {i}",
            )
        tracer.record_action(
            agent_id="agent-2",
            action_type=ActionType.TOOL_CALL,
            description="Other agent action",
        )

        all_actions = tracer.get_actions()
        assert len(all_actions) == 6

        agent1_actions = tracer.get_actions(agent_id="agent-1")
        assert len(agent1_actions) == 5

        tool_actions = tracer.get_actions(action_type=ActionType.TOOL_CALL)
        assert len(tool_actions) == 1

    def test_start_end_trace(self) -> None:
        tracer = ObserveTracer()
        trace = tracer.start_trace("agent-1", metadata={"test": True})
        assert trace.agent_id == "agent-1"
        assert trace.metadata == {"test": True}

        tracer.record_action(
            agent_id="agent-1",
            action_type=ActionType.LLM_CALL,
            description="Inside trace",
            trace_id=trace.trace_id,
        )

        completed = tracer.end_trace(trace.trace_id)
        assert completed is not None
        assert completed.end_time is not None
        assert len(completed.actions) == 1
        assert completed.duration_ms is not None
        assert completed.duration_ms >= 0

    def test_get_traces(self) -> None:
        tracer = ObserveTracer()
        t1 = tracer.start_trace("agent-1")
        t2 = tracer.start_trace("agent-2")
        tracer.end_trace(t1.trace_id)
        tracer.end_trace(t2.trace_id)

        traces = tracer.get_traces()
        assert len(traces) == 2

        agent1_traces = tracer.get_traces(agent_id="agent-1")
        assert len(agent1_traces) == 1

    def test_action_count(self) -> None:
        tracer = ObserveTracer()
        assert tracer.get_action_count() == 0
        tracer.record_action("a", ActionType.LLM_CALL, "test")
        tracer.record_action("a", ActionType.TOOL_CALL, "test2")
        assert tracer.get_action_count() == 2

    def test_clear(self) -> None:
        tracer = ObserveTracer()
        tracer.record_action("a", ActionType.LLM_CALL, "test")
        tracer.clear()
        assert tracer.get_action_count() == 0
        assert len(tracer.get_actions()) == 0

    def test_limit_enforcement(self) -> None:
        tracer = ObserveTracer(max_actions=10)
        for i in range(20):
            tracer.record_action("a", ActionType.LLM_CALL, f"action-{i}")
        # Should have trimmed to max
        all_actions = tracer.get_actions(limit=100)
        assert len(all_actions) <= 10
