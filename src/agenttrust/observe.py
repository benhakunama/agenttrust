"""Layer 1: AgentObserve — Tracing and observability for AI agents."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .abg import AgentBehavioralGraph
from .models import Action, ActionType, Trace


class ObserveTracer:
    """High-performance tracer for agent actions.

    Traces every agent action including tool calls, LLM calls, and chain
    executions. Designed for <5ms overhead with in-memory storage and
    async-ready collection.
    """

    def __init__(self, max_traces: int = 10000, max_actions: int = 100000) -> None:
        """Initialize the tracer.

        Args:
            max_traces: Maximum number of traces to retain in memory.
            max_actions: Maximum number of actions to retain in memory.
        """
        self._traces: Dict[str, Trace] = {}
        self._actions: List[Action] = []
        self._active_traces: Dict[str, Trace] = {}
        self._agent_actions: Dict[str, List[Action]] = defaultdict(list)
        self._max_traces = max_traces
        self._max_actions = max_actions
        self._lock = threading.Lock()
        self._action_count = 0
        self._abg = AgentBehavioralGraph()

    def start_trace(self, agent_id: str, metadata: Optional[Dict[str, Any]] = None) -> Trace:
        """Start a new trace for an agent.

        Args:
            agent_id: The ID of the agent being traced.
            metadata: Optional metadata to attach to the trace.

        Returns:
            The newly created Trace object.
        """
        trace = Trace(agent_id=agent_id, metadata=metadata or {})
        with self._lock:
            self._active_traces[trace.trace_id] = trace
        return trace

    def end_trace(self, trace_id: str) -> Optional[Trace]:
        """End an active trace.

        Args:
            trace_id: The ID of the trace to end.

        Returns:
            The completed Trace, or None if not found.
        """
        with self._lock:
            trace = self._active_traces.pop(trace_id, None)
            if trace:
                trace.end_time = time.time()
                self._traces[trace.trace_id] = trace
                self._enforce_limits()
            return trace

    def record_action(
        self,
        agent_id: str,
        action_type: ActionType,
        description: str,
        trace_id: Optional[str] = None,
        input_data: Optional[str] = None,
        output_data: Optional[str] = None,
        duration_ms: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Action:
        """Record a single agent action.

        Args:
            agent_id: The agent performing the action.
            action_type: Type of action (LLM call, tool call, etc.).
            description: Human-readable description of the action.
            trace_id: Optional trace to associate with.
            input_data: Input data for the action.
            output_data: Output data from the action.
            duration_ms: Duration of the action in milliseconds.
            metadata: Additional metadata.

        Returns:
            The recorded Action object.
        """
        action = Action(
            action_type=action_type,
            agent_id=agent_id,
            description=description,
            input_data=input_data,
            output_data=output_data,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )

        with self._lock:
            self._actions.append(action)
            self._agent_actions[agent_id].append(action)
            self._action_count += 1

            # Associate with trace if provided
            if trace_id and trace_id in self._active_traces:
                self._active_traces[trace_id].actions.append(action)

            # Build ABG node
            data_pattern = (metadata or {}).get("data_pattern", "")
            tool = (metadata or {}).get("tool", "")
            self._abg.add_action(
                agent_id=agent_id,
                action_type=action_type.value if hasattr(action_type, "value") else str(action_type),
                tool=tool,
                data_pattern=data_pattern,
                description=description,
                metadata=metadata,
            )

            self._enforce_limits()

        return action

    def get_traces(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Trace]:
        """Get recorded traces, optionally filtered by agent.

        Args:
            agent_id: Filter by agent ID (None for all).
            limit: Maximum number of traces to return.

        Returns:
            List of Trace objects.
        """
        with self._lock:
            traces = list(self._traces.values())
            if agent_id:
                traces = [t for t in traces if t.agent_id == agent_id]
            return sorted(traces, key=lambda t: t.start_time, reverse=True)[:limit]

    def get_actions(
        self,
        agent_id: Optional[str] = None,
        action_type: Optional[ActionType] = None,
        limit: int = 100,
    ) -> List[Action]:
        """Get recorded actions, optionally filtered.

        Args:
            agent_id: Filter by agent ID (None for all).
            action_type: Filter by action type.
            limit: Maximum number of actions to return.

        Returns:
            List of Action objects.
        """
        with self._lock:
            if agent_id:
                actions = list(self._agent_actions.get(agent_id, []))
            else:
                actions = list(self._actions)

            if action_type:
                actions = [a for a in actions if a.action_type == action_type]

            return sorted(actions, key=lambda a: a.timestamp, reverse=True)[:limit]

    def get_action_count(self) -> int:
        """Get the total number of actions recorded."""
        return self._action_count

    def get_abg(self) -> AgentBehavioralGraph:
        """Get the Agent Behavioral Graph.

        Returns:
            The AgentBehavioralGraph instance built from recorded actions.
        """
        return self._abg

    def clear(self) -> None:
        """Clear all traces and actions."""
        with self._lock:
            self._traces.clear()
            self._actions.clear()
            self._active_traces.clear()
            self._agent_actions.clear()
            self._action_count = 0
            self._abg = AgentBehavioralGraph()

    def _enforce_limits(self) -> None:
        """Enforce memory limits on stored data."""
        if len(self._traces) > self._max_traces:
            sorted_traces = sorted(self._traces.items(), key=lambda x: x[1].start_time)
            for trace_id, _ in sorted_traces[: len(self._traces) - self._max_traces]:
                del self._traces[trace_id]

        if len(self._actions) > self._max_actions:
            self._actions = self._actions[-self._max_actions:]
