"""LangChain integration for AgentTrust."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from ..models import Action, ActionType
from ..observe import ObserveTracer
from ..protect import BehavioralFirewall

try:
    from langchain_core.callbacks import BaseCallbackHandler

    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

    class BaseCallbackHandler:  # type: ignore[no-redef]
        """Stub when langchain-core is not installed."""
        pass


class AgentTrustCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that feeds into AgentTrust's security layers.

    Hooks into LangChain's callback system to trace agent actions and
    evaluate them through the behavioral firewall in real-time.

    Usage:
        ```python
        from agenttrust.integrations.langchain import AgentTrustCallbackHandler
        handler = AgentTrustCallbackHandler(tracer=tracer, firewall=firewall)
        agent.run("query", callbacks=[handler])
        ```
    """

    def __init__(
        self,
        tracer: ObserveTracer,
        firewall: BehavioralFirewall,
        agent_id: str = "default",
    ) -> None:
        """Initialize the callback handler.

        Args:
            tracer: ObserveTracer instance for recording actions.
            firewall: BehavioralFirewall for evaluating actions.
            agent_id: Default agent ID for actions.
        """
        self.tracer = tracer
        self.firewall = firewall
        self.agent_id = agent_id
        self._start_times: Dict[str, float] = {}

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM starts running."""
        self._start_times[str(run_id)] = time.time()
        action = self.tracer.record_action(
            agent_id=self.agent_id,
            action_type=ActionType.LLM_CALL,
            description=f"LLM call: {serialized.get('name', 'unknown')}",
            input_data=prompts[0] if prompts else None,
            metadata={"run_id": str(run_id), "model": serialized.get("name", "")},
        )
        # Evaluate through firewall
        self.firewall.evaluate_action(self.agent_id, action)

    def on_llm_end(
        self,
        response: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an LLM finishes."""
        start = self._start_times.pop(str(run_id), None)
        duration = (time.time() - start) * 1000 if start else None
        output = str(response) if response else None
        self.tracer.record_action(
            agent_id=self.agent_id,
            action_type=ActionType.LLM_CALL,
            description="LLM call completed",
            output_data=output,
            duration_ms=duration,
            metadata={"run_id": str(run_id)},
        )

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts running."""
        self._start_times[str(run_id)] = time.time()
        tool_name = serialized.get("name", "unknown_tool")
        action = self.tracer.record_action(
            agent_id=self.agent_id,
            action_type=ActionType.TOOL_CALL,
            description=f"Tool call: {tool_name}",
            input_data=input_str,
            metadata={"run_id": str(run_id), "tool": tool_name},
        )
        self.firewall.evaluate_action(self.agent_id, action)

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes."""
        start = self._start_times.pop(str(run_id), None)
        duration = (time.time() - start) * 1000 if start else None
        self.tracer.record_action(
            agent_id=self.agent_id,
            action_type=ActionType.TOOL_CALL,
            description="Tool call completed",
            output_data=output,
            duration_ms=duration,
            metadata={"run_id": str(run_id)},
        )

    def on_chain_start(
        self,
        serialized: Dict[str, Any],
        inputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain starts."""
        self._start_times[str(run_id)] = time.time()
        chain_name = serialized.get("name", "unknown_chain")
        action = self.tracer.record_action(
            agent_id=self.agent_id,
            action_type=ActionType.CHAIN_START,
            description=f"Chain started: {chain_name}",
            input_data=str(inputs)[:500],
            metadata={"run_id": str(run_id), "chain": chain_name},
        )
        self.firewall.evaluate_action(self.agent_id, action)

    def on_chain_end(
        self,
        outputs: Dict[str, Any],
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when a chain finishes."""
        start = self._start_times.pop(str(run_id), None)
        duration = (time.time() - start) * 1000 if start else None
        self.tracer.record_action(
            agent_id=self.agent_id,
            action_type=ActionType.CHAIN_END,
            description="Chain completed",
            output_data=str(outputs)[:500],
            duration_ms=duration,
            metadata={"run_id": str(run_id)},
        )

    def on_agent_action(
        self,
        action: Any,
        *,
        run_id: UUID,
        parent_run_id: Optional[UUID] = None,
        **kwargs: Any,
    ) -> None:
        """Called when an agent takes an action."""
        tool = getattr(action, "tool", "unknown")
        tool_input = str(getattr(action, "tool_input", ""))
        recorded = self.tracer.record_action(
            agent_id=self.agent_id,
            action_type=ActionType.AGENT_ACTION,
            description=f"Agent action: {tool}",
            input_data=tool_input[:500],
            metadata={"run_id": str(run_id), "tool": tool},
        )
        self.firewall.evaluate_action(self.agent_id, recorded)
