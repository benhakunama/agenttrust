"""AutoGen integration for AgentTrust."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from ..models import Action, ActionType
from ..observe import ObserveTracer
from ..protect import BehavioralFirewall


class AutoGenMonitor:
    """Monitor for AutoGen agent-to-agent communication.

    Hooks into AutoGen's message passing to trace and evaluate
    inter-agent communication for security threats.

    Usage:
        ```python
        monitor = AutoGenMonitor(tracer=tracer, firewall=firewall)
        monitor.attach(agent)
        ```
    """

    def __init__(
        self,
        tracer: Optional[ObserveTracer] = None,
        firewall: Optional[BehavioralFirewall] = None,
    ) -> None:
        """Initialize the AutoGen monitor.

        Args:
            tracer: ObserveTracer instance (uses default if None).
            firewall: BehavioralFirewall instance (uses default if None).
        """
        self.tracer = tracer or ObserveTracer()
        self.firewall = firewall or BehavioralFirewall()
        self._monitored_agents: Dict[str, Any] = {}

    def attach(self, agent: Any, agent_id: Optional[str] = None) -> None:
        """Attach monitoring to an AutoGen agent.

        Args:
            agent: The AutoGen agent to monitor.
            agent_id: Custom agent ID (uses agent.name if available).
        """
        aid = agent_id or getattr(agent, "name", "autogen-agent")
        self._monitored_agents[aid] = agent

        # Hook into message sending if possible
        if hasattr(agent, "send"):
            original_send = agent.send

            def monitored_send(message: Any, recipient: Any, **kwargs: Any) -> Any:
                return self._on_message_send(aid, message, recipient, original_send, **kwargs)

            agent.send = monitored_send

        # Hook into message receiving if possible
        if hasattr(agent, "receive"):
            original_receive = agent.receive

            def monitored_receive(message: Any, sender: Any, **kwargs: Any) -> Any:
                return self._on_message_receive(aid, message, sender, original_receive, **kwargs)

            agent.receive = monitored_receive

    def _on_message_send(
        self,
        agent_id: str,
        message: Any,
        recipient: Any,
        original_fn: Callable[..., Any],
        **kwargs: Any,
    ) -> Any:
        """Handle outgoing messages."""
        recipient_name = getattr(recipient, "name", str(recipient))
        msg_text = str(message)[:500]

        action = self.tracer.record_action(
            agent_id=agent_id,
            action_type=ActionType.MESSAGE_SEND,
            description=f"Message to {recipient_name}",
            input_data=msg_text,
            metadata={"recipient": recipient_name},
        )

        decision = self.firewall.evaluate_action(agent_id, action)
        if not decision.is_safe:
            self.tracer.record_action(
                agent_id=agent_id,
                action_type=ActionType.MESSAGE_SEND,
                description=f"BLOCKED: Message to {recipient_name}",
                metadata={"blocked": True, "reason": decision.reasoning},
            )
            return None

        return original_fn(message, recipient, **kwargs)

    def _on_message_receive(
        self,
        agent_id: str,
        message: Any,
        sender: Any,
        original_fn: Callable[..., Any],
        **kwargs: Any,
    ) -> Any:
        """Handle incoming messages."""
        sender_name = getattr(sender, "name", str(sender))
        msg_text = str(message)[:500]

        action = self.tracer.record_action(
            agent_id=agent_id,
            action_type=ActionType.MESSAGE_RECEIVE,
            description=f"Message from {sender_name}",
            input_data=msg_text,
            metadata={"sender": sender_name},
        )

        self.firewall.evaluate_action(agent_id, action)
        return original_fn(message, sender, **kwargs)

    def get_monitored_agents(self) -> List[str]:
        """Get list of monitored agent IDs.

        Returns:
            List of agent ID strings.
        """
        return list(self._monitored_agents.keys())
