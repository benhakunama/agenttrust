"""CrewAI integration for AgentTrust."""

from __future__ import annotations

import functools
import time
from typing import Any, Callable, Optional, TypeVar

from ..models import Action, ActionType
from ..observe import ObserveTracer
from ..protect import BehavioralFirewall

F = TypeVar("F", bound=Callable[..., Any])


def monitor(
    tracer: Optional[ObserveTracer] = None,
    firewall: Optional[BehavioralFirewall] = None,
    agent_id: str = "crewai-agent",
) -> Callable[[F], F]:
    """Decorator to monitor CrewAI agent methods.

    Wraps CrewAI agent task execution to trace actions and evaluate
    them through the behavioral firewall.

    Usage:
        ```python
        @agenttrust.monitor
        class MyAgent(Agent):
            ...
        ```

    Args:
        tracer: ObserveTracer instance (uses default if None).
        firewall: BehavioralFirewall instance (uses default if None).
        agent_id: Agent identifier for tracing.

    Returns:
        Decorated function/class.
    """
    _tracer = tracer or ObserveTracer()
    _firewall = firewall or BehavioralFirewall()

    def decorator(func_or_class: Any) -> Any:
        if isinstance(func_or_class, type):
            return _wrap_class(func_or_class, _tracer, _firewall, agent_id)
        return _wrap_function(func_or_class, _tracer, _firewall, agent_id)

    return decorator


def _wrap_function(
    func: Callable[..., Any],
    tracer: ObserveTracer,
    firewall: BehavioralFirewall,
    agent_id: str,
) -> Callable[..., Any]:
    """Wrap a function with monitoring."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start = time.time()

        # Record action start
        action = tracer.record_action(
            agent_id=agent_id,
            action_type=ActionType.AGENT_ACTION,
            description=f"CrewAI task: {func.__name__}",
            input_data=str(kwargs)[:500] if kwargs else str(args)[:500],
        )

        # Evaluate through firewall
        decision = firewall.evaluate_action(agent_id, action)

        if not decision.is_safe:
            raise SecurityError(
                f"Action blocked by AgentTrust: {decision.reasoning} "
                f"(trust_score={decision.trust_score:.2f})"
            )

        # Execute the function
        result = func(*args, **kwargs)

        # Record completion
        duration = (time.time() - start) * 1000
        tracer.record_action(
            agent_id=agent_id,
            action_type=ActionType.AGENT_ACTION,
            description=f"CrewAI task completed: {func.__name__}",
            output_data=str(result)[:500] if result else None,
            duration_ms=duration,
        )

        return result

    return wrapper


def _wrap_class(
    cls: type,
    tracer: ObserveTracer,
    firewall: BehavioralFirewall,
    agent_id: str,
) -> type:
    """Wrap a class's execute method with monitoring."""
    original_init = cls.__init__

    @functools.wraps(original_init)
    def new_init(self: Any, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        self._agenttrust_tracer = tracer
        self._agenttrust_firewall = firewall
        self._agenttrust_agent_id = agent_id

    cls.__init__ = new_init

    # Wrap execute_task if it exists
    if hasattr(cls, "execute_task"):
        cls.execute_task = _wrap_function(cls.execute_task, tracer, firewall, agent_id)

    return cls


class SecurityError(Exception):
    """Raised when an action is blocked by the behavioral firewall."""
    pass
