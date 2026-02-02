"""AgentTrust — Runtime security, observability, and compliance for AI agents.

Quick Start:
    ```python
    import agenttrust
    at = agenttrust.init(framework="langchain")
    ```

Or with more control:
    ```python
    from agenttrust import AgentTrust
    at = AgentTrust(api_key="at_...", framework="langchain")
    at.monitor()
    ```
"""

from __future__ import annotations

from typing import Any, Optional

from .comply import ComplianceEngine
from .config import Config
from .identity import AgentIdentityManager
from .models import (
    Action,
    ActionType,
    AgentCertificate,
    ComplianceFramework,
    ComplianceResult,
    ComplianceStatus,
    ResponseAction,
    RiskLevel,
    ThreatDetection,
    ThreatType,
    TrustDecision,
    VerificationResult,
)
from .observe import ObserveTracer
from .protect import BehavioralFirewall
from .scoring import TrustScoreEngine

__version__ = "0.1.0"
__all__ = [
    "AgentTrust",
    "init",
    "Action",
    "ActionType",
    "AgentCertificate",
    "BehavioralFirewall",
    "ComplianceEngine",
    "ComplianceFramework",
    "ComplianceResult",
    "ComplianceStatus",
    "Config",
    "AgentIdentityManager",
    "ObserveTracer",
    "ResponseAction",
    "RiskLevel",
    "ThreatDetection",
    "ThreatType",
    "TrustDecision",
    "TrustScoreEngine",
    "VerificationResult",
]


class AgentTrust:
    """Main entry point for AgentTrust SDK.

    Provides unified access to all four security layers:
    - ObserveTracer (Layer 1: Observability)
    - BehavioralFirewall (Layer 2: Protection)
    - ComplianceEngine (Layer 3: Compliance)
    - AgentIdentityManager (Layer 4: Identity)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        framework: str = "langchain",
        config: Optional[Config] = None,
    ) -> None:
        """Initialize AgentTrust.

        Args:
            api_key: API key for AgentTrust cloud (optional).
            framework: AI framework to integrate with.
            config: Custom configuration (loads default if None).
        """
        self.config = config or Config()
        if api_key:
            self.config.set("api_key", api_key)
        if framework:
            self.config.set("framework", framework)

        self._framework = framework
        self._scoring = TrustScoreEngine()
        self.tracer = ObserveTracer()
        self.firewall = BehavioralFirewall(scoring_engine=self._scoring)
        self.compliance = ComplianceEngine()
        self.identity = AgentIdentityManager(scoring_engine=self._scoring)
        self._monitoring = False

    def monitor(self) -> None:
        """Start monitoring agents."""
        self._monitoring = True

    def callback(self) -> Any:
        """Get a framework-specific callback handler.

        Returns:
            Callback handler for the configured framework.
        """
        return self.get_callback()

    def get_callback(self, agent_id: str = "default") -> Any:
        """Get a framework-specific callback handler.

        Args:
            agent_id: Agent ID for the callback handler.

        Returns:
            Callback handler for the configured framework.
        """
        if self._framework == "langchain":
            from .integrations.langchain import AgentTrustCallbackHandler
            return AgentTrustCallbackHandler(
                tracer=self.tracer,
                firewall=self.firewall,
                agent_id=agent_id,
            )
        elif self._framework == "crewai":
            from .integrations.crewai import monitor as crewai_monitor
            return crewai_monitor(
                tracer=self.tracer,
                firewall=self.firewall,
                agent_id=agent_id,
            )
        elif self._framework == "autogen":
            from .integrations.autogen import AutoGenMonitor
            return AutoGenMonitor(
                tracer=self.tracer,
                firewall=self.firewall,
            )
        else:
            raise ValueError(f"Unsupported framework: {self._framework}")

    def attach(self, agent: Any, agent_id: Optional[str] = None) -> None:
        """Attach monitoring to an agent (AutoGen style).

        Args:
            agent: The agent to monitor.
            agent_id: Custom agent ID.
        """
        if self._framework == "autogen":
            from .integrations.autogen import AutoGenMonitor
            mon = AutoGenMonitor(tracer=self.tracer, firewall=self.firewall)
            mon.attach(agent, agent_id)
        else:
            raise ValueError(f"attach() is for AutoGen. Use callback() for {self._framework}.")


def init(
    framework: str = "langchain",
    api_key: Optional[str] = None,
) -> AgentTrust:
    """Initialize AgentTrust with minimal configuration.

    This is the recommended 3-line setup:
        ```python
        import agenttrust
        at = agenttrust.init(framework="langchain")
        ```

    Args:
        framework: AI framework to integrate with.
        api_key: Optional API key.

    Returns:
        Configured AgentTrust instance.
    """
    at = AgentTrust(api_key=api_key, framework=framework)
    at.monitor()
    return at
