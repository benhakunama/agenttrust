"""Data models for AgentTrust."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ThreatType(str, Enum):
    """Types of threats that can be detected."""

    PROMPT_INJECTION = "PROMPT_INJECTION"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    BEHAVIORAL_DRIFT = "BEHAVIORAL_DRIFT"


class ResponseAction(str, Enum):
    """Graduated response actions for detected threats."""

    ALLOW = "ALLOW"
    WARN = "WARN"
    THROTTLE = "THROTTLE"
    ISOLATE = "ISOLATE"
    BLOCK = "BLOCK"


class ActionType(str, Enum):
    """Types of agent actions."""

    LLM_CALL = "llm_call"
    TOOL_CALL = "tool_call"
    CHAIN_START = "chain_start"
    CHAIN_END = "chain_end"
    AGENT_ACTION = "agent_action"
    RETRIEVAL = "retrieval"
    MESSAGE_SEND = "message_send"
    MESSAGE_RECEIVE = "message_receive"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""

    EU_AI_ACT = "EU_AI_ACT"
    NIST_RMF = "NIST_RMF"
    ISO_42001 = "ISO_42001"
    SOC2 = "SOC2"


class ComplianceStatus(str, Enum):
    """Compliance check result status."""

    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class RiskLevel(str, Enum):
    """Risk levels for compliance."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Action:
    """Represents a single agent action."""

    action_type: ActionType
    agent_id: str
    description: str
    timestamp: float = field(default_factory=time.time)
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)
    input_data: Optional[str] = None
    output_data: Optional[str] = None
    duration_ms: Optional[float] = None
    parent_id: Optional[str] = None


@dataclass
class Trace:
    """A collection of related actions forming a trace."""

    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    actions: List[Action] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> Optional[float]:
        """Total trace duration in milliseconds."""
        if self.end_time:
            return (self.end_time - self.start_time) * 1000
        return None


@dataclass
class ThreatDetection:
    """A detected threat."""

    threat_type: ThreatType
    confidence: float
    description: str
    evidence: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class TrustDecision:
    """Result of evaluating an action through the behavioral firewall."""

    action: ResponseAction
    trust_score: float
    threats: List[ThreatDetection] = field(default_factory=list)
    reasoning: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def is_safe(self) -> bool:
        """Whether the action is considered safe."""
        return self.action in (ResponseAction.ALLOW, ResponseAction.WARN)


@dataclass
class AgentCertificate:
    """Cryptographic certificate for an agent."""

    agent_id: str
    name: str
    capabilities: List[str]
    owner: str
    public_key: str
    created_at: float = field(default_factory=time.time)
    trust_score: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Result of verifying an agent's identity."""

    agent_id: str
    verified: bool
    trust_score: float
    message: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class ComplianceResult:
    """Result of a compliance check."""

    agent_id: str
    framework: ComplianceFramework
    status: ComplianceStatus
    risk_level: RiskLevel
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class AuditEntry:
    """A single entry in an audit trail."""

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    action: str = ""
    result: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskMetrics:
    """Risk dashboard metrics."""

    total_actions: int = 0
    threats_detected: int = 0
    threats_blocked: int = 0
    average_trust_score: float = 1.0
    compliance_rate: float = 1.0
    risk_level: RiskLevel = RiskLevel.LOW
    framework_scores: Dict[str, float] = field(default_factory=dict)
