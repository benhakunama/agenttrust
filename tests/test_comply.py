"""Tests for the ComplianceEngine module."""

import time

from agenttrust.comply import ComplianceEngine
from agenttrust.models import (
    Action,
    ActionType,
    ComplianceFramework,
    ComplianceStatus,
    RiskLevel,
)


class TestComplianceEngine:
    def test_check_compliance_compliant(self) -> None:
        engine = ComplianceEngine()
        action = Action(
            action_type=ActionType.TOOL_CALL,
            agent_id="test-agent",
            description="query_database",
            metadata={"identified_as_ai": True},
        )
        result = engine.check_compliance("test-agent", action, ComplianceFramework.EU_AI_ACT)
        assert result.agent_id == "test-agent"
        assert result.framework == ComplianceFramework.EU_AI_ACT
        assert result.status == ComplianceStatus.COMPLIANT

    def test_check_compliance_non_compliant(self) -> None:
        engine = ComplianceEngine()
        action = Action(
            action_type=ActionType.TOOL_CALL,
            agent_id="test-agent",
            description="handle PII data",
            metadata={"identified_as_ai": False, "data_protection_enabled": False},
        )
        result = engine.check_compliance("test-agent", action, ComplianceFramework.EU_AI_ACT)
        assert result.status in (ComplianceStatus.NON_COMPLIANT, ComplianceStatus.NEEDS_REVIEW)
        assert len(result.findings) > 0

    def test_generate_audit_trail(self) -> None:
        engine = ComplianceEngine()
        action = Action(
            action_type=ActionType.TOOL_CALL,
            agent_id="agent-1",
            description="test action",
        )
        engine.check_compliance("agent-1", action)
        engine.check_compliance("agent-1", action)

        trail = engine.generate_audit_trail("agent-1")
        assert len(trail) == 2

    def test_audit_trail_timeframe(self) -> None:
        engine = ComplianceEngine()
        action = Action(
            action_type=ActionType.TOOL_CALL,
            agent_id="agent-1",
            description="test",
        )
        engine.check_compliance("agent-1", action)

        now = time.time()
        trail = engine.generate_audit_trail("agent-1", timeframe=(now - 10, now + 10))
        assert len(trail) == 1

        trail_empty = engine.generate_audit_trail("agent-1", timeframe=(0, 1))
        assert len(trail_empty) == 0

    def test_risk_dashboard(self) -> None:
        engine = ComplianceEngine()
        action = Action(
            action_type=ActionType.TOOL_CALL,
            agent_id="agent-1",
            description="safe action",
            metadata={"identified_as_ai": True},
        )
        engine.check_compliance("agent-1", action)

        metrics = engine.get_risk_dashboard()
        assert metrics.total_actions >= 1
        assert 0.0 <= metrics.compliance_rate <= 1.0
        assert metrics.risk_level in list(RiskLevel)

    def test_multiple_frameworks(self) -> None:
        engine = ComplianceEngine(frameworks=[ComplianceFramework.SOC2, ComplianceFramework.NIST_RMF])
        action = Action(
            action_type=ActionType.TOOL_CALL,
            agent_id="a",
            description="test",
        )
        r1 = engine.check_compliance("a", action, ComplianceFramework.SOC2)
        r2 = engine.check_compliance("a", action, ComplianceFramework.NIST_RMF)
        assert r1.framework == ComplianceFramework.SOC2
        assert r2.framework == ComplianceFramework.NIST_RMF

    def test_empty_dashboard(self) -> None:
        engine = ComplianceEngine()
        metrics = engine.get_risk_dashboard()
        assert metrics.total_actions == 0
        assert metrics.compliance_rate == 1.0
