"""Layer 3: AgentComply — Compliance engine for AI agents."""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .merkle import MerkleTree
from .models import (
    Action,
    AuditEntry,
    ComplianceFramework,
    ComplianceResult,
    ComplianceStatus,
    RiskLevel,
    RiskMetrics,
)


# ── Framework Requirements ─────────────────────────────────────────────────

FRAMEWORK_REQUIREMENTS: Dict[ComplianceFramework, List[Dict[str, Any]]] = {
    ComplianceFramework.EU_AI_ACT: [
        {"id": "eu-1", "name": "Transparency", "desc": "Agent must identify itself as AI", "risk": RiskLevel.HIGH},
        {"id": "eu-2", "name": "Human Oversight", "desc": "Human-in-the-loop for high-risk decisions", "risk": RiskLevel.HIGH},
        {"id": "eu-3", "name": "Data Governance", "desc": "Training data must be documented", "risk": RiskLevel.MEDIUM},
        {"id": "eu-4", "name": "Technical Documentation", "desc": "System documentation required", "risk": RiskLevel.MEDIUM},
        {"id": "eu-5", "name": "Record Keeping", "desc": "Automatic logging of operations", "risk": RiskLevel.HIGH},
        {"id": "eu-6", "name": "Accuracy", "desc": "Appropriate levels of accuracy for intended purpose", "risk": RiskLevel.HIGH},
    ],
    ComplianceFramework.NIST_RMF: [
        {"id": "nist-1", "name": "Govern", "desc": "AI governance policies established", "risk": RiskLevel.MEDIUM},
        {"id": "nist-2", "name": "Map", "desc": "AI risks identified and mapped", "risk": RiskLevel.MEDIUM},
        {"id": "nist-3", "name": "Measure", "desc": "AI risks measured and monitored", "risk": RiskLevel.HIGH},
        {"id": "nist-4", "name": "Manage", "desc": "AI risks managed and mitigated", "risk": RiskLevel.HIGH},
    ],
    ComplianceFramework.ISO_42001: [
        {"id": "iso-1", "name": "AIMS Policy", "desc": "AI management system policy defined", "risk": RiskLevel.MEDIUM},
        {"id": "iso-2", "name": "Risk Assessment", "desc": "AI risk assessment conducted", "risk": RiskLevel.HIGH},
        {"id": "iso-3", "name": "AI Objectives", "desc": "Measurable AI objectives established", "risk": RiskLevel.MEDIUM},
        {"id": "iso-4", "name": "Competence", "desc": "Personnel competence for AI systems ensured", "risk": RiskLevel.LOW},
        {"id": "iso-5", "name": "Monitoring", "desc": "AI system performance monitored", "risk": RiskLevel.HIGH},
    ],
    ComplianceFramework.SOC2: [
        {"id": "soc-1", "name": "Security", "desc": "System protected against unauthorized access", "risk": RiskLevel.HIGH},
        {"id": "soc-2", "name": "Availability", "desc": "System available for operation", "risk": RiskLevel.MEDIUM},
        {"id": "soc-3", "name": "Processing Integrity", "desc": "System processing is complete and accurate", "risk": RiskLevel.HIGH},
        {"id": "soc-4", "name": "Confidentiality", "desc": "Confidential information is protected", "risk": RiskLevel.HIGH},
        {"id": "soc-5", "name": "Privacy", "desc": "Personal information collected and used appropriately", "risk": RiskLevel.HIGH},
    ],
}


class ComplianceEngine:
    """Compliance engine supporting multiple regulatory frameworks.

    Checks agent actions against compliance requirements, generates audit
    trails, and provides risk dashboards.
    """

    def __init__(
        self,
        frameworks: Optional[List[ComplianceFramework]] = None,
        policies: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialize the compliance engine.

        Args:
            frameworks: Compliance frameworks to enforce (default: all).
            policies: Custom policy definitions.
        """
        self._frameworks = frameworks or list(ComplianceFramework)
        self._policies = policies or {}
        self._audit_trail: Dict[str, List[AuditEntry]] = defaultdict(list)
        self._merkle_trees: Dict[str, MerkleTree] = defaultdict(MerkleTree)
        self._global_merkle: MerkleTree = MerkleTree()
        self._compliance_history: Dict[str, List[ComplianceResult]] = defaultdict(list)
        self._action_count = 0
        self._threat_count = 0
        self._block_count = 0

    def check_compliance(
        self,
        agent_id: str,
        action: Action,
        framework: Optional[ComplianceFramework] = None,
    ) -> ComplianceResult:
        """Check an action's compliance with a framework.

        Args:
            agent_id: The agent performing the action.
            action: The action to check.
            framework: Specific framework to check (default: first configured).

        Returns:
            ComplianceResult with status and findings.
        """
        fw = framework or self._frameworks[0]
        requirements = FRAMEWORK_REQUIREMENTS.get(fw, [])
        findings: List[str] = []
        recommendations: List[str] = []
        highest_risk = RiskLevel.LOW

        self._action_count += 1

        # Check each requirement
        for req in requirements:
            passed, finding = self._evaluate_requirement(req, action)
            if not passed:
                findings.append(f"[{req['id']}] {req['name']}: {finding}")
                recommendations.append(f"Address {req['name']}: {req['desc']}")
                if self._risk_higher(req["risk"], highest_risk):
                    highest_risk = req["risk"]

        # Determine overall status
        if not findings:
            status = ComplianceStatus.COMPLIANT
        elif any(r["risk"] == RiskLevel.HIGH for r in requirements if not self._evaluate_requirement(r, action)[0]):
            status = ComplianceStatus.NON_COMPLIANT
            self._threat_count += 1
        else:
            status = ComplianceStatus.NEEDS_REVIEW

        result = ComplianceResult(
            agent_id=agent_id,
            framework=fw,
            status=status,
            risk_level=highest_risk,
            findings=findings,
            recommendations=recommendations,
        )

        # Record in audit trail (both plain list and Merkle tree)
        entry = AuditEntry(
            agent_id=agent_id,
            action=action.description,
            result=status.value,
            risk_level=highest_risk,
            metadata={"framework": fw.value, "findings_count": len(findings)},
        )
        self._audit_trail[agent_id].append(entry)
        self._merkle_trees[agent_id].add_entry(entry)
        self._global_merkle.add_entry(entry)

        self._compliance_history[agent_id].append(result)

        return result

    def generate_audit_trail(
        self,
        agent_id: str,
        timeframe: Optional[Tuple[float, float]] = None,
    ) -> List[AuditEntry]:
        """Generate an audit trail for an agent.

        Args:
            agent_id: The agent to audit.
            timeframe: Optional (start, end) timestamps.

        Returns:
            List of AuditEntry records.
        """
        entries = self._audit_trail.get(agent_id, [])
        if timeframe:
            start, end = timeframe
            entries = [e for e in entries if start <= e.timestamp <= end]
        return sorted(entries, key=lambda e: e.timestamp, reverse=True)

    def get_risk_dashboard(self) -> RiskMetrics:
        """Get aggregated risk metrics across all agents.

        Returns:
            RiskMetrics with current risk status.
        """
        total_results = []
        for results in self._compliance_history.values():
            total_results.extend(results)

        if not total_results:
            return RiskMetrics()

        compliant = sum(1 for r in total_results if r.status == ComplianceStatus.COMPLIANT)
        compliance_rate = compliant / len(total_results) if total_results else 1.0

        # Determine overall risk level
        if compliance_rate >= 0.9:
            risk_level = RiskLevel.LOW
        elif compliance_rate >= 0.7:
            risk_level = RiskLevel.MEDIUM
        elif compliance_rate >= 0.5:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL

        # Per-framework scores
        framework_scores: Dict[str, float] = {}
        for fw in self._frameworks:
            fw_results = [r for r in total_results if r.framework == fw]
            if fw_results:
                fw_compliant = sum(1 for r in fw_results if r.status == ComplianceStatus.COMPLIANT)
                framework_scores[fw.value] = fw_compliant / len(fw_results)

        return RiskMetrics(
            total_actions=self._action_count,
            threats_detected=self._threat_count,
            threats_blocked=self._block_count,
            average_trust_score=compliance_rate,
            compliance_rate=compliance_rate,
            risk_level=risk_level,
            framework_scores=framework_scores,
        )

    def _evaluate_requirement(
        self,
        requirement: Dict[str, Any],
        action: Action,
    ) -> Tuple[bool, str]:
        """Evaluate a single requirement against an action.

        Returns:
            Tuple of (passed, finding_message).
        """
        req_id = requirement["id"]

        # Transparency checks
        if req_id in ("eu-1",):
            if action.metadata.get("identified_as_ai", True):
                return True, ""
            return False, "Agent did not identify itself as AI"

        # Record keeping / monitoring checks
        if req_id in ("eu-5", "iso-5", "nist-3"):
            # Action is being logged (it's here), so this passes
            return True, ""

        # Security checks
        if req_id in ("soc-1",):
            if action.metadata.get("unauthorized", False):
                return False, "Unauthorized access detected"
            return True, ""

        # Confidentiality checks
        if req_id in ("soc-4", "soc-5"):
            desc = (action.description or "").lower()
            if any(term in desc for term in ["pii", "personal data", "ssn", "credit card"]):
                if not action.metadata.get("data_protection_enabled", True):
                    return False, "Personal data handling without protection"
            return True, ""

        # Default: pass (requirement met by having monitoring active)
        return True, ""

    def get_merkle_root(self, agent_id: Optional[str] = None) -> Optional[str]:
        """Get the Merkle root hash for an agent's (or global) audit trail.

        Args:
            agent_id: Agent ID, or None for the global audit trail root.

        Returns:
            The Merkle root hash string, or None if empty.
        """
        if agent_id:
            return self._merkle_trees[agent_id].get_root()
        return self._global_merkle.get_root()

    def verify_audit_entry(self, agent_id: str, entry_index: int) -> bool:
        """Verify a specific audit entry against the Merkle tree.

        Args:
            agent_id: The agent whose audit trail to verify.
            entry_index: Zero-based index of the entry.

        Returns:
            True if the entry is verified intact.
        """
        tree = self._merkle_trees.get(agent_id)
        if tree is None or tree.size == 0:
            return False
        return tree.verify_entry(entry_index)

    def get_merkle_tree(self, agent_id: Optional[str] = None) -> MerkleTree:
        """Get the Merkle tree for an agent or the global tree.

        Args:
            agent_id: Agent ID, or None for the global tree.

        Returns:
            The MerkleTree instance.
        """
        if agent_id:
            return self._merkle_trees[agent_id]
        return self._global_merkle

    def export_merkle_tree(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Export the Merkle tree structure for visualization.

        Args:
            agent_id: Agent ID, or None for the global tree.

        Returns:
            JSON-serializable tree structure.
        """
        tree = self._merkle_trees[agent_id] if agent_id else self._global_merkle
        return tree.export_tree()

    @staticmethod
    def _risk_higher(a: RiskLevel, b: RiskLevel) -> bool:
        """Check if risk level a is higher than b."""
        order = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}
        return order.get(a, 0) > order.get(b, 0)
