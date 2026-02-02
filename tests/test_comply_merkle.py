"""Tests for Merkle tree integration in ComplianceEngine."""

from agenttrust.comply import ComplianceEngine
from agenttrust.models import Action, ActionType, ComplianceFramework


def _action(desc: str = "test") -> Action:
    return Action(action_type=ActionType.TOOL_CALL, agent_id="agent-1", description=desc)


class TestComplianceMerkle:
    def test_merkle_root_after_compliance(self) -> None:
        engine = ComplianceEngine()
        engine.check_compliance("agent-1", _action("a1"))
        root = engine.get_merkle_root("agent-1")
        assert root is not None
        assert len(root) == 64

    def test_merkle_root_changes(self) -> None:
        engine = ComplianceEngine()
        engine.check_compliance("agent-1", _action("a1"))
        root1 = engine.get_merkle_root("agent-1")
        engine.check_compliance("agent-1", _action("a2"))
        root2 = engine.get_merkle_root("agent-1")
        assert root1 != root2

    def test_global_merkle_root(self) -> None:
        engine = ComplianceEngine()
        engine.check_compliance("agent-1", _action("a1"))
        engine.check_compliance("agent-2", _action("a2"))
        global_root = engine.get_merkle_root()
        assert global_root is not None

    def test_verify_audit_entry(self) -> None:
        engine = ComplianceEngine()
        engine.check_compliance("agent-1", _action("a1"))
        engine.check_compliance("agent-1", _action("a2"))
        assert engine.verify_audit_entry("agent-1", 0)
        assert engine.verify_audit_entry("agent-1", 1)
        assert not engine.verify_audit_entry("agent-1", 5)

    def test_verify_nonexistent_agent(self) -> None:
        engine = ComplianceEngine()
        assert not engine.verify_audit_entry("ghost", 0)

    def test_export_merkle_tree(self) -> None:
        engine = ComplianceEngine()
        engine.check_compliance("agent-1", _action("a1"))
        engine.check_compliance("agent-1", _action("a2"))
        export = engine.export_merkle_tree("agent-1")
        assert export["size"] == 2
        assert export["root_hash"] is not None

    def test_get_merkle_tree(self) -> None:
        engine = ComplianceEngine()
        engine.check_compliance("agent-1", _action("a1"))
        tree = engine.get_merkle_tree("agent-1")
        assert tree.size == 1

    def test_global_export(self) -> None:
        engine = ComplianceEngine()
        engine.check_compliance("agent-1", _action("a1"))
        engine.check_compliance("agent-2", _action("a2"))
        export = engine.export_merkle_tree()
        assert export["size"] == 2
