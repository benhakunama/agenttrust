"""Tests for the Merkle tree audit log implementation."""

from agenttrust.merkle import MerkleNode, MerkleProof, MerkleTree
from agenttrust.models import AuditEntry, RiskLevel


def _make_entry(agent_id: str = "agent-1", action: str = "test", risk: RiskLevel = RiskLevel.LOW) -> AuditEntry:
    return AuditEntry(agent_id=agent_id, action=action, result="OK", risk_level=risk)


class TestMerkleTree:
    def test_empty_tree(self) -> None:
        tree = MerkleTree()
        assert tree.size == 0
        assert tree.get_root() is None

    def test_single_entry(self) -> None:
        tree = MerkleTree()
        entry = _make_entry()
        leaf_hash = tree.add_entry(entry)
        assert tree.size == 1
        assert tree.get_root() == leaf_hash
        assert len(leaf_hash) == 64  # SHA-256 hex

    def test_two_entries(self) -> None:
        tree = MerkleTree()
        h1 = tree.add_entry(_make_entry(action="action-1"))
        h2 = tree.add_entry(_make_entry(action="action-2"))
        root = tree.get_root()
        assert root is not None
        assert root != h1
        assert root != h2

    def test_multiple_entries_root_changes(self) -> None:
        tree = MerkleTree()
        tree.add_entry(_make_entry(action="a"))
        root1 = tree.get_root()
        tree.add_entry(_make_entry(action="b"))
        root2 = tree.get_root()
        tree.add_entry(_make_entry(action="c"))
        root3 = tree.get_root()
        assert root1 != root2 != root3

    def test_get_proof_and_verify(self) -> None:
        tree = MerkleTree()
        for i in range(5):
            tree.add_entry(_make_entry(action=f"action-{i}"))

        for i in range(5):
            proof = tree.get_proof(i)
            assert MerkleTree.verify_proof(proof.entry_hash, proof)

    def test_proof_fails_with_wrong_hash(self) -> None:
        tree = MerkleTree()
        for i in range(4):
            tree.add_entry(_make_entry(action=f"action-{i}"))

        proof = tree.get_proof(0)
        assert not MerkleTree.verify_proof("wrong_hash", proof)

    def test_verify_entry(self) -> None:
        tree = MerkleTree()
        for i in range(3):
            tree.add_entry(_make_entry(action=f"act-{i}"))

        assert tree.verify_entry(0)
        assert tree.verify_entry(1)
        assert tree.verify_entry(2)
        assert not tree.verify_entry(10)
        assert not tree.verify_entry(-1)

    def test_export_tree(self) -> None:
        tree = MerkleTree()
        tree.add_entry(_make_entry(action="a"))
        tree.add_entry(_make_entry(action="b"))

        export = tree.export_tree()
        assert export["root_hash"] == tree.get_root()
        assert export["size"] == 2
        assert export["tree"] is not None
        assert len(export["entries"]) == 2

    def test_export_tree_structure(self) -> None:
        tree = MerkleTree()
        for i in range(4):
            tree.add_entry(_make_entry(action=f"act-{i}"))

        export = tree.export_tree()
        root_node = export["tree"]
        assert root_node["type"] == "internal"
        assert "left" in root_node
        assert "right" in root_node

    def test_get_audit_chain(self) -> None:
        tree = MerkleTree()
        for i in range(3):
            tree.add_entry(_make_entry(action=f"act-{i}"))

        chain = tree.get_audit_chain()
        assert len(chain) == 3
        for item in chain:
            assert item["verified"] is True
            assert "hash" in item
            assert "entry_id" in item

    def test_get_entries(self) -> None:
        tree = MerkleTree()
        entries = [_make_entry(action=f"act-{i}") for i in range(3)]
        for e in entries:
            tree.add_entry(e)
        assert tree.get_entries() == entries

    def test_proof_out_of_range(self) -> None:
        tree = MerkleTree()
        tree.add_entry(_make_entry())

        try:
            tree.get_proof(5)
            assert False, "Should have raised IndexError"
        except IndexError:
            pass

    def test_proof_empty_tree(self) -> None:
        tree = MerkleTree()
        try:
            tree.get_proof(0)
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_large_tree(self) -> None:
        tree = MerkleTree()
        for i in range(100):
            tree.add_entry(_make_entry(action=f"action-{i}"))

        assert tree.size == 100
        root = tree.get_root()
        assert root is not None

        # Verify random entries
        for idx in [0, 25, 50, 75, 99]:
            assert tree.verify_entry(idx)

    def test_odd_number_of_entries(self) -> None:
        """Odd number should be handled by duplicating last leaf."""
        tree = MerkleTree()
        for i in range(7):
            tree.add_entry(_make_entry(action=f"act-{i}"))

        assert tree.size == 7
        for i in range(7):
            assert tree.verify_entry(i)
