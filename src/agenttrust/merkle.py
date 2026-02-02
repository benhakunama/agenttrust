"""Merkle tree audit log implementation for tamper-evident logging.

Implements a SHA-256 based Merkle tree that provides cryptographic
verification of audit trail integrity, as described in the AgentTrust paper.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .models import AuditEntry


@dataclass
class MerkleNode:
    """A node in the Merkle tree.

    Attributes:
        hash: SHA-256 hash of this node.
        left: Left child node (or None for leaves).
        right: Right child node (or None for leaves).
        data: The audit entry data (only present in leaf nodes).
    """

    hash: str
    left: Optional[MerkleNode] = None
    right: Optional[MerkleNode] = None
    data: Optional[AuditEntry] = None

    @property
    def is_leaf(self) -> bool:
        """Whether this is a leaf node."""
        return self.left is None and self.right is None


@dataclass
class MerkleProof:
    """A Merkle proof for verifying an entry's inclusion in the tree.

    Attributes:
        entry_hash: Hash of the entry being proved.
        siblings: List of (hash, position) tuples. Position is 'left' or 'right',
                  indicating where the sibling sits relative to the path.
        root_hash: The expected root hash.
    """

    entry_hash: str
    siblings: List[Tuple[str, str]]  # (hash, "left" | "right")
    root_hash: str


class MerkleTree:
    """SHA-256 Merkle tree for tamper-evident audit logging.

    Builds a binary hash tree from audit entries, enabling:
    - O(1) root hash retrieval for integrity checking
    - O(log n) inclusion proofs for individual entries
    - Full tree export for visualization and external verification
    """

    def __init__(self) -> None:
        """Initialize an empty Merkle tree."""
        self._entries: List[AuditEntry] = []
        self._leaves: List[MerkleNode] = []
        self._root: Optional[MerkleNode] = None

    @property
    def size(self) -> int:
        """Number of entries in the tree."""
        return len(self._entries)

    def add_entry(self, entry: AuditEntry) -> str:
        """Add an audit entry and rebuild the tree.

        Args:
            entry: The audit entry to add.

        Returns:
            The hash of the newly added leaf node.
        """
        self._entries.append(entry)
        leaf_hash = self._hash_entry(entry)
        leaf = MerkleNode(hash=leaf_hash, data=entry)
        self._leaves.append(leaf)
        self._root = self._build_tree(list(self._leaves))
        return leaf_hash

    def get_root(self) -> Optional[str]:
        """Get the Merkle root hash.

        Returns:
            The root hash string, or None if the tree is empty.
        """
        if self._root is None:
            return None
        return self._root.hash

    def get_proof(self, entry_index: int) -> MerkleProof:
        """Generate a Merkle proof for the entry at the given index.

        Args:
            entry_index: Zero-based index of the entry.

        Returns:
            A MerkleProof object with the sibling hashes needed to
            reconstruct the root from the leaf.

        Raises:
            IndexError: If entry_index is out of range.
            ValueError: If the tree is empty.
        """
        if not self._entries:
            raise ValueError("Tree is empty")
        if entry_index < 0 or entry_index >= len(self._entries):
            raise IndexError(f"Entry index {entry_index} out of range [0, {len(self._entries)})")

        siblings: List[Tuple[str, str]] = []
        leaf_hash = self._leaves[entry_index].hash

        # Walk up the tree collecting sibling hashes
        level_nodes = list(self._leaves)
        idx = entry_index

        while len(level_nodes) > 1:
            # Duplicate last if odd
            if len(level_nodes) % 2 == 1:
                level_nodes.append(level_nodes[-1])

            # Find sibling
            if idx % 2 == 0:
                # Sibling is to the right
                sibling_idx = idx + 1
                if sibling_idx < len(level_nodes):
                    siblings.append((level_nodes[sibling_idx].hash, "right"))
            else:
                # Sibling is to the left
                sibling_idx = idx - 1
                siblings.append((level_nodes[sibling_idx].hash, "left"))

            # Build next level
            next_level: List[MerkleNode] = []
            for i in range(0, len(level_nodes), 2):
                left = level_nodes[i]
                right = level_nodes[i + 1] if i + 1 < len(level_nodes) else level_nodes[i]
                combined = self._hash_pair(left.hash, right.hash)
                next_level.append(MerkleNode(hash=combined, left=left, right=right))

            level_nodes = next_level
            idx = idx // 2

        root_hash = self._root.hash if self._root else ""
        return MerkleProof(
            entry_hash=leaf_hash,
            siblings=siblings,
            root_hash=root_hash,
        )

    @staticmethod
    def verify_proof(entry_hash: str, proof: MerkleProof) -> bool:
        """Verify a Merkle proof against the expected root.

        Args:
            entry_hash: The hash of the entry to verify.
            proof: The MerkleProof containing siblings and root.

        Returns:
            True if the proof is valid (entry is in the tree).
        """
        current = entry_hash
        for sibling_hash, position in proof.siblings:
            if position == "left":
                current = MerkleTree._hash_pair(sibling_hash, current)
            else:
                current = MerkleTree._hash_pair(current, sibling_hash)
        return current == proof.root_hash

    def verify_entry(self, entry_index: int) -> bool:
        """Verify that a specific entry is intact in the tree.

        Args:
            entry_index: Zero-based index of the entry.

        Returns:
            True if the entry's proof verifies against the root.
        """
        if entry_index < 0 or entry_index >= len(self._entries):
            return False
        proof = self.get_proof(entry_index)
        return self.verify_proof(proof.entry_hash, proof)

    def export_tree(self) -> Dict[str, Any]:
        """Export the tree as a JSON-serializable structure.

        Returns:
            Dictionary representation of the full tree for visualization.
        """
        return {
            "root_hash": self.get_root(),
            "size": self.size,
            "tree": self._export_node(self._root) if self._root else None,
            "entries": [
                {
                    "index": i,
                    "hash": self._leaves[i].hash,
                    "entry_id": e.entry_id,
                    "agent_id": e.agent_id,
                    "action": e.action,
                    "result": e.result,
                    "risk_level": e.risk_level.value if hasattr(e.risk_level, "value") else str(e.risk_level),
                    "timestamp": e.timestamp,
                }
                for i, e in enumerate(self._entries)
            ],
        }

    def get_audit_chain(self) -> List[Dict[str, Any]]:
        """Return the full chain of entries with their hashes and positions.

        Returns:
            List of dictionaries with entry data and Merkle metadata.
        """
        chain: List[Dict[str, Any]] = []
        for i, entry in enumerate(self._entries):
            chain.append({
                "index": i,
                "hash": self._leaves[i].hash,
                "entry_id": entry.entry_id,
                "agent_id": entry.agent_id,
                "action": entry.action,
                "result": entry.result,
                "risk_level": entry.risk_level.value if hasattr(entry.risk_level, "value") else str(entry.risk_level),
                "timestamp": entry.timestamp,
                "metadata": entry.metadata,
                "verified": self.verify_entry(i),
            })
        return chain

    def get_entries(self) -> List[AuditEntry]:
        """Return all audit entries in order.

        Returns:
            List of AuditEntry objects.
        """
        return list(self._entries)

    # ── Internal helpers ───────────────────────────────────────────────

    def _build_tree(self, nodes: List[MerkleNode]) -> Optional[MerkleNode]:
        """Recursively build the Merkle tree from leaf nodes."""
        if not nodes:
            return None
        if len(nodes) == 1:
            return nodes[0]

        # Duplicate last node if odd count
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])

        next_level: List[MerkleNode] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1]
            combined = self._hash_pair(left.hash, right.hash)
            parent = MerkleNode(hash=combined, left=left, right=right)
            next_level.append(parent)

        return self._build_tree(next_level)

    @staticmethod
    def _hash_entry(entry: AuditEntry) -> str:
        """Hash an audit entry using SHA-256."""
        data = (
            f"{entry.entry_id}:{entry.agent_id}:{entry.action}:"
            f"{entry.result}:{entry.risk_level.value}:{entry.timestamp}:"
            f"{json.dumps(entry.metadata, sort_keys=True)}"
        )
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        """Hash two child hashes together."""
        combined = f"{left}{right}"
        return hashlib.sha256(combined.encode("utf-8")).hexdigest()

    def _export_node(self, node: Optional[MerkleNode]) -> Optional[Dict[str, Any]]:
        """Recursively export a node for visualization."""
        if node is None:
            return None
        result: Dict[str, Any] = {"hash": node.hash}
        if node.is_leaf and node.data:
            result["type"] = "leaf"
            result["entry_id"] = node.data.entry_id
            result["agent_id"] = node.data.agent_id
        else:
            result["type"] = "internal"
            result["left"] = self._export_node(node.left)
            result["right"] = self._export_node(node.right)
        return result
