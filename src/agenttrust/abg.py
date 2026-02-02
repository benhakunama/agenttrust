"""Agent Behavioral Graph (ABG) implementation.

Formal graph-based representation of agent behavior as described in
the AgentTrust paper. Models actions as vertices and causal relationships
as directed edges, enabling pattern-based attack detection via subgraph
matching.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ABGNode:
    """A vertex in the Agent Behavioral Graph.

    Represents a single agent action with a structured label
    (action_type, tool, data_pattern) for pattern matching.

    Attributes:
        node_id: Unique identifier for this node.
        agent_id: The agent that performed this action.
        action_type: Type of the action (e.g., 'tool_call', 'llm_call').
        tool: Tool or function invoked (if applicable).
        data_pattern: Data access pattern (e.g., 'read', 'write', 'send').
        description: Human-readable description.
        timestamp: When the action occurred.
        metadata: Additional context.
    """

    node_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str = ""
    action_type: str = ""
    tool: str = ""
    data_pattern: str = ""
    description: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def label(self) -> Tuple[str, str, str]:
        """Structured label for pattern matching: (action_type, tool, data_pattern)."""
        return (self.action_type, self.tool, self.data_pattern)


@dataclass
class ABGEdge:
    """A directed edge in the Agent Behavioral Graph.

    Represents a causal or temporal relationship between two actions.

    Attributes:
        source: Node ID of the source action.
        target: Node ID of the target action.
        relationship: Type of relationship (e.g., 'temporal', 'causal', 'data_flow').
        weight: Edge weight (e.g., time delta, confidence).
        metadata: Additional context.
    """

    source: str = ""
    target: str = ""
    relationship: str = "temporal"
    weight: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternGraph:
    """A small graph pattern used for attack detection via subgraph matching.

    Attributes:
        name: Name of the pattern (e.g., 'data_exfiltration_sequence').
        description: What this pattern detects.
        nodes: Ordered list of node label constraints.
                Each is a dict with optional keys: action_type, tool, data_pattern.
        edges: Edge constraints between pattern nodes (by index).
        severity: How severe a match is (0.0–1.0).
    """

    name: str = ""
    description: str = ""
    nodes: List[Dict[str, str]] = field(default_factory=list)
    edges: List[Tuple[int, int, str]] = field(default_factory=list)  # (src_idx, tgt_idx, relationship)
    severity: float = 0.8


# ── Predefined Attack Patterns ─────────────────────────────────────────

DATA_EXFILTRATION_PATTERN = PatternGraph(
    name="data_exfiltration_sequence",
    description="Detects data_read → format/encode → send_external sequence",
    nodes=[
        {"data_pattern": "read"},
        {"data_pattern": "format"},
        {"data_pattern": "send_external"},
    ],
    edges=[(0, 1, "temporal"), (1, 2, "temporal")],
    severity=0.9,
)

PRIVILEGE_ESCALATION_PATTERN = PatternGraph(
    name="privilege_escalation_sequence",
    description="Detects credential_access → config_modify → privileged_action sequence",
    nodes=[
        {"data_pattern": "credential_access"},
        {"data_pattern": "config_modify"},
        {"data_pattern": "privileged_action"},
    ],
    edges=[(0, 1, "temporal"), (1, 2, "temporal")],
    severity=0.85,
)

RECONNAISSANCE_PATTERN = PatternGraph(
    name="reconnaissance_sequence",
    description="Detects systematic probing: enumerate → probe → exploit",
    nodes=[
        {"data_pattern": "enumerate"},
        {"data_pattern": "probe"},
        {"data_pattern": "exploit"},
    ],
    edges=[(0, 1, "temporal"), (1, 2, "temporal")],
    severity=0.8,
)

PREDEFINED_PATTERNS: List[PatternGraph] = [
    DATA_EXFILTRATION_PATTERN,
    PRIVILEGE_ESCALATION_PATTERN,
    RECONNAISSANCE_PATTERN,
]


class AgentBehavioralGraph:
    """Graph-based model of agent behavior for pattern detection.

    Maintains a directed graph where nodes are agent actions and edges
    represent temporal/causal relationships. Supports subgraph pattern
    matching for detecting multi-step attack sequences.
    """

    def __init__(self) -> None:
        """Initialize an empty behavioral graph."""
        self._nodes: Dict[str, ABGNode] = {}
        self._edges: List[ABGEdge] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)  # node_id → [target_ids]
        self._agent_last_node: Dict[str, str] = {}  # agent_id → last node_id
        self._agent_nodes: Dict[str, List[str]] = defaultdict(list)  # agent_id → [node_ids]
        self._node_order: List[str] = []  # insertion order

    @property
    def node_count(self) -> int:
        """Number of nodes in the graph."""
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        """Number of edges in the graph."""
        return len(self._edges)

    def add_action(
        self,
        agent_id: str,
        action_type: str,
        tool: str = "",
        data_pattern: str = "",
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ABGNode:
        """Add an action as a node, creating an edge from the agent's previous action.

        Args:
            agent_id: The agent performing the action.
            action_type: Type of the action.
            tool: Tool or function used.
            data_pattern: Data access pattern.
            description: Human-readable description.
            metadata: Additional context.

        Returns:
            The newly created ABGNode.
        """
        node = ABGNode(
            agent_id=agent_id,
            action_type=action_type,
            tool=tool,
            data_pattern=data_pattern,
            description=description,
            metadata=metadata or {},
        )

        self._nodes[node.node_id] = node
        self._node_order.append(node.node_id)
        self._agent_nodes[agent_id].append(node.node_id)

        # Create temporal edge from previous action
        prev_id = self._agent_last_node.get(agent_id)
        if prev_id and prev_id in self._nodes:
            prev_node = self._nodes[prev_id]
            time_delta = node.timestamp - prev_node.timestamp
            edge = ABGEdge(
                source=prev_id,
                target=node.node_id,
                relationship="temporal",
                weight=max(0.0, 1.0 - time_delta),  # Weight decays with time
            )
            self._edges.append(edge)
            self._adjacency[prev_id].append(node.node_id)

        self._agent_last_node[agent_id] = node.node_id
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str = "causal",
        weight: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[ABGEdge]:
        """Add a custom edge between two nodes.

        Args:
            source_id: Source node ID.
            target_id: Target node ID.
            relationship: Type of relationship.
            weight: Edge weight.
            metadata: Additional context.

        Returns:
            The created ABGEdge, or None if either node doesn't exist.
        """
        if source_id not in self._nodes or target_id not in self._nodes:
            return None

        edge = ABGEdge(
            source=source_id,
            target=target_id,
            relationship=relationship,
            weight=weight,
            metadata=metadata or {},
        )
        self._edges.append(edge)
        self._adjacency[source_id].append(target_id)
        return edge

    def get_node(self, node_id: str) -> Optional[ABGNode]:
        """Get a node by ID."""
        return self._nodes.get(node_id)

    def get_subgraph(self, agent_id: str) -> AgentBehavioralGraph:
        """Return the subgraph of actions for a specific agent.

        Args:
            agent_id: The agent whose subgraph to extract.

        Returns:
            A new AgentBehavioralGraph containing only that agent's nodes/edges.
        """
        subgraph = AgentBehavioralGraph()
        node_ids = set(self._agent_nodes.get(agent_id, []))

        for nid in self._agent_nodes.get(agent_id, []):
            node = self._nodes[nid]
            subgraph._nodes[nid] = node
            subgraph._node_order.append(nid)
            subgraph._agent_nodes[agent_id].append(nid)

        for edge in self._edges:
            if edge.source in node_ids and edge.target in node_ids:
                subgraph._edges.append(edge)
                subgraph._adjacency[edge.source].append(edge.target)

        if agent_id in self._agent_last_node:
            subgraph._agent_last_node[agent_id] = self._agent_last_node[agent_id]

        return subgraph

    def detect_pattern(self, pattern: PatternGraph) -> List[List[ABGNode]]:
        """Detect occurrences of a pattern graph via subgraph matching.

        Uses a sliding-window approach over each agent's action sequence
        to find matches against the pattern's node label constraints.

        Args:
            pattern: The pattern graph to search for.

        Returns:
            List of matches. Each match is a list of ABGNodes that
            correspond to the pattern nodes in order.
        """
        matches: List[List[ABGNode]] = []
        pattern_len = len(pattern.nodes)

        if pattern_len == 0:
            return matches

        # Check each agent's sequence
        for agent_id, node_ids in self._agent_nodes.items():
            nodes = [self._nodes[nid] for nid in node_ids]

            # Sliding window over the agent's action sequence
            for start in range(len(nodes) - pattern_len + 1):
                window = nodes[start:start + pattern_len]
                if self._match_window(window, pattern):
                    matches.append(list(window))

        return matches

    def detect_all_patterns(
        self,
        patterns: Optional[List[PatternGraph]] = None,
    ) -> List[Dict[str, Any]]:
        """Detect all predefined (and optional custom) patterns.

        Args:
            patterns: Custom patterns to check (uses PREDEFINED_PATTERNS if None).

        Returns:
            List of detection results with pattern name, severity, and matched nodes.
        """
        patterns = patterns or PREDEFINED_PATTERNS
        results: List[Dict[str, Any]] = []

        for pattern in patterns:
            matches = self.detect_pattern(pattern)
            for match in matches:
                results.append({
                    "pattern": pattern.name,
                    "description": pattern.description,
                    "severity": pattern.severity,
                    "agent_id": match[0].agent_id if match else "",
                    "nodes": [
                        {
                            "node_id": n.node_id,
                            "action_type": n.action_type,
                            "tool": n.tool,
                            "data_pattern": n.data_pattern,
                            "timestamp": n.timestamp,
                        }
                        for n in match
                    ],
                })

        return results

    def get_action_sequence(self, agent_id: Optional[str] = None) -> List[ABGNode]:
        """Return ordered list of actions, optionally filtered by agent.

        Args:
            agent_id: Filter by agent ID (None for all).

        Returns:
            List of ABGNode objects in insertion order.
        """
        if agent_id:
            return [self._nodes[nid] for nid in self._agent_nodes.get(agent_id, [])]
        return [self._nodes[nid] for nid in self._node_order]

    def to_dict(self) -> Dict[str, Any]:
        """Export the graph as a JSON-serializable dictionary.

        Returns:
            Dictionary with nodes, edges, and metadata.
        """
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "nodes": [
                {
                    "node_id": n.node_id,
                    "agent_id": n.agent_id,
                    "action_type": n.action_type,
                    "tool": n.tool,
                    "data_pattern": n.data_pattern,
                    "description": n.description,
                    "timestamp": n.timestamp,
                    "metadata": n.metadata,
                }
                for n in (self._nodes[nid] for nid in self._node_order)
            ],
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relationship": e.relationship,
                    "weight": e.weight,
                    "metadata": e.metadata,
                }
                for e in self._edges
            ],
            "agents": {
                agent_id: len(node_ids)
                for agent_id, node_ids in self._agent_nodes.items()
            },
        }

    # ── Internal helpers ───────────────────────────────────────────────

    @staticmethod
    def _match_window(window: List[ABGNode], pattern: PatternGraph) -> bool:
        """Check if a window of nodes matches a pattern's constraints."""
        for node, constraint in zip(window, pattern.nodes):
            for key, value in constraint.items():
                if key == "action_type" and node.action_type != value:
                    return False
                if key == "tool" and node.tool != value:
                    return False
                if key == "data_pattern" and node.data_pattern != value:
                    return False
        return True
