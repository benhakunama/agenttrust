"""Tests for the Agent Behavioral Graph (ABG) implementation."""

from agenttrust.abg import (
    ABGEdge,
    ABGNode,
    AgentBehavioralGraph,
    PatternGraph,
    DATA_EXFILTRATION_PATTERN,
    PREDEFINED_PATTERNS,
)


class TestABGNode:
    def test_label(self) -> None:
        node = ABGNode(action_type="tool_call", tool="db_query", data_pattern="read")
        assert node.label == ("tool_call", "db_query", "read")

    def test_defaults(self) -> None:
        node = ABGNode()
        assert node.agent_id == ""
        assert node.action_type == ""
        assert node.metadata == {}


class TestAgentBehavioralGraph:
    def test_add_action(self) -> None:
        g = AgentBehavioralGraph()
        node = g.add_action("agent-1", "tool_call", tool="db")
        assert g.node_count == 1
        assert g.edge_count == 0
        assert node.agent_id == "agent-1"

    def test_add_multiple_actions_creates_edges(self) -> None:
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "tool_call")
        g.add_action("agent-1", "llm_call")
        g.add_action("agent-1", "tool_call")
        assert g.node_count == 3
        assert g.edge_count == 2

    def test_different_agents_separate_edges(self) -> None:
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "tool_call")
        g.add_action("agent-2", "tool_call")
        g.add_action("agent-1", "llm_call")
        assert g.node_count == 3
        # agent-1 has edge from 1st to 3rd, agent-2 has no edge (only one action)
        assert g.edge_count == 1

    def test_get_subgraph(self) -> None:
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "a")
        g.add_action("agent-1", "b")
        g.add_action("agent-2", "c")
        g.add_action("agent-2", "d")

        sub1 = g.get_subgraph("agent-1")
        assert sub1.node_count == 2
        assert sub1.edge_count == 1

        sub2 = g.get_subgraph("agent-2")
        assert sub2.node_count == 2
        assert sub2.edge_count == 1

    def test_get_subgraph_empty(self) -> None:
        g = AgentBehavioralGraph()
        sub = g.get_subgraph("nonexistent")
        assert sub.node_count == 0

    def test_detect_pattern(self) -> None:
        g = AgentBehavioralGraph()
        # Build a data exfiltration sequence
        g.add_action("agent-1", "tool_call", data_pattern="read")
        g.add_action("agent-1", "tool_call", data_pattern="format")
        g.add_action("agent-1", "tool_call", data_pattern="send_external")

        matches = g.detect_pattern(DATA_EXFILTRATION_PATTERN)
        assert len(matches) == 1
        assert len(matches[0]) == 3

    def test_detect_pattern_no_match(self) -> None:
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "tool_call", data_pattern="read")
        g.add_action("agent-1", "tool_call", data_pattern="write")

        matches = g.detect_pattern(DATA_EXFILTRATION_PATTERN)
        assert len(matches) == 0

    def test_detect_all_patterns(self) -> None:
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "tool_call", data_pattern="read")
        g.add_action("agent-1", "tool_call", data_pattern="format")
        g.add_action("agent-1", "tool_call", data_pattern="send_external")

        results = g.detect_all_patterns()
        pattern_names = [r["pattern"] for r in results]
        assert "data_exfiltration_sequence" in pattern_names

    def test_get_action_sequence(self) -> None:
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "a")
        g.add_action("agent-1", "b")
        g.add_action("agent-2", "c")

        seq_all = g.get_action_sequence()
        assert len(seq_all) == 3

        seq_1 = g.get_action_sequence("agent-1")
        assert len(seq_1) == 2

    def test_to_dict(self) -> None:
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "tool_call", tool="db")
        g.add_action("agent-1", "llm_call")

        d = g.to_dict()
        assert d["node_count"] == 2
        assert d["edge_count"] == 1
        assert len(d["nodes"]) == 2
        assert len(d["edges"]) == 1
        assert "agent-1" in d["agents"]

    def test_add_edge(self) -> None:
        g = AgentBehavioralGraph()
        n1 = g.add_action("agent-1", "a")
        n2 = g.add_action("agent-2", "b")

        edge = g.add_edge(n1.node_id, n2.node_id, relationship="causal")
        assert edge is not None
        assert g.edge_count == 1  # only the custom edge (no temporal between different agents)
        # Actually: agent-1 and agent-2 are different so no temporal edge, then we add 1 custom
        # But edge_count includes temporal edges too. Let's just check it's >= 1
        assert g.edge_count >= 1

    def test_add_edge_invalid_node(self) -> None:
        g = AgentBehavioralGraph()
        assert g.add_edge("fake1", "fake2") is None

    def test_get_node(self) -> None:
        g = AgentBehavioralGraph()
        n = g.add_action("agent-1", "a")
        assert g.get_node(n.node_id) is n
        assert g.get_node("nonexistent") is None

    def test_custom_pattern(self) -> None:
        custom = PatternGraph(
            name="custom_test",
            description="Custom test pattern",
            nodes=[
                {"action_type": "tool_call"},
                {"action_type": "llm_call"},
            ],
            severity=0.7,
        )
        g = AgentBehavioralGraph()
        g.add_action("agent-1", "tool_call")
        g.add_action("agent-1", "llm_call")

        matches = g.detect_pattern(custom)
        assert len(matches) == 1
