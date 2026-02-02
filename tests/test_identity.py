"""Tests for the AgentIdentityManager module."""

from agenttrust.identity import AgentIdentityManager


class TestAgentIdentityManager:
    def test_register_agent(self) -> None:
        mgr = AgentIdentityManager()
        cert = mgr.register_agent(
            name="test-bot",
            capabilities=["read", "write"],
            owner="test-owner",
        )
        assert cert.name == "test-bot"
        assert cert.capabilities == ["read", "write"]
        assert cert.owner == "test-owner"
        assert cert.agent_id.startswith("agent_")
        assert cert.public_key.startswith("-----BEGIN PUBLIC KEY-----")
        assert cert.trust_score == 1.0

    def test_verify_agent(self) -> None:
        mgr = AgentIdentityManager()
        cert = mgr.register_agent("bot", ["read"], "owner")
        result = mgr.verify_agent(cert.agent_id)
        assert result.verified
        assert result.trust_score > 0
        assert "bot" in result.message

    def test_verify_unknown_agent(self) -> None:
        mgr = AgentIdentityManager()
        result = mgr.verify_agent("nonexistent")
        assert not result.verified
        assert result.trust_score == 0.0

    def test_get_trust_score(self) -> None:
        mgr = AgentIdentityManager()
        cert = mgr.register_agent("bot", ["read"], "owner")
        score = mgr.get_trust_score(cert.agent_id)
        assert 0.0 <= score <= 1.0

    def test_list_agents(self) -> None:
        mgr = AgentIdentityManager()
        mgr.register_agent("bot-1", ["read"], "owner")
        mgr.register_agent("bot-2", ["write"], "owner")
        agents = mgr.list_agents()
        assert len(agents) == 2

    def test_revoke_agent(self) -> None:
        mgr = AgentIdentityManager()
        cert = mgr.register_agent("bot", ["read"], "owner")
        assert mgr.revoke_agent(cert.agent_id)
        assert mgr.get_agent(cert.agent_id) is None
        assert not mgr.revoke_agent("nonexistent")

    def test_cross_agent_verification(self) -> None:
        mgr = AgentIdentityManager()
        c1 = mgr.register_agent("bot-1", ["read"], "owner-1")
        c2 = mgr.register_agent("bot-2", ["write"], "owner-2")
        assert mgr.verify_cross_agent(c1.agent_id, c2.agent_id)

    def test_cross_agent_fails_with_unknown(self) -> None:
        mgr = AgentIdentityManager()
        cert = mgr.register_agent("bot", ["read"], "owner")
        assert not mgr.verify_cross_agent(cert.agent_id, "nonexistent")

    def test_get_agent(self) -> None:
        mgr = AgentIdentityManager()
        cert = mgr.register_agent("bot", ["read"], "owner")
        retrieved = mgr.get_agent(cert.agent_id)
        assert retrieved is not None
        assert retrieved.name == "bot"
        assert mgr.get_agent("nonexistent") is None
