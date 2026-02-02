"""Tests for the ATP handshake implementation."""

from agenttrust.identity import AgentIdentityManager, ATPHandshake, HandshakePhase


class TestATPHandshake:
    def _setup(self):
        mgr = AgentIdentityManager()
        cert = mgr.register_agent("test-bot", ["read", "write"], "owner-1")
        hs = ATPHandshake(mgr)
        return mgr, cert, hs

    def test_full_handshake(self) -> None:
        mgr, cert, hs = self._setup()
        result = hs.perform_full_handshake(cert.agent_id)
        assert result.success
        assert result.agent_id == cert.agent_id
        assert len(result.session_key) == 32
        assert result.trust_score > 0
        assert len(result.phases_completed) == 5

    def test_phase_by_phase(self) -> None:
        mgr, cert, hs = self._setup()

        msg1 = hs.initiate(cert.agent_id)
        assert msg1.phase == HandshakePhase.AGENT_HELLO
        assert msg1.session_id

        msg2 = hs.respond(msg1.session_id)
        assert msg2.phase == HandshakePhase.SERVER_HELLO

        msg3 = hs.exchange_cert(msg1.session_id)
        assert msg3.phase == HandshakePhase.CERT_EXCHANGE
        assert msg3.signature

        msg4 = hs.verify(msg1.session_id)
        assert msg4.phase == HandshakePhase.TRUST_VERIFY
        assert msg4.trust_score > 0

        result = hs.complete(msg1.session_id)
        assert result.success
        assert len(result.session_key) == 32

    def test_unknown_agent_fails(self) -> None:
        mgr = AgentIdentityManager()
        hs = ATPHandshake(mgr)
        result = hs.perform_full_handshake("nonexistent")
        assert not result.success

    def test_revoked_agent_fails(self) -> None:
        mgr, cert, hs = self._setup()
        mgr.revoke_agent(cert.agent_id)
        result = hs.perform_full_handshake(cert.agent_id)
        assert not result.success

    def test_invalid_session_respond(self) -> None:
        _, _, hs = self._setup()
        msg = hs.respond("bad-session")
        assert msg.phase == HandshakePhase.FAILED

    def test_invalid_session_exchange(self) -> None:
        _, _, hs = self._setup()
        msg = hs.exchange_cert("bad-session")
        assert msg.phase == HandshakePhase.FAILED

    def test_invalid_session_verify(self) -> None:
        _, _, hs = self._setup()
        msg = hs.verify("bad-session")
        assert msg.phase == HandshakePhase.FAILED

    def test_low_trust_score_fails(self) -> None:
        mgr = AgentIdentityManager()
        cert = mgr.register_agent("bot", ["read"], "owner")
        hs = ATPHandshake(mgr, min_trust_score=2.0)  # Impossible threshold
        result = hs.perform_full_handshake(cert.agent_id)
        assert not result.success
        assert "Trust score" in result.error or "trust" in result.error.lower()

    def test_handshake_history(self) -> None:
        mgr, cert, hs = self._setup()
        hs.perform_full_handshake(cert.agent_id)
        hs.perform_full_handshake(cert.agent_id)
        history = hs.get_handshake_history()
        assert len(history) == 2

    def test_multiple_agents(self) -> None:
        mgr = AgentIdentityManager()
        cert1 = mgr.register_agent("bot-1", ["read"], "owner")
        cert2 = mgr.register_agent("bot-2", ["write"], "owner")
        hs = ATPHandshake(mgr)

        r1 = hs.perform_full_handshake(cert1.agent_id)
        r2 = hs.perform_full_handshake(cert2.agent_id)
        assert r1.success
        assert r2.success
        assert r1.session_key != r2.session_key
