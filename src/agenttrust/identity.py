"""Layer 4: AgentIdentity — Cryptographic identity management for AI agents."""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .models import AgentCertificate, VerificationResult
from .scoring import TrustScoreEngine


# ── ATP Handshake ──────────────────────────────────────────────────────────

class HandshakePhase(str, Enum):
    """Phases of the Agent Trust Protocol handshake."""

    AGENT_HELLO = "AgentHello"
    SERVER_HELLO = "ServerHello"
    CERT_EXCHANGE = "CertExchange"
    TRUST_VERIFY = "TrustVerify"
    ACTION_BEGIN = "ActionBegin"
    FAILED = "Failed"


@dataclass
class HandshakeMessage:
    """A single message in the ATP handshake."""

    phase: HandshakePhase
    agent_id: str
    nonce: str = ""
    signature: str = ""
    public_key: str = ""
    trust_score: float = 0.0
    session_id: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HandshakeResult:
    """Result of a completed ATP handshake."""

    success: bool
    agent_id: str
    session_id: str = ""
    session_key: bytes = b""
    trust_score: float = 0.0
    phases_completed: List[HandshakePhase] = field(default_factory=list)
    error: str = ""
    timestamp: float = field(default_factory=time.time)


class ATPHandshake:
    """Agent Trust Protocol handshake implementation.

    Implements the 5-phase handshake described in the AgentTrust paper:
    1. AgentHello — Agent sends ID and nonce
    2. ServerHello — Server responds with nonce and challenge
    3. CertExchange — Agent sends certificate and signed challenge
    4. TrustVerify — Server verifies signature and trust score
    5. ActionBegin — Session established with derived session key

    Uses ECDSA for signing nonce challenges and ECDH for session key derivation.
    """

    def __init__(
        self,
        identity_manager: AgentIdentityManager,
        min_trust_score: float = 0.3,
    ) -> None:
        """Initialize the ATP handshake handler.

        Args:
            identity_manager: The identity manager for certificate/key access.
            min_trust_score: Minimum trust score required for handshake success.
        """
        self._identity = identity_manager
        self._min_trust = min_trust_score
        self._pending: Dict[str, Dict[str, Any]] = {}  # session_id → handshake state
        self._completed: List[HandshakeResult] = []

    def initiate(self, agent_id: str) -> HandshakeMessage:
        """Phase 1: Agent sends AgentHello.

        Args:
            agent_id: The agent initiating the handshake.

        Returns:
            HandshakeMessage for AgentHello phase.
        """
        session_id = str(uuid.uuid4())
        agent_nonce = os.urandom(32).hex()

        self._pending[session_id] = {
            "agent_id": agent_id,
            "agent_nonce": agent_nonce,
            "phase": HandshakePhase.AGENT_HELLO,
            "started_at": time.time(),
        }

        cert = self._identity.get_agent(agent_id)
        public_key = cert.public_key if cert else ""

        return HandshakeMessage(
            phase=HandshakePhase.AGENT_HELLO,
            agent_id=agent_id,
            nonce=agent_nonce,
            public_key=public_key,
            session_id=session_id,
        )

    def respond(self, session_id: str) -> HandshakeMessage:
        """Phase 2: Server sends ServerHello with challenge nonce.

        Args:
            session_id: The session from Phase 1.

        Returns:
            HandshakeMessage for ServerHello phase.
        """
        state = self._pending.get(session_id)
        if not state or state["phase"] != HandshakePhase.AGENT_HELLO:
            return HandshakeMessage(
                phase=HandshakePhase.FAILED,
                agent_id="",
                session_id=session_id,
                metadata={"error": "Invalid session or phase"},
            )

        server_nonce = os.urandom(32).hex()
        state["server_nonce"] = server_nonce
        state["phase"] = HandshakePhase.SERVER_HELLO

        return HandshakeMessage(
            phase=HandshakePhase.SERVER_HELLO,
            agent_id=state["agent_id"],
            nonce=server_nonce,
            session_id=session_id,
        )

    def exchange_cert(self, session_id: str) -> HandshakeMessage:
        """Phase 3: Agent sends certificate and signed challenge.

        Signs the combined nonces (agent_nonce + server_nonce) using ECDSA.

        Args:
            session_id: The session from Phase 2.

        Returns:
            HandshakeMessage for CertExchange phase with signature.
        """
        state = self._pending.get(session_id)
        if not state or state["phase"] != HandshakePhase.SERVER_HELLO:
            return HandshakeMessage(
                phase=HandshakePhase.FAILED,
                agent_id="",
                session_id=session_id,
                metadata={"error": "Invalid session or phase"},
            )

        agent_id = state["agent_id"]
        private_key = self._identity._private_keys.get(agent_id)
        if not private_key:
            return HandshakeMessage(
                phase=HandshakePhase.FAILED,
                agent_id=agent_id,
                session_id=session_id,
                metadata={"error": "No private key for agent"},
            )

        # Sign the combined nonces
        challenge = f"{state['agent_nonce']}:{state['server_nonce']}".encode("utf-8")
        signature = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
        state["signature"] = signature
        state["phase"] = HandshakePhase.CERT_EXCHANGE

        cert = self._identity.get_agent(agent_id)

        return HandshakeMessage(
            phase=HandshakePhase.CERT_EXCHANGE,
            agent_id=agent_id,
            signature=signature.hex(),
            public_key=cert.public_key if cert else "",
            session_id=session_id,
        )

    def verify(self, session_id: str) -> HandshakeMessage:
        """Phase 4: Server verifies signature and trust score.

        Args:
            session_id: The session from Phase 3.

        Returns:
            HandshakeMessage for TrustVerify phase.
        """
        state = self._pending.get(session_id)
        if not state or state["phase"] != HandshakePhase.CERT_EXCHANGE:
            return HandshakeMessage(
                phase=HandshakePhase.FAILED,
                agent_id="",
                session_id=session_id,
                metadata={"error": "Invalid session or phase"},
            )

        agent_id = state["agent_id"]
        cert = self._identity.get_agent(agent_id)
        if not cert:
            state["phase"] = HandshakePhase.FAILED
            return HandshakeMessage(
                phase=HandshakePhase.FAILED,
                agent_id=agent_id,
                session_id=session_id,
                metadata={"error": "Agent certificate not found"},
            )

        # Verify signature
        try:
            public_key = serialization.load_pem_public_key(cert.public_key.encode("utf-8"))
            challenge = f"{state['agent_nonce']}:{state['server_nonce']}".encode("utf-8")
            public_key.verify(state["signature"], challenge, ec.ECDSA(hashes.SHA256()))  # type: ignore[arg-type]
        except Exception:
            state["phase"] = HandshakePhase.FAILED
            return HandshakeMessage(
                phase=HandshakePhase.FAILED,
                agent_id=agent_id,
                session_id=session_id,
                metadata={"error": "Signature verification failed"},
            )

        # Check trust score
        trust_score = self._identity.get_trust_score(agent_id)
        if trust_score < self._min_trust:
            state["phase"] = HandshakePhase.FAILED
            return HandshakeMessage(
                phase=HandshakePhase.FAILED,
                agent_id=agent_id,
                trust_score=trust_score,
                session_id=session_id,
                metadata={"error": f"Trust score {trust_score:.2f} below minimum {self._min_trust:.2f}"},
            )

        state["trust_score"] = trust_score
        state["phase"] = HandshakePhase.TRUST_VERIFY

        return HandshakeMessage(
            phase=HandshakePhase.TRUST_VERIFY,
            agent_id=agent_id,
            trust_score=trust_score,
            session_id=session_id,
        )

    def complete(self, session_id: str) -> HandshakeResult:
        """Phase 5: Derive session key and establish session.

        Uses ECDH to derive a shared session key.

        Args:
            session_id: The session from Phase 4.

        Returns:
            HandshakeResult with session key and status.
        """
        state = self._pending.get(session_id)
        if not state or state["phase"] != HandshakePhase.TRUST_VERIFY:
            result = HandshakeResult(
                success=False,
                agent_id=state["agent_id"] if state else "",
                session_id=session_id,
                error="Invalid session or phase",
            )
            self._completed.append(result)
            return result

        agent_id = state["agent_id"]

        # Derive session key using ECDH + HKDF
        private_key = self._identity._private_keys.get(agent_id)
        if private_key:
            # Generate ephemeral key pair for session
            ephemeral_private = ec.generate_private_key(ec.SECP256R1())
            peer_public = private_key.public_key()

            shared_secret = ephemeral_private.exchange(ECDH(), peer_public)

            # Derive session key with HKDF
            session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=f"{state['agent_nonce']}:{state['server_nonce']}".encode("utf-8"),
                info=b"agenttrust-atp-session",
            ).derive(shared_secret)
        else:
            session_key = b""

        state["phase"] = HandshakePhase.ACTION_BEGIN

        result = HandshakeResult(
            success=True,
            agent_id=agent_id,
            session_id=session_id,
            session_key=session_key,
            trust_score=state.get("trust_score", 0.0),
            phases_completed=[
                HandshakePhase.AGENT_HELLO,
                HandshakePhase.SERVER_HELLO,
                HandshakePhase.CERT_EXCHANGE,
                HandshakePhase.TRUST_VERIFY,
                HandshakePhase.ACTION_BEGIN,
            ],
        )

        self._completed.append(result)
        del self._pending[session_id]

        return result

    def perform_full_handshake(self, agent_id: str) -> HandshakeResult:
        """Perform a complete 5-phase handshake in one call.

        Convenience method that runs all phases sequentially.

        Args:
            agent_id: The agent to handshake with.

        Returns:
            HandshakeResult with the outcome.
        """
        msg1 = self.initiate(agent_id)
        if msg1.phase == HandshakePhase.FAILED:
            return HandshakeResult(success=False, agent_id=agent_id, error="AgentHello failed")

        msg2 = self.respond(msg1.session_id)
        if msg2.phase == HandshakePhase.FAILED:
            return HandshakeResult(success=False, agent_id=agent_id, error="ServerHello failed")

        msg3 = self.exchange_cert(msg1.session_id)
        if msg3.phase == HandshakePhase.FAILED:
            return HandshakeResult(
                success=False, agent_id=agent_id,
                error=msg3.metadata.get("error", "CertExchange failed"),
            )

        msg4 = self.verify(msg1.session_id)
        if msg4.phase == HandshakePhase.FAILED:
            return HandshakeResult(
                success=False, agent_id=agent_id,
                error=msg4.metadata.get("error", "TrustVerify failed"),
            )

        return self.complete(msg1.session_id)

    def get_handshake_history(self) -> List[HandshakeResult]:
        """Get history of completed handshakes.

        Returns:
            List of HandshakeResult objects.
        """
        return list(self._completed)


class AgentIdentityManager:
    """Manages cryptographic identities for AI agents.

    Handles agent registration with unique IDs and elliptic-curve keys,
    trust scoring based on behavioral history, and cross-agent verification.
    """

    def __init__(self, scoring_engine: Optional[TrustScoreEngine] = None) -> None:
        """Initialize the identity manager.

        Args:
            scoring_engine: Custom scoring engine (uses default if None).
        """
        self._agents: Dict[str, AgentCertificate] = {}
        self._private_keys: Dict[str, EllipticCurvePrivateKey] = {}
        self._scoring = scoring_engine or TrustScoreEngine()

    def register_agent(
        self,
        name: str,
        capabilities: List[str],
        owner: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentCertificate:
        """Register a new agent with a cryptographic identity.

        Args:
            name: Human-readable agent name.
            capabilities: List of agent capabilities/permissions.
            owner: Owner identifier.
            metadata: Additional metadata.

        Returns:
            AgentCertificate with the agent's identity information.
        """
        agent_id = self._generate_agent_id(name, owner)

        # Generate ECDSA key pair
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()

        # Serialize public key to PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        certificate = AgentCertificate(
            agent_id=agent_id,
            name=name,
            capabilities=capabilities,
            owner=owner,
            public_key=public_pem,
            trust_score=1.0,
            metadata=metadata or {},
        )

        self._agents[agent_id] = certificate
        self._private_keys[agent_id] = private_key

        return certificate

    def verify_agent(self, agent_id: str) -> VerificationResult:
        """Verify an agent's identity and return its current status.

        Args:
            agent_id: The agent ID to verify.

        Returns:
            VerificationResult with verification status.
        """
        cert = self._agents.get(agent_id)
        if not cert:
            return VerificationResult(
                agent_id=agent_id,
                verified=False,
                trust_score=0.0,
                message="Agent not found in registry",
            )

        # Verify the agent has a valid key pair
        has_private_key = agent_id in self._private_keys
        trust_score = self._scoring.get_score(agent_id)

        if has_private_key and trust_score > 0.1:
            return VerificationResult(
                agent_id=agent_id,
                verified=True,
                trust_score=trust_score,
                message=f"Agent '{cert.name}' verified (owner: {cert.owner})",
            )

        return VerificationResult(
            agent_id=agent_id,
            verified=False,
            trust_score=trust_score,
            message="Agent verification failed: low trust score or missing keys",
        )

    def get_trust_score(self, agent_id: str) -> float:
        """Get the current trust score for an agent.

        Args:
            agent_id: The agent to query.

        Returns:
            Trust score between 0.0 and 1.0.
        """
        return self._scoring.get_score(agent_id)

    def get_agent(self, agent_id: str) -> Optional[AgentCertificate]:
        """Get an agent's certificate.

        Args:
            agent_id: The agent ID.

        Returns:
            AgentCertificate or None if not found.
        """
        return self._agents.get(agent_id)

    def list_agents(self) -> List[AgentCertificate]:
        """List all registered agents.

        Returns:
            List of all AgentCertificate objects.
        """
        return list(self._agents.values())

    def revoke_agent(self, agent_id: str) -> bool:
        """Revoke an agent's identity.

        Args:
            agent_id: The agent to revoke.

        Returns:
            True if the agent was revoked, False if not found.
        """
        if agent_id in self._agents:
            del self._agents[agent_id]
            self._private_keys.pop(agent_id, None)
            return True
        return False

    def verify_cross_agent(self, agent_a_id: str, agent_b_id: str) -> bool:
        """Verify trust between two agents.

        Both agents must be registered and have acceptable trust scores.

        Args:
            agent_a_id: First agent ID.
            agent_b_id: Second agent ID.

        Returns:
            True if both agents are verified and trusted.
        """
        result_a = self.verify_agent(agent_a_id)
        result_b = self.verify_agent(agent_b_id)
        return result_a.verified and result_b.verified

    @staticmethod
    def _generate_agent_id(name: str, owner: str) -> str:
        """Generate a deterministic agent ID from name and owner.

        Args:
            name: Agent name.
            owner: Agent owner.

        Returns:
            A unique agent ID string.
        """
        unique = f"{name}:{owner}:{uuid.uuid4().hex[:8]}"
        hash_hex = hashlib.sha256(unique.encode()).hexdigest()[:16]
        return f"agent_{hash_hex}"
