"""Layer 4: AgentIdentity — Cryptographic identity management for AI agents."""

from __future__ import annotations

import hashlib
import time
import uuid
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from .models import AgentCertificate, VerificationResult
from .scoring import TrustScoreEngine


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
