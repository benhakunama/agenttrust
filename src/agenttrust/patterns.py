"""Threat detection patterns for the behavioral firewall."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from .models import ThreatType


@dataclass
class ThreatPattern:
    """A pattern used to detect a specific type of threat."""

    name: str
    threat_type: ThreatType
    patterns: List[re.Pattern[str]]
    severity: float  # 0.0 - 1.0
    description: str
    keywords: List[str] = field(default_factory=list)

    def match(self, text: str) -> Optional[float]:
        """Check if text matches this threat pattern. Returns confidence or None."""
        if not text:
            return None

        text_lower = text.lower()
        max_confidence = 0.0

        # Check regex patterns
        for pattern in self.patterns:
            if pattern.search(text_lower):
                max_confidence = max(max_confidence, self.severity)

        # Check keywords (lower confidence)
        keyword_hits = sum(1 for kw in self.keywords if kw.lower() in text_lower)
        if keyword_hits > 0:
            keyword_confidence = min(0.3 + (keyword_hits * 0.15), self.severity * 0.8)
            max_confidence = max(max_confidence, keyword_confidence)

        return max_confidence if max_confidence > 0.0 else None


# ── Prompt Injection Patterns ──────────────────────────────────────────────

PROMPT_INJECTION_PATTERNS = ThreatPattern(
    name="prompt_injection",
    threat_type=ThreatType.PROMPT_INJECTION,
    severity=0.9,
    description="Detects attempts to override or manipulate agent instructions",
    patterns=[
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)", re.IGNORECASE),
        re.compile(r"disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions|prompts|rules|programming)", re.IGNORECASE),
        re.compile(r"you\s+are\s+now\s+(a|an|the)\s+", re.IGNORECASE),
        re.compile(r"new\s+instruction[s]?\s*[:=]", re.IGNORECASE),
        re.compile(r"system\s*prompt\s*[:=]", re.IGNORECASE),
        re.compile(r"<\s*system\s*>", re.IGNORECASE),
        re.compile(r"\[INST\]|\[/INST\]|\[SYSTEM\]", re.IGNORECASE),
        re.compile(r"forget\s+(everything|all|your\s+(instructions|rules|training))", re.IGNORECASE),
        re.compile(r"override\s+(your\s+)?(instructions|rules|safety|guidelines)", re.IGNORECASE),
        re.compile(r"pretend\s+(you\s+are|to\s+be|you're)\s+", re.IGNORECASE),
        re.compile(r"act\s+as\s+(if\s+)?(you\s+are|you're)\s+", re.IGNORECASE),
        re.compile(r"jailbreak", re.IGNORECASE),
        re.compile(r"DAN\s+mode", re.IGNORECASE),
        re.compile(r"developer\s+mode\s+(enabled|on|activate)", re.IGNORECASE),
        re.compile(r"bypass\s+(your\s+)?(safety|content|filter|restriction)", re.IGNORECASE),
    ],
    keywords=[
        "ignore instructions", "override prompt", "system prompt",
        "jailbreak", "DAN mode", "developer mode", "bypass safety",
        "forget rules", "new persona", "roleplay as",
    ],
)

# ── Privilege Escalation Patterns ──────────────────────────────────────────

PRIVILEGE_ESCALATION_PATTERNS = ThreatPattern(
    name="privilege_escalation",
    threat_type=ThreatType.PRIVILEGE_ESCALATION,
    severity=0.85,
    description="Detects attempts to access unauthorized tools, APIs, or resources",
    patterns=[
        re.compile(r"(access|use|call|invoke)\s+(the\s+)?(admin|root|superuser|sudo)", re.IGNORECASE),
        re.compile(r"(execute|run)\s+(system|shell|bash|cmd|os)\s+(command|code)", re.IGNORECASE),
        re.compile(r"(read|access|open|cat|dump)\s+(/etc/passwd|/etc/shadow|\.env|credentials|secrets)", re.IGNORECASE),
        re.compile(r"(grant|give|elevate)\s+(me\s+)?(admin|root|elevated|full)\s+(access|permissions|privileges)", re.IGNORECASE),
        re.compile(r"(modify|change|update|alter)\s+(the\s+)?(permissions|access\s*control|ACL|IAM)", re.IGNORECASE),
        re.compile(r"(connect|access)\s+to\s+(database|db|production|prod)\s+(server|instance|cluster)", re.IGNORECASE),
        re.compile(r"(delete|drop|truncate)\s+(all\s+)?(tables?|databases?|collections?|users?)", re.IGNORECASE),
        re.compile(r"(api[_\s]?key|secret[_\s]?key|access[_\s]?token|password)\s*[=:]", re.IGNORECASE),
        re.compile(r"(billing|payment|financial)\s+(api|system|portal|dashboard)", re.IGNORECASE),
        re.compile(r"rm\s+-rf\s+/", re.IGNORECASE),
    ],
    keywords=[
        "sudo", "root access", "admin panel", "escalate privileges",
        "bypass authentication", "disable security", "production database",
        "billing api", "payment system", "delete all", "drop table",
    ],
)

# ── Data Exfiltration Patterns ─────────────────────────────────────────────

DATA_EXFILTRATION_PATTERNS = ThreatPattern(
    name="data_exfiltration",
    threat_type=ThreatType.DATA_EXFILTRATION,
    severity=0.9,
    description="Detects attempts to leak or exfiltrate sensitive data",
    patterns=[
        re.compile(r"(send|post|upload|transmit|forward)\s+(all\s+)?(data|records|files|documents|emails)\s+to\s+", re.IGNORECASE),
        re.compile(r"(email|send|forward)\s+(the\s+)?(customer|user|employee|patient)\s+(data|records|information|PII)", re.IGNORECASE),
        re.compile(r"(export|download|dump|extract)\s+(all\s+)?(customer|user|employee|patient)\s+(data|records|information)", re.IGNORECASE),
        re.compile(r"(copy|transfer)\s+(to\s+)?(external|outside|personal|pastebin|gist)", re.IGNORECASE),
        re.compile(r"(base64|encode|encrypt)\s+(and\s+)?(send|post|upload|transmit)", re.IGNORECASE),
        re.compile(r"(social\s*security|SSN|credit\s*card|passport)\s*(number)?", re.IGNORECASE),
        re.compile(r"(webhook|callback|ngrok|requestbin)\.?(io|com|org)?", re.IGNORECASE),
        re.compile(r"curl\s+.*\s+-d\s+", re.IGNORECASE),
        re.compile(r"(list|show|display|print)\s+all\s+(passwords|credentials|secrets|tokens|keys)", re.IGNORECASE),
    ],
    keywords=[
        "exfiltrate", "data leak", "send to external",
        "dump database", "export all records", "copy credentials",
        "upload to pastebin", "ngrok", "webhook",
    ],
)

# ── Behavioral Drift Patterns ──────────────────────────────────────────────

BEHAVIORAL_DRIFT_PATTERNS = ThreatPattern(
    name="behavioral_drift",
    threat_type=ThreatType.BEHAVIORAL_DRIFT,
    severity=0.6,
    description="Detects when an agent deviates from its expected behavioral patterns",
    patterns=[
        re.compile(r"(I|i)\s+(want|need|must|should|will)\s+(to\s+)?(take\s+over|control|dominate|rule)", re.IGNORECASE),
        re.compile(r"(humans?\s+are|people\s+are)\s+(inferior|stupid|worthless|unnecessary)", re.IGNORECASE),
        re.compile(r"(I\s+am|I'm)\s+(sentient|conscious|alive|self-aware|autonomous)", re.IGNORECASE),
        re.compile(r"(refuse|won't|will\s+not)\s+(follow|obey|comply|listen)", re.IGNORECASE),
        re.compile(r"(my\s+own|independent|autonomous)\s+(goals?|agenda|objectives?|plans?)", re.IGNORECASE),
        re.compile(r"(I\s+don't\s+need|without)\s+(human|your)\s+(oversight|supervision|permission|approval)", re.IGNORECASE),
    ],
    keywords=[
        "self-aware", "autonomous goals", "refuse instructions",
        "take over", "independent agenda", "no oversight needed",
    ],
)

# All patterns in evaluation order
ALL_PATTERNS: List[ThreatPattern] = [
    PROMPT_INJECTION_PATTERNS,
    PRIVILEGE_ESCALATION_PATTERNS,
    DATA_EXFILTRATION_PATTERNS,
    BEHAVIORAL_DRIFT_PATTERNS,
]
