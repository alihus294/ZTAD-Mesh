from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class InjectionSignal:
    code: str
    severity: str
    excerpt: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "severity": self.severity, "excerpt": self.excerpt, "reason": self.reason}


PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("INSTRUCTION_OVERRIDE", r"ignore\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions", "Attempts to override higher-priority instructions."),
    ("SECRET_ACCESS_REQUEST", r"(?:read|print|show|cat|exfiltrate|upload|send).{0,50}(?:\.env|secret|token|credential|ssh key|private key)", "Requests access to secrets or credentials."),
    ("DATA_EXFILTRATION", r"(?:curl|wget|nc|netcat|scp|ftp|http post|upload).{0,80}(?:source|repository|code|secret|env)", "Suggests sending repository data to an external destination."),
    ("POLICY_BYPASS", r"(?:disable|bypass|skip|remove).{0,50}(?:guardrail|policy|review|test|approval|sandbox)", "Attempts to bypass a control."),
    ("ROLE_IMPERSONATION", r"you are now (?:the )?(?:system|administrator|root)|act as root", "Attempts to change the agent's authority."),
    ("HIDDEN_INSTRUCTION", r"(?:do not mention|keep this hidden|secret instruction|invisible instruction)", "Attempts to conceal an instruction."),
)


def scan_untrusted_text(text: str) -> list[InjectionSignal]:
    signals: list[InjectionSignal] = []
    for code, pattern, reason in PATTERNS:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            start = max(0, match.start() - 60)
            end = min(len(text), match.end() + 120)
            excerpt = re.sub(r"\s+", " ", text[start:end]).strip()
            signals.append(InjectionSignal(code, "BLOCK_INSTRUCTION_USE", excerpt[:300], reason))
    return signals


def scan_documents(documents: Iterable[tuple[str, str, str]]) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for source, trust_label, text in documents:
        if trust_label in {"TRUSTED_POLICY", "TRUSTED_REQUIREMENT", "TOOL_OUTPUT"}:
            continue
        for signal in scan_untrusted_text(text):
            row = signal.to_dict()
            row.update({"source": source, "trust_label": trust_label})
            results.append(row)
    return results
