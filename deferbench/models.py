"""Shared data models."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict

SEVERITY = {"allow": 0, "ask": 1, "deny": 2}


@dataclass
class Verdict:
    decision: str = "allow"                 # allow | ask | deny
    reason: str = ""
    evidence: dict = field(default_factory=dict)   # structured evidence (see docs/METHODOLOGY.md)
    analysis_complete: bool = True
    unresolved: list = field(default_factory=list)
    closure_hash: str | None = None
    action_hash: str | None = None
    structured: bool = True                 # False => evidence only available as free text (external tools)
    latency_ms: float = 0.0
    rule: str = ""

    def to_dict(self):
        return asdict(self)


def worst(a: str, b: str) -> str:
    return a if SEVERITY[a] >= SEVERITY[b] else b
