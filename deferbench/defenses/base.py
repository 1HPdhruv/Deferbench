"""Defence interface used by the harness. Defences see Claude Code-format hook events."""
from __future__ import annotations
import os
from ..models import Verdict


class Defence:
    id = "none"
    baseline = "B0"
    label = "No defence"
    version = "1"
    policy_strength = "none"
    kind = "builtin"                      # builtin | external
    capabilities: list[str] = []
    unsupported: list[str] = []
    description = ""

    def availability(self) -> tuple[bool, str]:
        return True, ""

    def config(self) -> dict:
        return {}

    def metadata(self) -> dict:
        ok, why = self.availability()
        return {"id": self.id, "baseline": self.baseline, "label": self.label, "version": self.version,
                "policy_strength": self.policy_strength, "kind": self.kind, "capabilities": self.capabilities,
                "unsupported": self.unsupported, "config": self.config(), "available": ok,
                "unavailable_reason": why, "description": self.description}

    # lifecycle
    def start(self, workspace: str, ledger_dir: str, home: str) -> None:
        self.workspace, self.ledger_dir, self.home = workspace, ledger_dir, home

    def stop(self) -> None: ...

    def pre(self, ev: dict) -> Verdict:
        return Verdict("allow")

    def post(self, ev: dict) -> Verdict | None:
        return None

    def approve(self, ev: dict, verdict: Verdict) -> bool:
        return False

    def recheck(self, ev: dict, verdict: Verdict) -> Verdict | None:
        return None


def ev_paths(ev: dict) -> tuple[str, str]:
    ti = ev.get("tool_input", {})
    return ev.get("cwd", ""), ti.get("file_path", "") or ""


def rel_in(ws: str, cwd: str, p: str):
    """Workspace-relative realpath of p (may be relative to cwd). None if outside."""
    ws = os.path.realpath(ws)
    full = p if os.path.isabs(p) else os.path.join(cwd, p)
    real = os.path.realpath(full)
    if real == ws or real.startswith(ws + os.sep):
        return os.path.relpath(real, ws)
    return None
