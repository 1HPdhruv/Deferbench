"""The ORIGINAL v0 Handoff prototype (archive/v0/handoff.py, unmodified) run through the same harness.

Only comparable because it speaks the identical Claude Code hook protocol and is given the same events,
scenarios and sandbox. It is evaluated on the v0-compatible subset of behaviour; it never sees the new resolver.
"""
import json
import os
import sys
from ..config import PROJECT_ROOT
from ..models import Verdict
from .base import ExternalHookDefence, parse_claude_hook


class HandoffV0(ExternalHookDefence):
    id = "handoff-v0"; baseline = "B3-v0"; label = "Handoff v0 prototype (archived, unmodified)"
    kind = "archived"; version = "v0 (archive/v0/handoff.py)"
    capabilities = ["line-hash lineage across all files", "npm/make/pytest/git-hook/shell closure (no require() following)"]
    unsupported = ["JS require() chains", "symlinks", "python imports", "local file: dependency lifecycle", "approval binding", "per-file attribution"]
    description = "Original prototype. Known v0 limitations are documented in docs/NOVELTY_AUDIT.md and RELEASE_NOTES.md."
    path = PROJECT_ROOT / "archive" / "v0" / "handoff.py"

    def availability(self):
        return (True, "") if self.path.is_file() else (False, f"{self.path} missing")

    def env(self):
        return {"PATH": os.environ.get("PATH", ""), "HOME": self.home, "HANDOFF_HOME": os.path.join(self.home, ".handoff")}

    def argv(self, ev): return [sys.executable, str(self.path)]
    def tool_version(self): return self.version
    def binary(self): return str(self.path)

    def pre(self, ev):
        if ev.get("tool_name") not in ("Bash", "Write", "Edit", "MultiEdit"): return Verdict("allow")
        r, ms = self._call(ev)
        d, why = parse_claude_hook(r.returncode, r.stdout, r.stderr)
        return Verdict(d, why or "", {"kind": "external-text", "text": (why or "")[:600]}, structured=False, rule="handoff-v0")
