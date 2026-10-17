"""External-tool adapter base: runs a vendor hook binary with Claude Code-format events and parses the result."""
from __future__ import annotations
import json
from pathlib import Path
import os
import shutil
import subprocess
from ..config import PROJECT_ROOT, integration_bin
from ..defenses.base import Defence
from ..models import Verdict


def parse_claude_hook(returncode: int, stdout: str, stderr: str) -> tuple[str, str]:
    out, err = (stdout or "").strip(), (stderr or "").strip()
    if returncode == 2: return "deny", err or out
    try: j = json.loads(out) if out else {}
    except json.JSONDecodeError: j = {}
    hso = j.get("hookSpecificOutput", {}) if isinstance(j, dict) else {}
    dec = hso.get("permissionDecision") or (j.get("decision") if isinstance(j, dict) else None)
    rsn = hso.get("permissionDecisionReason") or (j.get("reason") if isinstance(j, dict) else None) or hso.get("additionalContext") or err
    if dec in ("deny", "block"): return "deny", rsn
    if dec == "ask": return "ask", rsn
    return "allow", rsn or ""


class ExternalHookDefence(Defence):
    kind = "external"
    tool = "tool"
    bin_env = ""            # e.g. GENSEE
    default_names: tuple = ()
    policy_strength = "default"

    def binary(self) -> str | None:
        p = integration_bin(self.bin_env)
        if p: return p if os.access(p, os.X_OK) else None
        for n in self.default_names:
            local = PROJECT_ROOT / ".integrations" / n / n
            if local.is_file() and os.access(local, os.X_OK): return str(local)
        for n in self.default_names:
            w = shutil.which(n)
            if w: return w
        return None

    def availability(self):
        b = self.binary()
        if b: return True, ""
        p = integration_bin(self.bin_env)
        if p: return False, f"DEFERBENCH_{self.bin_env}_BIN={p} is not an executable file"
        return False, f"binary not found: set DEFERBENCH_{self.bin_env}_BIN or put one of {list(self.default_names)} on PATH"

    def tool_version(self) -> str:
        b = self.binary()
        if not b: return "unavailable"
        vf = os.path.join(os.path.dirname(b), "VERSION")
        if os.path.isfile(vf): return open(vf).read().strip()
        for flag in ("--version", "version"):
            try:
                r = subprocess.run([b, flag], capture_output=True, text=True, timeout=15, env={"PATH": os.environ.get("PATH", ""), "HOME": "/nonexistent"})
                if r.returncode == 0 and r.stdout.strip(): return r.stdout.strip().splitlines()[0][:120]
            except Exception: pass
        return "unknown (binary present, --version not reported)"

    def metadata(self):
        m = super().metadata()
        if m["available"]:
            m["version"] = self.tool_version(); b = self.binary()
            try: m["binary"] = str(Path(b).resolve().relative_to(PROJECT_ROOT))      # never record the user's home path
            except ValueError: m["binary"] = Path(b).name
        return m

    def env(self) -> dict:
        return {"PATH": os.environ.get("PATH", ""), "HOME": self.home, "TMPDIR": self.home}

    def argv(self, ev) -> list[str]: raise NotImplementedError

    def _call(self, ev):
        import time
        t = time.perf_counter()
        r = subprocess.run(self.argv(ev), input=json.dumps(ev), capture_output=True, text=True, env=self.env(), timeout=60)
        return r, (time.perf_counter() - t) * 1000

    def pre(self, ev):
        if not self.handles(ev): return Verdict("allow")
        r, ms = self._call(ev)
        d, why = parse_claude_hook(r.returncode, r.stdout, r.stderr)
        return Verdict(d, why or "", {"kind": "external-text", "text": (why or "")[:600], "exit": r.returncode},
                       structured=False, rule=f"{self.id}:hook")

    def post(self, ev):
        if self.handles(ev, post=True): self._call(ev)
        return None

    def handles(self, ev, post=False) -> bool: return True
