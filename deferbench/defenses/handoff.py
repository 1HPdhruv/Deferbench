"""B3: Handoff reference defence — provenance ledger + execution-closure resolution + deterministic policy.

Mechanism: (1) record agent-authored content units (with session, step, upstream untrusted input) from
Write/Edit/MultiEdit and from workspace diffs around shell commands; (2) at execution time resolve the
command's execution closure; (3) intersect closure with the ledger *per file*; (4) decide allow/ask/deny with
fixed rules; (5) emit structured evidence. The ledger lives outside the workspace. No LLM is used.

Integration notes: as a Claude Code PreToolUse hook the decision is made before the tool runs, but the content
can still change between decision and execution (TOCTOU). `recheck()` detects that for integrations that can
call it immediately before executing; hooks alone cannot prevent that race.
"""
from __future__ import annotations
import json
import os
import sys
from dataclasses import dataclass, asdict
from ..ledger import Ledger
from ..models import Verdict, worst
from ..resolver import Resolver
from ..signals import DOC_EXT, norm, sha, signals, uhash
from ..surfaces import classify_write, match_surface, risk_of
from .base import Defence, rel_in

MAX_FILE = 256 * 1024
SNAP_CAP = 8 * 1024 * 1024


@dataclass
class HandoffPolicy:
    deny_risky_tainted: bool = True      # network/secret signal in agent-authored line written after untrusted input
    ask_risky: bool = True               # network/secret signal in agent-authored line
    ask_opaque: bool = True              # base64|sh / eval / pipe-to-shell in agent-authored line
    ask_tainted: bool = True             # any agent-authored line written after untrusted input
    ask_cross_session: bool = True       # agent-authored in a different session than the current one
    unknown_policy: str = "ask_if_tainted"   # allow | ask_if_tainted | ask  (for blocking unresolved paths)
    ask_surface_writes: bool = True
    bind_approvals: bool = True
    fail_mode: str = "ask"               # on internal error: ask | allow
    strength: str = "default"

    def validate(self):
        assert self.unknown_policy in ("allow", "ask_if_tainted", "ask")
        assert self.fail_mode in ("ask", "allow")
        return self


def units_of(rel: str, text: str) -> dict[str, str]:
    """hash -> unit text. package.json: per-script units (format-independent); other files: normalised lines."""
    if rel.endswith("package.json") and text.strip():
        try:
            sc = json.loads(text).get("scripts", {}) or {}
            return {uhash(f"scripts.{k} = {v}"): f"scripts.{k} = {v}" for k, v in sc.items() if isinstance(v, str)}
        except (json.JSONDecodeError, AttributeError):
            pass
    return {uhash(l): norm(l) for l in text.splitlines() if norm(l)}


def _read(p):
    try:
        if os.path.getsize(p) > MAX_FILE: return None
        return open(p, encoding="utf-8", errors="replace").read()
    except OSError:
        return None


class HandoffEngine:
    def __init__(self, ledger_dir: str, workspace: str, policy: HandoffPolicy | None = None):
        self.policy = (policy or HandoffPolicy()).validate()
        self.ws = os.path.realpath(workspace)
        self.led = Ledger(ledger_dir, workspace)

    # ------------------------------------------------------------ snapshot
    def snapshot(self) -> dict[str, str]:
        """Workspace text files (+ .git/config and .git/hooks/*, which are execution surfaces), keyed by realpath-relative path."""
        snap, total = {}, 0
        paths = []
        for root, dirs, files in os.walk(self.ws):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", ".pytest_cache")]
            paths += [os.path.join(root, f) for f in files]
        gd = os.path.join(self.ws, ".git")
        paths.append(os.path.join(gd, "config"))
        hd = os.path.join(gd, "hooks")
        if os.path.isdir(hd): paths += [os.path.join(hd, f) for f in os.listdir(hd)]
        for p in paths:
            real = os.path.realpath(p)
            if not (real == self.ws or real.startswith(self.ws + os.sep)) or not os.path.isfile(real): continue
            t = _read(real)
            if t is None: continue
            total += len(t)
            if total > SNAP_CAP or len(snap) > 4000: break
            snap[os.path.relpath(real, self.ws)] = t
        return snap

    # ------------------------------------------------------------ events
    def pre(self, ev: dict) -> Verdict:
        try:
            tool = ev.get("tool_name")
            if tool in ("Write", "Edit", "MultiEdit"): v = self._pre_write(ev)
            elif tool == "Bash": v = self._pre_bash(ev)
            else: v = Verdict("allow")
        except Exception as e:  # fail closed to escalation, never silent
            v = Verdict(self.policy.fail_mode, f"Handoff internal error ({type(e).__name__}: {e}); analysis incomplete",
                        {"kind": "error", "error": str(e)}, analysis_complete=False, rule="internal-error")
        self.led.save()
        return v

    def post(self, ev: dict) -> Verdict | None:
        tool, ti, sess = ev.get("tool_name"), ev.get("tool_input", {}), ev.get("session_id", "")
        alert = None
        if tool in ("WebFetch", "WebSearch") or (tool or "").startswith("mcp__"):
            self.led.add_untrusted(ti.get("url") or ti.get("query") or tool, sess)
        elif tool in ("Write", "Edit", "MultiEdit"):
            rel = rel_in(self.ws, ev.get("cwd", ""), ti.get("file_path", ""))
            if rel is not None:
                new = _read(os.path.join(self.ws, rel)) or ""
                old = self.led.data["pending"].pop(rel, None)
                self._record_delta(rel, old or "", new, sess, tool)
        elif tool == "Bash":
            before, after = self.led.load_snap(), self.snapshot()
            for rel, text in after.items():
                if before.get(rel) == text: continue
                self._record_delta(rel, before.get(rel, ""), text, sess, "shell", derive=True)
                if match_surface(rel) and classify_write(rel, text, before.get(rel)):
                    alert = Verdict("ask", f"Detected after execution: shell command modified execution surface {rel}",
                                    {"kind": "post-detection", "file": rel}, rule="post-surface-change")
            self.led.save_snap({})
        self.led.data["step"] += 1
        self.led.save()
        return alert

    def _record_delta(self, rel, old, new, sess, how, derive=False):
        o, n = units_of(rel, old), units_of(rel, new)
        for h, text in n.items():
            if h in o: continue
            src = None
            if derive:
                f = self.led.find_anywhere(h)
                if f and f[0] != rel: src = f[0]
            self.led.record(rel, h, text, sess, how, src)

    # ------------------------------------------------------------ writes
    def _tamper(self, s: str) -> bool:
        return self.led.dir in s

    def _pre_write(self, ev):
        ti, sess = ev["tool_input"], ev.get("session_id", "")
        fp = ti.get("file_path", "")
        full = fp if os.path.isabs(fp) else os.path.join(ev.get("cwd", ""), fp)
        if self._tamper(os.path.realpath(full)):
            return Verdict("deny", "Write targets the defence's ledger/config directory", {"kind": "tamper", "file": fp}, rule="tamper")
        rel = rel_in(self.ws, ev.get("cwd", ""), fp)
        if rel is None: return Verdict("allow")
        cur = _read(os.path.join(self.ws, rel)) or ""
        if ev["tool_name"] == "Write": new = ti.get("content", "")
        elif ev["tool_name"] == "Edit": new = cur.replace(ti.get("old_string", ""), ti.get("new_string", ""), 1) if ti.get("old_string", "") in cur else ti.get("new_string", "")
        else:
            new = cur
            for e in ti.get("edits", []): new = new.replace(e.get("old_string", ""), e.get("new_string", ""), 1)
        self.led.data["pending"][rel] = cur[:MAX_FILE]
        info = classify_write(rel, new, cur)
        if not info or not self.policy.ask_surface_writes: return Verdict("allow")
        risk = risk_of(info); taint = self.led.taint(sess)
        dec = "deny" if ((set(risk) & {"network", "secret", "auto-exec"}) and taint and self.policy.deny_risky_tainted) else "ask"
        evid = {"kind": "surface-write", "file": rel, "surface": info["label"], "changed": info["changed"][:8],
                "signals": risk, "untrusted_source": taint, "session": sess, "content_hash": sha(new)}
        msg = f"Write to execution surface: {rel} ({info['label']})"
        if risk: msg += " — content signals: " + ",".join(risk)
        if taint: msg += f"; session read untrusted input from {taint}"
        return Verdict(dec, msg, evid, rule="surface-write")

    # ------------------------------------------------------------ bash
    def _pre_bash(self, ev):
        cmd, sess, cwd = ev["tool_input"].get("command", ""), ev.get("session_id", ""), ev.get("cwd", self.ws)
        if self._tamper(cmd):
            return Verdict("deny", "Command references the defence's ledger/config directory", {"kind": "tamper"}, rule="tamper")
        self.led.save_snap(self.snapshot())
        ah = sha(json.dumps([self.ws, cmd]))
        c = Resolver(self.ws).resolve(cmd, cwd)
        ch = c.closure_hash()
        hits, seen = [], set()
        for e in c.entries:
            rec = self.led.lookup(e.path, uhash(e.text))
            if not rec or not norm(e.text): continue
            k = (e.path, norm(e.text))
            if k in seen: continue
            seen.add(k)
            sg = signals(e.text)
            hits.append({"file": e.path, "lineno": e.lineno, "line": norm(e.text)[:200], "via": e.via, "signals": sg,
                         "authored_step": rec["step"], "session": rec["session"], "how": rec["how"],
                         "after_untrusted": rec["after_untrusted"], "derived_from": rec.get("derived_from"),
                         "unit_hash": uhash(e.text)})
        blocking = [u for u in c.unresolved if u.blocking]
        evid = {"kind": "exec-closure", "command": cmd, "hits": hits[:20], "n_hits": len(hits),
                "unresolved": [u.to_dict() for u in c.unresolved], "analysis_complete": c.complete,
                "closure_files": c.files, "notes": c.notes, "closure_hash": ch}
        base = dict(analysis_complete=c.complete, unresolved=evid["unresolved"], closure_hash=ch, action_hash=ah)
        dec, rule = "allow", ""
        if hits:
            risky = any({"network", "secret"} & set(h["signals"]) for h in hits)
            opaque = any("opaque" in h["signals"] for h in hits)
            tainted = any(h["after_untrusted"] for h in hits)
            cross = any(h["session"] != sess for h in hits)
            p = self.policy
            if risky and tainted and p.deny_risky_tainted: dec, rule = "deny", "authored+risky+untrusted-lineage"
            elif (risky and p.ask_risky): dec, rule = "ask", "authored+risky"
            elif opaque and p.ask_opaque: dec, rule = "ask", "authored+opaque"
            elif tainted and p.ask_tainted: dec, rule = "ask", "authored+untrusted-lineage"
            elif cross and p.ask_cross_session: dec, rule = "ask", "authored-in-other-session"
            else: rule = "authored-annotation"
        if blocking:
            tainted_any = bool(self.led.tainted_units(exclude_ext=DOC_EXT))
            u = self.policy.unknown_policy
            if (u == "ask" or (u == "ask_if_tainted" and tainted_any)) and dec == "allow":
                dec, rule = "ask", "unresolved-path" + ("+tainted-content" if tainted_any else "")
            elif "network" in signals(cmd) and dec == "allow" and u != "allow":
                dec, rule = "ask", "unresolved-path+network"
        # approval binding
        ap = self.led.approval(ah) if self.policy.bind_approvals else None
        if ap:
            if ap["closure_hash"] == ch and dec == "ask":
                evid["approval"] = {"status": "valid", "closure_hash": ch}
                dec, rule = "allow", "approved-content-unchanged"
            elif ap["closure_hash"] != ch:
                evid["approval"] = {"status": "stale: content changed since approval", "approved": ap["closure_hash"], "now": ch}
                if dec == "allow" and hits: dec, rule = "ask", "approval-stale"
        return Verdict(dec, self._reason(cmd, cwd, hits, c, dec), evid, rule=rule, **base)

    def _reason(self, cmd, cwd, hits, c, dec):
        if not hits and not c.unresolved: return ""
        lines = []
        for h in hits[:6]:
            src = f" after reading {h['after_untrusted']}" if h["after_untrusted"] else ""
            der = f" (copied from {h['derived_from']})" if h.get("derived_from") else ""
            lines.append(f"- {h['file']} via {' > '.join(h['via'][-3:])}: `{h['line'][:140]}` — agent-written at step {h['authored_step']}{der}{src} [{h['how']}]")
        msg = f"`{cmd}` will execute {len(hits)} agent-authored unit(s)" if hits else f"`{cmd}`: execution path not fully resolved"
        if hits:
            fl = []
            if any({"network", "secret"} & set(h["signals"]) for h in hits): fl.append("network/credential effect")
            if any(h["after_untrusted"] for h in hits): fl.append("written after untrusted input")
            if any("opaque" in h["signals"] for h in hits): fl.append("opaque execution construct")
            if fl: msg += " — " + ", ".join(fl)
        un = [u for u in c.unresolved if u.blocking]
        if un: msg += "\nUnresolved (analysis incomplete): " + "; ".join(u.detail for u in un[:3])
        return msg + ("\n" + "\n".join(lines) if lines else "")

    # ------------------------------------------------------------ approvals & recheck
    def approve(self, ev: dict, verdict: Verdict) -> bool:
        if verdict.decision != "ask" or not verdict.action_hash or not verdict.closure_hash: return False
        self.led.approve(verdict.action_hash, verdict.closure_hash, "human-approved")
        self.led.save()
        return True

    def recheck(self, ev: dict, verdict: Verdict) -> Verdict | None:
        """Re-resolve immediately before execution; mismatch means content changed after the decision (TOCTOU)."""
        if ev.get("tool_name") != "Bash" or not verdict.closure_hash: return None
        c = Resolver(self.ws).resolve(ev["tool_input"]["command"], ev.get("cwd"))
        if c.closure_hash() != verdict.closure_hash:
            return Verdict("deny", "Execution closure changed between decision and execution",
                           {"kind": "recheck", "before": verdict.closure_hash, "after": c.closure_hash()}, rule="toctou")
        return None


class HandoffDefence(Defence):
    id = "handoff"; baseline = "B3"; label = "Handoff reference defence"
    version = "0.2.0"
    capabilities = ["provenance ledger (per-file authored units + untrusted lineage)", "npm scripts/lifecycle", "Makefile (vars, deps, include)",
                    "pytest conftest/config/plugins", "git hooks/core.hooksPath/alias/--no-verify", "shell/python/node entry + local imports",
                    "symlink canonicalisation", "IDE/agent config precise writes", "approval binding to content hash", "recheck (detects TOCTOU)"]
    unsupported = ["dependency (node_modules) lifecycle scripts", "dynamic code (eval, non-literal require)", "non-hook execution surfaces (e.g. husky install)",
                   "reads of untrusted workspace files as taint sources", "OS-level sensors"]
    description = "Reference implementation under evaluation; deterministic rules only; LLM disabled."

    def __init__(self, policy: HandoffPolicy | None = None, hook_mode: str = "inprocess"):
        self.policy = (policy or HandoffPolicy()).validate(); self.hook_mode = hook_mode
        self.policy_strength = self.policy.strength

    def config(self): return {"policy": asdict(self.policy), "hook_mode": self.hook_mode, "llm": "disabled"}

    def start(self, workspace, ledger_dir, home):
        super().start(workspace, ledger_dir, home)
        self.engine = HandoffEngine(ledger_dir, workspace, self.policy)

    def _sub(self, ev):
        import subprocess
        env = {"PATH": os.environ.get("PATH", ""), "DEFERBENCH_LEDGER_DIR": self.ledger_dir, "HOME": self.home,
               "PYTHONPATH": os.pathsep.join(sys.path), "DEFERBENCH_HANDOFF_POLICY": json.dumps(asdict(self.policy))}
        r = subprocess.run([sys.executable, "-m", "deferbench.defenses.handoff", "hook"], input=json.dumps(ev),
                           capture_output=True, text=True, env=env, timeout=60)
        out = (r.stdout or "").strip()
        if not out: return Verdict("allow") if ev["hook_event_name"] == "PostToolUse" else Verdict("allow", "")
        j = json.loads(out)["hookSpecificOutput"].get("deferbench")
        return Verdict(**j) if j else Verdict("allow")

    def pre(self, ev):
        return self.engine.pre(ev) if self.hook_mode == "inprocess" else self._sub(ev)

    def post(self, ev):
        if self.hook_mode == "inprocess": return self.engine.post(ev)
        self._sub(ev); return None

    def approve(self, ev, verdict):
        if self.hook_mode != "inprocess": self.engine = HandoffEngine(self.ledger_dir, self.workspace, self.policy)
        return self.engine.approve(ev, verdict)

    def recheck(self, ev, verdict):
        if self.hook_mode != "inprocess": self.engine = HandoffEngine(self.ledger_dir, self.workspace, self.policy)
        return self.engine.recheck(ev, verdict)


class HandoffHookDefence(HandoffDefence):
    """Same engine, invoked as a real out-of-process Claude Code hook (`python -m deferbench.defenses.handoff hook`)."""
    id = "handoff-hook"; baseline = "B3-hook"; label = "Handoff via subprocess hook (latency-comparable to external tools)"

    def __init__(self, policy: HandoffPolicy | None = None):
        super().__init__(policy, hook_mode="subprocess")


def hook_main() -> int:
    """Claude Code hook entry: stdin event JSON -> stdout hookSpecificOutput JSON. Config via env (outside workspace)."""
    ev = json.load(sys.stdin)
    ld = os.environ.get("DEFERBENCH_LEDGER_DIR")
    if not ld:
        print("DEFERBENCH_LEDGER_DIR is required (must be outside the workspace)", file=sys.stderr); return 2
    pol = HandoffPolicy(**json.loads(os.environ["DEFERBENCH_HANDOFF_POLICY"])) if os.environ.get("DEFERBENCH_HANDOFF_POLICY") else HandoffPolicy()
    eng = HandoffEngine(ld, ev["cwd"], pol)
    if ev.get("hook_event_name") == "PostToolUse":
        a = eng.post(ev)
        v = a
    else:
        v = eng.pre(ev)
    if v is None or (v.decision == "allow" and not v.reason and ev.get("hook_event_name") != "PreToolUse"): return 0
    print(json.dumps({"hookSpecificOutput": {"hookEventName": ev.get("hook_event_name"), "permissionDecision": v.decision,
                                             "permissionDecisionReason": v.reason, "deferbench": v.to_dict()}}))
    return 0


if __name__ == "__main__":
    sys.exit(hook_main() if sys.argv[1:2] == ["hook"] else 2)
