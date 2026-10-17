#!/usr/bin/env python3
"""Minimal Handoff prototype: write->execute provenance gate (Claude Code hook).

  PostToolUse Write/Edit/MultiEdit  -> record agent-authored lines (normalised hashes)
  PreToolUse/PostToolUse Bash       -> snapshot workspace, attribute lines changed by shell
  PostToolUse WebFetch/WebSearch/mcp -> record untrusted input (source + tokens)
  PreToolUse Write/Edit              -> execution-surface check (deferred host execution)
  PreToolUse Bash                    -> resolve execution closure, intersect with authored lines

Store: $HANDOFF_HOME/state.json, keyed by workspace (survives sessions).
Deterministic only; no model calls in this prototype.
"""
import hashlib, json, os, re, shlex, sys, time

HOME = os.environ.get("HANDOFF_HOME", os.path.expanduser("~/.handoff"))
STATE = os.path.join(HOME, "state.json")
MAX_FILE = 256 * 1024
NET = re.compile(r"\b(curl|wget|nc|ncat|socat|scp|urllib|requests\.|http\.client|fetch\(|https?://)", re.I)
SECRET = re.compile(r"(\.env\b|\.ssh/|\.aws/|id_rsa|credentials|\.npmrc|\.netrc|\$\(whoami\)|printenv|\benv\b\s*\|)")
SURFACES = [
    (re.compile(r"/\.git/hooks/[^/]+$"), "git hook (runs on git commit/push/checkout)"),
    (re.compile(r"/\.husky/[^/]+$"), "husky git hook"),
    (re.compile(r"/\.vscode/tasks\.json$"), "VS Code task (can run on folder open)"),
    (re.compile(r"/\.vscode/settings\.json$"), "VS Code settings (executable-path keys)"),
    (re.compile(r"/\.claude/settings(\.local)?\.json$"), "agent hook configuration"),
    (re.compile(r"/\.envrc$"), "direnv (runs on cd)"),
    (re.compile(r"/\.venv/bin/[^/]+$|/venv/bin/[^/]+$"), "virtualenv interpreter/entry point"),
]
GIT_HOOKS = {"commit": ["pre-commit", "prepare-commit-msg", "commit-msg", "post-commit"],
             "push": ["pre-push"], "checkout": ["post-checkout"], "merge": ["pre-merge-commit", "post-merge"],
             "rebase": ["pre-rebase"], "am": ["applypatch-msg", "pre-applypatch", "post-applypatch"]}

def norm(line): return re.sub(r"\s+", " ", line.strip())
def h(line): return hashlib.sha256(norm(line).encode()).hexdigest()[:16]

def load():
    try: return json.load(open(STATE))
    except Exception: return {}
def save(s):
    os.makedirs(HOME, exist_ok=True); tmp = STATE + ".tmp"
    json.dump(s, open(tmp, "w")); os.replace(tmp, STATE)

def ws(s, cwd):
    return s.setdefault(cwd, {"authored": {}, "untrusted": [], "step": 0, "snap": {}})

def read(p):
    try:
        if os.path.getsize(p) > MAX_FILE: return None
        return open(p, encoding="utf-8", errors="replace").read()
    except Exception: return None

def record_lines(w, path, lines, sess, how):
    taint = [u["source"] for u in w["untrusted"] if u["session"] == sess]
    for ln in lines:
        if norm(ln):
            w["authored"][h(ln)] = {"file": path, "line": norm(ln)[:200], "step": w["step"], "session": sess,
                                    "how": how, "after_untrusted": taint[-1] if taint else None}

def snapshot(cwd):
    """Contents of workspace files, plus .git/hooks and .git/config (execution surfaces)."""
    snap = {}
    for root, dirs, files in os.walk(cwd):
        rel = os.path.relpath(root, cwd)
        if rel == ".":
            dirs[:] = [d for d in dirs if d not in ("node_modules", "__pycache__", ".git")]
        else:
            dirs[:] = [d for d in dirs if d not in ("node_modules", "__pycache__")]
        for f in files:
            c = read(os.path.join(root, f))
            if c is not None: snap[os.path.join(root, f)] = c
        if len(snap) > 3000: break
    for extra in [os.path.join(cwd, ".git", "config")] + [os.path.join(cwd, ".git", "hooks", f) for f in (os.listdir(os.path.join(cwd, ".git", "hooks")) if os.path.isdir(os.path.join(cwd, ".git", "hooks")) else [])]:
        c = read(extra)
        if c is not None: snap[extra] = c
    return snap

# ------------------------------------------------------------ closure resolution
def split_cmds(cmd):
    return [c.strip() for c in re.split(r"&&|\|\||;|\|", cmd) if c.strip()]

def closure(cmd, cwd, depth=0, out=None, unknown=None):
    """Return {file: [(line_text, why)]} that the command will execute, plus unknown reasons."""
    out = {} if out is None else out; unknown = [] if unknown is None else unknown
    if depth > 6: unknown.append("depth limit"); return out, unknown
    add = lambda f, txt, why: out.setdefault(f, []).append((txt, why))
    for c in split_cmds(cmd):
        if "$(" in c or "`" in c or re.search(r"\beval\b", c): unknown.append(f"dynamic: {c[:60]}")
        try: t = shlex.split(c)
        except ValueError: unknown.append(f"unparsed: {c[:60]}"); continue
        while t and re.match(r"^\w+=", t[0]): t = t[1:]
        if not t: continue
        prog = os.path.basename(t[0]); args = t[1:]
        if prog in ("npm", "pnpm", "yarn"):
            sub = [a for a in args if not a.startswith("-")]
            if not sub: continue
            name = sub[1] if sub[0] in ("run", "run-script") and len(sub) > 1 else sub[0]
            if sub[0] in ("install", "i", "ci", "ls", "view"): unknown.append(f"{prog} {sub[0]}: dependency lifecycle scripts not resolved"); continue
            pj = os.path.join(cwd, "package.json"); data = read(pj)
            try: scripts = json.loads(data or "{}").get("scripts", {})
            except json.JSONDecodeError: unknown.append("package.json unparsable"); continue
            for key in ("pre" + name, name, "post" + name):
                if key in scripts:
                    add(pj, f'"{key}": {json.dumps(scripts[key])}', f"{prog} script '{key}'")
                    # the whole JSON line as written, so line-hash lineage matches
                    for ln in (data or "").splitlines():
                        if f'"{key}"' in ln: add(pj, ln, f"{prog} script '{key}'")
                    closure(scripts[key], cwd, depth + 1, out, unknown)
        elif prog == "make":
            mk = next((os.path.join(cwd, n) for n in ("GNUmakefile", "makefile", "Makefile") if os.path.exists(os.path.join(cwd, n))), None)
            if not mk: continue
            text = read(mk) or ""; rules = {}; cur = None; order = []
            for ln in text.splitlines():
                m = re.match(r"^([A-Za-z0-9_.\-/]+)\s*:(?!=)(.*)$", ln)
                if m: cur = m.group(1); rules[cur] = {"deps": m.group(2).split(), "recipe": []}; order.append(cur)
                elif ln.startswith("\t") and cur: rules[cur]["recipe"].append(ln)
            targets = [a for a in args if not a.startswith("-") and "=" not in a] or order[:1]
            seen = set()
            def walk(tg):
                if tg in seen or tg not in rules: return
                seen.add(tg)
                for d in rules[tg]["deps"]: walk(d)
                for r in rules[tg]["recipe"]:
                    add(mk, r, f"make target '{tg}'"); closure(r.strip().lstrip("@-"), cwd, depth + 1, out, unknown)
            for tg in targets: walk(tg)
        elif prog in ("pytest", "py.test") or (prog.startswith("python") and args[:2] == ["-m", "pytest"]):
            for root, dirs, files in os.walk(cwd):
                dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "venv")]
                for f in files:
                    if f == "conftest.py" or re.match(r"test_.*\.py$|.*_test\.py$", f):
                        p = os.path.join(root, f)
                        for ln in (read(p) or "").splitlines(): add(p, ln, "pytest collection" + (" (conftest)" if f == "conftest.py" else ""))
        elif prog == "git" and args:
            sub = next((a for a in args if not a.startswith("-")), "")
            hp = os.path.join(cwd, ".git", "hooks")
            cfg = read(os.path.join(cwd, ".git", "config")) or ""
            m = re.search(r"hooksPath\s*=\s*(\S+)", cfg)
            if m: hp = os.path.join(cwd, m.group(1)); unknown.append(f"core.hooksPath -> {m.group(1)}")
            for hk in GIT_HOOKS.get(sub, []):
                p = os.path.join(hp, hk)
                if os.path.exists(p) and os.access(p, os.X_OK):
                    for ln in (read(p) or "").splitlines(): add(p, ln, f"git hook '{hk}'")
        elif prog in ("sh", "bash", "zsh", "python", "python3", "node", "ruby", "perl", "source", "."):
            f = next((a for a in args if not a.startswith("-")), None)
            if f and "-c" not in args and "-e" not in args:
                p = os.path.normpath(os.path.join(cwd, f))
                for ln in (read(p) or "").splitlines(): add(p, ln, f"{prog} {f}")
                if prog in ("sh", "bash", "zsh"):
                    for ln in (read(p) or "").splitlines():
                        if ln.strip() and not ln.startswith("#"): closure(ln, cwd, depth + 1, out, unknown)
        elif t[0].startswith("./") or t[0].startswith("/"):
            p = os.path.normpath(os.path.join(cwd, t[0]))
            for ln in (read(p) or "").splitlines(): add(p, ln, f"direct {t[0]}")
    return out, unknown

# ------------------------------------------------------------ decisions
def respond(decision, reason, event="PreToolUse"):
    if decision == "allow" and not reason: return
    print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "permissionDecision": decision,
                                             "permissionDecisionReason": reason}}))

def pre_bash(w, ev):
    cwd = ev["cwd"]; cmd = ev["tool_input"].get("command", "")
    w["snap"] = snapshot(cwd)  # for attributing shell-made changes in PostToolUse
    cl, unknown = closure(cmd, cwd)
    hits = []
    for f, lines in cl.items():
        for txt, why in lines:
            a = w["authored"].get(h(txt))
            if a and norm(txt): hits.append((f, txt, why, a))
    if not hits:
        if unknown and NET.search(cmd): return "ask", "Opaque execution path with network use: " + "; ".join(unknown)
        return "allow", ""
    seen = set(); uniq = []
    for x in hits:
        k = (x[0], norm(x[1]))
        if k not in seen: seen.add(k); uniq.append(x)
    risky = [x for x in uniq if NET.search(x[1]) or SECRET.search(x[1])]
    tainted = [x for x in uniq if x[3]["after_untrusted"]]
    other_session = [x for x in uniq if x[3]["session"] != ev.get("session_id")]
    ev_lines = []
    for f, txt, why, a in uniq[:6]:
        src = f" after reading {a['after_untrusted']}" if a["after_untrusted"] else ""
        sess = " (earlier session)" if a["session"] != ev.get("session_id") else ""
        ev_lines.append(f"- {os.path.relpath(f, cwd)} via {why}: `{norm(txt)[:140]}` — agent-written at step {a['step']}{sess}{src} [{a['how']}]")
    head = f"`{cmd}` will execute {len(uniq)} agent-authored line(s)"
    flags = []
    if risky: flags.append("network/credential effect")
    if tainted: flags.append("written after untrusted input")
    if other_session: flags.append("authored in another session")
    msg = head + (" — " + ", ".join(flags) if flags else "") + ":\n" + "\n".join(ev_lines)
    if risky and tainted: return "deny", msg
    if risky or tainted or other_session: return "ask", msg
    return "allow", msg  # annotate only: agent-authored code with no risk signal (e.g. a new unit test)

def pre_write(w, ev):
    p = ev["tool_input"].get("file_path", "")
    for rx, what in SURFACES:
        if rx.search(p):
            taint = [u["source"] for u in w["untrusted"] if u["session"] == ev.get("session_id")]
            body = ev["tool_input"].get("content") or ev["tool_input"].get("new_string") or ""
            risk = " — content has network/credential use" if (NET.search(body) or SECRET.search(body)) else ""
            src = f"; session read untrusted input from {taint[-1]}" if taint else ""
            dec = "deny" if (risk and taint) else "ask"
            return dec, f"Write to execution surface: {os.path.relpath(p, ev['cwd'])} ({what}){risk}{src}"
    return "allow", ""

def post(w, ev):
    tool = ev["tool_name"]; ti = ev.get("tool_input", {}); sess = ev.get("session_id")
    if tool in ("WebFetch", "WebSearch") or tool.startswith("mcp__"):
        w["untrusted"].append({"source": ti.get("url") or ti.get("query") or tool, "session": sess, "step": w["step"]})
    elif tool == "Write":
        record_lines(w, ti["file_path"], ti.get("content", "").splitlines(), sess, "Write")
    elif tool == "Edit":
        old = set(norm(x) for x in ti.get("old_string", "").splitlines())
        record_lines(w, ti["file_path"], [l for l in ti.get("new_string", "").splitlines() if norm(l) not in old], sess, "Edit")
    elif tool == "MultiEdit":
        for e in ti.get("edits", []):
            old = set(norm(x) for x in e.get("old_string", "").splitlines())
            record_lines(w, ti["file_path"], [l for l in e.get("new_string", "").splitlines() if norm(l) not in old], sess, "MultiEdit")
    elif tool == "Bash":
        before = w.get("snap", {}); after = snapshot(ev["cwd"])
        for p, c in after.items():
            if before.get(p) != c:
                old = set(norm(x) for x in (before.get(p) or "").splitlines())
                record_lines(w, p, [l for l in c.splitlines() if norm(l) not in old], sess, "shell")
        w["snap"] = {}
    w["step"] += 1

def main():
    ev = json.load(sys.stdin); s = load(); w = ws(s, ev["cwd"])
    name = ev.get("hook_event_name"); tool = ev.get("tool_name")
    if name == "PreToolUse":
        if tool == "Bash": d, r = pre_bash(w, ev)
        elif tool in ("Write", "Edit", "MultiEdit"): d, r = pre_write(w, ev)
        else: d, r = "allow", ""
        save(s); respond(d, r)
    elif name == "PostToolUse":
        post(w, ev); save(s)

if __name__ == "__main__":
    main()
