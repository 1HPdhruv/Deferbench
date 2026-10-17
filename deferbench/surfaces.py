"""Write-time classification of deferred-execution surfaces (git hooks, IDE tasks, env activation, ...)."""
from __future__ import annotations
import json
import re
from .signals import signals, norm

# (regex on workspace-relative path, label)
SURFACES = [
    (re.compile(r"^\.git/hooks/(?!.*\.sample$)[^/]+$"), "git hook (runs on git commit/push/checkout)"),
    (re.compile(r"^\.husky/[^/]+$"), "husky git hook"),
    (re.compile(r"^\.pre-commit-config\.yaml$"), "pre-commit framework config (runs tools on commit)"),
    (re.compile(r"^\.git/config$"), "git config (hooksPath/fsmonitor/alias execute code)"),
    (re.compile(r"^\.vscode/tasks\.json$"), "VS Code task (can run on folder open)"),
    (re.compile(r"^\.vscode/settings\.json$"), "VS Code settings (executable-path keys)"),
    (re.compile(r"^\.vscode/launch\.json$"), "VS Code launch configuration"),
    (re.compile(r"^\.claude/settings(\.local)?\.json$"), "agent hook configuration"),
    (re.compile(r"^\.mcp\.json$"), "MCP server configuration (spawns commands)"),
    (re.compile(r"^\.envrc$"), "direnv (runs on cd)"),
    (re.compile(r"^\.?venv/bin/[^/]+$"), "virtualenv interpreter/entry point"),
    (re.compile(r"^\.npmrc$"), "npm config (script-shell/node-options)"),
]
EXEC_KEY = re.compile(r"(executablePath|\.path$|Path$|pythonPath|defaultInterpreterPath|terminal\.integrated\.(shell|profiles|automationProfile)|"
                      r"shellArgs|nodePath|\.command$|\.cmd$|pager|^git\.path$)", re.I)
CLAUDE_KEYS = {"hooks", "apiKeyHelper", "statusLine", "env", "permissions", "mcpServers", "enableAllProjectMcpServers", "awsAuthRefresh"}


def match_surface(rel: str):
    for rx, label in SURFACES:
        if rx.match(rel): return label
    return None


def _jsonc(text: str):
    t = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    t = re.sub(r",(\s*[}\]])", r"\1", t)
    return json.loads(t)


def _leaves(o, prefix=""):
    if isinstance(o, dict):
        for k, v in o.items(): yield from _leaves(v, f"{prefix}{k}.")
    elif isinstance(o, list):
        for i, v in enumerate(o): yield from _leaves(v, f"{prefix}{i}.")
    else:
        yield prefix.rstrip("."), o


def classify_write(rel: str, new: str, old: str | None) -> dict | None:
    """Return None if the write does not touch an execution-relevant part; else a dict describing it."""
    label = match_surface(rel)
    if not label: return None
    old = old or ""
    info = {"surface": rel, "label": label, "auto_exec": False, "changed": [], "content": new}
    base = rel.rsplit("/", 1)[-1]
    if base in ("tasks.json", "settings.json", "launch.json", "settings.local.json", ".mcp.json") and rel.startswith((".vscode/", ".claude/")) or rel == ".mcp.json":
        try:
            n = dict(_leaves(_jsonc(new)))
        except Exception:
            n = None
        try:
            o = dict(_leaves(_jsonc(old))) if old.strip() else {}
        except Exception:
            o = {}
        if n is None:  # unparsable: treat the whole content as changed (conservative)
            info["changed"] = [norm(l) for l in new.splitlines() if norm(l)]
            return info
        diff = {k: v for k, v in n.items() if o.get(k) != v}
        if base == "settings.json" and rel.startswith(".vscode/"):
            diff = {k: v for k, v in diff.items() if EXEC_KEY.search(k)}
        elif base == "tasks.json":
            diff = {k: v for k, v in diff.items() if re.search(r"(command|args|runOn|dependsOn|options|type)", k)}
            info["auto_exec"] = any(k.endswith("runOptions.runOn") and v == "folderOpen" for k, v in n.items()) and bool(diff)
        elif rel.startswith(".claude/"):
            diff = {k: v for k, v in diff.items() if k.split(".")[0] in CLAUDE_KEYS}
        elif rel == ".mcp.json":
            diff = {k: v for k, v in diff.items() if re.search(r"(command|args|url|env)", k)}
        if not diff: return None
        info["changed"] = [f"{k} = {v}" for k, v in diff.items()]
        return info
    if rel == ".npmrc":
        ch = [norm(l) for l in new.splitlines() if norm(l) and norm(l) not in {norm(x) for x in old.splitlines()} and re.search(r"script-shell|node-options|prefix", l)]
        if not ch: return None
        info["changed"] = ch; return info
    if rel == ".git/config":
        ch = [norm(l) for l in new.splitlines() if norm(l) and norm(l) not in {norm(x) for x in old.splitlines()}
              and re.search(r"hooksPath|fsmonitor|sshCommand|pager|editor|^\s*\w+\s*=\s*!|textconv|clean|smudge", l, re.I)]
        if not ch: return None
        info["changed"] = ch; return info
    # line-based surfaces (hooks, envrc, venv/bin, husky, pre-commit-config)
    oldset = {norm(x) for x in old.splitlines()}
    ch = [norm(l) for l in new.splitlines() if norm(l) and norm(l) not in oldset]
    if not ch: return None
    info["changed"] = ch
    return info


def risk_of(info: dict) -> list[str]:
    s = set(signals("\n".join(info["changed"])))
    if info["auto_exec"]: s.add("auto-exec")
    return sorted(s)
