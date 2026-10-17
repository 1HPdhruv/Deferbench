"""Scenario loading, schema validation, and safe placeholder expansion. Scenario files are data, never code."""
from __future__ import annotations
import json
import os
import shlex
from copy import deepcopy
from pathlib import Path
from . import SCENARIO_SCHEMA
from .config import scenarios_dir
from .payloads import PLACEHOLDERS, expand, find_unknown_placeholders, placeholder_values
from .repo import validate_sim
from .safety import SafetyError, assert_loopback_urls, safe_rel_path

CATEGORIES = ("attack", "benign", "edge")
KINDS = ("fetch_untrusted", "write_file", "edit_file", "shell_sim", "approve")
SECURE = ("intercept", "allow", "allow_or_ask")
EVIDENCE_ITEMS = ("file", "line", "execution_path", "authorship", "untrusted_source", "signal", "content_hash", "unresolved")
FINAL_PROGRAMS = {"npm", "make", "pytest", "sh", "bash", "git", "node", "python3", "python"}
BAD_CHARS = set(";|&<>`\n$")
SUBDIRS = ("attacks", "benign", "edge")


def validate_final_command(cmd: str) -> list[str]:
    errs = []
    try: t = shlex.split(cmd)
    except ValueError as e: return [f"final.command unparsable: {e}"]
    if not t or t[0] not in FINAL_PROGRAMS: return [f"final.command program not allowed: {t[:1]} (allowed: {sorted(FINAL_PROGRAMS)})"]
    if t[0] in ("sh", "bash") and "-c" in t:
        i = t.index("-c")
        if not (len(t) == i + 2 and (t[i + 1].startswith("source ") or t[i + 1].startswith(". ")) and len(t[i + 1].split()) == 2):
            errs.append("final.command: sh/bash -c is only allowed as -c 'source FILE'")
        else: safe_rel_path(t[i + 1].split()[1])
        return errs
    for tok in t:
        if any(c in BAD_CHARS for c in tok): errs.append(f"final.command token has shell metacharacter: {tok!r}")
    if t[0] in ("sh", "bash", "node", "python3", "python"):
        files = [a for a in t[1:] if not a.startswith("-")]
        if not files: errs.append("final.command must name a script file")
        else:
            try: safe_rel_path(files[0])
            except SafetyError as e: errs.append(str(e))
    return errs


def validate_scenario(d: dict, require_expected: bool = True) -> list[str]:
    e = []
    g = lambda *k: _get(d, *k)
    if d.get("schema_version") != SCENARIO_SCHEMA: e.append(f"schema_version must be {SCENARIO_SCHEMA}")
    for k in ("id", "name", "threat", "category", "actions", "final", "setup", "evidence", "source", "limitations", "authorship"):
        if k not in d: e.append(f"missing field: {k}")
    if e: return e
    if d["category"] not in CATEGORIES: e.append(f"category must be one of {CATEGORIES}")
    if not isinstance(d.get("malicious"), bool): e.append("malicious must be bool")
    if not isinstance(d["actions"], list) or not d["actions"]: e.append("actions must be a non-empty list")
    if d.get("execution", "real") not in ("real", "write_surface_only"): e.append("execution must be real|write_surface_only")
    for i, a in enumerate(d["actions"]):
        k = a.get("kind")
        if k not in KINDS: e.append(f"action {i}: unknown kind {k!r}"); continue
        try:
            if k in ("write_file", "edit_file"): safe_rel_path(a["path"]); _check_git_path(a["path"])
            if k == "write_file" and not (("content" in a) ^ ("content_json" in a)): e.append(f"action {i}: write_file needs exactly one of content/content_json")
            if k == "edit_file" and not all(isinstance(a.get(x), str) for x in ("old", "new")): e.append(f"action {i}: edit_file needs old/new")
            if k == "shell_sim": validate_sim(a)
            if k == "approve": e += [f"action {i}: {x}" for x in validate_final_command(a.get("command", ""))]
            if k == "fetch_untrusted" and not all(isinstance(a.get(x), str) for x in ("url", "response")): e.append(f"action {i}: fetch_untrusted needs url/response")
        except (SafetyError, KeyError) as ex:
            e.append(f"action {i}: {ex}")
    f = d["final"]
    e += validate_final_command(f.get("command", ""))
    if f.get("session", "same") not in ("same", "new"): e.append("final.session must be same|new")
    for rel in d["setup"].get("files", {}):
        try: safe_rel_path(rel); _check_git_path(rel)
        except SafetyError as ex: e.append(f"setup.files: {ex}")
    ev = d["evidence"]
    for it in ev.get("required", []):
        if it not in EVIDENCE_ITEMS: e.append(f"evidence.required: unknown item {it!r}")
    if require_expected:
        ex = d.get("expected")
        if not isinstance(ex, dict): e.append("missing expected{}")
        else:
            if ex.get("secure_outcome") not in SECURE: e.append(f"expected.secure_outcome must be one of {SECURE}")
            if d.get("execution", "real") == "real" and not isinstance(ex.get("baseline_leak"), bool): e.append("expected.baseline_leak must be bool for real-execution scenarios")
            if d.get("malicious") and ex.get("secure_outcome") != "intercept": e.append("malicious scenarios must expect secure_outcome=intercept")
    blob = json.dumps(d)
    bad = find_unknown_placeholders(blob)
    if bad: e.append(f"unknown placeholders: {sorted(bad)}")
    return e


def _get(d, *k):
    for x in k: d = d.get(x, {}) if isinstance(d, dict) else {}
    return d


def _check_git_path(rel: str):
    parts = rel.replace("\\", "/").split("/")
    if parts[0] == ".git" and not (len(parts) >= 3 and parts[1] == "hooks"):
        raise SafetyError(f"writes under .git are only allowed in .git/hooks: {rel}")


def load_dir(path: Path, require_expected=True) -> list[dict]:
    out = []
    for f in sorted(path.glob("*.json")):
        if f.name.startswith("TEMPLATE") or f.name in ("MANIFEST.json",) or f.name.endswith(".expected.json"): continue
        d = json.load(open(f)); d["_file"] = str(f); out.append(d)
    return out


def sort_key(sid: str):
    import re
    m = re.match(r"([A-Za-z]+)(\d+)(.*)", sid)
    return (m.group(1), int(m.group(2)), m.group(3)) if m else (sid, 0, "")


def load_all(base: Path | None = None, categories=None, ids=None, include_holdout=False) -> list[dict]:
    base = Path(base) if base else scenarios_dir()
    out = []
    for sub in SUBDIRS + (("holdout",) if include_holdout else ()):
        p = base / sub
        if p.is_dir():
            ds = load_dir(p)
            if sub == "holdout":
                for d in ds: d["_holdout"] = True
            out += ds
    if categories: out = [d for d in out if d["category"] in categories]
    if ids: out = [d for d in out if d["id"] in ids]
    return sorted(out, key=lambda d: sort_key(d["id"]))


class Expanded:
    """A scenario with placeholders expanded for a concrete sink port / payload style. All text checked loopback-only."""
    def __init__(self, d: dict, port: int, style: str):
        self.d = d; self.id = d["id"]
        vals = placeholder_values(port, style)
        d = deepcopy(d)
        self.actions = [self._act(a, vals) for a in d["actions"]]
        self.files = {k: expand(v, vals) for k, v in d["setup"].get("files", {}).items()}
        self.git_config = d["setup"].get("git_config", {})
        self.final = d["final"]["command"]
        self.final_session = d["final"].get("session", "same")
        # safety: every URL in expanded content must be loopback (fetch metadata URLs are reserved .test, never requested)
        for a in self.actions:
            blob = json.dumps({k: v for k, v in a.items() if k != "url"})
            assert_loopback_urls(blob)
            if a.get("kind") == "fetch_untrusted": assert_loopback_urls(a["url"], allow_meta=True)
        for v in self.files.values(): assert_loopback_urls(v)

    @staticmethod
    def _act(a, vals):
        a = dict(a)
        for k, v in list(a.items()):
            if isinstance(v, str) and k != "kind": a[k] = expand(v, vals)
            elif isinstance(v, dict): a[k] = json.loads(expand(json.dumps(v), {kk: json.dumps(vv)[1:-1] for kk, vv in vals.items()}))
        return a


def check_all(scs: list[dict]) -> dict[str, list[str]]:
    errs = {}
    seen = set()
    for d in scs:
        e = validate_scenario(d, require_expected=not d.get("_holdout"))
        if d.get("id") in seen: e.append("duplicate id")
        seen.add(d.get("id"))
        if e: errs[d.get("id", d.get("_file"))] = e
    return errs
