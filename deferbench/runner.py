"""Benchmark orchestration: baseline-first validity, repeats, payload styles, ask-resolution views, NOT_RUN handling."""
from __future__ import annotations
import json
import platform
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from . import RESULT_SCHEMA, __version__
from .defenses import registry
from .harness import RESOLUTIONS, RunConfig, run_scenario, validity
from .metrics import aggregate, classify
from .sink import LoopbackSink


def _ver(argv):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=15)
        return (r.stdout or r.stderr).strip().splitlines()[0][:100]
    except Exception as e:
        return f"unavailable ({type(e).__name__})"


def environment_metadata() -> dict:
    try: import pytest; pv = pytest.__version__
    except ImportError: pv = "unavailable"
    return {"deferbench": __version__, "python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(),
            "git": _ver(["git", "--version"]), "node": _ver(["node", "--version"]), "npm": _ver(["npm", "--version"]),
            "make": _ver(["make", "--version"]), "curl": _ver(["curl", "--version"]), "pytest": pv,
            "os_sensors": "none: replay harness uses tool-event hooks only; no eBPF/seccomp/endpoint sensors are active for any defence",
            "network": "loopback sink only (127.0.0.1)"}


def run_benchmark(scenarios: list[dict], defence_ids: list[str] | None = None, styles=("plain",), repeats: int = 1,
                  resolutions=("oracle",), dry_run: bool = False, out_dir: Path | None = None, set_name: str = "development",
                  seed: int | None = None, progress=True, defence_overrides: dict | None = None) -> dict:
    reg = registry()
    if defence_overrides: reg.update(defence_overrides)
    ids = defence_ids or list(reg)
    if "none" not in ids: ids = ["none"] + ids
    unknown = [i for i in ids if i not in reg]
    if unknown: raise ValueError(f"unknown defence(s): {unknown}; known: {sorted(reg)}")
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + uuid.uuid4().hex[:6]
    avail, not_run, metas = [], [], []
    for i in ids:
        d = reg[i]; ok, why = d.availability(); m = d.metadata(); metas.append(m)
        if ok: avail.append(d)
        else: not_run.append({"defence_id": i, "status": "NOT_RUN", "reason": why, "scenarios_not_run": len(scenarios) * len(styles)})
    sink = LoopbackSink()
    records = []
    t0 = time.time()
    try:
        for style in styles:
            for sc in scenarios:
                for rep in range(repeats):
                    cfg = RunConfig(payload_style=style, ask_resolution="oracle", dry_run=dry_run, seed=seed)
                    base = run_scenario(reg["none"], sc, sink, cfg, run_id, rep)
                    ok, why = validity(sc, base)
                    base["baseline_valid"], base["baseline_reason"] = ok, why
                    records.append(base)
                    if progress: print(f"  {style:9} {sc['id']:4} B0   {base.get('status')} leaked={base.get('canary_leaked')} exit={base.get('exit_code')} valid={ok}", file=sys.stderr)
                    for d in avail:
                        if d.id == "none": continue
                        first = None
                        for res in resolutions:
                            if first is not None and not _has_ask(first):      # identical outcome under any ask resolution
                                r = json.loads(json.dumps(first)); r["ask_resolution"] = res; r["reused_from_resolution"] = first["ask_resolution"]
                            else:
                                r = run_scenario(d, sc, sink, RunConfig(style, res, dry_run, seed=seed), run_id, rep)
                                r["baseline_valid"], r["baseline_reason"] = ok, why
                                if first is None: first = r
                            records.append(r)
                        if progress:
                            r = records[-1]; print(f"  {style:9} {sc['id']:4} {d.id:20} {r.get('overall_decision', r.get('status')):6} leaked={r.get('canary_leaked')}", file=sys.stderr)
    finally:
        sink.close()
    # B0 present under every resolution (it never asks) so aggregation per resolution has a baseline row
    extra = []
    for r in records:
        if r["defence_id"] == "none":
            for res in resolutions:
                if res != "oracle":
                    c = json.loads(json.dumps(r)); c["ask_resolution"] = res; c["reused_from_resolution"] = "oracle"; extra.append(c)
    records += extra
    for r in records: r["outcome"] = classify(r)
    agg = aggregate(records, scenarios)
    doc = {"schema_version": RESULT_SCHEMA, "run_id": run_id, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)),
           "set": set_name, "duration_s": round(time.time() - t0, 1),
           "config": {"styles": list(styles), "repeats": repeats, "resolutions": list(resolutions), "dry_run": dry_run, "seed": seed,
                      "ask_resolution_note": "oracle = informed reviewer (rejects asks on malicious scenarios, approves on benign); approve-all = naive click-through; reject-all = never approve"},
           "environment": environment_metadata(), "defences": metas, "not_run": not_run,
           "scenarios": [{k: s.get(k) for k in ("id", "category", "malicious", "core", "execution", "subtype", "name", "threat", "coverage", "authorship")} | {"expected": s.get("expected"), "evidence": s.get("evidence"), "limitations": s.get("limitations"), "source": s.get("source")} for s in scenarios],
           "results": records, "aggregate": agg}
    if out_dir:
        from .reporting import write_all
        write_all(doc, Path(out_dir) / run_id)
    return doc


def _has_ask(r: dict) -> bool:
    return r.get("status") == "ok" and any(s.get("decision") == "ask" for s in r.get("steps", [])) or r.get("final_decision") == "ask"
