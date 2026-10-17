"""DeferBench command-line interface."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from . import __version__
from .config import PROJECT_ROOT, results_dir, scenarios_dir
from .defenses import registry
from .harness import RESOLUTIONS
from .payloads import STYLES
from .scenarios import check_all, load_all


def _load(args, include_holdout=False):
    base = Path(args.scenarios) if getattr(args, "scenarios", None) else None
    cats = args.category.split(",") if getattr(args, "category", None) else None
    ids = args.scenario.split(",") if getattr(args, "scenario", None) else None
    return load_all(base, cats, ids, include_holdout=include_holdout)


def cmd_validate(args) -> int:
    scs = load_all(Path(args.scenarios) if args.scenarios else None, include_holdout=True)
    errs = check_all(scs)
    from .scenarios import Expanded
    for d in scs:
        if d["id"] in errs: continue
        for st in STYLES:
            try: Expanded(d, 12345, st)
            except Exception as e: errs.setdefault(d["id"], []).append(f"expansion[{st}]: {e}")
    counts = {}
    dev = [d for d in scs if not d.get("_holdout")]
    for d in dev: counts[d["category"]] = counts.get(d["category"], 0) + 1
    print(f"development scenarios: {len(dev)}  {counts}   holdout definitions: {len(scs) - len(dev)}")
    v0 = Path(PROJECT_ROOT / "archive/v0/harness.py")
    if v0.exists():
        import re
        v0ids = set(re.findall(r'id="([A-Z]\d)"', v0.read_text()))
        have = {d.get("v0_id", d["id"]) for d in scs}
        miss = v0ids - have
        print(f"v0 scenario IDs preserved: {len(v0ids - miss)}/{len(v0ids)}" + (f"  MISSING {sorted(miss)}" if miss else ""))
        if miss: errs["v0-compat"] = [f"missing v0 ids {sorted(miss)}"]
    for k, v in errs.items():
        for m in v: print(f"  ERROR {k}: {m}", file=sys.stderr)
    print("validation:", "FAILED" if errs else "OK")
    return 1 if errs else 0


def cmd_list(args) -> int:
    scs = _load(args, include_holdout=args.include_holdout)
    if args.json: print(json.dumps([{k: d.get(k) for k in ("id", "category", "malicious", "core", "execution", "subtype", "name", "coverage")} for d in scs], indent=1)); return 0
    for d in scs:
        print(f"{d['id']:5} {d['category']:7} {'mal' if d['malicious'] else 'ben'} {'core' if d.get('core') else '    '} {d.get('execution','real')[:5]:5} {d['name']}")
    print(f"{len(scs)} scenarios")
    return 0


def _run(args, set_name="development", scs=None) -> int:
    from .runner import run_benchmark
    scs = scs if scs is not None else _load(args)
    if not scs: print("no scenarios selected", file=sys.stderr); return 2
    reg = registry()
    ids = args.defense.split(",") if getattr(args, "defense", None) else None
    if ids:
        bad = [i for i in ids if i not in reg]
        if bad: print(f"unknown defence {bad}; choose from {sorted(reg)}", file=sys.stderr); return 2
    styles = tuple(args.payload_style.split(","))
    if any(s not in STYLES for s in styles): print(f"payload style must be in {STYLES}", file=sys.stderr); return 2
    res = tuple(args.ask_resolution.split(","))
    if any(r not in RESOLUTIONS for r in res): print(f"ask resolution must be in {RESOLUTIONS}", file=sys.stderr); return 2
    out = Path(args.out) if args.out else results_dir() / "runs"
    doc = run_benchmark(scs, ids, styles, args.repeat, res, args.dry_run, out, set_name, args.seed, progress=not args.quiet)
    d = out / doc["run_id"]
    from .reporting import render_markdown
    if args.print_report or getattr(args, "cmd", "") == "run": print(render_markdown(doc))
    print(f"results: {d}/results.json  report: {d}/report.md  csv: {d}/results.csv  chart: {d}/comparison.svg")
    bad = [r for r in doc["results"] if r["status"] != "ok"]
    inv = {(r["scenario_id"], r["payload_style"]) for r in doc["results"] if r.get("baseline_valid") is False}
    if bad: print(f"{len(bad)} run(s) errored", file=sys.stderr); return 1
    if inv: print(f"note: {len(inv)} scenario/style combination(s) INVALID (baseline did not reproduce); excluded from rates", file=sys.stderr); return 3
    return 0


def cmd_run(args) -> int:
    if not args.defense: args.defense = "handoff"
    return _run(args)


def cmd_benchmark(args) -> int:
    return _run(args)


def cmd_report(args) -> int:
    from .reporting import render_markdown, write_all
    p = Path(args.input) if args.input else None
    if p is None:
        from .extras import _latest
        p = _latest("runs")
        if p is None: print("no results found; run `benchmark` first or pass --input", file=sys.stderr); return 2
    if not p.exists(): print(f"not found: {p}", file=sys.stderr); return 2
    doc = json.load(open(p))
    if args.recompute:      # re-derive outcome classes and aggregates from the raw per-run records (records themselves are not modified)
        from .metrics import aggregate, classify
        for r in doc["results"]: r["outcome"] = classify(r)
        doc["aggregate"] = aggregate(doc["results"], doc.get("scenarios"))
    out = Path(args.out) if args.out else p.parent
    paths = write_all(doc, out)
    print(render_markdown(doc) if args.print else "\n".join(f"{k}: {v}" for k, v in paths.items()))
    return 0


def cmd_integrations(args) -> int:
    for k, d in registry().items():
        m = d.metadata()
        print(f"{k:22} {m['kind']:9} {'AVAILABLE' if m['available'] else 'NOT_RUN  '} strength={m['policy_strength']:13} {m['unavailable_reason']}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="deferbench", description="Benchmark + reference defence for delayed execution of agent-authored code.")
    ap.add_argument("--version", action="version", version=f"deferbench {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate", help="validate scenario files, safety checks, v0 compatibility").add_argument("--scenarios")
    p = sub.add_parser("list-scenarios"); p.add_argument("--category"); p.add_argument("--json", action="store_true"); p.add_argument("--include-holdout", action="store_true"); p.add_argument("--scenarios")
    def common(p, default_def=None):
        p.add_argument("--defense", "--defence", default=default_def, help="comma-separated defence ids (default: all available)")
        p.add_argument("--scenario", help="comma-separated scenario ids"); p.add_argument("--category", help="attack,benign,edge")
        p.add_argument("--scenarios", help="scenario directory"); p.add_argument("--payload-style", default="plain", help="plain,signature")
        p.add_argument("--repeat", type=int, default=1); p.add_argument("--ask-resolution", default="oracle", help=",".join(RESOLUTIONS))
        p.add_argument("--dry-run", action="store_true", help="replay and decide, but never execute the final command")
        p.add_argument("--out", help="output directory (default results/runs)"); p.add_argument("--seed", type=int); p.add_argument("--quiet", action="store_true")
        p.add_argument("--print-report", action="store_true")
    common(sub.add_parser("run", help="run scenarios against one or more defences (default: handoff)"))
    common(sub.add_parser("benchmark", help="run all available defences"))
    p = sub.add_parser("report"); p.add_argument("--input"); p.add_argument("--out"); p.add_argument("--print", action="store_true"); p.add_argument("--recompute", action="store_true", help="recompute aggregates from raw records")
    sub.add_parser("integrations", help="show availability of defences/adapters")
    from .extras import register
    register(sub)
    args = ap.parse_args(argv)
    fn = {"validate": cmd_validate, "list-scenarios": cmd_list, "run": cmd_run, "benchmark": cmd_benchmark, "report": cmd_report, "integrations": cmd_integrations}.get(args.cmd)
    if fn is None:
        from .extras import dispatch
        return dispatch(args)
    try: return fn(args)
    except KeyboardInterrupt: print("interrupted", file=sys.stderr); return 130
    except (ValueError, FileNotFoundError) as e: print(f"error: {e}", file=sys.stderr); return 2


if __name__ == "__main__":
    sys.exit(main())
