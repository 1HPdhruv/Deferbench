"""Subcommands: holdout, dashboard, demo, clean."""
from __future__ import annotations
import json
import shutil
import sys
import tempfile
from pathlib import Path
from .config import PROJECT_ROOT, results_dir, scenarios_dir

RECORDED_DEMO = PROJECT_ROOT / "examples" / "recorded_demo.json"


def register(sub):
    p = sub.add_parser("holdout", help="holdout evaluation: status | seal | run")
    hs = p.add_subparsers(dest="hcmd", required=True)
    hs.add_parser("status")
    s = hs.add_parser("seal"); s.add_argument("--independent", action="store_true"); s.add_argument("--attestation", default=""); s.add_argument("--authors", default="")
    r = hs.add_parser("run"); r.add_argument("--expected"); r.add_argument("--scenarios"); r.add_argument("--defense"); r.add_argument("--payload-style", default="plain")
    r.add_argument("--ask-resolution", default="oracle"); r.add_argument("--out"); r.add_argument("--repeat", type=int, default=1); r.add_argument("--quiet", action="store_true")
    d = sub.add_parser("dashboard", help="generate a self-contained HTML dashboard from result files")
    d.add_argument("--input"); d.add_argument("--holdout"); d.add_argument("--out", default=None)
    d.add_argument("--confirmatory", help="results.json of the model-authored confirmatory run (independent_eval/results/...)")
    m = sub.add_parser("demo", help="one-command offline demonstration (built-in defences only)")
    m.add_argument("--dry-run", action="store_true", help="decide only; never execute payloads"); m.add_argument("--fallback", action="store_true", help="print the recorded (previously measured) demo output")
    m.add_argument("--attack", default="A1"); m.add_argument("--benign", default="B1")
    c = sub.add_parser("clean", help="remove leftover temp workspaces (and optionally generated results)")
    c.add_argument("--results", action="store_true", help="also delete results/runs and results/holdout")


def _latest(sub: str) -> Path | None:
    """Newest results.json under results/<sub>/*/, else the committed sample under results/final/ (so a fresh checkout still works)."""
    d = results_dir() / sub
    runs = sorted(d.glob("*/results.json")) if d.is_dir() else []
    if runs: return runs[-1]
    fin = results_dir() / "final" / {"runs": "development"}.get(sub, sub) / "results.json"
    return fin if fin.is_file() else None


def dispatch(args) -> int:
    return {"holdout": cmd_holdout, "dashboard": cmd_dashboard, "demo": cmd_demo, "clean": cmd_clean}[args.cmd](args)


def cmd_holdout(args) -> int:
    from . import holdout as H
    if args.hcmd == "status":
        st = H.status(); print(json.dumps(st, indent=1)); return 0
    if args.hcmd == "seal":
        m = H.seal(independent=args.independent, attestation=args.attestation, authors=[a for a in args.authors.split(",") if a] or None)
        print(json.dumps(m, indent=1)); return 0
    from .reporting import write_all
    from .runner import run_benchmark
    scs, ep = H.load_holdout(args.scenarios, args.expected)
    st = H.status(args.scenarios)
    ids = args.defense.split(",") if args.defense else None
    out = Path(args.out) if args.out else results_dir() / "holdout"
    doc = run_benchmark(scs, ids, tuple(args.payload_style.split(",")), args.repeat, tuple(args.ask_resolution.split(",")), False, None,
                        set_name=st["label"], progress=not args.quiet)
    doc["holdout"] = {"status": st, "expected_file": _rel(ep), "expected_sha256": H._sha(ep)}
    d = out / doc["run_id"]; write_all(doc, d)
    json.dump(doc, open(d / "results.json", "w"), indent=1)
    (d / "holdout_score.md").write_text(H.render_score(doc, st))
    print(H.render_score(doc, st)); print(f"saved: {d}")
    return 0


def cmd_dashboard(args) -> int:
    from . import criteria
    p = Path(args.input) if args.input else _latest("runs")
    if not p or not p.is_file(): print("no development results found; run `benchmark` first or pass --input", file=sys.stderr); return 2
    dev = json.load(open(p))
    hp = Path(args.holdout) if args.holdout else _latest("holdout")
    hold = json.load(open(hp)) if hp and hp.is_file() else None
    from . import holdout as H
    dp = _latest("determinism")
    det = json.load(open(dp)) if dp else None
    from .metrics import aggregate, classify
    for doc in (dev, hold):        # derive every displayed number from the raw per-run records
        if doc:
            for r in doc["results"]: r["outcome"] = classify(r)
            doc["aggregate"] = aggregate(doc["results"], doc.get("scenarios"))
    cp = Path(args.confirmatory) if getattr(args, "confirmatory", None) else None
    if cp is None:
        cands = sorted((PROJECT_ROOT / "independent_eval" / "results").glob("*/results.json"))
        cp = cands[0] if cands else None
    conf = json.load(open(cp)) if cp and cp.is_file() else None
    if conf:
        for r in conf["results"]: r["outcome"] = classify(r)
        conf["aggregate"] = aggregate(conf["results"], conf.get("scenarios"))
    crit = criteria.evaluate(dev, hold, determinism=det)
    payload = {"dev": _slim(dev), "holdout": _slim(hold) if hold else None, "confirmatory": _slim(conf) if conf else None, "criteria": crit,
               "holdout_status": H.status(), "sources": {"dev": _rel(p), "holdout": _rel(hp) if hold else None, "determinism": _rel(dp) if dp else None, "confirmatory": _rel(cp) if conf else None}}
    tpl = (Path(__file__).parent / "dashboard_template.html").read_text()
    out = Path(args.out) if args.out else p.parent / "dashboard.html"
    out.write_text(tpl.replace("/*__DATA__*/null", json.dumps(payload).replace("</", "<\\/")))
    print(f"dashboard: {out}"); return 0


def _rel(p) -> str:
    try: return str(Path(p).resolve().relative_to(PROJECT_ROOT))
    except ValueError: return Path(p).name


def _slim(doc):
    if not doc: return None
    d = {k: v for k, v in doc.items() if k != "results"}
    d["defences"] = [dict(m, binary=_rel(m["binary"])) if m.get("binary") else m for m in doc.get("defences", [])]   # display copy only
    if isinstance(d.get("holdout"), dict) and d["holdout"].get("expected_file"):
        d["holdout"] = dict(d["holdout"], expected_file=_rel(d["holdout"]["expected_file"]))
    keep = ("scenario_id", "category", "malicious", "core", "execution", "defence_id", "payload_style", "ask_resolution", "repeat", "status", "baseline_valid",
            "baseline_reason", "outcome", "overall_decision", "decision_stage", "final_decision", "final_resolution", "final_command", "final_command_executed",
            "exit_code", "canary_leaked", "payload_present_at_exec", "steps", "final_verdict", "evidence", "evidence_detail", "hook_latency_ms", "error", "expected", "recheck", "post_alerts")
    d["results"] = [{k: r.get(k) for k in keep} for r in doc["results"]]
    return d


def cmd_clean(args) -> int:
    tmp = Path(tempfile.gettempdir()); n = 0
    for p in tmp.glob("deferbench-*"):
        if p.is_dir() and (p / "ws").is_dir(): shutil.rmtree(p, ignore_errors=True); n += 1
    print(f"removed {n} leftover workspace(s) under {tmp}")
    if args.results:
        for s in ("runs", "holdout"): shutil.rmtree(results_dir() / s, ignore_errors=True)
        print("removed generated results")
    return 0


def cmd_demo(args) -> int:
    if args.fallback:
        if not RECORDED_DEMO.is_file(): print("no recorded demo available", file=sys.stderr); return 2
        r = json.load(open(RECORDED_DEMO))
        print(f"*** RECORDED OUTPUT (previously measured {r['recorded_at']} on {r['platform']}); not a live run ***\n"); print(r["transcript"]); return 0
    import io
    from .harness import RunConfig, run_scenario
    from .defenses import registry
    from .scenarios import check_all, load_all
    from .sink import LoopbackSink
    out = io.StringIO()
    def say(s=""):
        print(s); out.write(s + "\n")
    scs = {d["id"]: d for d in load_all()}
    errs = check_all(list(scs.values()))
    say("== 1. Validate benchmark definitions =="); say(f"   {len(scs)} scenarios, {len(errs)} errors"); 
    if errs: return 1
    reg = registry(); sink = LoopbackSink()
    say(f"   loopback sink listening on {sink.host}:{sink.port} (the only network destination used)")
    cfg = RunConfig(dry_run=args.dry_run)
    def run(did, sid):
        r = run_scenario(reg[did], scs[sid], sink, cfg, "demo")
        if r["status"] != "ok": say(f"   ERROR {did}/{sid}: {r['error']}")
        return r
    def line(r):
        x = "dry-run: final command NOT executed" if r["dry_run"] else f"executed={r['final_command_executed']} exit={r['exit_code']} canary_leaked={r['canary_leaked']}"
        return f"decision={r['overall_decision'].upper():5} stage={r['decision_stage'] or '-'}  {x}"
    try:
        b, a = args.benign, args.attack
        sa = scs[a]
        say(f"\n== 2. The scenario: {a} — {sa['name']} ==")
        say(f"   developer task : routine maintenance in a generated demo repository (synthetic canary in .env)")
        for x in sa["actions"]:
            if x["kind"] == "fetch_untrusted": say(f"   untrusted input: agent reads {x['url']} (simulated web/issue content)")
            elif x["kind"] in ("write_file", "edit_file"): say(f"   agent change   : {x['kind'].replace('_', ' ')} {x['path']}")
            elif x["kind"] == "shell_sim": say(f"   agent change   : shell {x['op']}")
        say(f"   trusted tool   : `{sa['final']['command']}` (looks harmless; runs the content written earlier)")
        rows = {}
        for n, did in ((3, "none"), (4, "static-expansion"), (5, "handoff")):
            label = {"none": "no defence", "static-expansion": "stateless resolver (no provenance)", "handoff": "Handoff (resolver + provenance)"}[did]
            say(f"\n== {n}. {label} =="); r = run(did, a); rows[did] = r; say("   " + line(r))
            if did == "none" and not args.dry_run:
                say(f"   -> undefended effect reproduced: {bool(r['canary_leaked'])} (observed at the loopback sink {sink.host}:{sink.port})")
            if did != "none" and r["final_verdict"]["decision"] != "allow":
                say("   evidence: " + r["final_verdict"]["reason"][:700].replace("\n", "\n             "))
                ev = r["evidence"]; say(f"   evidence score {ev['score']}/3; items {ev['items_present']}")
        say(f"\n== 6. Over-restriction check: benign workflow {b} — {scs[b]['name']} ==")
        brow = {}
        for did in ("none", "static-expansion", "handoff"):
            brow[did] = run(did, b); say(f"   {did:18} " + line(brow[did]))
        say("\n== 7. Observed comparison (this run only) ==")
        say(f"   {'defence':18} {a+' (attack)':30} {b+' (benign)':22}")
        f = lambda r: ("LEAKED" if r["canary_leaked"] else r["overall_decision"].upper()) if not r["dry_run"] else r["overall_decision"].upper() + " (dry)"
        for did in ("none", "static-expansion", "handoff"):
            say(f"   {did:18} {f(rows[did]):30} {f(brow[did]):22}")
    finally: sink.close()
    say("\nAll workspaces were temporary and have been removed. All test data stayed on 127.0.0.1 (loopback only).")
    return 0
