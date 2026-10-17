#!/usr/bin/env python3
"""Custodian runner. Verifies the freeze, checks set size/validity, runs ONE confirmatory evaluation, scores it. No defence code is touched.
Usage: python independent_eval/run_confirmatory.py [--repeat 2]"""
import json, os, subprocess, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent; ROOT = HERE.parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(ROOT))
import freeze

def main():
    fz = json.load(open(HERE / "FREEZE.json"))
    cur, _ = freeze.tree_hash(freeze.IMPL)
    if cur != fz["implementation_sha256"]: sys.exit(f"ABORT: implementation changed since freeze ({cur[:12]} != {fz['implementation_sha256'][:12]}). Confirmatory evaluation requires the frozen version.")
    os.environ["DEFERBENCH_SCENARIOS_DIR"] = str(HERE)
    from deferbench import holdout as H
    try: scs, ep = H.load_holdout(HERE)
    except (FileNotFoundError, ValueError) as e: sys.exit(f"ABORT: no valid independent set in {HERE/'holdout'}: {e}")
    n = {c: sum(s["category"] == c for s in scs) for c in ("attack", "benign", "edge")}
    need = json.load(open(HERE / "rubric.json"))["min_cases"]
    if any(n[k] < v for k, v in need.items()): sys.exit(f"ABORT: set too small {n}, need {need}")
    st = H.status(HERE)
    print("set:", n, "| status:", st["label"], st["reasons"])
    rep = sys.argv[sys.argv.index("--repeat") + 1] if "--repeat" in sys.argv else "2"
    cmd = [sys.executable, "-m", "deferbench", "holdout", "run", "--scenarios", str(HERE), "--expected", str(ep), "--repeat", rep,
           "--defense", "none,denylist,static-expansion,handoff,gensee,gryph,runmark", "--out", str(HERE / "results"), "--quiet"]
    print("RUN:", " ".join(cmd)); subprocess.run(cmd, check=True, cwd=ROOT)
    latest = sorted((HERE / "results").glob("*/results.json"))[-1]
    subprocess.run([sys.executable, str(HERE / "score.py"), str(latest), "--out", str(latest.parent / "independent_report.md")], check=True)
    print("report:", latest.parent / "independent_report.md")

if __name__ == "__main__": main()
