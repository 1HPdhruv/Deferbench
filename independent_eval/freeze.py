#!/usr/bin/env python3
"""Write FREEZE.json: hash of the implementation under test + environment + (optionally) the independent scenario set.
Run by the IMPLEMENTATION author BEFORE receiving the independent set; re-run by the custodian to verify nothing changed."""
import hashlib, json, os, platform, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
IMPL = ["deferbench", "scripts/fetch_integrations.sh", "pyproject.toml", "scenarios/attacks", "scenarios/benign", "scenarios/edge"]

def tree_hash(paths):
    h = hashlib.sha256(); files = []
    for p in paths:
        base = ROOT / p
        files += [base] if base.is_file() else sorted(f for f in base.rglob("*") if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc")
    for f in files: h.update(str(f.relative_to(ROOT)).encode()); h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest(), len(files)

def ver(argv):
    try: return subprocess.run(argv, capture_output=True, text=True, timeout=15).stdout.strip().splitlines()[0]
    except Exception: return "unavailable"

def main():
    impl, n = tree_hash(IMPL)
    sd = ROOT / "independent_eval" / "holdout"
    sset = tree_hash(["independent_eval/holdout"]) if any(sd.glob("*.json")) else (None, 0)
    ex = ROOT / "independent_eval" / "holdout" / "EXPECTED.json.sealed"
    out = {"schema_version": "deferbench.freeze/1", "frozen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "implementation_sha256": impl, "implementation_files": n, "vcs": "none (not a git repository; source-tree hash used)",
           "scenario_set_sha256": sset[0], "scenario_files": sset[1],
           "expected_sha256": hashlib.sha256(ex.read_bytes()).hexdigest() if ex.is_file() else None,
           "python": sys.version.split()[0], "platform": platform.platform(), "node": ver(["node", "--version"]), "npm": ver(["npm", "--version"]),
           "git": ver(["git", "--version"]), "make": ver(["make", "--version"]),
           "deferbench": json.loads(subprocess.run([sys.executable, "-c", "import deferbench,json;print(json.dumps(deferbench.__version__))"], capture_output=True, text=True, cwd=ROOT).stdout),
           "integrations": {k: (ROOT / ".integrations" / k / "VERSION").read_text().strip() if (ROOT / ".integrations" / k / "VERSION").exists() else "see results.json defences[].version" for k in ("gensee", "gryph", "runmark")}}
    (ROOT / "independent_eval" / "FREEZE.json").write_text(json.dumps(out, indent=1)); print(json.dumps(out, indent=1))

if __name__ == "__main__": main()
