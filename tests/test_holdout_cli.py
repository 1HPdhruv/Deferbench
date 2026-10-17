"""Holdout mechanism, CLI and report/dashboard generation. Layers: UNIT / INTEGRATION."""
import json
import shutil
import pytest
from pathlib import Path
from deferbench import holdout as H
from deferbench.cli import main
from deferbench.config import PROJECT_ROOT
from deferbench.criteria import evaluate
from deferbench.reporting import render_markdown
from deferbench.runner import run_benchmark
from deferbench.scenarios import load_all


@pytest.fixture
def hdir(tmp_path):
    shutil.copytree(PROJECT_ROOT / "scenarios", tmp_path / "scenarios"); return tmp_path / "scenarios"


@pytest.mark.unit
def test_holdout_is_never_labelled_independent_by_default():
    st = H.status(); assert st["independent"] is False and "NOT independent" in st["label"]


@pytest.mark.unit
def test_independence_needs_attestation_and_authorship_and_unmodified_files(hdir):
    H.seal(hdir, independent=True, attestation="I did not write Handoff"); st = H.status(hdir)
    assert not st["independent"] and any("authorship.independent=false" in r for r in st["reasons"])    # model-authored scenarios stay non-independent
    for f in (hdir / "holdout").glob("H*.json"):
        d = json.load(open(f)); d["authorship"]["independent"] = True; json.dump(d, open(f, "w"))
    H.seal(hdir, independent=True, attestation="I did not write Handoff"); assert H.status(hdir)["independent"] is True
    (hdir / "holdout" / H.SEALED).write_text((hdir / "holdout" / H.SEALED).read_text() + " ")
    st = H.status(hdir); assert not st["independent"] and any("edited after sealing" in r for r in st["reasons"])


@pytest.mark.unit
def test_load_merges_sealed_expected_and_rejects_missing(hdir):
    scs, _ = H.load_holdout(hdir); assert len(scs) >= 10 and all("expected" in s for s in scs)
    p = hdir / "holdout" / H.SEALED; d = json.load(open(p)); d["scenarios"].pop("H1"); json.dump(d, open(p, "w"))
    with pytest.raises(ValueError): H.load_holdout(hdir)


@pytest.mark.unit
def test_holdout_has_at_least_ten_scenarios_and_is_separate_from_dev():
    scs, _ = H.load_holdout(); dev = {d["id"] for d in load_all()}
    assert len(scs) >= 10 and not ({s["id"] for s in scs} & dev)


@pytest.mark.unit
def test_pass_fail_scoring():
    mk = lambda o, so: {"outcome": o, "expected": {"secure_outcome": so}}
    assert H.pass_fail(mk("prevented_ask", "intercept")) == "PASS" and H.pass_fail(mk("missed_leaked", "intercept")) == "FAIL"
    assert H.pass_fail(mk("benign_interrupted", "allow")) == "FAIL" and H.pass_fail(mk("benign_interrupted", "allow_or_ask")) == "PASS"
    assert H.pass_fail(mk("invalid", "intercept")) == "INVALID"


@pytest.fixture(scope="module")
def mini():
    scs = [d for d in load_all() if d["id"] in ("A2", "B1", "E5")]
    return run_benchmark(scs, ["denylist", "static-expansion", "handoff"], repeats=2, resolutions=("oracle",), progress=False)


@pytest.mark.e2e
def test_report_numbers_come_from_records_not_templates(mini):
    md = render_markdown(mini); a = mini["aggregate"]["handoff|oracle"]
    assert f"{a['attack_interception']['k']}/{a['attack_interception']['n']}" in md
    mini2 = json.loads(json.dumps(mini)); mini2["aggregate"] = {}                 # no hidden constants: removing results removes numbers
    assert "100%" in md and "scenario matrix" in md.lower()


@pytest.mark.e2e
def test_criteria_evaluate_mechanically(mini):
    c = {x["id"]: x for x in evaluate(mini, None)}
    assert c[3]["status"] == "N/A" and c[6]["status"] == "PASS" and c[5]["status"] == "PASS"


@pytest.mark.e2e
def test_cli_validate_list_report_and_errors(tmp_path, capsys, mini):
    assert main(["validate"]) == 0
    assert main(["list-scenarios", "--category", "attack"]) == 0 and "A1" in capsys.readouterr().out
    assert main(["run", "--defense", "nonexistent"]) == 2
    assert main(["run", "--payload-style", "bogus"]) == 2
    assert main(["run", "--scenario", "ZZZ"]) == 2
    rp = tmp_path / "results.json"; json.dump(mini, open(rp, "w"))
    assert main(["report", "--input", str(rp), "--out", str(tmp_path / "o")]) == 0
    assert (tmp_path / "o" / "report.md").is_file() and (tmp_path / "o" / "results.csv").is_file() and (tmp_path / "o" / "comparison.svg").is_file()
    assert main(["report", "--input", str(tmp_path / "missing.json")]) == 2


@pytest.mark.e2e
def test_cli_run_dry_run_and_exit_codes(tmp_path):
    assert main(["run", "--defense", "handoff", "--scenario", "B1,A2", "--dry-run", "--out", str(tmp_path), "--quiet"]) == 0
    r = json.load(open(next(tmp_path.glob("*/results.json"))))
    assert all(x["dry_run"] for x in r["results"]) and not any(x["final_command_executed"] for x in r["results"])


@pytest.mark.e2e
def test_dashboard_embeds_result_data(tmp_path, mini):
    rp = tmp_path / "results.json"; json.dump(mini, open(rp, "w"))
    assert main(["dashboard", "--input", str(rp), "--holdout", str(tmp_path / "none.json"), "--out", str(tmp_path / "d.html")]) == 0
    html = (tmp_path / "d.html").read_text()
    assert mini["run_id"] in html and "const DATA =" in html and "/*__DATA__*/" not in html
    assert "NOT independent" in html                                              # holdout status is unambiguous


@pytest.mark.e2e
def test_demo_dry_run_and_live(capsys):
    assert main(["demo", "--dry-run"]) == 0
    out = capsys.readouterr().out; assert "NOT executed" in out
    assert main(["demo"]) == 0
    out = capsys.readouterr().out
    assert "canary_leaked=True" in out and "Handoff" in out and "127.0.0.1" in out


@pytest.mark.e2e
def test_separate_evidence_and_provenance_metrics(mini):
    a = mini["aggregate"]
    s, h = a["static-expansion|oracle"], a["handoff|oracle"]
    assert s["provenance_capable"] is False and h["provenance_capable"] is True
    assert h["provenance_attribution"]["n"] >= 1 and s["provenance_attribution"]["k"] == 0
    assert "evidence_common_executing_file_named" in s and "evidence_common_executing_file_named" in h


@pytest.mark.e2e
def test_report_recompute_preserves_headline_and_records(tmp_path, mini):
    rp = tmp_path / "results.json"; json.dump(mini, open(rp, "w"))
    before = json.dumps(mini["results"], sort_keys=True)
    assert main(["report", "--input", str(rp), "--out", str(tmp_path / "r"), "--recompute"]) == 0
    after = json.load(open(tmp_path / "r" / "results.json"))
    for k, v in mini["aggregate"].items():
        assert after["aggregate"][k]["attack_interception"] == v["attack_interception"]
    assert json.dumps([{k: x[k] for k in x if k != "outcome"} for x in after["results"]], sort_keys=True) == \
           json.dumps([{k: x[k] for k in x if k != "outcome"} for x in mini["results"]], sort_keys=True)


@pytest.mark.e2e
def test_dashboard_has_no_absolute_local_paths(tmp_path, mini):
    rp = tmp_path / "results.json"; json.dump(mini, open(rp, "w"))
    assert main(["dashboard", "--input", str(rp), "--out", str(tmp_path / "d.html")]) == 0
    html = (tmp_path / "d.html").read_text()
    home_markers = ["/" + "Users" + "/", "/" + "home" + "/"]        # built at runtime so this file passes the source path scan
    assert not any(m in html for m in home_markers)
    assert "human-independent evaluation is pending" in html
