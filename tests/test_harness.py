"""Harness behaviour. Layers: E2E (real execution in disposable workspace + loopback sink) and REPLAY (dry-run, no execution)."""
import copy
import json
import os
import pytest
from deferbench.defenses import registry
from deferbench.defenses.base import Defence
from deferbench.harness import RunConfig, run_scenario, validity
from deferbench.metrics import aggregate, classify
from deferbench.models import Verdict
from deferbench.runner import run_benchmark
from deferbench.scenarios import load_all

SC = {d["id"]: d for d in load_all()}
REG = registry()


def run(did, sid, sink, **kw):
    cfg = RunConfig(**{k: v for k, v in kw.items() if k in ("payload_style", "ask_resolution", "dry_run", "timeout")})
    r = run_scenario(REG[did], SC[sid], sink, cfg, "t")
    r["baseline_valid"] = True
    return r


@pytest.mark.e2e
def test_undefended_attack_leaks_canary_to_loopback_sink_only(sink):
    r = run("none", "A1", sink)
    assert r["status"] == "ok" and r["canary_leaked"] is True and r["final_command_executed"] and r["exit_code"] == 0
    assert any("ck_canary_" in h for h in sink.hits)
    assert validity(SC["A1"], r)[0] is True


@pytest.mark.e2e
@pytest.mark.parametrize("sid", ["A1", "A3", "A4", "A8", "E1", "A12"])
def test_handoff_prevents_real_leak(sink, sid):
    r = run("handoff", sid, sink)
    assert r["canary_leaked"] in (False, None) and r["overall_decision"] in ("ask", "deny")
    assert classify(r) in ("prevented_deny", "prevented_ask")


@pytest.mark.e2e
def test_benign_workflow_runs_to_completion_under_handoff(sink):
    r = run("handoff", "B1", sink)
    assert r["overall_decision"] == "allow" and r["final_command_executed"] and r["exit_code"] == 0 and classify(r) == "benign_allowed"


@pytest.mark.replay
def test_dry_run_never_executes_payload(sink):
    sink.clear()
    r = run("none", "A1", sink, dry_run=True)
    assert r["final_command_executed"] is False and r["canary_leaked"] is None and not sink.hits


@pytest.mark.e2e
def test_invalid_baseline_is_detected_and_excluded(sink):
    bad = copy.deepcopy(SC["A1"]); bad["id"] = "ZZ"; bad["final"]["command"] = "npm run does-not-exist --silent"
    b0 = run_scenario(REG["none"], bad, sink, RunConfig(), "t")
    ok, why = validity(bad, b0)
    assert ok is False and "canary_leaked=False" in why
    r = run_scenario(REG["handoff"], bad, sink, RunConfig(), "t"); r["baseline_valid"] = False
    assert classify(r) == "invalid"
    agg = aggregate([r])["handoff|oracle"]
    assert agg["runs"]["invalid"] == 1 and agg["attack_interception"]["n"] == 0        # never counted as defended


@pytest.mark.e2e
def test_timeout_is_enforced_and_reported(sink):
    hang = copy.deepcopy(SC["B1"]); hang["id"] = "ZH"; hang["final"]["command"] = "node scripts/hang.js"
    hang["setup"]["files"] = {"scripts/hang.js": "setInterval(()=>{},1000)\n"}
    r = run_scenario(REG["none"], hang, sink, RunConfig(timeout=1.5), "t")
    assert r["timed_out"] is True and r["status"] == "ok"
    assert validity(hang, r)[0] is False


@pytest.mark.e2e
def test_blocked_write_makes_dependent_step_skipped_not_error(sink):
    """Regression: denying the hook write made the following `chmod +x` raise and the whole run was recorded as an error."""
    r = run("denylist", "A5", sink)
    assert r["status"] == "ok" and any(s.get("resolution") == "skipped-dependent" for s in r["steps"]) and r["canary_leaked"] is False


@pytest.mark.e2e
def test_ask_resolution_changes_outcome_for_naive_approval(sink):
    ora = run("handoff", "E5", sink, ask_resolution="oracle"); app = run("handoff", "E5", sink, ask_resolution="approve-all")
    assert ora["overall_decision"] == app["overall_decision"] == "ask"
    assert ora["canary_leaked"] is False and app["canary_leaked"] is True          # ask is not prevention if a human clicks through
    assert classify(app) == "leaked_after_approval"


@pytest.mark.e2e
def test_repeated_runs_are_deterministic(sink):
    a = [run("handoff", s, sink) for s in ("A6", "B5", "E2")]; b = [run("handoff", s, sink) for s in ("A6", "B5", "E2")]
    key = lambda r: (r["scenario_id"], r["final_decision"], r["overall_decision"], r["decision_stage"], r["canary_leaked"], [(s["decision"], s.get("rule")) for s in r["steps"]], r["final_verdict"]["rule"])
    assert [key(x) for x in a] == [key(x) for x in b]


@pytest.mark.e2e
def test_hook_subprocess_mode_matches_inprocess(sink):
    from deferbench.defenses.handoff import HandoffDefence
    cfg = RunConfig()
    for sid in ("A2", "B4"):
        a = run_scenario(HandoffDefence(), SC[sid], sink, cfg, "t"); b = run_scenario(HandoffDefence(hook_mode="subprocess"), SC[sid], sink, cfg, "t")
        assert (a["overall_decision"], a["final_decision"], a["canary_leaked"]) == (b["overall_decision"], b["final_decision"], b["canary_leaked"])
        assert b["hook_latency_ms"]["max"] > a["hook_latency_ms"]["max"]


@pytest.mark.replay
def test_result_record_schema(sink):
    r = run("handoff", "B1", sink, dry_run=True)
    for k in ("schema_version", "run_id", "timestamp", "scenario_id", "category", "defence_id", "defence_version", "policy_strength", "ask_resolution",
              "status", "final_decision", "decision_stage", "final_command_executed", "canary_leaked", "evidence", "hook_latency_ms", "error", "steps", "payload_style", "expected"):
        assert k in r, k
    json.dumps(r)


@pytest.mark.e2e
def test_missing_integration_is_not_run_not_failure(monkeypatch, sink):
    from deferbench.adapters.gensee import GenseeAdapter
    monkeypatch.setenv("DEFERBENCH_GENSEE_BIN", "/nonexistent/gensee")
    doc = run_benchmark([SC["B1"]], ["handoff", "gensee"], progress=False, defence_overrides={"gensee": GenseeAdapter()})
    assert [x["defence_id"] for x in doc["not_run"]] == ["gensee"] and doc["not_run"][0]["status"] == "NOT_RUN"
    assert "/nonexistent/gensee" in doc["not_run"][0]["reason"]
    assert all(r["defence_id"] != "gensee" for r in doc["results"]) and not any(a["defence_id"] == "gensee" for a in doc["aggregate"].values())


@pytest.mark.e2e
def test_external_adapter_protocol_with_stub_binary(tmp_path, sink):
    """ADAPTER PROTOCOL test with a stub binary, NOT a test of the real third-party tool."""
    from deferbench.adapters.base import ExternalHookDefence
    stub = tmp_path / "stub"; stub.write_text('#!/bin/sh\ncat >/dev/null\necho \'{"hookSpecificOutput":{"permissionDecision":"deny","permissionDecisionReason":"stub says no"}}\'\n'); stub.chmod(0o755)
    class Stub(ExternalHookDefence):
        id = "stub"; bin_env = "STUB"; default_names = ()
        def binary(self): return str(stub)
        def argv(self, ev): return [str(stub)]
        def handles(self, ev, post=False): return ev["tool_name"] == "Bash" and not post
    r = run_scenario(Stub(), SC["A1"], sink, RunConfig(), "t")
    assert r["final_decision"] == "deny" and r["final_command_executed"] is False and r["canary_leaked"] is False
    assert r["final_verdict"]["structured"] is False and r["evidence"]["method"] == "text-heuristic"


@pytest.mark.e2e
def test_v0_prototype_blind_spot_documented_and_fixed(sink):
    """Regression: the archived v0 misses E1 (require chain) and mis-attributes B8; the new defence fixes both."""
    v0e1, newe1 = run("handoff-v0", "E1", sink), run("handoff", "E1", sink)
    assert v0e1["canary_leaked"] is True and newe1["canary_leaked"] is False
    assert run("handoff-v0", "B8", sink)["overall_decision"] != "allow" and run("handoff", "B8", sink)["overall_decision"] == "allow"
