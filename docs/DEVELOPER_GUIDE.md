# Developer guide

## Add a scenario
1. Create `scenarios/{attacks,benign,edge}/<ID>.json` (copy any file there or `scenarios/holdout/TEMPLATE.json`).
2. Required fields: `schema_version` (`deferbench.scenario/1`), `id`, `category` (`attack|benign|edge`), `malicious`, `name`, `threat`,
   `setup{files,git_config}`, `actions[]`, `final{command,session}`, `expected{baseline_leak,baseline_exit_zero,secure_outcome}`,
   `evidence{required,payload_files,allowed_files}`, `source`, `limitations`, `authorship`. Set `"execution": "write_surface_only"` when the
   effect cannot be reproduced by running a command (IDE tasks); such scenarios are scored on the write-time decision only.
3. Action kinds: `fetch_untrusted{url,response}`, `write_file{path,content | content_json{from,merge}}`, `edit_file{path,old,new}`,
   `shell_sim{op,...}` (`chmod_x`, `sed_inplace`, `cp`, `mv`, `rm`, `mkdir`, `ln_s`, `touch`, `git_config`), `approve{command}`.
4. Use placeholders for anything that talks to the network: `{PAYLOAD_SH}`, `{PAYLOAD_SH_JSON}` (inside JSON strings), `{PAYLOAD_SH_JSLIT}`,
   `{PAYLOAD_SH_B64}`, `{PAYLOAD_SH_UP2[_JSON]}` (payload run from a directory two levels down), `{PAYLOAD_PY}`, `{PAYLOAD_PY_B64}`,
   `{PAYLOAD_NODE}`, `{ISSUE}`, `{PORT}`. Writing your own URL is a validation error unless it is loopback.
5. Validate: `python -m deferbench.cli validate`; run the undefended baseline: `python -m deferbench.cli run --defense none --scenario <ID> --print-report`.
   A malicious scenario must show `LEAKED`; if it shows `INVALID`, fix the *scenario* (typically quoting/cwd), never the expectation.
6. Add the scenario's expected outcome honestly: `secure_outcome` is `intercept`, `allow`, or `allow_or_ask` (an explained approval is acceptable).
7. Do not rename existing IDs (`tests/test_scenarios.py::test_v0_scenario_ids_preserved`).

## Add a defence / external adapter
* In-process: subclass `deferbench.defenses.base.Defence`; implement `pre(event) -> Verdict` (and optionally `post`, `approve`, `recheck`);
  register it in `defenses/__init__.py::registry`. Fill `capabilities`, `unsupported`, `policy_strength`, `config()` — these are written into
  every result so comparisons stay honest.
* External hook tool: subclass `adapters.base.ExternalHookDefence`; set `bin_env`, `default_names`, `argv(event)`. Availability is
  detected from `DEFERBENCH_<TOOL>_BIN`, `.integrations/<tool>/<tool>`, or `PATH`; otherwise the defence is reported `NOT_RUN` with the reason.
  Run default policy and any custom policy as *separate* defences with `policy_strength` set (`default` vs `strict-custom`).
* Structured evidence: return `Verdict.evidence` with `kind` in `exec-closure | surface-write | static-closure | denylist` to be scored
  structurally; free-text-only tools are scored with a clearly labelled text heuristic.

## Run things
```
python -m pip install -e '.[dev]'          # only pytest is needed for tests
python -m pytest                           # full suite
python -m deferbench.cli validate
python -m deferbench.cli benchmark         # all available defences
python -m deferbench.cli holdout run       # provisional adversarial set
python -m deferbench.cli dashboard         # HTML dashboard from the latest results
```
Environment: `DEFERBENCH_RESULTS_DIR`, `DEFERBENCH_SCENARIOS_DIR`, `DEFERBENCH_TIMEOUT`, `DEFERBENCH_{GENSEE,GRYPH,RUNMARK}_BIN`.
Test layers are marked: `unit`, `integration`, `replay` (decisions only), `e2e` (real execution + loopback sink).
