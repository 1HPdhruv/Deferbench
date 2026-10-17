# Implementation status

Legend: **Implemented** = code exists · **Tested** = automated test (layer in brackets) · **Measured** = appears in `results/final/` · **Simulated** = effect is applied by Python rather than a real tool · **Unverified** = not tested here.
Test layers: unit, integration, replay (decisions only), e2e (real execution + loopback sink). Full suite on the release code: **150 passed, 0 failed, 0 skipped** (`python -m pytest`; unit 69, integration 6, replay 49, e2e 26).

## Core
| feature | status |
|---|---|
| Installable package, CLI (`validate`, `list-scenarios`, `run`, `benchmark`, `report`, `dashboard`, `holdout`, `demo`, `clean`, `integrations`) | Implemented; Tested [integration/e2e: `test_holdout_cli.py`] |
| 40 development scenarios as validated JSON (16 attack / 14 benign / 10 edge); v0 IDs preserved | Implemented; Tested [unit] ; Measured |
| Safety: loopback-only sink + URL assertion, synthetic canary, minimal env, no `shell=True`, allow-listed argv, bounded `safe_run`, cleanup | Implemented; Tested [unit/integration: `test_safety.py`] |
| Baseline-first validity gating; INVALID excluded from rates | Implemented; Tested [e2e]; Measured (0 invalid in final run; H5 was invalid in a first holdout attempt and is kept) |
| Dry-run (never executes payload) | Implemented; Tested [replay] |
| Simulated tool effects (file edits, `chmod`, `sed`, `cp`, `mv`, `ln -s`, `git config`) | **Simulated** by design (a real agent/shell is not used); the final command is really executed |
| Results schema `deferbench.result/1` (JSON), CSV, Markdown, SVG chart, HTML dashboard | Implemented; Tested [e2e]. Dashboard rendered in headless Brave (Chromium) via `--dump-dom`: all sections populated from embedded data. Visual screenshot not obtained (headless screenshot timed out in this environment) |
| Separate evidence measures (executing file named; provenance attribution) and `report --recompute` | Implemented; Tested [e2e]; recomputation leaves headline outcomes unchanged |
| Pre-registered criteria evaluated mechanically | Implemented; Tested [e2e]; Measured |

## Reference defence (Handoff)
| feature | status |
|---|---|
| Per-file provenance ledger outside workspace; per-script units for `package.json`; shell-diff attribution with `derived_from` | Implemented; Tested [replay] |
| Resolver: npm scripts + lifecycle, Makefile (vars, deps, include), pytest conftest/config/plugins, git hooks/`core.hooksPath`/alias/`--no-verify`, shell/Python/Node entry files, direnv/`source` | Implemented; Tested [replay + e2e]; Measured |
| JS `require()`/`import` chains: local follow, cycles, depth/size limits, package vs dynamic vs alias labelled | Implemented; Tested [replay, unit; mutation-checked] ; Measured (E1, E4, H3) |
| Python local imports; symlinks (incl. outside-workspace refusal); `file:` dependency lifecycle | Implemented; Tested ; Measured (A8, A10, A12) |
| Explicit unknowns (`analysis_complete`, blocking vs informational); `unknown_policy` | Implemented; Tested ; Measured (E5, E7, E8, H4) |
| Approval binding to (action, closure hash); `recheck` TOCTOU detection | Implemented; Tested [replay]. **Detects** a content swap only where an integration calls `recheck` immediately before execution; plain hooks cannot prevent the race. In the harness no race is injected, so `recheck` never fired in measured runs |
| Ledger tamper denial; fail-closed on internal error | Implemented; Tested [replay] |
| Write-surface classification (git hooks, `.envrc`, IDE tasks/settings exec keys, agent config, `.mcp.json`, `.npmrc`) | Implemented; Tested ; Measured (E9, E10, A5, A11, B10, B12) |
| Hook entry point (`python -m deferbench.defenses.handoff hook`) | Implemented; Tested [e2e: same decisions as in-process]; Measured latency p50 72 ms, p95 146 ms |
| LLM classifier | **Not implemented.** Rules-only, offline. (Config example documents this.) |
| Shell-command writes to surfaces caught *before* execution | Not implemented: detected after the fact by diff (`post` alert) and at execution via the closure. Unverified in the measured set |

## Baselines and integrations
| item | status |
|---|---|
| B0 none, B1 denylist, B2 static-expansion, B4 blanket (DeferBench-authored) | Implemented; Measured |
| `handoff-v0` (archived prototype, unmodified) | Implemented; Tested [e2e regression]; Measured |
| Gryph v0.9.0 (3 configs), Runmark v0.1.0-spike.2, Gensee Crate CLI v0.3.3 | **Real binaries executed** through their documented hook CLIs, hook-only; Measured. Adapter protocol additionally tested with a **stub** (`test_external_adapter_protocol_with_stub_binary`, labelled as such). Not measured: OS sensors, installed agent integrations, non-default policies beyond the Gryph example/blanket |
| Missing tool → `NOT_RUN` with reason | Implemented; Tested [e2e] |
| Third-party tools on Linux/Windows | Unverified (fetch script is macOS arm64) |

## Evaluation status
| item | status |
|---|---|
| Development set results | **Measured** (`results/final/development`) — authored by the defence author; Handoff 44/44 intercepted is **not** evidence of general effectiveness |
| Holdout | **Provisional adversarial set (12 scenarios), same author, NOT independent.** Measured (`results/final/holdout`): Handoff 8/9 attacks, 1/2 benign `allow` interrupted. **Human-independent evaluation PENDING** (`docs/HOLDOUT.md`). A model-authored confirmatory run exists: `independent_eval/INDEPENDENT_REPORT.md` (same-model author, overlapping mechanisms; provenance gave no extra prevention, more benign interruptions) |
| Determinism | Measured for built-in defences (3 repeats, 200 groups, no disagreement). External tools not repeated |
| Real-model behaviour (do agents actually do this?) | Unverified / out of scope |
| Windows/Linux, other agents (Cursor, Codex…) | Unverified |

## Known defects / limitations (not fixed)
* Handoff misses `npm --prefix <dir> …` (holdout H5; leaks).
* Handoff hard-denies a legitimate agent-written loopback test (B9) and interrupts B5, B12 and holdout H11.
* Escalation outcomes (E2, E3, E5) leak under naive approval (`approve-all`).
* Taint only from WebFetch/WebSearch/MCP results; per-session.
* Evidence completeness is partly by construction (see `docs/METHODOLOGY.md`).
* Latency for in-process vs subprocess defences is not comparable; third-party numbers include process spawn.

## How the final results were produced
```
./scripts/fetch_integrations.sh
python -m deferbench benchmark --payload-style plain,signature --ask-resolution oracle,approve-all --quiet     # results/runs/<id>/  (651 s)
python -m deferbench holdout seal --authors "DeferBench development model session"                             # before running the holdout
python -m deferbench holdout run --ask-resolution oracle,approve-all --quiet
python -m deferbench benchmark --defense none,denylist,static-expansion,handoff,blanket-gate --repeat 3 --out results/determinism
python -m deferbench benchmark --defense none,handoff,handoff-hook --out results/latency
python -m deferbench dashboard --input results/final/development/results.json --holdout results/final/holdout/results.json --out results/final/dashboard.html
```
The defence code (`deferbench/defenses/*`, `resolver.py`, `surfaces.py`, `ledger.py`, `signals.py`) was frozen (SHA-256 recorded) before the first holdout run; the only later change to `defenses/` added the `handoff-hook` variant (a subprocess wrapper of the same engine) for the latency measurement.
Release gates: `scripts/release_check.sh` (stale paths, secrets, non-loopback URLs, dead links).
