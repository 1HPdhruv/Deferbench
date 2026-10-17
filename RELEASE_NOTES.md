# Release notes — v0.2.0 (from the v0 hackathon prototype)

## Behaviour changes (all have tests)
* **Project structure:** installable package `deferbench/`, CLI (`python -m deferbench …`), no machine-specific paths, results/scenario dirs configurable. v0 files archived unmodified in `archive/v0/`.
* **Scenarios** are validated JSON data (40 development scenarios; v0 IDs A1–A6, B1–B6, C1–C2, E1–E3 preserved; v0 `control` C1/C2 are `attack`, v0 `E*` are `edge`). New: A7–A14, B7–B14, E4–E10 (symlinks, `core.hooksPath`, `.envrc`, `file:` dependency lifecycle, Python imports, `cp`/`mv` laundering, IDE surfaces, dynamic/opaque paths, approval reuse).
* **Safety:** no `shell=True`; simulated shell effects are a closed Python op set; final commands are allow-listed argv; loopback-only assertion on all expanded content; minimal sandbox environment; process-group timeouts, bounded output; guaranteed workspace cleanup; `--dry-run`.
* **Scenario defects fixed** (found by baseline-validity gating): A1 `signature` payload produced invalid JSON; GNU-only `sed -i`; A12/H5 payload cwd.
* **Handoff:** per-file attribution (v0 matched hashed lines across files → B8 false positive); per-script units for `package.json` (formatting-independent); resolver now follows JS `require()`/`import` chains (cycle-safe, depth/size limits, local vs package vs dynamic labelled — fixes v0's E1 blind spot), Python local imports, symlinks, Makefile variables/includes, pytest config/plugins/conftest, git `core.hooksPath`/aliases/`--no-verify`, `file:` dependency lifecycle; explicit `unresolved` records and `analysis_complete`; policy knobs (`unknown_policy`…); approvals bound to (action, closure content hash); `recheck` for TOCTOU; ledger outside workspace with tamper denial; precise IDE/agent-config write classification (v0 asked on any `settings.json` write); fail-closed to `ask` on internal error; subprocess hook entry point.
* **Comparison fairness:** defaults vs custom policies are separate defences (`policy_strength`); unavailable tools are `NOT_RUN` with reasons; baseline-first validity; ask/deny/leaked-after-approval separated; ask-resolution models (`oracle`, `approve-all`); Wilson intervals; evidence scored from structured fields (text heuristic only for prose-only tools).
* **Corrections to accounting:** surface-only scenarios no longer count exec-time blocks as interception; a blocked step's dependents are skipped, not errors; `canary_leaked=false` (not null) when a live command was blocked.

## Added
Baselines B1–B4, adapters for Gensee/Gryph/Runmark and the archived v0, holdout workflow with sealed expectations, pre-registered criteria evaluator, CSV/MD/SVG reports, HTML dashboard, one-command demo with recorded fallback, `scripts/fetch_integrations.sh`, `scripts/release_check.sh`, docs (architecture, threat model, methodology, novelty audit, safety, developer guide, demo script, pitch, status, team plan).

## Not carried over / not done
LLM classifier (never implemented; rules-only). Windows/Linux. Independent holdout (pending). Full Gensee with OS sensor. Measuring real-model behaviour.

## v0 results
Preserved for reference in `archive/v0/` and **not comparable** to v0.2.0 numbers (see its README). For a same-harness comparison use the `handoff-v0` row in `results/final/`.

---
# Release notes — v0.2.1 (hackathon submission, 2026-10-13)
* **Positioning:** DeferBench is presented as a focused evaluation of security controls against delayed execution through trusted developer tools; Handoff is a reference defence. Novelty claims narrowed (docs/NOVELTY_AUDIT.md §§7–8).
* **Metrics:** two separate evidence measures added to every aggregate — *executing file named* (all controls) and *provenance attribution* (authoring event + untrusted input; not provided by stateless controls by design). `report --recompute` re-derives aggregates from raw records; headline outcomes are unchanged.
* **Demo:** `python -m deferbench demo` now walks the scenario story (untrusted read → agent change → trusted command) and compares no defence, stateless resolver and Handoff, then runs a benign over-restriction check. Recorded fallback refreshed.
* **Dashboard:** rebuilt layout: purpose statement, at-a-glance cards, a resolver-vs-Handoff panel (development and confirmatory sets), per-cell attack→decision timeline, limitations panel, independence banner; numbers recomputed from raw records at generation time; no absolute local paths embedded.
* **Hygiene:** adapter metadata records project-relative binary paths; holdout records store relative expected-file paths; release check exempts the hash-sealed verbatim author log.
* **Results:** fresh full benchmark `20261013T115905Z-bde81a` reproduced all 1,760 overlapping outcomes of the previous run exactly; stored as `results/final/development_release_rerun/` (originals kept).
* **Model-authored confirmatory run** (`independent_eval/`): both resolvers 12/12 attacks; Handoff 2/6 benign interruptions vs 0/6. Not human-independent.
* **Unchanged:** defence decision logic, scenario definitions, baselines, historical result files.
