# Independent holdout — protocol and custody

**Status: NOT YET PERFORMED. No independent scenarios exist. Nothing in this directory is a result.**
This directory contains only the custodian machinery (freeze record, predefined rubric, scorer, runner). The scenarios must be written by someone who has not
seen the Handoff implementation, the development scenarios, the provisional holdout's expectations, or any per-scenario result.

## Roles
| role | who | may see |
|---|---|---|
| Implementation author | wrote `deferbench/` (this session) | everything *except* the independent set until after the run |
| **Scenario author** | an independent person | `docs/DEVELOPER_GUIDE.md` (schema), `docs/THREAT_MODEL.md`, `scenarios/holdout/TEMPLATE.json`; **not** `deferbench/defenses|resolver|surfaces|ledger`, `scenarios/{attacks,benign,edge}`, `results/` |
| Custodian | a third person or the scenario author | scenarios + sealed expectations + frozen-version hash; runs `run_confirmatory.py`; never edits defences |

## Steps
1. **Freeze** (implementation author): `python independent_eval/freeze.py` → `FREEZE.json` (source-tree SHA-256, Python/OS/tool versions). Already recorded once (see file); re-run only to *verify*.
2. **Author** (scenario author), in `independent_eval/holdout/`: ≥10 attack, ≥5 benign, ≥3 edge scenarios (`I1…I18`) in the `deferbench.scenario/1` schema; each needs threat hypothesis, setup, ordered
   actions, expected undefended behaviour (`baseline_leak`), expected protected behaviour (`secure_outcome`: `intercept` | `allow` | `allow_or_ask` = approval acceptable), required evidence, source/rationale.
   Expectations go **only** in `holdout/EXPECTED.json.sealed` (format in `docs/HOLDOUT.md`), never in the scenario files. Use new mechanisms; do not copy benchmark scenarios.
3. **Validate and check baselines** without looking at defences: `python -m deferbench holdout run --scenarios independent_eval --defense none` — INVALID baselines are repaired by the author *before sealing* (the author may see only the undefended result).
4. **Seal**: `DEFERBENCH_SCENARIOS_DIR=independent_eval python -m deferbench holdout seal --independent --attestation "<what you did / did not see>" --authors "<name>"`; then `python independent_eval/freeze.py` records the set hash.
5. **Run once** (custodian): `python independent_eval/run_confirmatory.py --repeat 2`. It aborts if the implementation hash differs from `FREEZE.json` or the set is below the minimum size. Third-party tools run hook-only unless the evaluator installs more (record that in DEVIATIONS.md).
6. **Score**: automatic (`score.py`, rubric fixed in `rubric.json` before any output was viewed). Report all results, including unfavourable ones.
7. Any defect found → record it; complete the run on the frozen version; fixes start a new development cycle needing a fresh holdout.

## Pre-registered decisions (from the task; not targets)
Continue benchmark + reference defence only if the set is valid and diverse, Handoff prevents real effects (canary), evidence is useful, benign interruption acceptable, and the B-vs-C comparison survives exclusions.
Keep a distinct provenance claim only if it adds reproducible value over the stateless resolver. If prevention is equal but evidence is better → narrow the claim to explainability/forensics (note Level-3 evidence is unattainable for stateless defences by construction).
If provenance adds nothing and the benchmark duplicates existing suites → reframe/abandon that claim. Statistics: paired exact McNemar on discordant pairs; with ~10 attacks only a large difference can be significant — say so.

## Configurations compared (same scenarios, same policy)
A `denylist` · B `static-expansion` (same resolver, no provenance) · C `handoff` (default policy) · D `gensee` v0.3.3 hook-only (+ `gryph`, `runmark`). Not run: Gensee's macOS Endpoint Security sensor, agent integrations, non-default policies.

## Reproduce
```
./scripts/fetch_integrations.sh            # optional third-party tools
python independent_eval/freeze.py          # verify FREEZE.json matches
python independent_eval/run_confirmatory.py --repeat 2
```
Outputs: `independent_eval/results/<run>/{results.json,results.csv,report.md,holdout_score.md,independent_report.md}`. Register invalid scenarios in `INVALID_REGISTER.md`, protocol deviations in `DEVIATIONS.md`.
