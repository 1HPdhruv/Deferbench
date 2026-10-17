# Team plan (two developers)

Roles are suggestions; the repository was built so either person can run everything offline with one command.

| owner | work package | status source |
|---|---|---|
| Dev A (defence) | Handoff engine/resolver improvements; policy knobs; adapters | `docs/IMPLEMENTATION_STATUS.md` |
| Dev B (benchmark) | scenarios, holdout set, baselines, reporting/dashboard | `docs/IMPLEMENTATION_STATUS.md` |
| **Dev B first** | **write the independent holdout set (≤2 h) — it must be written by the person who did *not* write Handoff** | `docs/HOLDOUT.md` |

## 24-hour plan
| hour | task | exit check |
|---|---|---|
| 0–1 | `pip install -e .[dev]`, `pytest`, `deferbench demo` | green tests, demo prints LEAKED vs DENY |
| 1–3 | Dev B writes 10 independent scenarios + sealed expectations; Dev A does **not** read them | `holdout status` |
| 3–5 | run `scripts/fetch_integrations.sh`, full `benchmark`, regenerate dashboard | `results/runs/<id>/` |
| 5–8 | run `holdout run`; record results unedited; fix real defects (note: set becomes development after any tuning) | `holdout_score.md` |
| 8–12 | review `docs/NOVELTY_AUDIT.md` claims against fresh sources; rehearse `docs/DEMO_SCRIPT.md` | one clean rehearsal |
| 12–16 | record the demo (checklist in DEMO_SCRIPT); prepare slide from `docs/PITCH.md` | video + fallback file |
| 16–24 | buffer; answer judge questions; do **not** add features | — |

## Rules of the road
* Never edit expected outcomes or weaken a baseline to improve a number; report failures.
* Every claim in slides/README must trace to a file under `results/` or to a dated source in `docs/NOVELTY_AUDIT.md`.
* If an external tool breaks, run with built-in defences; tools show up as `NOT_RUN`, never as a failure.
