# Final verification report — 2026-10-13 (v0.2.1)

| check | command | result |
|---|---|---|
| automated tests | `python -m pytest` | **150 passed, 0 failed, 0 skipped** (unit 69 · integration 6 · replay 49 · e2e 26) |
| release check (stale paths, secrets, non-loopback URLs, dead links) | `./scripts/release_check.sh` | exit 0, no findings |
| scenario validation | `python -m deferbench validate` | 40 development scenarios, 17/17 v0 IDs preserved, OK |
| live demo | `python -m deferbench demo` | exit 0; undefended attack leaked the canary to 127.0.0.1; stateless resolver and Handoff blocked before execution (canary not leaked); benign workflow allowed by all three |
| dry-run demo | `python -m deferbench demo --dry-run` | exit 0; no command executed |
| recorded fallback | `python -m deferbench demo --fallback` | prints the recorded transcript, labelled as not live |
| full benchmark | `python -m deferbench benchmark --payload-style plain,signature --ask-resolution oracle,approve-all` | exit 0; 1,920 records; 0 invalid; 0 errors; identical outcomes to the previous run on 1,760 overlapping records |
| report regeneration | `python -m deferbench report --input results/final/development_release_rerun/results.json --recompute` | regenerated report identical to the committed one |
| dashboard data loading | `python -m deferbench dashboard …` + headless Brave `--dump-dom` | all sections rendered from embedded result data; 0 absolute local paths in HTML |
| integrations | `python -m deferbench integrations` | all 12 controls available locally (third-party binaries from `scripts/fetch_integrations.sh`); on a machine without them they report NOT_RUN |
| workspace cleanup | count of `deferbench-*` temp dirs after runs | 0 |
| clean install | fresh venv: `python -m pip install -e '.[dev]'`, then `validate`, `demo --dry-run`, unit+replay tests | install OK; validation OK; dry-run demo OK; 118 unit+replay tests passed |

**Not verified:** visual appearance in a browser window (headless screenshot timed out); Linux/Windows; third-party tools beyond hook-only defaults; any human-independent evaluation.
