# results/final — measured sample results (provenance)

These files were produced by the commands below on **macOS 26.5 (arm64), Python 3.11.9, Node 24.7, npm 11.5, git 2.51**, on 2026-10-13, hook-only for third-party tools
(no OS sensors). They are *measurements of this harness*, not a security guarantee. Third-party binaries: Gryph v0.9.0, Runmark v0.1.0-spike.2, Gensee Crate CLI v0.3.3
(fetched with `scripts/fetch_integrations.sh`, checksum-verified; the Gensee app's Endpoint Security sensor was not installed).

| folder | command | what it is |
|---|---|---|
| `development/` | `python -m deferbench.cli benchmark --payload-style plain,signature --ask-resolution oracle,approve-all` | 40 development scenarios × 2 styles × 11 defences (run `20261013T060051Z-29383e`) |
| `development_release_rerun/` | same command, re-run for the release on 2026-10-13 (run `20261013T115905Z-bde81a`, adds the `handoff-hook` control) | outcomes identical to `development/` on all 1,760 overlapping records; reports regenerated with `report --recompute` |
| `holdout/` | `python -m deferbench.cli holdout run --ask-resolution oracle,approve-all` | **provisional-adversarial set, NOT independent** (12 scenarios). `_attempt1_H5_baseline_invalid/` is the first run, kept: H5's baseline was INVALID for every defence (scenario defect), fixed and re-sealed before the run in `holdout/` |
| `determinism/` | `python -m deferbench.cli benchmark --defense none,denylist,static-expansion,handoff,blanket-gate --repeat 3` | repeat-3 run used for the determinism criterion (built-in defences only) |
| `latency/` | `python -m deferbench.cli benchmark --defense none,handoff,handoff-hook` | in-process vs. real subprocess-hook latency for Handoff |
| `dashboard.html` | `python -m deferbench dashboard --input results/final/development_release_rerun/results.json --holdout results/final/holdout/results.json` (also embeds the confirmatory run from `independent_eval/results/`) | self-contained dashboard; every number computed from the embedded result JSON |

Regenerate everything with `docs/IMPLEMENTATION_STATUS.md#how-the-final-results-were-produced`. Fresh runs go to `results/runs/` (git-ignored).
