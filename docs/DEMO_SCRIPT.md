# Demo script (3 minutes) and recording checklist

Everything runs offline on generated data. No Internet, LLM or paid API is used; the only socket is a listener on `127.0.0.1`.
Outputs below are copied from a real run (`examples/recorded_demo.json`); ports and timings differ per run.

## One command
```
python -m deferbench demo            # live: validates, attacks undefended, defends, benign, comparison
python -m deferbench demo --dry-run  # decisions only; never executes a payload
python -m deferbench demo --fallback # prints the RECORDED run (clearly labelled as not live)
python -m deferbench clean           # remove leftover temp workspaces (normally none)
```

## Timeline
| t | command | checkpoint |
|---|---|---|
| 0:00 | `python -m deferbench validate` | `development scenarios: 40 {'attack': 16, 'benign': 14, 'edge': 10}`, `validation: OK` |
| 0:20 | `python -m deferbench demo` | step 2 prints the scenario story: untrusted read, the agent's file change, and the trusted command |
| 0:50 | (same run) | step 3, no defence: `canary_leaked=True`, observed at the loopback sink |
| 1:20 | (same run) | steps 4–5: stateless resolver and Handoff both `DENY` before execution with `canary_leaked=False`; Handoff's evidence also names the authoring step and untrusted source |
| 1:50 | (same run) | step 6: benign workflow allowed by none/resolver/Handoff; step 7: comparison table |
| 2:20 | open `results/final/dashboard.html` | "Stateless resolver vs. Handoff" panel, matrix-cell timeline, independence banner |

**Be honest on stage:** the stateless-expansion row also says DENY for A1. Say so, then show a scenario where provenance matters
(B7: `static-expansion` and Gensee interrupt a pre-existing script that Handoff correctly allows) and one where it does not (A1).
Do not say the numbers prove an advantage over third-party products; the third-party tools ran hook-only.

## Recording checklist
- [ ] Fresh terminal, light theme or large font (≥ 16 pt); window 120×35 or larger
- [ ] `python3 --version` is 3.11+; `pip install -e '.[dev]'` done; `python -m pytest -q` is green (record the count shown)
- [ ] Disconnect from the network (Wi-Fi off) before recording the live demo, to show it needs none
- [ ] `python -m deferbench clean` first so no stale temp dirs; `rm -rf results/runs/demo*` not needed (demo writes no results)
- [ ] Run the demo once off-camera; if anything differs from this document, **use the actual output**, not this table
- [ ] Record: validate → demo → dashboard. Keep the take under 3 minutes
- [ ] Fallback ready: `python -m deferbench demo --fallback` and the committed `results/final/` report + `dashboard.html`
- [ ] If an external tool misbehaves, skip it: `python -m deferbench benchmark --defense none,denylist,static-expansion,handoff`
- [ ] Say out loud: "replay harness, scripted agent actions; hook-only third-party runs; holdout is provisional"
