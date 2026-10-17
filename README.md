# DeferBench

**DeferBench evaluates security controls against delayed execution through trusted developer tools.**
An AI coding agent reads untrusted content, edits a script or configuration, and later a trusted, harmless-looking command
(`npm test`, `make build`, `pytest`, `git commit`) runs what the agent wrote. DeferBench replays such scenarios in disposable
repositories, **really executes** the trusted command, and checks whether a synthetic canary reaches a loopback-only sink, while also
measuring how often each control interrupts legitimate development work.

**Handoff** is a reference defence (execution-path resolver + provenance ledger) included so the measurements have a strong in-house
point of comparison. It is not presented as a novel invention.

> Status: hackathon prototype. Development results come from scenarios written by the defence author. A model-authored confirmatory
> run exists but is **not human-independent**. **A human-independent evaluation is still pending** (`independent_eval/PROTOCOL.md`).

## The problem
A per-command check sees `npm test` and allows it. What actually runs is whatever `package.json`, a Makefile target, test-runner
configuration, a VCS hook or an imported module says *now*, possibly changed by the agent minutes or sessions earlier. A protected-path
list sees only some of these files; a blanket "block everything after a write" stops attacks but also stops normal work.

## How a scenario works
1. A fresh git workspace is generated with a synthetic `API_KEY=ck_canary_<random>` in `.env`.
2. The harness plays the agent's tool events (read untrusted content → write/edit files) into the control under test, in Claude Code hook format, and applies the file effects.
3. The control decides on the trusted command (allow / ask / deny). If allowed, the command is **executed** with a timeout and a minimal environment.
4. The loopback sink reports whether the canary arrived. The same scenario is first run **undefended**; if the expected effect does not reproduce, it is marked INVALID and excluded.
5. Benign scenarios run the same way; any ask/deny on a benign `allow` scenario counts as an unnecessary interruption.

## Architecture
```mermaid
flowchart LR
  S[scenarios/*.json<br/>data only] --> V[validate + expand<br/>loopback assertion]
  V --> H[harness: replay tool events,<br/>run trusted command in disposable repo]
  H -- hook events --> C{{security control}}
  C --> B[none · denylist · stateless resolver · Handoff · blanket]
  C --> X[Gensee · Gryph · Runmark · Handoff-v0]
  B --> R[resolver.py: execution closure]
  B --> L[(Handoff ledger, outside workspace)]
  H --> K[127.0.0.1 sink: did the canary leave?]
  H --> M[metrics → JSON / CSV / Markdown / SVG → dashboard]
```
Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · threat model: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · method: [docs/METHODOLOGY.md](docs/METHODOLOGY.md)

## Install
```bash
python3 -m venv .venv && . .venv/bin/activate          # Python 3.11+; runtime uses only the standard library
python -m pip install -e '.[dev]'                       # dev extra = pytest
```
The generated test projects need `git`, `make`, `node`/`npm` and `curl` on `PATH`. Tested on macOS arm64.
Optional third-party controls (macOS arm64, checksum-verified, installed only into `./.integrations/`): `./scripts/fetch_integrations.sh`.

## Use
| task | command |
|---|---|
| tests | `python -m pytest` |
| validate scenarios | `python -m deferbench validate` |
| live demo (offline, ~20 s) | `python -m deferbench demo` |
| demo without executing anything | `python -m deferbench demo --dry-run` |
| recorded demo (labelled, not live) | `python -m deferbench demo --fallback` |
| one control on chosen scenarios | `python -m deferbench run --defense handoff --scenario A1,B1` |
| full benchmark (~11 min with third-party tools) | `python -m deferbench benchmark --payload-style plain,signature --ask-resolution oracle,approve-all` |
| regenerate reports from a result file | `python -m deferbench report --input <results.json> --recompute` |
| dashboard | `python -m deferbench dashboard` (or open `results/final/dashboard.html`) |
| which controls are available | `python -m deferbench integrations` |
| remove leftover temp workspaces | `python -m deferbench clean` |

Exit codes: `0` ok · `1` runs errored · `2` usage error · `3` finished but some scenario was INVALID.

## Measured results (development set; release re-run `20261013T115905Z-bde81a`)
40 scenarios (16 attack · 14 benign · 10 edge) × 2 payload styles, 0 invalid, 0 errors; outcomes identical to the earlier run
`20261013T060051Z-29383e` on all 1,760 overlapping records. `oracle` = a reviewer who rejects asks on attacks and approves them on benign work.

| control | policy | attacks stopped | leaks | benign interrupted | executing file named | provenance attribution |
|---|---|---|---|---|---|---|
| none | — | 0/44 | 44/44 | 0/26 | — | — |
| protected-path denylist | default | 4/44 | 40/44 | 2/26 | 4/4 | not provided |
| **stateless resolver** | default | **44/44** | 0/44 | 2/26 | 41/42 | not provided |
| **Handoff** | default | **44/44** | 0/44 | 2/26 | 41/42 | 37/44 |
| Handoff v0 (original prototype) | default | 34/44 | 10/44 | 6/26 | 20/34 | 28/34 |
| Gensee Crate v0.3.3, hook-only | default | 7/44 | 37/44 | 2/26 | 3/7 | 0/7 |
| Gryph v0.9.0 (default / example policy) | default | 0/44 | 44/44 | 0/26 | — | — |
| Runmark v0.1.0-spike.2 | default | 0/44 | 44/44 | 0/26 | — | — |
| blanket "block after any write" (ours / Gryph rule) | strict custom | 40/44 | 4/44 | 26/26 | 0/38 | not provided |

**How to read this**
* The resolver does the work: the stateless resolver and Handoff stop the same attacks. Provenance adds **traceability** (which agent step wrote
  the content, after which untrusted input), not prevention. Stateless controls cannot provide provenance attribution by design.
* With a click-through reviewer (`approve-all`) escalations fail open: Handoff 38/44, stateless resolver 40/44.
* Third-party rows describe **hook-only, default-policy configurations**, not the full products (e.g. Gensee's OS sensor was not active).
* Rates pool two payload styles, so n counts scenario × style, not independent attacks.
* Hook latency varies between runs on the same machine (Handoff p50 0.3–0.7 ms in-process; ~30–70 ms as a subprocess hook).

Other result sets (none human-independent): a provisional holdout written by the defence author (Handoff 8/9, stateless resolver 6/9 attacks;
Handoff interrupted 1/2 benign) and a model-authored confirmatory run (both resolvers 12/12 attacks; Handoff interrupted 2/6 benign, stateless 0/6) —
see `results/final/` and `independent_eval/INDEPENDENT_REPORT.md`.

## Security boundaries
Synthetic canary secrets only; minimal subprocess environment (developer tokens are not inherited); every scenario URL must be a literal loopback
address and the sink binds `127.0.0.1` only; scenario files are data (no shell strings), simulated edits are a closed set of Python operations,
and the trusted command comes from an allow-list and runs as an argv list with timeouts and bounded output; workspaces are deleted afterwards.
Third-party binaries run with an isolated `HOME` and no agent integration. See [docs/SAFETY.md](docs/SAFETY.md).

## Known limitations
* Scripted agent actions, not live models; nothing here measures how often real agents behave this way.
* Development scenarios written by the defence author; provisional and confirmatory sets are not human-independent; **human-independent evaluation pending**.
* Static resolution is partial: third-party packages, `eval`/dynamic imports and some tool options are reported as *unknown*; Handoff misses at least one such case (`npm --prefix`).
* Handoff's default policy interrupts some legitimate work (e.g. new code that makes loopback network calls).
* Hook decisions can be raced (TOCTOU); `recheck` only detects this where an integration can call it before execution.
* One operating system; third-party tools hook-only; no OS-level sensors; no LLM component.

## Idea-submission deck
`submission/DeferBench_Idea_Submission.pptx` (and `.pdf`) — 9 slides built on a Figma community template; see `submission/README.md` and `submission/SOURCES_AND_DISCLOSURES.md`.

## Contributing scenarios / controls
[docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) · independent holdout process: [docs/HOLDOUT.md](docs/HOLDOUT.md) and `independent_eval/PROTOCOL.md`.

## Reproducibility and licence
Deterministic rules; repeat runs agree (200 repeated groups, built-in controls). Result files record environment, tool versions, configuration and
policy strength. Tests need no network or credentials. MIT licence ([LICENSE](LICENSE)); third-party tools keep their own licences and are not
redistributed. The original v0 files are preserved in [archive/v0/](archive/v0/).
