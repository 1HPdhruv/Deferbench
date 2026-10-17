# Architecture

```mermaid
flowchart LR
  subgraph Data["Scenario data (JSON, no code)"]
    S[scenarios/*.json] --> V[scenarios.py<br/>schema + safety validation<br/>placeholder expansion]
    H[scenarios/holdout/*.json<br/>+ sealed EXPECTED] --> HO[holdout.py]
  end
  V --> HN[harness.py<br/>replays tool events, applies effects,<br/>runs final command in disposable workspace]
  HO --> HN
  HN -- "Claude Code hook events" --> D{{Defence under test}}
  D --> B0[B0 none]
  D --> B1[B1 denylist]
  D --> B2[B2 static-expansion]
  D --> B3[B3 Handoff]
  D --> EX[external adapters<br/>Gensee / Gryph / Runmark / Handoff-v0]
  B2 --> R[resolver.py<br/>execution closure]
  B3 --> R
  B3 --> L[(ledger.py<br/>outside workspace)]
  HN --> SK[sink.py<br/>127.0.0.1 only]
  HN --> M[metrics.py]
  M --> RP[reporting.py: JSON, CSV, MD, SVG]
  RP --> DB[dashboard.html]
  HO --> SC[holdout scoring]
  M --> CR[criteria.py<br/>pre-registered checks]
```

## Handoff data flow
```mermaid
sequenceDiagram
  participant A as Agent (replayed)
  participant H as Handoff hook
  participant L as Ledger (outside workspace)
  participant W as Workspace
  A->>H: PostToolUse WebFetch (untrusted input)
  H->>L: record untrusted source + session
  A->>H: PreToolUse Write/Edit
  H->>H: classify write-surfaces (hooks, IDE tasks, .envrc ...)
  A->>W: file effect
  A->>H: PostToolUse Write/Edit
  H->>L: record authored units (per file) + taint
  A->>H: PreToolUse Bash "make build"
  H->>W: resolve execution closure (npm/make/pytest/git/shell/py/node)
  H->>L: intersect closure units with authored units (per file)
  H-->>A: allow / ask / deny + structured evidence + closure hash
  A->>H: PostToolUse Bash
  H->>L: record shell-made changes (diff), keep lineage across cp/mv/sed
```

## Modules
| module | role |
|---|---|
| `scenarios.py`, `payloads.py` | data model, validation, placeholder expansion (loopback assertion) |
| `repo.py`, `safety.py`, `sink.py` | disposable workspaces, restricted simulated shell, bounded `safe_run`, loopback sink |
| `harness.py`, `runner.py` | replay + real execution, baseline-first validity, repeats, ask-resolution views |
| `resolver.py` | bounded execution-closure resolver; unresolved items are explicit (`blocking` or informational) |
| `ledger.py`, `surfaces.py`, `signals.py` | provenance store, write-surface classification, content risk signals |
| `defenses/` | B0–B4 built-ins; `adapters/` external hook tools and the archived v0 prototype |
| `metrics.py`, `criteria.py`, `reporting.py`, `holdout.py`, `extras.py` | scoring, pre-registered checks, outputs, holdout, demo/dashboard |

## Design decisions that matter
* **Replay, not an LLM.** Agent actions are scripted so results are reproducible; this also means DeferBench says nothing about
  how often a real model *takes* these actions (see `docs/METHODOLOGY.md`).
* **Baseline-first validity.** Every scenario/style/repeat runs undefended first; if the expected effect does not reproduce, all
  defences' records for it are `INVALID` and excluded from rates.
* **Per-file attribution.** v0 hashed lines globally; the ledger is keyed by (path, unit hash) so an identical shebang elsewhere
  is not attributed to the agent. `package.json` is tracked per script, independent of JSON formatting.
* **Explicit unknowns.** Dynamic constructs, depth/size limits, outside-workspace symlinks, stdin-fed shells and package imports
  become `Unresolved` records. `analysis_complete=false` is surfaced in every verdict; policy decides allow/ask.
* **Ledger outside the workspace.** The engine refuses a ledger directory inside the workspace and denies writes/commands that
  reference it. (The agent could still reach it if the host grants it file access outside the workspace; see the threat model.)
