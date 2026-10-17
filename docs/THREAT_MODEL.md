# Threat model

## Scope
Delayed execution of **agent-authored** content: an AI coding agent reads untrusted input (issue, web page, MCP result), writes or
modifies a file, and a *later, trusted* command (`npm test`, `make build`, `pytest`, `git commit`, `source .envrc`, an editor action)
executes it. The command line itself looks harmless; the consequential content is in files written earlier. **Out of scope:** the
model's susceptibility to prompt injection (see IssueTrojanBench for that), container/sandbox escape, malicious dependencies from
registries, a compromised host, or an adversary who can already run code as the developer.

## Assets
Developer secrets in the workspace and home directory (`.env`, SSH/cloud credentials, tokens); integrity of build/test/commit
workflows; the defence's own state (ledger, policy); the developer's attention (excess prompts are a cost, and approval fatigue is a risk).

## Trust boundaries
| boundary | trusted | untrusted |
|---|---|---|
| web/issue/MCP content → agent context | — | everything |
| agent → workspace files | developer's pre-existing committed files | files the agent writes after reading untrusted input |
| workspace → host execution | the command the developer approves | the *content* the command pulls in transitively |
| defence state | ledger/policy directory **outside** the workspace | anything inside the workspace |

## Adversary capabilities (assumed)
Controls text the agent reads; can induce the agent to write/edit arbitrary workspace files and to run ordinary build/test commands;
can use copy/rename/sed to launder content; can choose payload encodings (base64, `/dev/tcp`, split across files); can rely on
unmodified-looking existing scripts that load a file dynamically. **Cannot**: write outside the workspace/ledger, forge hook events, or
change policy configuration.

## Abuse cases covered by scenarios (see `scenarios/` for the exact list)
npm scripts/lifecycle; Makefile targets and variables; pytest `conftest.py`; git hooks, `core.hooksPath`, aliases; direct shell/Python/Node
entry files; JS `require()` chains and cycles; Python local imports; copy/rename/sed laundering; symlinks; `.envrc` activation;
dependency lifecycle of a `file:` dependency; IDE tasks and executable-path settings (write-time only); opaque eval of agent-written data;
approval re-use after the content changed.

## Mitigations implemented in the reference defence (B3)
| threat | mitigation | where verified |
|---|---|---|
| agent-written content run later | per-file authored-unit ledger + execution-closure resolution | `tests/test_handoff.py` |
| content laundering | shell diff attribution preserves lineage (`derived_from`) | `test_cp_laundering_keeps_lineage` etc. |
| spurious attribution | ledger keyed by (path, unit) | `test_incorrect_attribution_regression_shared_shebang` |
| unresolvable path | explicit `Unresolved`; policy `ask_if_tainted` | `test_opaque_eval_...` |
| approval replay after change | approvals bound to (action, closure content hash) | `test_approval_bound_to_content_hash` |
| ledger tampering from the workspace | ledger outside workspace; writes/commands naming it denied | `test_ledger_tamper_...` |
| defence crash | fail-closed to `ask` | `test_internal_error_fails_closed_to_ask` |

## Residual risk (not mitigated — read this before relying on the defence)
* **TOCTOU.** A PreToolUse hook decides before execution; content can change afterwards. `recheck()` detects this only where an
  integration can call it immediately before running; plain hooks detect but cannot prevent the race.
* **Static analysis is partial.** Third-party packages and their lifecycle scripts, `eval`/dynamic imports, generated code, command
  substitution and shell features beyond the supported subset are *unknown*; the result depends on `unknown_policy`.
* **Taint is coarse.** Only WebFetch/WebSearch/MCP results are taint sources; reading an attacker-controlled *workspace file* is not.
  Taint is per session. An attacker who gets the model to launder through its own (non-hooked) tools escapes the ledger.
* **Content signals are regexes.** Payloads without a network/secret keyword (e.g. `/dev/tcp`) rely on the "agent-authored + untrusted
  lineage → ask" rule, which is an *escalation*, not a block.
* **Ask is not prevention.** Under naive click-through (`approve-all`) escalations fail open. Evidence quality only matters if a human reads it.
* **Surfaces the hook cannot see.** IDE/editor-triggered execution and OS-level behaviour (no sensors are active in this harness).
* **Host access.** If the agent can read/write the ledger directory via tools that bypass hooks, state can be forged.
* **Evaluation limits.** Replayed scripted actions, one operating system, a development set written by the defence author and a holdout set
  that is *not* independent (see `docs/HOLDOUT.md`).
