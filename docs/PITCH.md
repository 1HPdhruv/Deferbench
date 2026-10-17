# Pitch material

Audience: hackathon judges. All numbers are in the README's measured-results table and in `results/final/`; this page does not restate them so they cannot drift.

## 30-second pitch
DeferBench is a focused, reproducible evaluation of how security controls for AI coding agents handle one specific problem: content an agent writes
now that a trusted developer tool executes later. Instead of asking a model or judging text, it runs each scenario for real in a disposable repository
and checks an objective signal: did a synthetic secret reach a local-only sink? It also counts how often each control gets in the way of normal
development. Handoff, our reference defence, is there to make the comparison meaningful, not as the headline.

## Two-minute explanation
* **Unit of evaluation: the control, not the model.** Agent steps are replayed deterministically, so differences between rows are differences between controls.
* **Observed ground truth.** Each run ends with a real execution and a canary check at 127.0.0.1. Scenarios whose undefended run does not reproduce are INVALID and excluded.
* **Separate measures.** Attacks stopped before execution, residual leaks, benign interruptions, whether the evidence names the executing file, and provenance
  attribution are reported separately. Ask and block are reported separately, with and without a click-through reviewer.
* **Ablation built in.** The same resolver runs with and without provenance. Result: prevention is the same; provenance adds traceability and its default policy
  adds a few benign interruptions.
* **Real comparison points.** Released Gensee Crate, Gryph and Runmark binaries run through their documented hook entry points (hook-only, default policies), plus
  a denylist, a blanket rule and the original v0 prototype.

## Three-minute live demo
| time | command | what to point at |
|---|---|---|
| 0:00 | `python -m deferbench validate` | 40 scenarios (16 attack, 14 benign, 10 edge); validation OK |
| 0:20 | `python -m deferbench demo` | step 2: the scenario story (untrusted read, agent change, trusted tool) |
| 0:50 | (same run) | step 3: no defence, canary observed at the loopback sink |
| 1:20 | (same run) | steps 4–5: stateless resolver and Handoff both block before execution; compare their evidence (Handoff adds the authoring step and untrusted source) |
| 1:50 | (same run) | step 6: a benign workflow allowed by all three; step 7: comparison table |
| 2:20 | open `results/final/dashboard.html` | "Stateless resolver vs. Handoff" panel; click a matrix cell for the timeline; the independence banner |
If live output differs from this script, show the live output. Fallback: `python -m deferbench demo --fallback` (clearly labelled as recorded).

## Closest existing work (see docs/NOVELTY_AUDIT.md §§1, 8)
AgentCanary (arXiv:2606.10484) evaluates agents in real environments and compares three runtime defences, using an LLM judge. IssueTrojanBench
(arXiv:2607.20759) measures whether coding agents follow malicious issue text. SandboxEscapeBench (ICML 2026) measures container escape. AgentTrust
(arXiv:2605.04785) evaluates one runtime interceptor's verdict accuracy. HOL Guard's coding-agent benchmark compares policies on 11 policy-evaluated fixtures.
Gensee Crate documents provenance of agent-authored artifacts; Gryph provides session-scoped policy; Runmark reports pre-execution command facts.

## Qualified differentiation claim
A small, deterministic, execution-verified benchmark of *security controls* against delayed execution through trusted developer tools, reporting
canary-verified prevention, benign disruption, common evidence and provenance attribution separately. We do not claim the first agent-security benchmark,
a novel provenance mechanism, or independent validation.

## Hard questions
1. **"Your stateless resolver matches Handoff. What did provenance buy?"** No extra prevention on any of our sets. It buys traceability (which step wrote the
   content, after which untrusted input) and, on the provisional holdout, two cases the stateless resolver missed. Its default policy also interrupts more benign work.
   That is why Handoff is a reference, not the contribution.
2. **"Who wrote the scenarios?"** The defence author wrote the development set; an isolated model instance wrote the confirmatory set. Neither is human-independent.
   `independent_eval/PROTOCOL.md` defines the process for a human evaluator, and the dashboard says this on every view.
3. **"Aren't the third-party tools just mis-configured?"** They ran hook-only with default policies, and some never claim this coverage. The rows describe those
   configurations, not the products; a full-product test (e.g. with Gensee's OS sensor) is future work.

## Limitations and next steps
Scripted actions, one OS, partial static resolution, hook-only third-party runs, no human-independent holdout. Next: a human-authored holdout with new
mechanism families, and a full-product run of the strongest existing tool.
