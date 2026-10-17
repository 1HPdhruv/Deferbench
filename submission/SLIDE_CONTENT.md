# Slide content (generated from DeferBench_Idea_Submission.pptx)

9 slides, 16:9 (1920x1080 design px). Template: Figma community file "Hackathon Presentation Slide Deck"; layout used per slide is listed.


## Slide 1 — template layout: Project name

- AI & CYBERSECURITY
- DeferBench
- Benchmarking Delayed-Execution Risks in AI-Assisted Development
- Testing whether security controls stop AI-authored code from causing unintended execution through trusted developer tools.

**Speaker notes**

DeferBench: Benchmarking Delayed-Execution Risks in AI-Assisted Development. Hackathon theme: AI & Cybersecurity.

One-line message: we test whether security controls stop AI-authored changes from causing unintended execution through trusted developer tools.

Status to state out loud: development results come from scenarios written by the defence author; human-independent evaluation is pending.

## Slide 2 — template layout: Problem statement (4 cards)

- The command looks safe. What it executes may not be.
- 1
- 2
- 3
- 4
- Untrusted input
- Agent-authored change
- Trusted tool executes it
- Unintended execution
- An AI coding agent reads an untrusted issue or document.
- It modifies a project script or configuration file.
- Later, npm test, make build or pytest runs that content.
- The effect goes beyond what the command line reveals.
- EXAMPLE
- npm test
- package.json gained a pretest script, edited by the agent
- It runs a command the developer never reviewed
- Illustrative scenario class, not a claim that every coding agent or approval system is vulnerable.

**Speaker notes**

Walk the four steps left to right. The example: `npm test` is a normal command, but an earlier agent edit added a `pretest` script to package.json, so the tool runs content the developer never reviewed.

Caveat to say: this is a scenario class we study; it is not a claim that every coding agent or every approval system is vulnerable.

## Slide 3 — template layout: heading (title + panel)

- Can security controls stop delayed execution?
- THE GAP
- RESEARCH QUESTION
- Controls look at different things: commands, policies, artifact provenance. We need one reproducible way to compare what each one actually does on the same scenarios.
- Does the control prevent the effect, and what does it cost legitimate work?
- Related benchmarks and controls already exist (AgentCanary, IssueTrojanBench, Gensee Crate, Gryph, Runmark). Our proposed distinction: delayed execution through trusted developer tools, observed prevention, and benign-workflow disruption. Novelty of this combination: not yet independently validated.

**Speaker notes**

Research question: do controls actually stop the effect, and what does that cost legitimate work?

Related work exists and we cite it: AgentCanary (arXiv:2606.10484) evaluates agents in real executable environments and compares three runtime defences; IssueTrojanBench (arXiv:2607.20759) measures coding agents following malicious issues; SandboxEscapeBench (ICML 2026, PMLR v306) measures container escape. Controls: Gensee Crate, Gryph, Runmark.

Our proposed distinction is narrow: delayed execution through trusted developer tools, observed prevention, benign-workflow disruption. Novelty of that combination is not independently validated.

## Slide 4 — template layout: Timeline

- DeferBench: Test the defence, not just the alert.
- Baseline check first. Every scenario runs undefended; if its expected effect does not reproduce, it is marked invalid and never counted as a defence success.
- Scenario generator
- Security controls
- Comparative report
- Fixed attack, benign and edge scenarios
- Includes Handoff, our reference defence
- Prevention, leaks, benign disruption, evidence
- Disposable workspace
- Canary verification
- Fresh git repo with a synthetic canary secret
- The trusted command really runs; a loopback sink watches

**Speaker notes**

Each scenario is a fixed, replayable JSON file. The harness builds a fresh git workspace with a synthetic canary secret, plays the agent's steps into the control, then really runs the trusted command.

A loopback-only sink (127.0.0.1) reports whether the canary left. Before any control is scored, the scenario is run undefended; if the expected effect does not reproduce it is INVALID and excluded.

Handoff is one control under evaluation (execution-path resolver + provenance ledger), not the whole product. Current run: 40 scenarios (16 attack, 14 benign, 10 edge) x 2 payload styles, 0 invalid.

## Slide 5 — template layout: Flowchart

- Measure prevention, usability, and traceability.
- SECURITY CONTROLS UNDER TEST
- Path denylist protected files only
- Stateless resolver execution-path resolver
- Canary verification real run, 127.0.0.1 sink only
- Scenario runner scripted agent actions
- Handoff (reference) resolver + provenance ledger
- Third-party, hook-only Gensee · Gryph · Runmark
- Results engine JSON, CSV, HTML dashboard
- Stateless resolver and Handoff share one resolver; Handoff adds provenance.
- Implemented today
- Where the AI comes in
- Not implemented
- Python package and CLI · scripted scenario replays · synthetic canary verification · JSON and CSV reports · HTML dashboard · automated tests and documented commands
- The benchmark evaluates risks created by AI-assisted coding. Agent actions are scripted so results are reproducible. Handoff is rules-based.
- Optional LLM classifier (proposed only) · live-agent runs · human-independent evaluation

**Speaker notes**

Components: scenario runner (JSON scenarios, scripted agent actions), security-control baselines (path denylist; stateless execution-path resolver; Handoff = same resolver + provenance ledger; third-party tools run through their hook entry points), a synthetic canary and a loopback-only sink, and a results engine that writes JSON and CSV and feeds an HTML dashboard.

Implementation facts: Python package and CLI, no runtime dependencies beyond the standard library; automated tests; documented reproduction commands (README.md).

AI honesty: the benchmark evaluates risks created by AI-assisted coding. The evaluation replays scripted agent actions for reproducibility; no live model is in the loop. Handoff is rules-based. An optional LLM classifier was proposed but is not implemented.

Third-party tools (Gensee Crate CLI, Gryph, Runmark) are separate projects run unmodified through adapters we wrote; they are not our code.

## Slide 6 — template layout: Diagrams (panel)

- Handoff improves traceability, not proven prevention.
- Attack runs prevented
- canary never reached the sink · higher is better
- Tie on prevention.
- Stateless resolver
- 44/44
- Handoff
- 44/44
- Handoff adds attribution evidence, but its added value over the stateless resolver has not been established.
- Benign workflows interrupted
- lower is better
- Stateless resolver
- 2/26
- Handoff
- 2/26
- Provenance attribution
- which agent step wrote the content, after which untrusted input
- Development-authored scenarios. Human-independent evaluation pending.
- Stateless resolver
- not provided by design
- Handoff
- 37/44
- Run 20261013T115905Z-bde81a: 40 scenarios × 2 payload styles, 0 invalid runs. Counted as prevented when a control asks or denies and a reviewer rejects asks; if every ask is approved: Handoff 38/44, stateless resolver 40/44. Other controls (default policy, hook-only; configurations, not product comparisons): Gensee 7/44, Gryph 0/44, Runmark 0/44.

**Speaker notes**

Source: results/final/development_release_rerun/results.json, run 20261013T115905Z-bde81a; 40 scenarios (16 attack, 14 benign, 10 edge) x 2 payload styles; 0 invalid runs. Rates pool the two payload styles, so n counts scenario x style, not independent attacks.

Stateless resolver: prevented 44/44 attack runs, interrupted 2/26 benign runs. Handoff: prevented 44/44, interrupted 2/26; provenance attribution 37/44.

If every ask is approved by a reviewer: Handoff 38/44, stateless resolver 40/44.

Other controls (default policies, hook-only, not product comparisons): path denylist 4/44; Gensee Crate v0.3.3 7/44; Gryph v0.9.0 0/44; Runmark v0.1.0-spike.2 0/44; blanket 'block after any write' rule 40/44 attacks prevented but 26/26 benign interrupted.

Independence: development-authored scenarios; neither this set nor the confirmatory set is human-independent. Human-independent evaluation is pending.

Model-authored confirmatory run 20261013T112557Z-42397e (isolated model instance wrote the scenarios; 12 attack scenarios and 6 benign scenarios, 2 repeats each): attack trials prevented: stateless resolver 24/24, Handoff 24/24; benign trials interrupted: stateless resolver 0/12, Handoff 4/12.

## Slide 7 — template layout: Future scopes (4 cards)

- Related work and limits
- Related benchmarks
- Related controls
- 1
- 2
- AgentCanary: agents in real executable environments, compares three runtime defences. IssueTrojanBench: agents following malicious issues. SandboxEscapeBench: container escape.
- Gensee Crate documents artifact provenance; Gryph provides policy rules; Runmark reports pre-execution command facts. We ran released tools hook-only with default policies.
- 3
- Our qualified claim
- 4
- Limits and open work
- A focused, execution-verified comparison of controls for delayed execution through trusted developer tools. Novelty of the combination is not independently validated.
- Scripted agent actions, not live agents · one OS (macOS) · scenarios written by the defence author · human-independent evaluation pending.
- Sources: AgentCanary arXiv:2606.10484 · IssueTrojanBench arXiv:2607.20759 · SandboxEscapeBench PMLR v306 (ICML 2026) · github.com/GenseeAI/gensee-crate · github.com/safedep/gryph · github.com/phaethix/runmark

**Speaker notes**

Related benchmarks (read for this submission): AgentCanary arXiv:2606.10484 (full paper read: agents in real executable environments; compares three runtime defences; LLM-judge scoring); IssueTrojanBench arXiv:2607.20759 (abstract read: coding agents following malicious issue requests); SandboxEscapeBench, ICML 2026, PMLR v306 (abstract and repository README read: container sandbox escape).

Related controls: Gensee Crate (documents artifact provenance), Gryph (policy rules over session counters), Runmark (pre-execution command facts). We ran released command-line tools through their hook entry points with default policies; no endorsement or partnership is implied.

Full list of third-party tools, fonts, dependencies and AI tools: submission/SOURCES_AND_DISCLOSURES.md.

## Slide 8 — template layout: Team members (4 cards -> 2)

- The Team
- Add photo
- Add photo
- [Team Member 1 Name]
- [Team Member 2 Name]
- Suggested role: defence and resolver (Handoff)
- Suggested role: benchmark, scenarios and reporting

**Speaker notes**

Exactly two team members. Names and photos are editable placeholders because no names are recorded in the project documentation; replace them before submitting.

Roles shown are suggested from docs/TEAM_PLAN.md (defence/resolver work vs benchmark/scenarios/reporting), not recorded assignments.

## Slide 9 — template layout: Thank you

- DeferBench
- Making delayed-execution security measurable.

**Speaker notes**

Closing. Repository link intentionally omitted: no public repository URL is recorded in the project files. Add one here if the team publishes the code.
