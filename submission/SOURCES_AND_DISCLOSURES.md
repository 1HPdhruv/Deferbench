# Sources and disclosures

Applies to the DeferBench idea-submission deck (`DeferBench_Idea_Submission.pptx` / `.pdf`) and the project it describes.
No third-party project named here has endorsed, reviewed, or partnered with DeferBench.

## 1. What is original and what is not

| item | status |
|---|---|
| `deferbench/` Python package (scenario engine, harness, metrics, reporting, CLI), `scenarios/`, `tests/`, `docs/`, `scripts/` | Original project code, MIT licence (`LICENSE`). Written with AI assistance (see §5). |
| Handoff reference defence (`deferbench/defenses/handoff.py`, `resolver.py`, `ledger.py`, `surfaces.py`) and the stateless resolver / denylist / blanket baselines | Original code. Handoff is a reference defence under evaluation, **not** claimed as a novel invention (provenance of agent-authored artifacts is documented by Gensee Crate). |
| `deferbench/adapters/{gensee,gryph,runmark}.py` | Original thin wrappers that call third-party binaries through their documented hook command lines. They contain none of those tools' code. |
| `deferbench/adapters/v0.py`, `archive/v0/` | Wrapper and archive of the team's own earlier prototype. |
| Gensee Crate v0.3.3 CLI, Gryph v0.9.0, Runmark v0.1.0-spike.2 | **Third-party tools, not ours.** Downloaded on demand by `scripts/fetch_integrations.sh` (checksum-verified against each release), run unmodified in an isolated home directory, hook-only, default policies, and **not redistributed** in the repository or ZIP. All three are Apache-2.0 per their repositories. |
| Deck design | Based on the Figma Community file "Hackathon Presentation Slide Deck": https://www.figma.com/design/kcV1VcAXvb8AKoIKlrc8xN/Hackathon-Presentation-Slide-Deck--Community- . Slide order, layouts, gradient, dot grid, rail, timeline curves and planet graphic come from that file (graphics downloaded into `submission/assets/template/`). Its licence terms were not stated in the material available to us; check the Figma file's page before redistributing the template-derived assets. All slide text and the diagrams are original and editable. |

## 2. Related work (read for this submission; links as supplied)

| source | how it was reviewed | used for |
|---|---|---|
| AgentCanary — https://arxiv.org/abs/2606.10484 | full paper text read (HTML version) | related benchmark: agents in real executable environments; compares three runtime defences |
| IssueTrojanBench — https://arxiv.org/abs/2607.20759 | abstract page only | related benchmark: coding agents following malicious issue requests |
| SandboxEscapeBench — https://proceedings.mlr.press/v306/marchand26a.html | abstract page and the benchmark repository README | related benchmark: container sandbox escape |
| Gensee Crate — https://github.com/GenseeAI/gensee-crate | repository docs (`docs/policy.md`, `docs/lineage-graph.md`) read; released CLI executed | related control; documents artifact provenance |
| Gryph — https://github.com/safedep/gryph | README and `docs/security-policy.md` read; released binary executed | related control; policy rules over session counters |
| Runmark — https://github.com/phaethix/runmark | repository description and released binary's usage output; binary executed | related control; pre-execution command facts |

We did not read the source code of any of the six projects. Statements about them are limited to what their papers/documentation say and what their released binaries did in our harness. More detail and dates: `docs/NOVELTY_AUDIT.md`.

## 3. Results shown on the slides

* Source: `results/final/development_release_rerun/results.json` (run `20261013T115905Z-bde81a`; 40 scenarios × 2 payload styles; 0 invalid, 0 errors). Every number on slide 6 is read from that file by `submission/build/build_deck.py`; `submission/build/` also contains the checker used before export.
* The confirmatory-run figures that appear only in speaker notes come from `independent_eval/results/*/results.json`.
* Scenario authorship: development scenarios by the defence author; confirmatory scenarios by an isolated model instance. **Neither is human-independent; human-independent evaluation is pending.**
* Third-party rows are hook-only, default-policy configurations. They are not comparisons of the full products (e.g. Gensee's OS-level sensor was not active).

## 4. Software and fonts

| component | role | licence | in deliverables? |
|---|---|---|---|
| Python standard library | DeferBench runtime (`dependencies = []` in `pyproject.toml`) | PSF | no (user's Python) |
| pytest ≥7,<9 | DeferBench tests (`dev` extra) | MIT | no |
| git, make, node/npm, curl | invoked inside generated disposable test workspaces | their own licences | no |
| python-pptx | builds the .pptx | MIT | no (build tool) |
| Pillow, NumPy | render template backgrounds | HPND / BSD-3-Clause | no (build tools) |
| LibreOffice 26.8.1 | converts the .pptx to the PDF; run from a scratch folder, not installed | MPL-2.0 | no |
| PyMuPDF, fontTools | verification and render-only font instancing | AGPL-3.0 / MIT | no (never distributed) |
| DM Sans, DM Serif Display | deck fonts (both also used by the Figma template) | SIL OFL 1.1 | yes, in `submission/assets/fonts/` with their licence texts |

The Figma template's heading and body fonts (Nohemi, Aeonik Pro TRIAL) are commercial/trial fonts and are **not** used or included; DM Sans is the substitute. To see the PPTX exactly as exported, install the fonts in `submission/assets/fonts/` before opening it (the PDF already embeds them).

## 5. AI tools

* **Claude (Anthropic), used through Claude Code** wrote most of the DeferBench code, tests, documentation, scenario files and this deck (including reading the Figma template through its Figma integration), under the team's direction. One isolated Claude subagent authored the model-authored confirmatory scenarios in `independent_eval/holdout/`.
* **No AI model runs inside DeferBench or Handoff.** The reference defence is rules-based and the evaluation replays scripted agent actions. An optional LLM classifier was proposed but is not implemented.

## 6. Items the team must complete before submitting

* Team slide: replace `[Team Member 1 Name]`, `[Team Member 2 Name]` and the photo placeholders. The roles shown are suggestions from `docs/TEAM_PLAN.md`, not recorded assignments.
* Add a repository URL to the closing slide only if the code is published; none is recorded in the project files, so none is shown.
