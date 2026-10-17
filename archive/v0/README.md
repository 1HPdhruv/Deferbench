# v0 — original hackathon prototype (preserved, unmodified)

Files here are byte-identical copies of the first release (see `SHA256SUMS.txt`). They were produced on a different machine
(`/home/claude/...` paths, GNU `sed`, a Linux layout) and **cannot run from this directory as-is** (`harness.py`, `summarize.py` hard-code those paths).
`handoff.py` is still executable and is run unmodified by the new harness as the `handoff-v0` defence for a same-harness comparison.

* `run_plain.log`, `run_signature.log`, `matrix.json`, `summary.md` are the **original v0 measurements**, kept for comparison; they were produced by a different harness, different
  policies per tool (including a custom blanket Gryph rule next to default policies) and on scenarios whose `signature` A1 was invalid (unescaped quotes). Do not compare them numerically with `results/final/`.
* Known v0 limitations, all addressed or documented in the new project: environment-specific paths; results written to a hard-coded directory; `shell=True`; `require()` blind spot (E1);
  hash-only attribution across files (B8 false positive); GNU-only `sed -i`; unequal policy strengths in one comparison table; a report mixing proposals with measurements.
