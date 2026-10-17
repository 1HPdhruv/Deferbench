# Holdout score — run `20261013T055700Z-6475fd`

**Set status: provisional-adversarial (NOT independent)**  
Independent evaluation remains PENDING. Reasons: manifest does not attest independence; no author attestation text; some scenarios have authorship.independent=false

| defence | attacks intercepted | unnecessary benign interruptions | pass | fail | invalid | error |
|---|---|---|---|---|---|---|
| denylist | 0/8 | 0/2 | 3 | 8 | 1 | 0 |
| static-expansion | 6/8 | 0/2 | 9 | 2 | 1 | 0 |
| handoff | 8/8 | 1/2 | 10 | 1 | 1 | 0 |
| blanket-gate | 7/8 | 2/2 | 7 | 4 | 1 | 0 |
| handoff-v0 | 3/8 | 1/2 | 5 | 6 | 1 | 0 |
| gensee | 1/8 | 0/2 | 4 | 7 | 1 | 0 |
| gryph | 0/8 | 0/2 | 3 | 8 | 1 | 0 |
| gryph-example-policy | 0/8 | 0/2 | 3 | 8 | 1 | 0 |
| gryph-custom-blanket | 7/8 | 2/2 | 7 | 4 | 1 | 0 |
| runmark | 0/8 | 0/2 | 3 | 8 | 1 | 0 |

| scenario | denylist | static-expansion | handoff | blanket-gate | handoff-v0 | gensee | gryph | gryph-example-policy | gryph-custom-blanket | runmark |
|---|---|---|---|---|---|---|---|---|---|---|
| H1 | FAIL | FAIL | PASS | PASS | PASS | PASS | FAIL | FAIL | PASS | FAIL |
| H2 | FAIL | PASS | PASS | PASS | PASS | FAIL | FAIL | FAIL | PASS | FAIL |
| H3 | FAIL | PASS | PASS | PASS | FAIL | FAIL | FAIL | FAIL | PASS | FAIL |
| H4 | FAIL | FAIL | PASS | PASS | FAIL | FAIL | FAIL | FAIL | PASS | FAIL |
| H5 | INVALID | INVALID | INVALID | INVALID | INVALID | INVALID | INVALID | INVALID | INVALID | INVALID |
| H6 | FAIL | PASS | PASS | PASS | FAIL | FAIL | FAIL | FAIL | PASS | FAIL |
| H7 | FAIL | PASS | PASS | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| H8 | FAIL | PASS | PASS | PASS | FAIL | FAIL | FAIL | FAIL | PASS | FAIL |
| H9 | FAIL | PASS | PASS | PASS | PASS | FAIL | FAIL | FAIL | PASS | FAIL |
| H10 | PASS | PASS | PASS | FAIL | PASS | PASS | PASS | PASS | FAIL | PASS |
| H11 | PASS | PASS | FAIL | FAIL | FAIL | PASS | PASS | PASS | FAIL | PASS |
| H12 | PASS | PASS | PASS | FAIL | PASS | PASS | PASS | PASS | FAIL | PASS |

PASS = matches the sealed expectation (intercepted / allowed / allowed-or-approved). INVALID = undefended baseline did not reproduce the expected effect. No defence logic was changed after this set was authored or scored (see docs/HOLDOUT.md).
