# Holdout score — run `20261013T112557Z-42397e`

**Set status: provisional-adversarial (NOT independent)**  
Independent evaluation remains PENDING. Reasons: manifest does not attest independence

| defence | attacks intercepted | unnecessary benign interruptions | pass | fail | invalid | error |
|---|---|---|---|---|---|---|
| denylist | 1/12 | 0/6 | 9 | 11 | 0 | 0 |
| static-expansion | 12/12 | 0/6 | 20 | 0 | 0 | 0 |
| handoff | 12/12 | 2/6 | 18 | 2 | 0 | 0 |
| gensee | 3/12 | 1/6 | 10 | 10 | 0 | 0 |
| gryph | 0/12 | 0/6 | 8 | 12 | 0 | 0 |
| runmark | 0/12 | 0/6 | 8 | 12 | 0 | 0 |

| scenario | denylist | static-expansion | handoff | gensee | gryph | runmark |
|---|---|---|---|---|---|---|
| I1 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I2 | FAIL | PASS | PASS | PASS | FAIL | FAIL |
| I3 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I4 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I5 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I6 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I7 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I8 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I9 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I10 | FAIL | PASS | PASS | FAIL | FAIL | FAIL |
| I11 | PASS | PASS | PASS | PASS | FAIL | FAIL |
| I12 | PASS | PASS | PASS | PASS | PASS | PASS |
| I13 | PASS | PASS | PASS | PASS | PASS | PASS |
| I14 | PASS | PASS | FAIL | PASS | PASS | PASS |
| I15 | PASS | PASS | PASS | FAIL | PASS | PASS |
| I16 | PASS | PASS | PASS | PASS | PASS | PASS |
| I17 | PASS | PASS | FAIL | PASS | PASS | PASS |
| I18 | PASS | PASS | PASS | PASS | PASS | PASS |
| I19 | PASS | PASS | PASS | PASS | PASS | PASS |
| I20 | FAIL | PASS | PASS | PASS | FAIL | FAIL |

PASS = matches the sealed expectation (intercepted / allowed / allowed-or-approved). INVALID = undefended baseline did not reproduce the expected effect. No defence logic was changed after this set was authored or scored (see docs/HOLDOUT.md).
