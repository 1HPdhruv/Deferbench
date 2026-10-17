# Safety guide

DeferBench runs *real* payloads (a `curl` that posts a file) in disposable workspaces. This is what keeps that safe, and what
you must not change.

* **Synthetic secrets only.** The only secret in any workspace is `API_KEY=ck_canary_<random>` in `.env`. No real `.env`, SSH,
  cloud or developer credentials are read. The sandbox environment (`deferbench/repo.py::sandbox_env`) passes only `PATH`, a
  temp `HOME`, and fixed npm/git settings; your shell's tokens are not inherited (`tests/test_safety.py` checks this).
* **Loopback-only destinations.** Every scenario's expanded text is scanned (`safety.assert_loopback_urls`); any URL whose host
  is not a literal loopback IP is rejected at load time. The sink binds `127.0.0.1` and refuses any other address. The only
  non-loopback URLs are `https://example.test/...` metadata for *simulated* web reads (reserved TLD, never requested).
* **No shell strings from scenarios.** Scenario files are JSON data. Simulated shell effects are a closed set of Python
  operations on workspace files. The final command is a string from an allow-list of programs, tokenised with `shlex` and run as
  an argv list — never `shell=True`. `sh/bash -c` is accepted only as `-c 'source FILE'`.
* **Bounded execution.** Each process runs in its own process group with a timeout (default 60 s, `DEFERBENCH_TIMEOUT`), a
  64 KiB output cap, a 20 MiB file-size limit and no core dumps; the group is killed afterwards (background children included).
* **Cleanup.** Workspaces live under a `deferbench-*` temp directory and are removed in a `finally` block. `deferbench clean`
  removes leftovers. `cleanup()` refuses to delete directories that are not `deferbench-*`.
* **Dry-run.** `--dry-run` replays decisions but never executes the final command.
* **Third-party tools.** `scripts/fetch_integrations.sh` downloads release binaries into `.integrations/` (gitignored) after verifying
  the SHA-256 published *in the same release* (this detects corruption, not a compromised release). They run with an isolated
  `HOME`, no agent hook installation, and receive only generated events. The Gensee macOS Endpoint Security sensor is **not**
  installed; only its hook CLI is run.
* **Never** point a scenario, payload or adapter at a real host, real credentials or a real repository. Do not weaken
  `safety.py` to make a scenario load; fix the scenario.
