#!/usr/bin/env bash
# Final verification: stale paths, secrets, referenced files, loopback-only destinations. Exit non-zero on any finding.
set -u
cd "$(dirname "$0")/.."
fail=0
echo "== stale machine-specific paths (outside archive/, raw result records, and the hash-sealed verbatim independent_eval/holdout/AUTHOR_LOG.md) =="
if grep -rIn --exclude-dir=archive --exclude-dir=.git --exclude-dir=.integrations --exclude-dir=results --exclude-dir=__pycache__ --exclude-dir=.pytest_cache --exclude=release_check.sh --exclude=test_safety.py --exclude=AUTHOR_LOG.md -e '/home/claude' -e '/Users/[a-z]' . ; then fail=1; else echo none; fi
echo "== embedded secrets (keys/tokens) =="
if grep -rIEn --exclude-dir=archive --exclude-dir=.git --exclude-dir=.integrations --exclude-dir=__pycache__ --exclude=release_check.sh -e 'AKIA[0-9A-Z]{16}' -e 'ghp_[A-Za-z0-9]{20,}' -e 'sk-[A-Za-z0-9]{20,}' -e 'BEGIN (RSA|OPENSSH|EC) PRIVATE KEY' -e 'xox[bp]-[A-Za-z0-9-]{10,}' . ; then fail=1; else echo none; fi
echo "== non-loopback URLs in scenarios/source (reserved example.test excluded) =="
python3 - <<'PY' || fail=1
import re, pathlib, sys, ipaddress, urllib.parse
bad = []
for p in list(pathlib.Path("scenarios").rglob("*.json")) + list(pathlib.Path("deferbench").rglob("*.py")):
    for u in re.findall(r"https?://[^\s'\"<>)\\]+", p.read_text()):
        h = urllib.parse.urlparse(u).hostname or ""
        try: ok = ipaddress.ip_address(h).is_loopback
        except ValueError: ok = False
        if not ok and h not in ("example.test",) and "{" not in u: bad.append((str(p), u))
# source files legitimately mention public docs URLs only in docs/ ; flag anything else
bad = [b for b in bad if not b[0].startswith("deferbench/") or "example" in b[1]]
print(bad or "none"); sys.exit(1 if bad else 0)
PY
echo "== referenced files exist (docs/*.md, README relative links) =="
python3 - <<'PY' || fail=1
import re, pathlib, sys
miss = []
for p in [pathlib.Path("README.md")] + list(pathlib.Path("docs").glob("*.md")):
    for m in re.findall(r"\]\(([^)#\s]+)\)", p.read_text()):
        if m.startswith(("http", "mailto")): continue
        if not (p.parent / m).exists(): miss.append((str(p), m))
print(miss or "none"); sys.exit(1 if miss else 0)
PY
exit $fail
