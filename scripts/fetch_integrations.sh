#!/usr/bin/env bash
# Download third-party comparison tools into ./.integrations (gitignored), verifying each against the checksum file
# published in the same GitHub release. Nothing is installed system-wide and no agent hooks are modified.
# macOS arm64 only (the platform this project was measured on). Pinned versions below are the ones recorded in results.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; D="$ROOT/.integrations"; mkdir -p "$D"
GRYPH_V=v0.9.0; RUNMARK_V=v0.1.0-spike.2; GENSEE_V=v0.3.3
verify() { # file expected-sha
  got=$(shasum -a 256 "$1" | cut -d' ' -f1); [ "$got" = "$2" ] || { echo "CHECKSUM MISMATCH for $1" >&2; exit 1; }; }
want() { grep -E "$2" "$1" | head -1 | cut -d' ' -f1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
which=${1:-all}
if [ "$which" = all ] || [ "$which" = gryph ]; then
  b=https://github.com/safedep/gryph/releases/download/$GRYPH_V
  curl -fsSL -o "$tmp/c.txt" $b/checksums.txt; curl -fsSL -o "$tmp/g.tgz" $b/gryph_Darwin_all.tar.gz
  verify "$tmp/g.tgz" "$(want "$tmp/c.txt" gryph_Darwin_all.tar.gz)"; mkdir -p "$D/gryph"; tar -xzf "$tmp/g.tgz" -C "$D/gryph"; echo "gryph $GRYPH_V ok"
fi
if [ "$which" = all ] || [ "$which" = runmark ]; then
  b=https://github.com/phaethix/runmark/releases/download/$RUNMARK_V
  curl -fsSL -o "$tmp/r.txt" $b/SHA256SUMS.txt; curl -fsSL -o "$tmp/runmark" $b/runmark-darwin-arm64
  verify "$tmp/runmark" "$(want "$tmp/r.txt" runmark-darwin-arm64)"; mkdir -p "$D/runmark"; cp "$tmp/runmark" "$D/runmark/runmark"; chmod +x "$D/runmark/runmark"; echo "runmark $RUNMARK_V ok"
fi
if [ "$which" = all ] || [ "$which" = gensee ]; then
  b=https://github.com/GenseeAI/gensee-crate/releases/download/$GENSEE_V
  curl -fsSL -o "$tmp/s.txt" $b/SHA256SUMS.txt; curl -fsSL -o "$tmp/gc.dmg" $b/Gensee-Crate.dmg
  verify "$tmp/gc.dmg" "$(cut -d' ' -f1 "$tmp/s.txt" | head -1)"
  hdiutil attach -readonly -nobrowse -noverify -mountpoint "$tmp/mnt" "$tmp/gc.dmg" >/dev/null
  mkdir -p "$D/gensee"; cp "$tmp/mnt/Gensee Crate.app/Contents/Resources/bin/gensee" "$D/gensee/gensee"; hdiutil detach "$tmp/mnt" >/dev/null
  echo "$GENSEE_V" > "$D/gensee/VERSION"; echo "gensee $GENSEE_V ok (CLI only; the app's macOS Endpoint Security sensor is NOT installed or active)"
fi
