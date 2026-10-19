#!/usr/bin/env bash
# bundle.sh <out dir>
#
# Zips the claims corpus in this repo as a published snapshot: the corpus files at their paths
# relative to the repo root, entries sorted, one fixed time and mode, no directory entries and no
# extra fields, so one commit always zips to the same bytes. The zip is written to <out dir> named
# by its sha256, and the digest is printed as sha256:<hex>.
#
# Only the corpus is bundled. Everything else here (scripts, CI, docs) is repo plumbing that
# yardstick has no business reading.
set -euo pipefail

# what a claims source holds, per yardstick's corpus layout
CORPUS_PATHS=(catalog.yaml vocabulary.yaml pkg sbom global)

root=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$1"
out=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# a copy, so normalizing times and modes leaves the checkout alone
mkdir "$work/tree"
for p in "${CORPUS_PATHS[@]}"; do
  if [ -e "$root/$p" ]; then
    cp -R "$root/$p" "$work/tree/"
  fi
done
cd "$work/tree"
find . -type f -exec chmod 0644 {} +
find . -type d -exec chmod 0755 {} +
# zip stores local time: pin the zone so every machine writes the same timestamps
export TZ=UTC
find . -exec touch -t 198001010000.00 {} +
find . -type f | sed 's#^\./##' | LC_ALL=C sort | zip -X -D -q -@ "$work/claims.zip"

digest=$(shasum -a 256 "$work/claims.zip" | cut -d' ' -f1)
mv "$work/claims.zip" "$out/$digest.zip"
echo "sha256:$digest"
