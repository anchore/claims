#!/usr/bin/env bash
# validate_changed.sh [<base>]
#
# Validates only what changed since <base> (default $BASE, else origin/main): the image
# directories under pkg/oci/ the diff touches, with catalog.yaml, vocabulary.yaml, global/ and
# sbom/, as a corpus of their own under .tmp/changed. Only those images' SBOMs are fetched.
#
# Every check yardstick runs is per file or per image directory, so the subset validates the
# same as it would inside the whole corpus. A change to catalog.yaml or vocabulary.yaml can
# affect any label, and so can a new yardstick pinned in .binny.yaml, so any of those, or a base
# this clone does not hold, validates the whole corpus.
set -euo pipefail

base=${1:-${BASE:-origin/main}}
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/.tmp/changed"
cd "$root"

if ! git rev-parse --verify -q "$base^{commit}" >/dev/null; then
  echo "$base is not a commit here; validating the whole corpus"
  exec make validate-corpus
fi
changed=$(git diff --name-only "$base"...HEAD)
if grep -qxE 'catalog\.yaml|vocabulary\.yaml|\.binny\.yaml' <<<"$changed"; then
  echo "catalog.yaml, vocabulary.yaml or .binny.yaml changed since $base; validating the whole corpus"
  exec make validate-corpus
fi

# image directories still in the tree, so a removed image is not validated. A changed label file
# sits in a kind directory under its image's (matches/deb.json), so the image's is the sha256-<hex> one
dirs=()
while IFS= read -r d; do
  [ -d "$d" ] && dirs+=("$d")
done < <(grep '^pkg/oci/' <<<"$changed" | sed -nE 's#^(pkg/oci/.*/sha256-[0-9a-f]{64})/.*#\1#p' | sort -u)

echo "validating ${#dirs[@]} image directories changed since $base"
if [ ${#dirs[@]} -gt 0 ]; then
  python3 scripts/sboms.py fetch -v "${dirs[@]}"
fi

rm -rf "$out" && mkdir -p "$out"
cp catalog.yaml vocabulary.yaml "$out/"
for p in global sbom ${dirs[@]+"${dirs[@]}"}; do
  if [ -e "$p" ]; then
    mkdir -p "$out/$(dirname "$p")"
    cp -R "$p" "$out/$p"
  fi
done
.tool/yardstick claims validate "$out"
