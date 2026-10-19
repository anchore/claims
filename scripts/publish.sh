#!/usr/bin/env bash
# publish.sh <digest> <zip>
#
# Publishes a snapshot built by bundle.sh from HEAD, in the layout yardstick's remote claims
# source reads:
#
#   claims/snapshots/<hex>.zip        the snapshot, never overwritten
#   claims/commits/<sha>.json         {"digest"} for HEAD
#   claims/latest-<format>.json       {"digest","commit"} for what publish.yaml says, written last
#
# the format comes from publish.yaml. Needs R2_BUCKET, plus the aws cli's own AWS_ACCESS_KEY_ID,
# AWS_SECRET_ACCESS_KEY and AWS_ENDPOINT_URL. DRY_RUN=1 prints each write instead of making it.
set -euo pipefail

digest=$1
zip=$2
: "${R2_BUCKET:?}"
hex=${digest#sha256:}
commit=$(git rev-parse HEAD)
root=$(cd "$(dirname "$0")/.." && pwd)

put() {
  if [ "${DRY_RUN:-}" = 1 ]; then
    echo "would put s3://$R2_BUCKET/$1 ($2): $(head -c 200 "$4")"
    return
  fi
  aws s3api put-object --bucket "$R2_BUCKET" --key "$1" --content-type "$2" --cache-control "$3" --body "$4" "${@:5}" >/dev/null
}

record() {
  printf '%s\n' "$1" >"$work/$2"
  echo "$work/$2"
}

format=$(sed -n 's/^format:[[:space:]]*//p' "$root/publish.yaml" | tr -d "\"' ")
if ! grep -Eq '^v[0-9]+$' <<<"$format"; then
  echo "publish.yaml: format is \"$format\"; want a major like v1" >&2
  exit 1
fi
# a file in another MODEL would be published under the wrong pointer; a file says 1.2.0 where
# publish.yaml says v1
stray=$(grep -rLE "\"schema\": *\"${format#v}\\.[0-9]+\\.[0-9]+\"" --include='*.json' --exclude='sbom*.json' "$root/pkg" $([ -d "$root/global" ] && echo "$root/global") || true)
if [ -n "$stray" ]; then
  echo "these files are not in format $format, which publish.yaml names:" >&2
  echo "$stray" >&2
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# a snapshot is named by its digest, so one already there holds these bytes
if ! err=$(put "claims/snapshots/$hex.zip" application/zip "public, max-age=31536000, immutable" "$zip" --if-none-match '*' 2>&1); then
  if ! grep -q PreconditionFailed <<<"$err"; then
    echo "$err" >&2
    exit 1
  fi
  echo "snapshot $digest was already published"
else
  [ -n "$err" ] && echo "$err"
  echo "published snapshot $digest"
fi

body=$(printf '{"digest":"%s"}' "$digest")
put "claims/commits/$commit.json" application/json no-cache "$(record "$body" commit.json)"
echo "recorded $commit as $digest"

pin=$(sed -n 's/^latest:[[:space:]]*//p' "$root/publish.yaml" | tr -d "\"' ")
case "$pin" in
  main)
    latest_commit=$commit latest_digest=$digest
    ;;
  *)
    if ! grep -Eq '^[0-9a-f]{40}$' <<<"$pin"; then
      echo "publish.yaml: latest is \"$pin\"; want main or a full 40-character commit sha" >&2
      exit 1
    fi
    if ! git merge-base --is-ancestor "$pin" "$commit"; then
      echo "publish.yaml: latest is pinned to $pin, which is not a commit on main" >&2
      exit 1
    fi
    if [ "${DRY_RUN:-}" = 1 ]; then
      latest_digest="<the digest in claims/commits/$pin.json>"
    else
      latest_digest=$(aws s3 cp "s3://$R2_BUCKET/claims/commits/$pin.json" - | sed -n 's/.*"digest":"\([^"]*\)".*/\1/p')
    fi
    if [ -z "$latest_digest" ]; then
      echo "publish.yaml: latest is pinned to $pin, but no snapshot was published for it" >&2
      exit 1
    fi
    latest_commit=$pin
    ;;
esac

body=$(printf '{"digest":"%s","commit":"%s"}' "$latest_digest" "$latest_commit")
put "claims/latest-$format.json" application/json no-cache "$(record "$body" latest.json)"
echo "latest-$format is $latest_digest (commit $latest_commit)"
