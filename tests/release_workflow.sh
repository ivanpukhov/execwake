#!/usr/bin/env bash
set -euo pipefail

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow=$repository/.github/workflows/release.yml

publish_job=$(sed -n '/^  publish:/,$p' "$workflow")

if [[ "$publish_job" != *'gh release create --repo "$GITHUB_REPOSITORY" "${release_args[@]}"'* ]]; then
  echo "release publishing must select the repository explicitly" >&2
  exit 1
fi

if [[ "$publish_job" == *'--clobber'* ]]; then
  echo "release publishing must not overwrite existing assets" >&2
  exit 1
fi

if [[ "$publish_job" != *'--verify-tag'* || "$publish_job" != *'--prerelease'* ]]; then
  echo "release publishing must verify tags and mark prereleases" >&2
  exit 1
fi

echo "Release workflow checks passed"
