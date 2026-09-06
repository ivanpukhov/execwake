#!/usr/bin/env bash
set -euo pipefail

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow=$repository/.github/workflows/release.yml
ci_workflow=$repository/.github/workflows/ci.yml
reproducibility_script=$repository/scripts/verify-reproducible-package.sh
compatibility_script=$repository/scripts/verify-linux-compatibility.sh

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

if ! grep -Fq 'scripts/verify-reproducible-package.sh "$TARGET"' "$workflow"; then
  echo "release packages must pass the reproducibility check" >&2
  exit 1
fi
if ! grep -Fq 'scripts/verify-reproducible-package.sh "$EXECWAKE_TARGET"' "$ci_workflow"; then
  echo "CI packages must pass the reproducibility check" >&2
  exit 1
fi
if ! grep -Fq 'scripts/verify-linux-compatibility.sh "$ARCHIVE" "$TARGET" "$PLATFORM"' "$workflow"; then
  echo "release packages must pass distribution compatibility checks" >&2
  exit 1
fi
if ! grep -Fq 'scripts/verify-linux-compatibility.sh' "$ci_workflow"; then
  echo "CI packages must pass distribution compatibility checks" >&2
  exit 1
fi
if ! grep -Fq 'scripts/verify-glibc-baseline.sh' "$compatibility_script" ||
  ! grep -Fq 'debian:12-slim@sha256:' "$compatibility_script"; then
  echo "compatibility checks must enforce the glibc baseline and pinned Debian runtime" >&2
  exit 1
fi
if ! grep -Fq 'for build in first second' "$reproducibility_script" ||
  ! grep -Fq 'cmp -s "$first_archive" "$second_archive"' "$reproducibility_script"; then
  echo "the reproducibility check must compare two independent package builds" >&2
  exit 1
fi

echo "Release workflow checks passed"
