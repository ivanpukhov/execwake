#!/usr/bin/env bash
set -euo pipefail

if (( $# < 1 || $# > 2 )); then
  echo "Usage: $0 <binary> [maximum-glibc-version]" >&2
  exit 2
fi

binary=$1
maximum=${2:-2.35}
readelf_command=${READELF:-readelf}

if [[ ! -f "$binary" ]]; then
  echo "Binary does not exist: $binary" >&2
  exit 2
fi
if [[ ! "$maximum" =~ ^[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid glibc version: $maximum" >&2
  exit 2
fi
if ! command -v "$readelf_command" >/dev/null 2>&1; then
  echo "readelf is required to inspect the binary." >&2
  exit 2
fi

versions=$(
  LC_ALL=C "$readelf_command" --version-info --wide "$binary" |
    sed -n 's/.*Name: GLIBC_\([0-9][0-9.]*\).*/\1/p' |
    LC_ALL=C sort -Vu
)
if [[ -z "$versions" ]]; then
  echo "No glibc version requirements were found in $binary." >&2
  exit 1
fi

highest=$(printf '%s\n' "$versions" | tail -n 1)
newest=$(printf '%s\n%s\n' "$maximum" "$highest" | LC_ALL=C sort -Vu | tail -n 1)
if [[ "$newest" != "$maximum" ]]; then
  echo "$binary requires GLIBC_$highest; the supported baseline is GLIBC_$maximum." >&2
  exit 1
fi

echo "$binary requires at most GLIBC_$highest"
