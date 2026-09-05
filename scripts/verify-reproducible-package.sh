#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <target> [destination]" >&2
  exit 2
fi
if [[ $(uname -s) != Linux ]]; then
  echo "Linux package reproducibility must be checked on Linux." >&2
  exit 2
fi

target=$1
case "$target" in
  x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu) ;;
  *)
    echo "unsupported Linux target: $target" >&2
    exit 2
    ;;
esac

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination=${2:-"$repository/dist"}
mkdir -p "$destination"
destination=$(CDPATH= cd -- "$destination" && pwd)
version=$(awk -F '"' '/^version = "/ { print $2; exit }' "$repository/Cargo.toml")
package="execwake-v${version}-${target}"
source_date_epoch=${SOURCE_DATE_EPOCH:-}
if [[ -z "$source_date_epoch" ]]; then
  source_date_epoch=$(git -C "$repository" log -1 --format=%ct 2>/dev/null || true)
fi
source_date_epoch=${source_date_epoch:-0}

test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

for build in first second; do
  mkdir -p "$test_root/$build/dist"
  CARGO_TARGET_DIR="$test_root/$build/target" \
    EXECWAKE_TARGET="$target" \
    SOURCE_DATE_EPOCH="$source_date_epoch" \
    "$repository/scripts/package-linux.sh" "$test_root/$build/dist"
done

first_archive="$test_root/first/dist/$package.tar.gz"
second_archive="$test_root/second/dist/$package.tar.gz"
if ! cmp -s "$first_archive" "$second_archive"; then
  echo "Linux package is not reproducible: $package" >&2
  sha256sum "$first_archive" "$second_archive" >&2
  exit 1
fi

"$repository/scripts/verify-linux-package.sh" "$first_archive" "$target"

archive="$destination/$package.tar.gz"
checksum="$archive.sha256"
if [[ -e "$archive" || -e "$checksum" ]]; then
  echo "Release output already exists: $archive" >&2
  exit 2
fi
install -m 0644 "$first_archive" "$archive"
install -m 0644 "$first_archive.sha256" "$checksum"

echo "Reproducible $package"
echo "$archive"
echo "$checksum"
