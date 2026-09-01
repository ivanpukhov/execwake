#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <archive> <target>" >&2
  exit 2
fi

archive=$1
target=$2
case "$target" in
  x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu) ;;
  *)
    echo "unsupported Linux target: $target" >&2
    exit 2
    ;;
esac

if [[ ! -f "$archive" || ! -f "$archive.sha256" ]]; then
  echo "release archive or checksum is missing: $archive" >&2
  exit 1
fi

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(awk -F '"' '/^version = "/ { print $2; exit }' "$repository/Cargo.toml")
package=execwake-v${version}-${target}
if [[ $(basename -- "$archive") != "$package.tar.gz" ]]; then
  echo "unexpected release archive name: $(basename -- "$archive")" >&2
  exit 1
fi

archive_directory=$(CDPATH= cd -- "$(dirname -- "$archive")" && pwd)
(
  cd "$archive_directory"
  sha256sum --check "$package.tar.gz.sha256"
)

while IFS= read -r member; do
  case "$member" in
    "$package/" | \
      "$package/LICENSE" | \
      "$package/README.md" | \
      "$package/README.ru.md" | \
      "$package/benchmarks/" | \
      "$package/benchmarks/RESULTS.md" | \
      "$package/docs/" | \
      "$package/docs/assets/" | \
      "$package/docs/assets/execwake-report.gif" | \
      "$package/docs/assets/execwake-report.jpg" | \
      "$package/execwake") ;;
    *)
      echo "unexpected release archive member: $member" >&2
      exit 1
      ;;
  esac
done < <(tar -tzf "$archive")

for required in \
  "$package/" \
  "$package/LICENSE" \
  "$package/README.md" \
  "$package/README.ru.md" \
  "$package/benchmarks/" \
  "$package/benchmarks/RESULTS.md" \
  "$package/docs/" \
  "$package/docs/assets/" \
  "$package/docs/assets/execwake-report.gif" \
  "$package/docs/assets/execwake-report.jpg" \
  "$package/execwake"; do
  if [[ $(tar -tzf "$archive" | grep -Fxc -- "$required") -ne 1 ]]; then
    echo "release archive must contain exactly one $required" >&2
    exit 1
  fi
done

if tar -tvzf "$archive" | awk '$1 !~ /^[-d]/ { found = 1 } END { exit found ? 0 : 1 }'; then
  echo "release archive contains a non-regular entry" >&2
  exit 1
fi

staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
tar -xzf "$archive" -C "$staging" --no-same-owner --no-same-permissions
binary=$staging/$package/execwake
if [[ ! -x "$binary" ]]; then
  echo "release binary is not executable" >&2
  exit 1
fi
if [[ $("$binary" --version) != "execwake $version" ]]; then
  echo "release binary version does not match Cargo.toml" >&2
  exit 1
fi

echo "Verified $package"
