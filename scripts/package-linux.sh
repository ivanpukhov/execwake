#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ $(uname -s) != Linux ]]; then
  echo "Linux packaging must run on Linux." >&2
  exit 2
fi

target=${EXECWAKE_TARGET:-}
if [[ -z "$target" ]]; then
  case $(uname -m) in
    x86_64) target=x86_64-unknown-linux-gnu ;;
    aarch64) target=aarch64-unknown-linux-gnu ;;
    *)
      echo "Unsupported Linux architecture: $(uname -m)" >&2
      exit 2
      ;;
  esac
fi
if [[ "$target" != x86_64-unknown-linux-gnu && "$target" != aarch64-unknown-linux-gnu ]]; then
  echo "Unsupported Linux target: $target" >&2
  exit 2
fi

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
destination=${1:-"$repository/dist"}
mkdir -p "$destination"
destination=$(CDPATH= cd -- "$destination" && pwd)
cd "$repository"

version=$(awk -F '"' '/^version = "/ { print $2; exit }' Cargo.toml)
if [[ -z "$version" ]]; then
  echo "Could not read the package version." >&2
  exit 2
fi
package="execwake-v${version}-${target}"
archive="$destination/${package}.tar.gz"
checksum="$archive.sha256"
if [[ -e "$archive" || -e "$checksum" ]]; then
  echo "Release output already exists: $archive" >&2
  exit 2
fi

source_date_epoch=${SOURCE_DATE_EPOCH:-}
if [[ -z "$source_date_epoch" ]]; then
  source_date_epoch=$(git log -1 --format=%ct 2>/dev/null || true)
fi
source_date_epoch=${source_date_epoch:-0}
if [[ ! "$source_date_epoch" =~ ^[0-9]+$ ]]; then
  echo "SOURCE_DATE_EPOCH must be an unsigned integer." >&2
  exit 2
fi

cargo build --locked --release --target "$target"
binary="${CARGO_TARGET_DIR:-target}/$target/release/execwake"

staging=$(mktemp -d)
trap 'rm -rf -- "$staging"' EXIT
mkdir -p "$staging/$package/docs/assets" "$staging/$package/benchmarks"
install -m 0755 "$binary" "$staging/$package/execwake"
install -m 0644 LICENSE README.md "$staging/$package/"
install -m 0644 docs/assets/execwake-report.gif docs/assets/execwake-report.jpg \
  "$staging/$package/docs/assets/"
install -m 0644 benchmarks/RESULTS.md "$staging/$package/benchmarks/"

tar --sort=name \
  --mtime="@$source_date_epoch" \
  --owner=0 --group=0 --numeric-owner \
  -C "$staging" -cf - "$package" | gzip -n >"$archive"
(
  cd "$destination"
  sha256sum "${package}.tar.gz" >"${package}.tar.gz.sha256"
)

echo "$archive"
echo "$checksum"
