#!/usr/bin/env bash
set -euo pipefail
umask 022

usage() {
  echo "usage: $0 <release-tag> [destination-directory]" >&2
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

if [[ $(uname -s) != Linux ]]; then
  echo "ExecWake release binaries are currently available only for Linux." >&2
  exit 2
fi

release_tag=$1
if [[ ! "$release_tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  echo "Invalid release tag: $release_tag" >&2
  exit 2
fi
version=${release_tag#v}

case $(uname -m) in
  x86_64) target=x86_64-unknown-linux-gnu ;;
  aarch64 | arm64) target=aarch64-unknown-linux-gnu ;;
  *)
    echo "Unsupported Linux architecture: $(uname -m)" >&2
    exit 2
    ;;
esac

if [[ $# -eq 2 ]]; then
  destination=$2
else
  if [[ -z ${HOME:-} ]]; then
    echo "HOME is unset; provide a destination directory." >&2
    exit 2
  fi
  destination=$HOME/.local/bin
fi
if [[ "$destination" != /* ]]; then
  echo "Destination directory must be absolute: $destination" >&2
  exit 2
fi

for command in curl cosign sha256sum tar install mktemp awk; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command is unavailable: $command" >&2
    exit 2
  fi
done

archive="execwake-v${version}-${target}.tar.gz"
checksum="$archive.sha256"
bundle="$checksum.sigstore.json"
base_url="https://github.com/ivanpukhov/execwake/releases/download/$release_tag"

download_directory=$(mktemp -d)
temporary_target=
cleanup() {
  rm -rf -- "$download_directory"
  if [[ -n "$temporary_target" ]]; then
    rm -f -- "$temporary_target"
  fi
}
trap cleanup EXIT

for file in "$archive" "$checksum" "$bundle"; do
  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --proto '=https' \
    --tlsv1.2 \
    --output "$download_directory/$file" \
    "$base_url/$file"
done

identity="https://github.com/ivanpukhov/execwake/.github/workflows/release.yml@refs/tags/$release_tag"
cosign verify-blob \
  --bundle "$download_directory/$bundle" \
  --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$download_directory/$checksum"

expected_checksum=$(
  awk -v archive="$archive" \
    '$2 == archive { count += 1; checksum = $1 }
     END { if (count == 1) print checksum }' \
    "$download_directory/$checksum"
)
if [[ ! "$expected_checksum" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Checksum manifest does not contain exactly one valid entry for $archive." >&2
  exit 1
fi
actual_checksum=$(sha256sum "$download_directory/$archive" | awk '{ print $1 }')
if [[ "$actual_checksum" != "$expected_checksum" ]]; then
  echo "Checksum verification failed for $archive." >&2
  exit 1
fi

package=${archive%.tar.gz}
tar -xzf "$download_directory/$archive" \
  -C "$download_directory" \
  "$package/execwake"
binary="$download_directory/$package/execwake"
if [[ $("$binary" --version) != "execwake $version" ]]; then
  echo "Release binary version does not match $release_tag." >&2
  exit 1
fi

mkdir -p -- "$destination"
target_path=$destination/execwake
if [[ -L "$target_path" || -d "$target_path" ]]; then
  echo "Refusing to replace a symlink or directory: $target_path" >&2
  exit 1
fi
temporary_target=$destination/.execwake.install.$$
if [[ -e "$temporary_target" || -L "$temporary_target" ]]; then
  echo "Temporary install path already exists: $temporary_target" >&2
  exit 1
fi
install -m 0755 "$binary" "$temporary_target"
mv -f -- "$temporary_target" "$target_path"
temporary_target=

echo "Installed execwake $version to $target_path"
