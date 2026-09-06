#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "Usage: $0 <archive> <target> <platform>" >&2
  exit 2
fi

archive=$1
target=$2
platform=$3
case "$target:$platform" in
  x86_64-unknown-linux-gnu:linux/amd64) ;;
  aarch64-unknown-linux-gnu:linux/arm64) ;;
  *)
    echo "Target and platform do not match: $target, $platform" >&2
    exit 2
    ;;
esac
if [[ $(uname -s) != Linux ]]; then
  echo "Linux package compatibility must be checked on Linux." >&2
  exit 2
fi
if [[ ! -f "$archive" ]]; then
  echo "Package archive does not exist: $archive" >&2
  exit 2
fi

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
archive=$(realpath -- "$archive")
package=${archive##*/}
package=${package%.tar.gz}
if [[ "$package" != execwake-v*-${target} ]]; then
  echo "Package name does not match target: ${archive##*/}" >&2
  exit 2
fi

test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
tar -xzf "$archive" -C "$test_root" "$package/execwake"
binary=$test_root/$package/execwake
"$repository/scripts/verify-glibc-baseline.sh" "$binary" 2.35

state=$test_root/state
mkdir -p "$state/home"
debian_image=debian:12-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
docker run --rm \
  --platform "$platform" \
  --network none \
  --read-only \
  --security-opt seccomp=unconfined \
  --pids-limit 256 \
  --memory 512m \
  --user "$(id -u):$(id -g)" \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  --mount "type=bind,src=$binary,dst=/opt/execwake,readonly" \
  --mount "type=bind,src=$state,dst=/state" \
  --env CI=1 \
  --env HOME=/state/home \
  --env XDG_STATE_HOME=/state \
  "$debian_image" \
  sh -ceu '
    /opt/execwake --version
    /opt/execwake run --collector ptrace -- /usr/bin/true
  '

sessions=$state/execwake/sessions
database=$(find "$sessions" -maxdepth 1 -type f -name '*.sqlite3' -print -quit)
marker=$(find "$sessions" -maxdepth 1 -type f -name '*.finalized' -print -quit)
if [[ -z "$database" || -z "$marker" ]]; then
  echo "Debian smoke test did not produce a finalized session." >&2
  exit 1
fi
"$binary" diff --json --exit-code "$database" "$database" >/dev/null

echo "Package compatibility checks passed for Debian 12 on $platform"
