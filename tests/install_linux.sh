#!/usr/bin/env bash
set -euo pipefail

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

fake_bin=$test_root/bin
fixture_root=$test_root/release
install_root=$test_root/install
mkdir -p "$fake_bin" "$fixture_root" "$install_root"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'case ${1:-} in' \
  '  -s) printf "Linux\\n" ;;' \
  '  -m) printf "x86_64\\n" ;;' \
  '  *) exit 2 ;;' \
  'esac' >"$fake_bin/uname"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'output=' \
  'url=' \
  'while [[ $# -gt 0 ]]; do' \
  '  case $1 in' \
  '    --output) output=$2; shift 2 ;;' \
  '    https://*) url=$1; shift ;;' \
  '    *) shift ;;' \
  '  esac' \
  'done' \
  'if [[ -z "$output" || -z "$url" ]]; then exit 2; fi' \
  'cp -- "$FIXTURE_ROOT/${url##*/}" "$output"' >"$fake_bin/curl"

printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  'printf "%s\\n" "$@" >"$COSIGN_LOG"' >"$fake_bin/cosign"
chmod 0755 "$fake_bin/uname" "$fake_bin/curl" "$fake_bin/cosign"

version=0.1.0-rc.3
target=x86_64-unknown-linux-gnu
package=execwake-v${version}-${target}
archive=$package.tar.gz
mkdir -p "$test_root/package/$package"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ ${1:-} == --version ]]; then' \
  '  printf "execwake 0.1.0-rc.3\\n"' \
  'else' \
  '  exit 2' \
  'fi' >"$test_root/package/$package/execwake"
chmod 0755 "$test_root/package/$package/execwake"
tar -czf "$fixture_root/$archive" -C "$test_root/package" "$package"
(
  cd "$fixture_root"
  sha256sum "$archive" >"$archive.sha256"
)
printf 'fixture bundle\n' >"$fixture_root/$archive.sha256.sigstore.json"

cosign_log=$test_root/cosign.log
PATH="$fake_bin:$PATH" \
  FIXTURE_ROOT="$fixture_root" \
  COSIGN_LOG="$cosign_log" \
  HOME="$test_root/home" \
  bash "$repository/scripts/install-linux.sh" "v$version" "$install_root"

if [[ $("$install_root/execwake" --version) != "execwake $version" ]]; then
  echo "installed binary has the wrong version" >&2
  exit 1
fi
expected_identity="https://github.com/ivanpukhov/execwake/.github/workflows/release.yml@refs/tags/v$version"
if ! grep -Fqx -- "$expected_identity" "$cosign_log"; then
  echo "installer did not verify the release workflow identity" >&2
  exit 1
fi

printf tampered >>"$fixture_root/$archive"
if PATH="$fake_bin:$PATH" \
  FIXTURE_ROOT="$fixture_root" \
  COSIGN_LOG="$cosign_log" \
  HOME="$test_root/home" \
  bash "$repository/scripts/install-linux.sh" "v$version" "$test_root/tampered"; then
  echo "installer accepted a tampered archive" >&2
  exit 1
fi
if [[ -e "$test_root/tampered/execwake" ]]; then
  echo "installer wrote a binary after checksum failure" >&2
  exit 1
fi

tar -czf "$fixture_root/$archive" -C "$test_root/package" "$package"
(
  cd "$fixture_root"
  sha256sum "$archive" >"$archive.sha256"
)
symlink_root=$test_root/symlink
mkdir -p "$symlink_root"
printf 'do not replace\n' >"$test_root/protected"
ln -s "$test_root/protected" "$symlink_root/execwake"
if PATH="$fake_bin:$PATH" \
  FIXTURE_ROOT="$fixture_root" \
  COSIGN_LOG="$cosign_log" \
  HOME="$test_root/home" \
  bash "$repository/scripts/install-linux.sh" "v$version" "$symlink_root"; then
  echo "installer replaced a symlink" >&2
  exit 1
fi
if [[ $(<"$test_root/protected") != "do not replace" ]]; then
  echo "installer changed the symlink target" >&2
  exit 1
fi

if PATH="$fake_bin:$PATH" \
  FIXTURE_ROOT="$fixture_root" \
  COSIGN_LOG="$cosign_log" \
  HOME="$test_root/home" \
  bash "$repository/scripts/install-linux.sh" 'v0.1.0/../../invalid' "$test_root/invalid"; then
  echo "installer accepted an invalid release tag" >&2
  exit 1
fi

echo "Linux installer tests passed"
