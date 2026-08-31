#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "collector conformance requires Linux" >&2
  exit 2
fi

cargo_command=${CARGO:-cargo}

echo "Testing ptrace collector"
env -u EXECWAKE_REQUIRE_EBPF EXECWAKE_FORCE_PTRACE=1 \
  "$cargo_command" test --lib --all-features

echo "Testing eBPF collector"
env -u EXECWAKE_FORCE_PTRACE EXECWAKE_REQUIRE_EBPF=1 \
  "$cargo_command" test --lib --all-features
