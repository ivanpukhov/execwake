#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "eBPF conformance requires Linux" >&2
  exit 2
fi

cargo_command=${CARGO:-cargo}

env -u EXECWAKE_FORCE_PTRACE EXECWAKE_REQUIRE_EBPF=1 \
  "$cargo_command" test --lib --all-features -- --test-threads=1
