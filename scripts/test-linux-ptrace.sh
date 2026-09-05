#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "ptrace conformance requires Linux" >&2
  exit 2
fi

cargo_command=${CARGO:-cargo}

env -u EXECWAKE_REQUIRE_EBPF EXECWAKE_FORCE_PTRACE=1 \
  "$cargo_command" test --lib --all-features -- --test-threads=1

env -u EXECWAKE_REQUIRE_EBPF -u EXECWAKE_FORCE_PTRACE \
  "$cargo_command" test --test cli_lifecycle -- --test-threads=1
