#!/usr/bin/env bash
set -euo pipefail

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compiler=${BPF_CLANG:-clang}

compiler_version=$("$compiler" --version | sed -n '1p')
if [[ "$compiler_version" != *'19.1.7'* ]]; then
  echo "Clang 19.1.7 is required to verify the embedded eBPF object." >&2
  exit 2
fi

temporary_directory=$(mktemp -d)
trap 'rm -rf -- "$temporary_directory"' EXIT
rebuilt=$temporary_directory/collector.bpf.o

BPF_CLANG=$compiler "$repository/scripts/build-bpf.sh" "$rebuilt"
if ! cmp --silent "$repository/bpf/collector.bpf.o" "$rebuilt"; then
  echo "bpf/collector.bpf.o does not match the eBPF sources." >&2
  echo "committed: $(sha256sum "$repository/bpf/collector.bpf.o" | awk '{ print $1 }')" >&2
  echo "rebuilt:   $(sha256sum "$rebuilt" | awk '{ print $1 }')" >&2
  exit 1
fi

echo "Embedded eBPF object matches its sources"
