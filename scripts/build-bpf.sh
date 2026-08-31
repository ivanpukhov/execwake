#!/usr/bin/env bash
set -euo pipefail

repository=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
compiler=${BPF_CLANG:-clang}
output=${1:-"$repository/bpf/collector.bpf.o"}

if ! "$compiler" -print-targets 2>/dev/null | grep -Eq '^[[:space:]]*bpf(el)?[[:space:]]'; then
  echo "Clang with the little-endian BPF target is required." >&2
  exit 2
fi

mkdir -p "$(dirname -- "$output")"
temporary=$(mktemp "${output}.tmp.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
"$compiler" \
  -target bpfel \
  -mcpu=v2 \
  -O2 \
  -Wall \
  -Werror \
  -I "$repository/bpf" \
  -c "$repository/bpf/collector.c" \
  -o "$temporary"
mv -- "$temporary" "$output"
trap - EXIT
