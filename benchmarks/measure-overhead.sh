#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 /path/to/execwake [odd-iteration-count]" >&2
  exit 2
fi

execwake_bin=$(realpath "$1")
iterations=${2:-7}
if [[ ! -x "$execwake_bin" ]]; then
  echo "execwake binary is not executable: $execwake_bin" >&2
  exit 2
fi
if (( iterations < 3 || iterations % 2 == 0 )); then
  echo "iteration count must be an odd number greater than one" >&2
  exit 2
fi

for tool in npm pnpm bun python3 cargo; do
  if ! command -v "$tool" >/dev/null; then
    echo "required tool is missing: $tool" >&2
    exit 2
  fi
done

benchmark_root=$(mktemp -d)
trap 'rm -rf -- "$benchmark_root"' EXIT
cp -R "$(dirname "$0")/fixtures/workload/." "$benchmark_root/workload"
mkdir -p "$benchmark_root/state"
cd "$benchmark_root/workload"

measure_ns() {
  local start_ns end_ns
  start_ns=$(date +%s%N)
  "$@" >/dev/null 2>&1
  end_ns=$(date +%s%N)
  echo $((end_ns - start_ns))
}

median_ns() {
  sort -n "$1" | awk -v row=$((iterations / 2 + 1)) 'NR == row { print; exit }'
}

run_case() {
  local name=$1
  shift
  local baseline_file="$benchmark_root/${name}.baseline"
  local traced_file="$benchmark_root/${name}.traced"

  "$@" >/dev/null 2>&1
  CI=1 XDG_STATE_HOME="$benchmark_root/state" "$execwake_bin" run -- "$@" >/dev/null 2>&1
  : >"$baseline_file"
  : >"$traced_file"
  for ((iteration = 0; iteration < iterations; iteration += 1)); do
    measure_ns "$@" >>"$baseline_file"
    CI=1 XDG_STATE_HOME="$benchmark_root/state" measure_ns \
      "$execwake_bin" run -- "$@" >>"$traced_file"
  done

  local baseline traced
  baseline=$(median_ns "$baseline_file")
  traced=$(median_ns "$traced_file")
  awk -v name="$name" -v baseline="$baseline" -v traced="$traced" \
    'BEGIN {
       printf "| %s | %.1f | %.1f | %.1f | %.2fx |\n", name,
              baseline / 1000000, traced / 1000000,
              (traced - baseline) / 1000000, traced / baseline
     }'
}

echo "Host: $(uname -srmo)"
echo "ExecWake: $($execwake_bin --version)"
echo "npm: $(npm --version)"
echo "pnpm: $(pnpm --version)"
echo "bun: $(bun --version)"
echo "pip: $(python3 -m pip --version)"
echo "cargo: $(cargo --version)"
echo "Iterations: $iterations (median after one warm-up)"
echo
echo "| Workload | Baseline ms | ExecWake ms | Added ms | Ratio |"
echo "| --- | ---: | ---: | ---: | ---: |"
run_case npm npm run --silent noop
run_case pnpm pnpm run --silent noop
run_case bun bun run noop
run_case pip python3 -m pip show pip
run_case cargo cargo metadata --quiet --no-deps --format-version 1
