#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 /path/to/execwake [odd-iteration-count] [expected-backend]" >&2
  exit 2
fi

execwake_bin=$(realpath "$1")
iterations=${2:-7}
expected_backend=${3:-}
max_added_ms=${EXECWAKE_MAX_ADDED_MS:-1000}
if [[ ! -x "$execwake_bin" ]]; then
  echo "execwake binary is not executable: $execwake_bin" >&2
  exit 2
fi
if (( iterations < 3 || iterations % 2 == 0 )); then
  echo "iteration count must be an odd number greater than one" >&2
  exit 2
fi
if [[ -n $expected_backend && $expected_backend != ebpf && $expected_backend != ptrace ]]; then
  echo "expected backend must be ebpf or ptrace" >&2
  exit 2
fi
if [[ ! $max_added_ms =~ ^[0-9]+([.][0-9]+)?$ ]] ||
  ! awk -v value="$max_added_ms" 'BEGIN { exit !(value > 0) }'; then
  echo "EXECWAKE_MAX_ADDED_MS must be a positive number" >&2
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

verify_latest_session() {
  python3 - "$benchmark_root/state" "$expected_backend" <<'PY'
import sqlite3
import sys
from pathlib import Path

sessions = Path(sys.argv[1]) / "execwake" / "sessions"
databases = list(sessions.glob("*.sqlite3"))
if not databases:
    raise SystemExit("benchmark session was not created")
database = max(databases, key=lambda path: path.stat().st_mtime_ns)
with sqlite3.connect(database) as connection:
    backend = connection.execute(
        "SELECT collector_backend FROM session WHERE singleton = 1"
    ).fetchone()[0]
    coverage = dict(
        connection.execute("SELECT category, lost_events FROM coverage")
    )
if backend != sys.argv[2]:
    raise SystemExit(f"expected {sys.argv[2]} backend, got {backend}")
for category in ("processes", "network"):
    if coverage.get(category, 0) != 0:
        raise SystemExit(f"unexpected {category} event loss: {coverage[category]}")
PY
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
  if [[ -n $expected_backend ]]; then
    verify_latest_session
  fi

  local baseline traced
  baseline=$(median_ns "$baseline_file")
  traced=$(median_ns "$traced_file")
  awk -v name="$name" -v baseline="$baseline" -v traced="$traced" \
      -v max_added_ms="$max_added_ms" \
    'BEGIN {
       added_ms = (traced - baseline) / 1000000
       printf "| %s | %.1f | %.1f | %.1f | %.2fx |\n", name,
              baseline / 1000000, traced / 1000000, added_ms, traced / baseline
       if (added_ms > max_added_ms) {
         printf "%s exceeded the %.1f ms added-latency budget\n", \
                name, max_added_ms > "/dev/stderr"
         exit 1
       }
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
echo "Added-latency budget: ${max_added_ms} ms"
if [[ -n $expected_backend ]]; then
  echo "Required backend: $expected_backend"
fi
echo
echo "| Workload | Baseline ms | ExecWake ms | Added ms | Ratio |"
echo "| --- | ---: | ---: | ---: | ---: |"
over_budget=0
run_case npm npm run --silent noop || over_budget=1
run_case pnpm pnpm run --silent noop || over_budget=1
run_case bun bun run noop || over_budget=1
run_case pip python3 -m pip show pip || over_budget=1
run_case cargo cargo metadata --quiet --no-deps --format-version 1 || over_budget=1

if ((over_budget)); then
  exit 1
fi
