#!/usr/bin/env bash
set -euo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "collector preflight requires Linux" >&2
  exit 2
fi

case $(uname -m) in
  x86_64 | aarch64) ;;
  *)
    echo "unsupported Linux architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if [[ ! -r /sys/fs/cgroup/cgroup.controllers ]]; then
  echo "cgroup v2 is not mounted at /sys/fs/cgroup" >&2
  exit 1
fi

membership=$(awk -F: '$1 == "0" && $2 == "" { print $3; exit }' /proc/self/cgroup)
if [[ -z "$membership" || "$membership" != /* ]]; then
  echo "the process does not have a valid cgroup v2 membership" >&2
  exit 1
fi

cgroup=/sys/fs/cgroup${membership%/}
if [[ ! -d "$cgroup" || ! -w "$cgroup" ]]; then
  echo "the current cgroup does not allow a child scope: $cgroup" >&2
  exit 1
fi

tracefs=
for candidate in /sys/kernel/tracing /sys/kernel/debug/tracing; do
  if [[ -r "$candidate/events/sched/sched_process_fork/id" && \
        -r "$candidate/events/sched/sched_process_exec/id" && \
        -r "$candidate/events/sched/sched_process_exit/id" && \
        -r "$candidate/events/raw_syscalls/sys_enter/id" && \
        -r "$candidate/events/raw_syscalls/sys_exit/id" ]]; then
    tracefs=$candidate
    break
  fi
done
if [[ -z "$tracefs" ]]; then
  echo "required sched and raw_syscalls tracepoints are unavailable" >&2
  exit 1
fi

if [[ ! -r bpf/collector.bpf.o || ! -s bpf/collector.bpf.o ]]; then
  echo "bpf/collector.bpf.o is missing or empty" >&2
  exit 1
fi

echo "Linux collector preflight passed"
echo "cgroup: $cgroup"
echo "tracefs: $tracefs"
