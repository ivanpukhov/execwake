# Changelog

## 0.1.0-rc.4 — 2026-09-14

- Made eBPF event draining account for the complete final buffer and classify
  overload as partial coverage.
- Added bounded eBPF startup failure reasons and required automatic fallback
  checks on restricted Ubuntu 24.04 runners.
- Hardened signal forwarding, collector shutdown, and failed-start session
  finalization.
- Added read-only report and diff support for session schemas written by the
  first three release candidates.
- Added `run --output` for exporting a finalized session without overwriting an
  existing path.
- Added deterministic `diff --json` output and opt-in CI exit codes for changed
  and incomparable results.
- Added package smoke tests on Debian 12 and a GLIBC 2.35 compatibility ceiling
  for release artifacts on amd64 and arm64.

## 0.1.0-rc.3 — 2026-09-06

- Added explicit `auto`, `ebpf`, and `ptrace` collector selection.
- Recorded the requested collector, selected backend, and bounded fallback reason
  in session manifests and reports.
- Added a coverage-aware terminal summary after each finalized run.
- Added unprivileged ptrace conformance on Ubuntu 22.04 and 24.04 for amd64 and
  arm64.
- Added embedded eBPF object verification and a wider eBPF compatibility matrix.
- Made release packaging reproducibility-checked and release publishing
  repository-specific.
