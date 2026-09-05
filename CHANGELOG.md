# Changelog

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
