# ExecWake

![ExecWake report from the conformance fixture](docs/assets/execwake-report.gif)

ExecWake records observable side effects of a command and compares behavior
across runs.

The image above was captured from the Linux conformance fixture: 12 processes,
2,458 events, complete process coverage, and partial filesystem, network, and
environment coverage.

## Status

ExecWake 0.1.0 is a Linux alpha. The collector records:

- process fork, clone, exec, exit, exit code, and terminating signal;
- file operations and verified final state deltas;
- TCP and UDP connect, bind, listen, send, and receive operations for IPv4 and
  IPv6;
- DNS names only when a captured response provides a high-confidence address
  correlation;
- inherited environment variable names, never their values.

Process coverage is complete unless events are lost. Filesystem, network, and
environment coverage is reported as partial because syscall observation cannot
prove that every behavior was captured. ExecWake reports sockets, not HTTP
requests, and does not store general application payloads.

The default Linux backend combines ptrace detail capture with a cgroup-scoped
eBPF loss monitor. It falls back to ptrace when the eBPF probe or cgroup v2
scope is unavailable. Current overhead measurements are published in
[benchmarks/RESULTS.md](benchmarks/RESULTS.md).

## Build

Rust 1.67 or newer is required.

```sh
cargo build --locked --release
cargo test --all-targets
```

The built report assets are committed. To change the Svelte application, use
Node.js 22 and rebuild them:

```sh
cd web
npm ci
npm run check
npm run build
```

## Run

Everything after `--` is passed directly as argv. ExecWake does not interpret a
shell command string.

```sh
execwake run -- npm install some-package
execwake run -- cargo test
```

stdin, stdout, stderr, signals, terminal detection, and the child exit status
are preserved. Interactive graphical terminals open the local report. CI and
headless runs print the SQLite session path.

Pipelines require an explicit shell:

```sh
execwake run -- sh -c 'printf input | sort'
```

Compare two finalized session files with:

```sh
execwake diff before.sqlite3 after.sqlite3
```

The comparison classifies comparable behavior as `NEW`, `REMOVED`, `CHANGED`,
or `UNCHANGED`. Categories with incompatible schema, backend, privacy profile,
coverage, or lost-event state are marked incomparable instead of being treated
as absent.

## Local report security

Reports bind to a random loopback port and require a per-process token. The
server validates `Host` and `Origin`, does not enable CORS, applies a restrictive
content security policy, limits request bodies and time, and stops after five
minutes without activity. Web assets are embedded in the binary.

Imported session files are opened read-only and checked before use. Displayed
text makes markup, terminal controls, OSC-8 sequences, and bidirectional control
characters visible. Raw evidence remains in SQLite.

## Linux package

On Linux, build a versioned archive and SHA-256 file with:

```sh
scripts/package-linux.sh
sha256sum --check dist/execwake-v0.1.0-*-unknown-linux-gnu.tar.gz.sha256
```

The packaging script uses the current architecture and refuses to overwrite an
existing archive. Tagged builds and manual runs of the release workflow produce
the x86_64 artifact.

![Static ExecWake report overview](docs/assets/execwake-report.jpg)

The report assets in this README were captured from
`tests/fixtures/conformance.rs` running under the eBPF backend. The fixture uses
only loopback TCP, UDP, and DNS servers.
