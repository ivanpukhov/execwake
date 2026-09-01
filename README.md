# ExecWake

[Русский](README.ru.md)

![ExecWake report from the conformance fixture](docs/assets/execwake-report.gif)

ExecWake records observable side effects of a command and compares behavior
across runs.

The image above was captured from the Linux conformance fixture: 12 processes,
2,458 events, complete process coverage, and partial filesystem, network, and
environment coverage.

## Status

ExecWake 0.1.0-rc.1 is a Linux alpha. The collector records:

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

The default Linux backend uses a cgroup-scoped eBPF collector for process,
filesystem, and socket events. It requires cgroup v2, the tracefs `sched` and
`raw_syscalls` tracepoints, permission to create a child cgroup, and permission
to load eBPF programs. ExecWake falls back to ptrace when those requirements
are unavailable. The selected backend is stored in every session manifest.
Current overhead measurements are published in
[benchmarks/RESULTS.md](benchmarks/RESULTS.md).

## Install

The installer requires Linux, `curl`, `cosign`, `sha256sum`, and `tar`. Download
it from the same tag as the release, inspect it, and run it with that exact tag:

```sh
tag=v0.1.0-rc.2
curl --fail --location --proto '=https' --tlsv1.2 --remote-name \
  "https://raw.githubusercontent.com/ivanpukhov/execwake/$tag/scripts/install-linux.sh"
less install-linux.sh
bash install-linux.sh "$tag"
```

The default destination is `~/.local/bin`; pass an absolute directory as the
second argument to change it. The installer verifies the checksum manifest's
Sigstore identity before using it, verifies the archive checksum and binary
version, and refuses to replace a symlink or directory.

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

### Node enrichment

Node enrichment is disabled by default. Enable it for a Node command with:

```sh
execwake run --node-enrichment -- node app.js
```

The resulting manifest uses `instrumented` mode and reports
`node_enrichment` coverage as partial. Runtime evidence contains only:

- the HTTP method and cleaned host and path;
- the name of a property read through `process.env`;
- the process identity and a monotonic timestamp.

Query strings, fragments, environment values, headers, cookies, request and
response bodies are not collected. Runtime HTTP evidence is stored separately
from kernel socket facts and does not replace them.

ExecWake appends a CommonJS `--require` preload to `NODE_OPTIONS`, preserving
existing options. The preload subscribes to the Node
`http.client.request.start` diagnostics channel and the Undici
`undici:request:create` channel used by built-in `fetch`. Node processes that
inherit `NODE_OPTIONS`, including ordinary child Node processes and workers,
also load the preload. CommonJS and ESM entry points are supported.

The integration test uses Node 22 and covers CommonJS, ESM, child processes,
workers, built-in `fetch`, and `https.request` against loopback servers.

`NODE_OPTIONS` is visible to the traced program and can affect startup in the
same way as a manually supplied `--require`. A program can bypass or disrupt
enrichment by clearing or replacing `NODE_OPTIONS` for a child, changing worker
execution options, replacing `process.env`, using native environment access,
changing the control event file, forging runtime records, using an HTTP client
that does not publish these channels, or writing directly to sockets. The
diagnostics channels and runtime HTTP implementations can also change between
Node releases. These limits are why enrichment remains partial and is not a
security boundary.

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

Report vulnerabilities through [SECURITY.md](SECURITY.md). For ordinary defects,
use the [diagnostic checklist](docs/diagnostics.md) before opening an issue.

## Linux package

On Linux, build a versioned archive and SHA-256 file with:

```sh
scripts/package-linux.sh
(cd dist && sha256sum --check *.tar.gz.sha256)
```

The packaging script uses the current architecture and refuses to overwrite an
existing archive. Tagged builds and manual runs of the release workflow produce
artifacts for x86_64 and arm64.

![Static ExecWake report overview](docs/assets/execwake-report.jpg)

The report assets in this README were captured from
`tests/fixtures/conformance.rs` running under the eBPF backend. The fixture uses
only loopback TCP, UDP, and DNS servers.
