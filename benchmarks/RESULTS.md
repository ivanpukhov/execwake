# Linux alpha measurements

Measured on 2026-08-31 with ExecWake 0.1.0. The Linux collector ran in a
privileged arm64 container with the eBPF backend required. The container used
Linux 6.4.16-linuxkit on an Apple M1 Pro host with 16 GiB memory and Docker
Engine 29.5.2.

## Command overhead

Each result is the median of seven runs after one warm-up. Baseline and traced
runs used the same local fixture and did not contact package registries. The
fixture is in `benchmarks/fixtures/workload` and the complete command is
`benchmarks/measure-overhead.sh /path/to/execwake 7 ebpf`. The run required the
eBPF backend, verified zero process and network event loss, and enforced a
1,000 ms added-latency budget for each workload.

Tool versions: npm 9.2.0, pnpm 8.15.9, bun 1.1.38, pip 23.0.1 with Python
3.11.2, and cargo 1.88.0.

| Workload | Baseline ms | ExecWake ms | Added ms | Ratio |
| --- | ---: | ---: | ---: | ---: |
| `npm run --silent noop` | 418.1 | 708.4 | 290.4 | 1.69x |
| `pnpm run --silent noop` | 541.3 | 720.0 | 178.7 | 1.33x |
| `bun run noop` | 77.8 | 231.0 | 153.2 | 2.97x |
| `python3 -m pip show pip` | 206.9 | 457.5 | 250.6 | 2.21x |
| `cargo metadata --quiet --no-deps --format-version 1` | 48.3 | 189.6 | 141.2 | 3.92x |

These short workloads emphasize collector startup and final state-delta work.
They are not install or build throughput measurements.

## Report scale

The scale sessions were derived from a finalized session and populated with
`benchmarks/generate-scale-session.py`. Production web assets were served by
the local report server. Server-ready time runs from process start until the
tokenized loopback URL is printed. Client-ready time runs from application
bootstrap through session metadata, timeline sampling, the first 500-event
page, and two animation frames. It excludes report-server startup and the
initial HTML and asset transfer.

| Events | SQLite size | Server ready median | Client ready median | Event rows in DOM |
| ---: | ---: | ---: | ---: | ---: |
| 100,000 | 6.4 MiB | 33.3 ms | 158.8 ms | 30 |
| 1,000,000 | 64 MiB | 291.4 ms | 370.3 ms | 30 |

Client-ready samples in milliseconds:

- 100,000: 154.1, 149.4, 163.9, 165.7, 160.0, 158.8, 156.1
- 1,000,000: 370.3, 349.1, 363.1, 359.3, 407.7, 370.6, 412.3

The million-event table was also scrolled to its last page. It loaded the tail
page and kept 20 visible rows in the DOM at the end of the scroll range.
