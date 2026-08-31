#!/usr/bin/env python3
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 5:
        print(
            f"usage: {sys.argv[0]} EXECWAKE HOME SESSION_ID ITERATIONS",
            file=sys.stderr,
        )
        return 2

    executable = Path(sys.argv[1]).resolve()
    home = Path(sys.argv[2]).resolve()
    session_id = sys.argv[3]
    iterations = int(sys.argv[4])
    if not executable.is_file() or not os.access(executable, os.X_OK):
        print(f"execwake binary is not executable: {executable}", file=sys.stderr)
        return 2
    if not home.is_dir() or iterations < 1:
        print("HOME must exist and iterations must be positive", file=sys.stderr)
        return 2

    environment = os.environ.copy()
    environment["HOME"] = str(home)
    samples = []
    for _ in range(iterations):
        started = time.perf_counter()
        process = subprocess.Popen(
            [executable, "__serve-report", session_id],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            line = process.stdout.readline() if process.stdout else ""
            samples.append((time.perf_counter() - started) * 1000)
            if not line.startswith("http://127.0.0.1:"):
                error = process.stderr.read() if process.stderr else ""
                print(f"report server did not become ready: {error.strip()}", file=sys.stderr)
                return 1
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    print("samples_ms=" + ",".join(f"{sample:.1f}" for sample in samples))
    print(f"median_ms={statistics.median(samples):.1f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
