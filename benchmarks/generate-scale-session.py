#!/usr/bin/env python3
import sqlite3
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} SESSION.sqlite3 EVENT_COUNT", file=sys.stderr)
        return 2

    database = Path(sys.argv[1])
    event_count = int(sys.argv[2])
    if not database.is_file():
        print(f"session database does not exist: {database}", file=sys.stderr)
        return 2
    if event_count not in (100_000, 1_000_000):
        print("event count must be 100000 or 1000000", file=sys.stderr)
        return 2

    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = OFF")
        connection.execute("DELETE FROM finding_evidence")
        connection.execute("DELETE FROM finding")
        connection.execute("DELETE FROM event")
        connection.execute("DELETE FROM process")
        connection.execute(
            "UPDATE session SET command_name = ?, argument_count = 0 WHERE singleton = 1",
            (f"ui-scale-{event_count}",),
        )
        batch_size = 10_000
        for start in range(0, event_count, batch_size):
            rows = (
                (
                    "filesystem" if index % 3 else "network",
                    "read" if index % 5 else "connect",
                    f"/workspace/fixture/path-{index % 10000}",
                    index,
                    "observed",
                )
                for index in range(start, min(start + batch_size, event_count))
            )
            connection.executemany(
                """INSERT INTO event (
                       category, operation, target, process_id, occurred_at_ms, evidence
                   ) VALUES (?, ?, ?, NULL, ?, ?)""",
                rows,
            )
            connection.commit()
        result = connection.execute("PRAGMA quick_check").fetchone()
        if result != ("ok",):
            print(f"database integrity check failed: {result}", file=sys.stderr)
            return 1
    finally:
        connection.close()

    print(database)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
