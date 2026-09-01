# Diagnostics

[Русский](diagnostics.ru.md)

Collect only the information needed to reproduce the problem. Review every
command output and screenshot before sharing it.

## Basic information

Record the ExecWake version and operating system:

```sh
execwake --version
uname -srmo
sed -n '1,20p' /etc/os-release
```

Include the exact traced argv after replacing secrets with placeholders. State
whether stdin was interactive, whether a TTY was present, and the child exit
code or terminating signal.

## Collector problems

Run a minimal trace with the same user and environment that showed the problem:

```sh
execwake run -- /usr/bin/true
```

Keep the printed session path private. In a source checkout, the Linux collector
preflight can provide additional context:

```sh
scripts/check-linux-collector.sh
```

The preflight output can contain a cgroup path or container identifier. Review
it before posting. Do not rerun it with elevated privileges unless the original
ExecWake run also used those privileges.

If `sqlite3` is available, the following read-only query extracts only session
metadata and coverage state:

```sh
session=/absolute/path/to/session.sqlite3
sqlite3 -readonly "$session" \
  'SELECT schema_version, mode, state, finalized, collector_backend,
          privacy_profile FROM session;
   SELECT category, state, lost_events FROM coverage ORDER BY category;'
```

Do not post other database tables without reviewing their contents.

## Report UI problems

Include the browser name and version, the report error text, the session event
and process counts, and whether the problem appears with a newly recorded
`/usr/bin/true` session. Screenshots can contain traced paths and endpoints.

## Performance problems

Include the traced command and package-manager version, collector backend,
event count, baseline duration, traced duration, and whether coverage reports
lost events. Use a command that can be shared safely.
