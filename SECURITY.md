# Security policy

[Русский](SECURITY.ru.md)

## Supported versions

Security fixes are provided for the most recent published release candidate.
Older alpha builds may be used to reproduce a report, but they are not supported.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/ivanpukhov/execwake/security/advisories/new).
Do not open a public issue for a vulnerability.

Include the affected ExecWake version, Linux distribution and kernel, a minimal
reproduction, and the expected security impact. Remove tokens, credentials,
private hostnames, usernames, and unrelated paths from logs and screenshots.

Do not attach an ExecWake session database to a public issue. A session can
contain command arguments, file paths, process names, and network endpoints from
the traced command. If a database is necessary for a private report, describe
its contents before attaching it and provide the smallest possible fixture.

Relevant reports include defects in collector isolation, privilege handling,
the local report server, hostile session-file handling, privacy guarantees, and
the release verification chain. Suspicious behavior correctly recorded from a
third-party command is not by itself an ExecWake vulnerability.

For ordinary defects, use the repository's bug report form and follow the
[diagnostic checklist](docs/diagnostics.md).
