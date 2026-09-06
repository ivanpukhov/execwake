CREATE TABLE session (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    id TEXT NOT NULL,
    schema_version INTEGER NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('observe', 'instrumented')),
    state TEXT NOT NULL CHECK (state IN ('running', 'finalized', 'interrupted')),
    finalized INTEGER NOT NULL CHECK (finalized IN (0, 1)),
    command_name TEXT NOT NULL,
    argument_count INTEGER NOT NULL CHECK (argument_count >= 0),
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER,
    runner_pid INTEGER NOT NULL,
    collector_requested TEXT NOT NULL CHECK (
        collector_requested IN ('auto', 'ebpf', 'ptrace')
    ),
    collector_backend TEXT CHECK (collector_backend IN ('ebpf', 'ptrace')),
    collector_fallback_reason TEXT CHECK (
        collector_fallback_reason IN (
            'cgroup_unavailable', 'permission_denied',
            'platform_incompatible', 'initialization_failed'
        )
    ),
    privacy_profile TEXT NOT NULL,
    exit_code INTEGER,
    termination_signal INTEGER,
    interruption TEXT,
    CHECK (
        collector_fallback_reason IS NULL
        OR (collector_requested = 'auto' AND collector_backend = 'ptrace')
    )
);
