use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use rusqlite::{params, Connection, OpenFlags};

use crate::collector::{
    CollectorEvent, CollectorSink, DnsCorrelationRecord, EnvironmentVariableRecord,
    FileDeltaRecord, ProcessExecRecord, ProcessExitRecord, ProcessRecord, SinkError,
};
use crate::findings::{evaluate, EvidenceReference, FindingEvent};
use crate::limits::{CaptureLimits, SQLITE_CACHE_KIB, SQLITE_CAPTURE_BATCH_WRITES};
use crate::node_enrichment::{
    cleanup_session_files, NodeEnrichmentFact, NodeEnrichmentRecord, NODE_ENRICHMENT_EVIDENCE,
};
use crate::privacy::CURRENT_PRIVACY_PROFILE;
use crate::session::{
    CategoryCoverage, CollectorBackend, CollectorDecision, EvidenceKind, SessionCoverage,
    SessionMode, CURRENT_SCHEMA_VERSION,
};

#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Database(rusqlite::Error),
    InvalidInput(&'static str),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "session storage error: {error}"),
            Self::Database(error) => write!(formatter, "session database error: {error}"),
            Self::InvalidInput(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionOutcome {
    pub exit_code: Option<i32>,
    pub termination_signal: Option<i32>,
}

impl SessionOutcome {
    pub const fn exited(exit_code: i32) -> Self {
        Self {
            exit_code: Some(exit_code),
            termination_signal: None,
        }
    }

    pub const fn signaled(signal: i32) -> Self {
        Self {
            exit_code: None,
            termination_signal: Some(signal),
        }
    }

    pub const fn without_status() -> Self {
        Self {
            exit_code: None,
            termination_signal: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionId(String);

impl SessionId {
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0_u8; 16];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "random source unavailable"))?;

        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut value, "{byte:02x}").expect("writing to a string cannot fail");
        }

        Ok(Self(value))
    }

    pub fn parse(value: &str) -> Option<Self> {
        (value.len() == 32
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionPaths {
    id: SessionId,
    database: PathBuf,
    lock: PathBuf,
    finalized: PathBuf,
}

impl SessionPaths {
    pub fn id(&self) -> &SessionId {
        &self.id
    }

    pub fn database(&self) -> &Path {
        &self.database
    }

    pub fn lock(&self) -> &Path {
        &self.lock
    }

    pub fn finalized(&self) -> &Path {
        &self.finalized
    }
}

#[derive(Clone, Debug)]
pub struct SessionStore {
    root: PathBuf,
}

impl SessionStore {
    pub fn discover() -> io::Result<Self> {
        Self::at(default_storage_root()?)
    }

    pub fn at(root: PathBuf) -> io::Result<Self> {
        if !root.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session storage path must be absolute",
            ));
        }

        ensure_private_directory(&root)?;
        let root = fs::canonicalize(root)?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn new_session_paths(&self) -> io::Result<SessionPaths> {
        for _ in 0..8 {
            let id = SessionId::generate()?;
            let paths = self.paths(&id);

            if !paths.database.exists() && !paths.lock.exists() && !paths.finalized.exists() {
                return Ok(paths);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique session id",
        ))
    }

    pub fn paths(&self, id: &SessionId) -> SessionPaths {
        let base = self.root.join(id.as_str());
        SessionPaths {
            id: id.clone(),
            database: base.with_extension("sqlite3"),
            lock: base.with_extension("lock"),
            finalized: base.with_extension("finalized"),
        }
    }

    pub fn begin(
        &self,
        command_name: &str,
        argument_count: usize,
    ) -> Result<ActiveSession, StoreError> {
        self.begin_in_mode(command_name, argument_count, SessionMode::Observe)
    }

    pub(crate) fn begin_in_mode(
        &self,
        command_name: &str,
        argument_count: usize,
        mode: SessionMode,
    ) -> Result<ActiveSession, StoreError> {
        self.begin_in_mode_with_limits(command_name, argument_count, mode, CaptureLimits::DEFAULT)
    }

    #[cfg(test)]
    fn begin_with_limits(
        &self,
        command_name: &str,
        argument_count: usize,
        limits: CaptureLimits,
    ) -> Result<ActiveSession, StoreError> {
        self.begin_in_mode_with_limits(command_name, argument_count, SessionMode::Observe, limits)
    }

    fn begin_in_mode_with_limits(
        &self,
        command_name: &str,
        argument_count: usize,
        mode: SessionMode,
        limits: CaptureLimits,
    ) -> Result<ActiveSession, StoreError> {
        if command_name.is_empty() || command_name.chars().any(|character| character.is_control()) {
            return Err(StoreError::InvalidInput("invalid command name"));
        }
        if limits.event_count == 0
            || limits.text_bytes == 0
            || limits.finalization_bytes >= limits.session_bytes
        {
            return Err(StoreError::InvalidInput("invalid capture limits"));
        }

        let argument_count = i64::try_from(argument_count)
            .map_err(|_| StoreError::InvalidInput("argument count is too large"))?;
        let paths = self.new_session_paths()?;
        let lock_file = create_private_file(paths.lock())?;
        FileExt::try_lock_exclusive(&lock_file)?;
        create_private_file(paths.database())?;

        let result = initialize_database(&paths, command_name, argument_count, mode, limits);
        match result {
            Ok(connection) => Ok(ActiveSession {
                paths,
                connection,
                lock_file: Some(lock_file),
                finalized: false,
                limits,
                recorded_events: 0,
                capture_losses: CaptureLosses::default(),
                capture_batch_losses: CaptureLosses::default(),
                database_saturated: false,
                writes_until_size_check: 0,
                capture_batch_writes: 0,
                capture_transaction_open: false,
            }),
            Err(error) => {
                let _ = FileExt::unlock(&lock_file);
                drop(lock_file);
                let _ = fs::remove_file(paths.lock());
                let _ = fs::remove_file(paths.database());
                Err(error)
            }
        }
    }

    pub fn recover_interrupted(&self) -> Result<Vec<SessionPaths>, StoreError> {
        let mut recovered = Vec::new();

        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("lock") {
                continue;
            }

            let Some(id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(SessionId::parse)
            else {
                continue;
            };
            let paths = self.paths(&id);
            if recover_session(&paths)? {
                recovered.push(paths);
            }
        }

        Ok(recovered)
    }
}

pub struct ActiveSession {
    paths: SessionPaths,
    connection: Connection,
    lock_file: Option<File>,
    finalized: bool,
    limits: CaptureLimits,
    recorded_events: u64,
    capture_losses: CaptureLosses,
    capture_batch_losses: CaptureLosses,
    database_saturated: bool,
    writes_until_size_check: u16,
    capture_batch_writes: u16,
    capture_transaction_open: bool,
}

#[derive(Clone, Copy, Debug, Default)]
struct CaptureLosses {
    processes: u64,
    filesystem: u64,
    network: u64,
    environment: u64,
    node_enrichment: u64,
}

impl CaptureLosses {
    fn record(&mut self, category: &str) {
        self.record_count(category, 1);
    }

    fn record_count(&mut self, category: &str, count: u64) {
        let counter = match category {
            "process" | "processes" => &mut self.processes,
            "filesystem" => &mut self.filesystem,
            "network" => &mut self.network,
            "environment" => &mut self.environment,
            "node_enrichment" => &mut self.node_enrichment,
            _ => return,
        };
        *counter = counter.saturating_add(count);
    }

    const fn any(self) -> bool {
        self.processes > 0
            || self.filesystem > 0
            || self.network > 0
            || self.environment > 0
            || self.node_enrichment > 0
    }

    fn merge(&mut self, other: Self) {
        self.processes = self.processes.saturating_add(other.processes);
        self.filesystem = self.filesystem.saturating_add(other.filesystem);
        self.network = self.network.saturating_add(other.network);
        self.environment = self.environment.saturating_add(other.environment);
        self.node_enrichment = self.node_enrichment.saturating_add(other.node_enrichment);
    }
}

impl ActiveSession {
    pub fn paths(&self) -> &SessionPaths {
        &self.paths
    }

    pub fn set_collector_decision(
        &mut self,
        decision: CollectorDecision,
    ) -> Result<(), StoreError> {
        self.flush_capture_batch()?;
        self.connection.execute(
            "UPDATE session
             SET collector_requested = ?1, collector_backend = ?2,
                 collector_fallback_reason = ?3
             WHERE singleton = 1",
            params![
                decision.requested.as_str(),
                decision.backend.as_str(),
                decision.fallback_reason.map(|reason| reason.as_str()),
            ],
        )?;
        Ok(())
    }

    fn capture_allowed(
        &mut self,
        category: &str,
        text: &[&str],
        event: bool,
    ) -> Result<bool, SinkError> {
        if self.database_saturated
            || (event && self.recorded_events >= self.limits.event_count)
            || text
                .iter()
                .any(|value| value.len() > self.limits.text_bytes)
        {
            self.capture_losses.record(category);
            return Ok(false);
        }

        if self.writes_until_size_check == 0 {
            let page_count: i64 = self
                .connection
                .query_row("PRAGMA page_count", [], |row| row.get(0))
                .map_err(|error| Box::new(error) as SinkError)?;
            let page_size: i64 = self
                .connection
                .query_row("PRAGMA page_size", [], |row| row.get(0))
                .map_err(|error| Box::new(error) as SinkError)?;
            let allocated_bytes = u64::try_from(page_count)
                .ok()
                .and_then(|count| {
                    u64::try_from(page_size)
                        .ok()
                        .and_then(|size| count.checked_mul(size))
                })
                .ok_or_else(|| {
                    Box::new(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "session database size is invalid",
                    )) as SinkError
                })?;
            let capture_budget = self
                .limits
                .session_bytes
                .saturating_sub(self.limits.finalization_bytes);
            if allocated_bytes >= capture_budget {
                self.database_saturated = true;
                self.capture_losses.record(category);
                return Ok(false);
            }
            self.writes_until_size_check = 64;
        }

        self.begin_capture_batch(category)?;
        Ok(true)
    }

    fn begin_capture_batch(&mut self, category: &str) -> Result<(), SinkError> {
        if !self.capture_transaction_open {
            self.connection
                .execute_batch("BEGIN IMMEDIATE")
                .map_err(|error| Box::new(error) as SinkError)?;
            self.capture_transaction_open = true;
            self.capture_batch_writes = 0;
            self.capture_batch_losses = CaptureLosses::default();
        }
        self.capture_batch_losses.record(category);
        Ok(())
    }

    fn flush_capture_batch(&mut self) -> rusqlite::Result<()> {
        if !self.capture_transaction_open {
            return Ok(());
        }

        let result = self.connection.execute_batch("COMMIT");
        if result.is_err() {
            let _ = self.connection.execute_batch("ROLLBACK");
            self.capture_losses.merge(self.capture_batch_losses);
        }
        self.capture_transaction_open = false;
        self.capture_batch_writes = 0;
        self.capture_batch_losses = CaptureLosses::default();

        match result {
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DiskFull =>
            {
                self.database_saturated = true;
                Ok(())
            }
            result => result,
        }
    }

    fn abandon_capture_batch(&mut self) {
        if self.capture_transaction_open {
            let _ = self.connection.execute_batch("ROLLBACK");
            self.capture_losses.merge(self.capture_batch_losses);
        }
        self.capture_transaction_open = false;
        self.capture_batch_writes = 0;
        self.capture_batch_losses = CaptureLosses::default();
    }

    fn checkpoint_capture_write(&mut self) -> Result<(), SinkError> {
        self.capture_batch_writes = self.capture_batch_writes.saturating_add(1);
        if self.capture_batch_writes >= SQLITE_CAPTURE_BATCH_WRITES {
            self.flush_capture_batch()
                .map_err(|error| Box::new(error) as SinkError)?;
        }
        Ok(())
    }

    fn finish_capture(
        &mut self,
        category: &str,
        event: bool,
        result: rusqlite::Result<usize>,
    ) -> Result<(), SinkError> {
        match result {
            Ok(0) => {
                self.capture_losses.record(category);
                self.checkpoint_capture_write()
            }
            Ok(_) => {
                self.writes_until_size_check = self.writes_until_size_check.saturating_sub(1);
                if event {
                    self.recorded_events = self.recorded_events.saturating_add(1);
                }
                self.checkpoint_capture_write()
            }
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::DiskFull =>
            {
                self.abandon_capture_batch();
                self.database_saturated = true;
                Ok(())
            }
            Err(error) => {
                self.abandon_capture_batch();
                Err(Box::new(error))
            }
        }
    }

    pub fn record_root_process(&mut self, process_id: u32) -> Result<(), StoreError> {
        self.flush_capture_batch()?;
        let transaction = self.connection.transaction()?;
        let (command_name, started_at_ms) = transaction.query_row(
            "SELECT command_name, started_at_ms FROM session WHERE singleton = 1",
            [],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )?;
        transaction.execute(
            "INSERT INTO process (
                 process_id, operating_system_id, start_time_ticks, parent_process_id, executable,
                 started_at_ms, evidence
             ) VALUES (?1, ?1, NULL, NULL, ?2, ?3, 'observed')",
            params![i64::from(process_id), command_name, started_at_ms],
        )?;
        transaction.execute(
            "INSERT INTO event (
                 category, operation, target, process_id, occurred_at_ms, evidence
             ) VALUES ('process', 'start', ?1, ?2, ?3, 'observed')",
            params![command_name, i64::from(process_id), started_at_ms],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn record_node_enrichment(
        &mut self,
        record: NodeEnrichmentRecord,
    ) -> Result<(), SinkError> {
        let Ok(monotonic_ns) = i64::try_from(record.monotonic_ns) else {
            self.record_node_enrichment_loss(1);
            return Ok(());
        };
        let operating_system_id = i64::from(record.operating_system_id);
        let result = match record.fact {
            NodeEnrichmentFact::Http { method, host, path } => {
                if !self.capture_allowed(
                    "node_enrichment",
                    &[method.as_str(), host.as_str(), path.as_str()],
                    true,
                )? {
                    return Ok(());
                }
                self.connection.execute(
                    "INSERT INTO node_enrichment (
                         kind, method, host, path, environment_name, process_id,
                         monotonic_ns, evidence
                     )
                     SELECT 'http', ?1, ?2, ?3, NULL, process_id, ?5, ?6
                     FROM process AS candidate
                     WHERE operating_system_id = ?4
                       AND NOT EXISTS (
                           SELECT 1 FROM process AS other
                           WHERE other.operating_system_id = candidate.operating_system_id
                             AND other.process_id != candidate.process_id
                       )
                     LIMIT 1",
                    params![
                        method,
                        host,
                        path,
                        operating_system_id,
                        monotonic_ns,
                        NODE_ENRICHMENT_EVIDENCE,
                    ],
                )
            }
            NodeEnrichmentFact::Environment { name } => {
                if !self.capture_allowed("node_enrichment", &[name.as_str()], true)? {
                    return Ok(());
                }
                self.connection.execute(
                    "INSERT INTO node_enrichment (
                         kind, method, host, path, environment_name, process_id,
                         monotonic_ns, evidence
                     )
                     SELECT 'environment', NULL, NULL, NULL, ?1, process_id, ?3, ?4
                     FROM process AS candidate
                     WHERE operating_system_id = ?2
                       AND NOT EXISTS (
                           SELECT 1 FROM process AS other
                           WHERE other.operating_system_id = candidate.operating_system_id
                             AND other.process_id != candidate.process_id
                       )
                     LIMIT 1",
                    params![
                        name,
                        operating_system_id,
                        monotonic_ns,
                        NODE_ENRICHMENT_EVIDENCE,
                    ],
                )
            }
        };
        self.finish_capture("node_enrichment", true, result)
    }

    pub(crate) fn record_node_enrichment_loss(&mut self, count: u64) {
        self.capture_losses.record_count("node_enrichment", count);
    }

    pub fn finalize(mut self, outcome: SessionOutcome) -> Result<SessionPaths, StoreError> {
        self.flush_capture_batch()?;
        let ended_at_ms = unix_time_ms()?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE process
             SET ended_at_ms = ?1, exit_code = ?2, termination_signal = ?3
             WHERE parent_process_id IS NULL",
            params![ended_at_ms, outcome.exit_code, outcome.termination_signal],
        )?;
        transaction.execute(
            "INSERT INTO event (
                 category, operation, target, process_id, occurred_at_ms, evidence
             )
             SELECT 'process', 'exit', executable, process_id, ?1, 'observed'
             FROM process
             WHERE parent_process_id IS NULL
               AND NOT EXISTS (
                   SELECT 1 FROM event
                   WHERE event.category = 'process'
                     AND event.operation = 'exit'
                     AND event.process_id = process.process_id
               )",
            [ended_at_ms],
        )?;
        if !self.database_saturated {
            persist_findings(&transaction)?;
        }
        apply_capture_losses(&transaction, self.capture_losses)?;
        let updated = transaction.execute(
            "UPDATE session
             SET state = 'finalized', finalized = 1, ended_at_ms = ?1,
                 exit_code = ?2, termination_signal = ?3
             WHERE singleton = 1 AND state = 'running' AND finalized = 0",
            params![ended_at_ms, outcome.exit_code, outcome.termination_signal],
        )?;
        if updated != 1 {
            return Err(StoreError::InvalidInput("session is not running"));
        }
        transaction.commit()?;

        create_finalized_marker(self.paths.finalized())?;
        self.finalized = true;
        let lock_file = self
            .lock_file
            .take()
            .ok_or(StoreError::InvalidInput("session lock is missing"))?;
        FileExt::unlock(&lock_file)?;
        drop(lock_file);
        fs::remove_file(self.paths.lock())?;

        Ok(self.paths.clone())
    }
}

impl CollectorSink for ActiveSession {
    fn set_backend(&mut self, backend: &'static str) -> Result<(), SinkError> {
        if CollectorBackend::parse(backend).is_none() {
            return Err(Box::new(StoreError::InvalidInput(
                "collector backend is invalid",
            )));
        }
        self.flush_capture_batch()
            .map_err(|error| Box::new(error) as SinkError)?;
        self.connection
            .execute(
                "UPDATE session SET collector_backend = ?1 WHERE singleton = 1",
                [backend],
            )
            .map(|_| ())
            .map_err(|error| Box::new(error) as SinkError)
    }

    fn record_process(&mut self, process: ProcessRecord) -> Result<(), SinkError> {
        if !self.capture_allowed("processes", &[&process.executable], false)? {
            return Ok(());
        }
        let process_id = database_process_id(process.identity.get())?;
        let parent_process_id = process
            .parent
            .map(|identity| database_process_id(identity.get()))
            .transpose()?;
        let result = self.connection.execute(
                "INSERT INTO process (
                     process_id, operating_system_id, start_time_ticks, parent_process_id, executable,
                     started_at_ms, evidence
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7
                 WHERE ?4 IS NULL OR EXISTS (
                     SELECT 1 FROM process WHERE process_id = ?4
                 )",
                params![
                    process_id,
                    i64::from(process.operating_system_id),
                    process.start_time_ticks,
                    parent_process_id,
                    process.executable,
                    process.occurred_at_ms,
                    process.evidence.as_str(),
                ],
            );
        self.finish_capture("processes", false, result)
    }

    fn record_process_exec(&mut self, process: ProcessExecRecord) -> Result<(), SinkError> {
        if !self.capture_allowed("processes", &[&process.executable], false)? {
            return Ok(());
        }
        let process_id = database_process_id(process.identity.get())?;
        let result = self.connection.execute(
            "UPDATE process SET executable = ?1 WHERE process_id = ?2",
            params![process.executable, process_id],
        );
        self.finish_capture("processes", false, result)
    }

    fn record_process_exit(&mut self, process: ProcessExitRecord) -> Result<(), SinkError> {
        if !self.capture_allowed("processes", &[], false)? {
            return Ok(());
        }
        let process_id = database_process_id(process.identity.get())?;
        let result = self.connection.execute(
            "UPDATE process
                 SET ended_at_ms = ?1, exit_code = ?2, termination_signal = ?3
                 WHERE process_id = ?4",
            params![
                process.occurred_at_ms,
                process.exit_code,
                process.termination_signal,
                process_id,
            ],
        );
        self.finish_capture("processes", false, result)
    }

    fn record_file_delta(&mut self, delta: FileDeltaRecord) -> Result<(), SinkError> {
        if !self.capture_allowed("filesystem", &[&delta.path], false)? {
            return Ok(());
        }
        let result = self.connection.execute(
            "INSERT INTO filesystem_delta (
                     path, before_kind, before_size, before_modified_at_ns,
                     after_kind, after_size, after_modified_at_ns, evidence
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'derived')",
            params![
                delta.path,
                delta.before.kind.as_str(),
                delta.before.size,
                delta.before.modified_at_ns,
                delta.after.kind.as_str(),
                delta.after.size,
                delta.after.modified_at_ns,
            ],
        );
        self.finish_capture("filesystem", false, result)
    }

    fn record_dns_correlation(&mut self, dns: DnsCorrelationRecord) -> Result<(), SinkError> {
        if !self.capture_allowed("network", &[&dns.hostname, &dns.address], false)? {
            return Ok(());
        }
        let result = self.connection.execute(
            "INSERT INTO dns_correlation (
                     hostname, address, process_id, occurred_at_ms, evidence, confidence
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6
                 WHERE EXISTS (SELECT 1 FROM process WHERE process_id = ?3)",
            params![
                dns.hostname,
                dns.address,
                database_process_id(dns.process.get())?,
                dns.occurred_at_ms,
                dns.evidence.as_str(),
                dns.confidence.as_str(),
            ],
        );
        self.finish_capture("network", false, result)
    }

    fn record_environment_variable(
        &mut self,
        environment: EnvironmentVariableRecord,
    ) -> Result<(), SinkError> {
        if !self.capture_allowed("environment", &[&environment.name], false)? {
            return Ok(());
        }
        let result = self.connection.execute(
            "INSERT INTO environment_variable (name, process_id, evidence)
                 SELECT ?1, ?2, ?3
                 WHERE EXISTS (SELECT 1 FROM process WHERE process_id = ?2)",
            params![
                environment.name,
                database_process_id(environment.process.get())?,
                environment.evidence.as_str(),
            ],
        );
        self.finish_capture("environment", false, result)
    }

    fn record_event(&mut self, event: CollectorEvent) -> Result<(), SinkError> {
        if !self.capture_allowed(event.category, &[&event.target], true)? {
            return Ok(());
        }
        let process_id = event
            .process
            .map(|identity| database_process_id(identity.get()))
            .transpose()?;
        let result = self.connection.execute(
            "INSERT INTO event (
                     category, operation, target, process_id, occurred_at_ms, evidence
                 )
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6
                 WHERE ?4 IS NULL OR EXISTS (
                     SELECT 1 FROM process WHERE process_id = ?4
                 )",
            params![
                event.category,
                event.operation,
                event.target,
                process_id,
                event.occurred_at_ms,
                event.evidence.as_str(),
            ],
        );
        self.finish_capture(event.category, true, result)
    }

    fn record_lost_events(&mut self, category: &'static str, count: u64) -> Result<(), SinkError> {
        self.capture_losses.record_count(category, count);
        Ok(())
    }

    fn set_coverage(&mut self, coverage: SessionCoverage) -> Result<(), SinkError> {
        self.flush_capture_batch()
            .map_err(|error| Box::new(error) as SinkError)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|error| Box::new(error) as SinkError)?;
        for (category, category_coverage) in [
            ("processes", coverage.processes),
            ("filesystem", coverage.filesystem),
            ("network", coverage.network),
            ("environment", coverage.environment),
        ] {
            update_coverage(&transaction, category, category_coverage)
                .map_err(|error| Box::new(error) as SinkError)?;
        }
        transaction
            .commit()
            .map_err(|error| Box::new(error) as SinkError)
    }
}

fn database_process_id(identity: u64) -> Result<i64, SinkError> {
    i64::try_from(identity).map_err(|_| {
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process identity is out of range",
        )) as SinkError
    })
}

fn update_coverage(
    transaction: &rusqlite::Transaction<'_>,
    category: &str,
    coverage: CategoryCoverage,
) -> rusqlite::Result<()> {
    transaction.execute(
        "UPDATE coverage SET state = ?1, lost_events = ?2 WHERE category = ?3",
        params![coverage.state().as_str(), coverage.lost_events(), category],
    )?;
    Ok(())
}

fn apply_capture_losses(
    transaction: &rusqlite::Transaction<'_>,
    losses: CaptureLosses,
) -> rusqlite::Result<()> {
    if !losses.any() {
        return Ok(());
    }
    for (category, lost_events) in [
        ("processes", losses.processes),
        ("filesystem", losses.filesystem),
        ("network", losses.network),
        ("environment", losses.environment),
        ("node_enrichment", losses.node_enrichment),
    ] {
        if lost_events == 0 {
            continue;
        }
        transaction.execute(
            "UPDATE coverage
             SET state = 'partial', lost_events = lost_events + ?1
             WHERE category = ?2",
            params![lost_events, category],
        )?;
    }
    Ok(())
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        if !self.finalized {
            if let Some(lock_file) = self.lock_file.as_ref() {
                let _ = FileExt::unlock(lock_file);
            }
        }
    }
}

fn initialize_database(
    paths: &SessionPaths,
    command_name: &str,
    argument_count: i64,
    mode: SessionMode,
    limits: CaptureLimits,
) -> Result<Connection, StoreError> {
    let mut connection = Connection::open_with_flags(
        paths.database(),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    connection.execute_batch(
        "PRAGMA journal_mode = DELETE;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = FILE;
         PRAGMA mmap_size = 0;
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
         CREATE TABLE coverage (
             category TEXT PRIMARY KEY,
             state TEXT NOT NULL CHECK (state IN ('complete', 'partial', 'unavailable')),
             lost_events INTEGER NOT NULL CHECK (
                 lost_events >= 0 AND (lost_events = 0 OR state = 'partial')
             )
         );
         CREATE TABLE process (
             process_id INTEGER PRIMARY KEY,
             operating_system_id INTEGER NOT NULL,
             start_time_ticks INTEGER,
             parent_process_id INTEGER REFERENCES process(process_id),
             executable TEXT NOT NULL,
             started_at_ms INTEGER NOT NULL,
             ended_at_ms INTEGER,
             exit_code INTEGER,
             termination_signal INTEGER,
             evidence TEXT NOT NULL CHECK (evidence IN ('observed', 'inferred', 'derived'))
         );
         CREATE TABLE event (
             event_id INTEGER PRIMARY KEY AUTOINCREMENT,
             category TEXT NOT NULL,
             operation TEXT NOT NULL,
             target TEXT NOT NULL,
             process_id INTEGER REFERENCES process(process_id),
             occurred_at_ms INTEGER NOT NULL,
             evidence TEXT NOT NULL CHECK (evidence IN ('observed', 'inferred', 'derived'))
         );
         CREATE TABLE filesystem_delta (
             path TEXT PRIMARY KEY,
             before_kind TEXT NOT NULL,
             before_size INTEGER,
             before_modified_at_ns INTEGER,
             after_kind TEXT NOT NULL,
             after_size INTEGER,
             after_modified_at_ns INTEGER,
             evidence TEXT NOT NULL CHECK (evidence = 'derived')
         );
         CREATE TABLE dns_correlation (
             correlation_id INTEGER PRIMARY KEY AUTOINCREMENT,
             hostname TEXT NOT NULL,
             address TEXT NOT NULL,
             process_id INTEGER NOT NULL REFERENCES process(process_id),
             occurred_at_ms INTEGER NOT NULL,
             evidence TEXT NOT NULL CHECK (evidence IN ('observed', 'inferred', 'derived')),
             confidence TEXT NOT NULL CHECK (confidence IN ('high'))
         );
         CREATE TABLE environment_variable (
             name TEXT NOT NULL,
             process_id INTEGER NOT NULL REFERENCES process(process_id),
             evidence TEXT NOT NULL CHECK (evidence IN ('observed', 'inferred', 'derived')),
             PRIMARY KEY (name, process_id)
         );
         CREATE TABLE node_enrichment (
             enrichment_id INTEGER PRIMARY KEY AUTOINCREMENT,
             kind TEXT NOT NULL CHECK (kind IN ('http', 'environment')),
             method TEXT,
             host TEXT,
             path TEXT,
             environment_name TEXT,
             process_id INTEGER NOT NULL REFERENCES process(process_id),
             monotonic_ns INTEGER NOT NULL CHECK (monotonic_ns >= 0),
             evidence TEXT NOT NULL CHECK (evidence = 'observed'),
             CHECK (
                 (kind = 'http' AND method IS NOT NULL AND host IS NOT NULL
                  AND path IS NOT NULL AND environment_name IS NULL)
                 OR
                 (kind = 'environment' AND method IS NULL AND host IS NULL
                  AND path IS NULL AND environment_name IS NOT NULL
                  AND instr(environment_name, '=') = 0)
             )
         );
         CREATE TABLE finding (
             finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
             rule_id TEXT NOT NULL,
             rule_version INTEGER NOT NULL CHECK (rule_version > 0),
             severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
             process_id INTEGER NOT NULL REFERENCES process(process_id),
             subject TEXT NOT NULL,
             UNIQUE (rule_id, rule_version, process_id, subject)
         );
         CREATE TABLE finding_evidence (
             finding_id INTEGER NOT NULL REFERENCES finding(finding_id) ON DELETE CASCADE,
             event_id INTEGER NOT NULL REFERENCES event(event_id),
             PRIMARY KEY (finding_id, event_id)
         );",
    )?;
    connection.pragma_update(None, "cache_size", -SQLITE_CACHE_KIB)?;
    let page_size: i64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let page_size = u64::try_from(page_size)
        .map_err(|_| StoreError::InvalidInput("invalid SQLite page size"))?;
    let max_pages = limits.session_bytes / page_size;
    if max_pages == 0 {
        return Err(StoreError::InvalidInput("session size limit is too small"));
    }
    connection.pragma_update(None, "max_page_count", max_pages)?;

    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT INTO session (
             singleton, id, schema_version, mode, state, finalized,
             command_name, argument_count, started_at_ms, runner_pid,
             collector_requested, privacy_profile
         ) VALUES (1, ?1, ?2, ?3, 'running', 0, ?4, ?5, ?6, ?7, 'auto', ?8)",
        params![
            paths.id().as_str(),
            i64::from(CURRENT_SCHEMA_VERSION),
            mode.as_str(),
            command_name,
            argument_count,
            unix_time_ms()?,
            i64::from(std::process::id()),
            CURRENT_PRIVACY_PROFILE,
        ],
    )?;
    for (category, state) in [
        ("processes", "partial"),
        ("filesystem", "unavailable"),
        ("network", "unavailable"),
        ("environment", "unavailable"),
    ] {
        transaction.execute(
            "INSERT INTO coverage (category, state, lost_events) VALUES (?1, ?2, 0)",
            params![category, state],
        )?;
    }
    if mode == SessionMode::Instrumented {
        transaction.execute(
            "INSERT INTO coverage (category, state, lost_events)
             VALUES ('node_enrichment', 'partial', 0)",
            [],
        )?;
    }
    transaction.commit()?;

    Ok(connection)
}

fn persist_findings(transaction: &rusqlite::Transaction<'_>) -> rusqlite::Result<()> {
    let mut statement = transaction.prepare(
        "SELECT event_id, category, operation, target, process_id, evidence
         FROM event ORDER BY event_id",
    )?;
    let events = statement
        .query_map([], |row| {
            let evidence: String = row.get(5)?;
            Ok(FindingEvent {
                event_id: row.get(0)?,
                category: row.get(1)?,
                operation: row.get(2)?,
                target: row.get(3)?,
                process: optional_process_identity(row.get(4)?)?,
                evidence: parse_evidence_kind(&evidence, 5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);

    for finding in evaluate(events) {
        transaction.execute(
            "INSERT INTO finding (
                 rule_id, rule_version, severity, process_id, subject
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                finding.rule_id,
                i64::from(finding.rule_version),
                finding.severity.as_str(),
                database_process_id(finding.process.get())
                    .map_err(|error| { rusqlite::Error::ToSqlConversionFailure(error) })?,
                finding.subject,
            ],
        )?;
        let finding_id = transaction.last_insert_rowid();
        for reference in finding.evidence {
            let EvidenceReference::Event(event_id) = reference;
            transaction.execute(
                "INSERT INTO finding_evidence (finding_id, event_id) VALUES (?1, ?2)",
                params![finding_id, event_id],
            )?;
        }
    }

    Ok(())
}

fn optional_process_identity(
    value: Option<i64>,
) -> rusqlite::Result<Option<crate::collector::ProcessIdentity>> {
    value
        .map(|value| {
            u64::try_from(value)
                .map(crate::collector::ProcessIdentity::new)
                .map_err(|_| {
                    invalid_database_value(
                        4,
                        rusqlite::types::Type::Integer,
                        "process identity is out of range",
                    )
                })
        })
        .transpose()
}

fn parse_evidence_kind(value: &str, column: usize) -> rusqlite::Result<EvidenceKind> {
    EvidenceKind::parse(value).ok_or_else(|| {
        invalid_database_value(column, rusqlite::types::Type::Text, "invalid evidence kind")
    })
}

fn invalid_database_value(
    column: usize,
    data_type: rusqlite::types::Type,
    message: &'static str,
) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        data_type,
        Box::new(io::Error::new(io::ErrorKind::InvalidData, message)),
    )
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    options.open(path)
}

fn open_private_lock(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        let file = options.open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }

    #[cfg(not(unix))]
    {
        options.open(path)
    }
}

fn recover_session(paths: &SessionPaths) -> Result<bool, StoreError> {
    let lock_file = open_private_lock(paths.lock())?;
    match FileExt::try_lock_exclusive(&lock_file) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(error) => return Err(error.into()),
    }

    if !is_regular_file(paths.database())? {
        cleanup_session_files(paths);
        FileExt::unlock(&lock_file)?;
        drop(lock_file);
        fs::remove_file(paths.lock())?;
        return Ok(false);
    }

    let mut connection = Connection::open_with_flags(
        paths.database(),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let transaction = connection.transaction()?;
    let (state, finalized) = transaction.query_row(
        "SELECT state, finalized FROM session WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
    )?;

    let interrupted = state == "running" && finalized == 0;
    if interrupted {
        persist_findings(&transaction)?;
        transaction.execute(
            "UPDATE coverage
             SET state = 'partial', lost_events = lost_events + 1
             WHERE category != 'node_enrichment'
                OR EXISTS (
                    SELECT 1 FROM session
                    WHERE singleton = 1 AND mode = 'instrumented'
                )",
            [],
        )?;
        transaction.execute(
            "UPDATE session
             SET state = 'interrupted', finalized = 1, ended_at_ms = ?1,
                 exit_code = NULL, termination_signal = NULL,
                 interruption = 'runner exited before finalization'
             WHERE singleton = 1",
            [unix_time_ms()?],
        )?;
    }
    transaction.commit()?;

    if finalized == 1 || interrupted {
        create_finalized_marker(paths.finalized())?;
    }
    cleanup_session_files(paths);

    FileExt::unlock(&lock_file)?;
    drop(lock_file);
    fs::remove_file(paths.lock())?;

    Ok(interrupted)
}

fn create_finalized_marker(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => return Ok(()),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "finalized marker is not a regular file",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let marker = create_private_file(path)?;
    marker.sync_all()
}

fn is_regular_file(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_file()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn unix_time_ms() -> Result<i64, StoreError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::InvalidInput("system clock is before the Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| StoreError::InvalidInput("system time is out of range"))
}

fn default_storage_root() -> io::Result<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        return absolute_environment_path("HOME")
            .map(|home| home.join("Library/Application Support/ExecWake/sessions"));
    }

    #[cfg(target_os = "windows")]
    {
        return absolute_environment_path("LOCALAPPDATA")
            .map(|root| root.join("ExecWake/sessions"));
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(root) = env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
        {
            return Ok(root.join("execwake/sessions"));
        }

        return absolute_environment_path("HOME")
            .map(|home| home.join(".local/state/execwake/sessions"));
    }

    #[allow(unreachable_code)]
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "no platform session storage directory is available",
    ))
}

fn absolute_environment_path(name: &str) -> io::Result<PathBuf> {
    env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{name} does not contain an absolute path"),
            )
        })
}

fn ensure_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
    }

    #[cfg(not(unix))]
    fs::create_dir_all(path)?;

    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "session storage path is not a directory",
        ));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use rusqlite::Connection;

    use crate::collector::{
        CollectorEvent, CollectorSink, DnsConfidence, DnsCorrelationRecord,
        EnvironmentVariableRecord, ProcessExecRecord, ProcessExitRecord, ProcessIdentity,
        ProcessRecord,
    };
    use crate::limits::{CaptureLimits, SQLITE_CAPTURE_BATCH_WRITES};
    use crate::node_enrichment::NodeEnrichmentRecord;
    use crate::privacy::CURRENT_PRIVACY_PROFILE;
    use crate::session::{
        CategoryCoverage, CollectorBackend, CollectorDecision, CollectorFallbackReason,
        CollectorRequest, EvidenceKind, SessionCoverage, SessionMode,
    };

    use super::{SessionId, SessionOutcome, SessionStore};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            Self(
                std::env::temp_dir()
                    .join(format!("execwake-storage-{}-{nonce}", std::process::id())),
            )
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn session_ids_are_fixed_lowercase_hex() {
        let id = SessionId::generate().expect("a session id should be generated");

        assert_eq!(id.as_str().len(), 32);
        assert_eq!(SessionId::parse(id.as_str()), Some(id));
        assert!(SessionId::parse("../outside").is_none());
        assert!(SessionId::parse("ABCDEF0123456789ABCDEF0123456789").is_none());
    }

    #[test]
    fn storage_requires_an_absolute_path() {
        assert!(SessionStore::at(PathBuf::from("sessions")).is_err());
    }

    #[test]
    fn storage_rejects_a_file_in_place_of_the_directory() {
        let directory = TestDirectory::new();
        fs::create_dir(&directory.0).expect("the test directory should be created");
        let file = directory.0.join("sessions");
        fs::write(&file, b"not a directory").expect("the test file should be created");

        assert!(SessionStore::at(file).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn storage_rejects_a_symlink_in_place_of_the_directory() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        fs::create_dir(&directory.0).expect("the test directory should be created");
        let target = directory.0.join("target");
        let link = directory.0.join("sessions");
        fs::create_dir(&target).expect("the target directory should be created");
        symlink(target, &link).expect("the symlink should be created");

        assert!(SessionStore::at(link).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn storage_resolves_symlinks_in_parent_directories() {
        use std::os::unix::fs::symlink;

        let directory = TestDirectory::new();
        fs::create_dir(&directory.0).expect("the test directory should be created");
        let parent = directory.0.join("parent");
        let link = directory.0.join("parent-link");
        fs::create_dir(&parent).expect("the parent should be created");
        symlink(&parent, &link).expect("the parent symlink should be created");

        let store =
            SessionStore::at(link.join("sessions")).expect("a symlinked parent should be resolved");

        assert_eq!(
            store.root(),
            fs::canonicalize(parent.join("sessions"))
                .expect("the storage directory should be canonical")
        );
    }

    #[test]
    fn session_paths_stay_under_the_storage_root() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let paths = store
            .new_session_paths()
            .expect("session paths should be allocated");

        assert!(paths.database().starts_with(store.root()));
        assert!(paths.lock().starts_with(store.root()));
        assert!(paths.finalized().starts_with(store.root()));
    }

    #[cfg(unix)]
    #[test]
    fn storage_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let mode = fs::metadata(store.root())
            .expect("storage metadata should be available")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn sessions_are_finalized_in_sqlite_and_on_disk() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("printf", 2)
            .expect("a session should be started");
        let database = session.paths().database().to_owned();
        let marker = session.paths().finalized().to_owned();

        let paths = session
            .finalize(SessionOutcome::exited(7))
            .expect("the session should be finalized");

        assert_eq!(paths.database(), database);
        assert!(marker.exists());
        assert!(!paths.lock().exists());

        let connection = Connection::open(database).expect("the database should open");
        let row = connection
            .query_row(
                "SELECT state, finalized, command_name, argument_count, exit_code
                 FROM session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .expect("the session row should exist");

        assert_eq!(row, ("finalized".to_owned(), 1, "printf".to_owned(), 2, 7));
    }

    #[test]
    fn capture_limits_keep_a_partial_finalized_session() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let limits = CaptureLimits {
            event_count: 2,
            session_bytes: 512 * 1024,
            finalization_bytes: 64 * 1024,
            text_bytes: 8,
        };
        let mut session = store
            .begin_with_limits("fixture", 0, limits)
            .expect("a limited session should start");

        for target in ["first", "second", "third", "target-too-long"] {
            session
                .record_event(CollectorEvent {
                    category: "filesystem",
                    operation: "read",
                    target: target.to_owned(),
                    process: None,
                    occurred_at_ms: 1,
                    evidence: EvidenceKind::Observed,
                })
                .expect("capture pressure should not fail the session");
        }
        let paths = session
            .finalize(SessionOutcome::exited(0))
            .expect("the limited session should finalize");

        let connection = Connection::open(paths.database()).expect("the database should open");
        let event_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM event", [], |row| row.get(0))
            .expect("events should be counted");
        let coverage: (String, i64) = connection
            .query_row(
                "SELECT state, lost_events FROM coverage WHERE category = 'filesystem'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("coverage should be readable");
        let page_count: i64 = connection
            .query_row("PRAGMA page_count", [], |row| row.get(0))
            .expect("page count should be readable");
        let page_size: i64 = connection
            .query_row("PRAGMA page_size", [], |row| row.get(0))
            .expect("page size should be readable");

        assert_eq!(event_count, 2);
        assert_eq!(coverage, ("partial".to_owned(), 2));
        assert!(page_count * page_size <= limits.session_bytes as i64);
    }

    #[test]
    fn capture_batches_are_checkpointed_while_a_session_is_active() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let mut session = store
            .begin("fixture", 0)
            .expect("a session should be started");

        for index in 0..SQLITE_CAPTURE_BATCH_WRITES {
            session
                .record_event(CollectorEvent {
                    category: "filesystem",
                    operation: "read",
                    target: format!("path-{index}"),
                    process: None,
                    occurred_at_ms: i64::from(index),
                    evidence: EvidenceKind::Observed,
                })
                .expect("the capture batch should be stored");
        }

        let connection = Connection::open(session.paths().database())
            .expect("the active database should be readable");
        let event_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM event", [], |row| row.get(0))
            .expect("checkpointed events should be counted");
        assert_eq!(event_count, i64::from(SQLITE_CAPTURE_BATCH_WRITES));

        session
            .finalize(SessionOutcome::exited(0))
            .expect("the session should finalize");
    }

    #[test]
    fn dropped_process_metadata_does_not_abort_the_trace() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let limits = CaptureLimits {
            event_count: 10,
            session_bytes: 512 * 1024,
            finalization_bytes: 64 * 1024,
            text_bytes: 8,
        };
        let mut session = store
            .begin_with_limits("fixture", 0, limits)
            .expect("a limited session should start");
        let process = ProcessIdentity::new(1);

        session
            .record_process(ProcessRecord {
                identity: process,
                operating_system_id: 70,
                start_time_ticks: Some(80),
                parent: None,
                executable: "executable-too-long".to_owned(),
                occurred_at_ms: 1,
                evidence: EvidenceKind::Observed,
            })
            .expect("oversized process metadata should be dropped");
        session
            .record_process(ProcessRecord {
                identity: ProcessIdentity::new(2),
                operating_system_id: 71,
                start_time_ticks: Some(81),
                parent: Some(process),
                executable: "child".to_owned(),
                occurred_at_ms: 2,
                evidence: EvidenceKind::Observed,
            })
            .expect("a process with missing parent metadata should be dropped");
        session
            .record_process_exec(ProcessExecRecord {
                identity: process,
                executable: "renamed".to_owned(),
                occurred_at_ms: 3,
            })
            .expect("exec metadata for a missing process should be dropped");
        session
            .record_process_exit(ProcessExitRecord {
                identity: process,
                occurred_at_ms: 4,
                exit_code: Some(0),
                termination_signal: None,
            })
            .expect("exit metadata for a missing process should be dropped");
        session
            .record_event(CollectorEvent {
                category: "filesystem",
                operation: "read",
                target: "input".to_owned(),
                process: Some(process),
                occurred_at_ms: 5,
                evidence: EvidenceKind::Observed,
            })
            .expect("dependent events should be dropped without an integrity error");
        session
            .record_dns_correlation(DnsCorrelationRecord {
                hostname: "host".to_owned(),
                address: "::1".to_owned(),
                process,
                occurred_at_ms: 6,
                evidence: EvidenceKind::Observed,
                confidence: DnsConfidence::High,
            })
            .expect("dependent DNS metadata should also be dropped");
        session
            .record_environment_variable(EnvironmentVariableRecord {
                name: "PATH".to_owned(),
                process,
                evidence: EvidenceKind::Derived,
            })
            .expect("dependent environment metadata should also be dropped");
        let paths = session
            .finalize(SessionOutcome::exited(0))
            .expect("the partial session should finalize");

        let connection = Connection::open(paths.database()).expect("the database should open");
        let process_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM process", [], |row| row.get(0))
            .expect("processes should be counted");
        let event_count: i64 = connection
            .query_row("SELECT COUNT(*) FROM event", [], |row| row.get(0))
            .expect("events should be counted");
        let coverage: Vec<(String, String, i64)> = connection
            .prepare(
                "SELECT category, state, lost_events FROM coverage
                 WHERE category IN ('processes', 'filesystem', 'network', 'environment')
                 ORDER BY category",
            )
            .expect("the coverage query should prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("coverage should be queried")
            .collect::<Result<_, _>>()
            .expect("coverage should be read");

        assert_eq!(process_count, 0);
        assert_eq!(event_count, 0);
        assert_eq!(
            coverage,
            [
                ("environment".to_owned(), "partial".to_owned(), 1),
                ("filesystem".to_owned(), "partial".to_owned(), 1),
                ("network".to_owned(), "partial".to_owned(), 1),
                ("processes".to_owned(), "partial".to_owned(), 4),
            ]
        );
    }

    #[test]
    fn instrumented_sessions_store_only_bounded_node_evidence_fields() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let mut session = store
            .begin_in_mode("node", 1, SessionMode::Instrumented)
            .expect("an instrumented session should start");
        let started_at_ms: i64 = session
            .connection
            .query_row(
                "SELECT started_at_ms FROM session WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("the start time should be readable");
        let process = ProcessIdentity::new(1);
        session
            .record_process(ProcessRecord {
                identity: process,
                operating_system_id: 77,
                start_time_ticks: Some(88),
                parent: None,
                executable: "node".to_owned(),
                occurred_at_ms: started_at_ms,
                evidence: EvidenceKind::Observed,
            })
            .expect("the Node process should be stored");
        session
            .record_node_enrichment(
                NodeEnrichmentRecord::http(
                    77,
                    100,
                    "post",
                    "LOCALHOST:443",
                    "/events?token=secret#fragment",
                )
                .expect("the HTTP evidence should be valid"),
            )
            .expect("the HTTP evidence should be stored");
        session
            .record_node_enrichment(
                NodeEnrichmentRecord::environment(77, 101, "GITHUB_TOKEN")
                    .expect("the environment evidence should be valid"),
            )
            .expect("the environment evidence should be stored");
        session.record_node_enrichment_loss(1);
        let paths = session
            .finalize(SessionOutcome::exited(0))
            .expect("the instrumented session should finalize");

        let connection = Connection::open(paths.database()).expect("the database should open");
        let mode: String = connection
            .query_row("SELECT mode FROM session WHERE singleton = 1", [], |row| {
                row.get(0)
            })
            .expect("the mode should be read");
        let coverage: (String, i64) = connection
            .query_row(
                "SELECT state, lost_events FROM coverage WHERE category = 'node_enrichment'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the enrichment coverage should be read");
        type StoredNodeRow = (
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        );
        let rows: Vec<StoredNodeRow> = connection
            .prepare(
                "SELECT kind, method, host, path, environment_name
                     FROM node_enrichment ORDER BY enrichment_id",
            )
            .expect("the enrichment query should prepare")
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })
            .expect("the enrichment rows should be queried")
            .collect::<Result<_, _>>()
            .expect("the enrichment rows should be read");
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(node_enrichment)")
            .expect("the schema query should prepare")
            .query_map([], |row| row.get(1))
            .expect("the schema should be queried")
            .collect::<Result<_, _>>()
            .expect("the schema should be read");

        assert_eq!(mode, "instrumented");
        assert_eq!(coverage, ("partial".to_owned(), 1));
        assert_eq!(
            rows,
            [
                (
                    "http".to_owned(),
                    Some("POST".to_owned()),
                    Some("localhost:443".to_owned()),
                    Some("/events".to_owned()),
                    None,
                ),
                (
                    "environment".to_owned(),
                    None,
                    None,
                    None,
                    Some("GITHUB_TOKEN".to_owned()),
                ),
            ]
        );
        assert!(!columns.iter().any(|column| {
            matches!(
                column.as_str(),
                "value" | "headers" | "cookies" | "query" | "request_body" | "response_body"
            )
        }));
    }

    #[test]
    fn collector_records_keep_reused_operating_system_ids_distinct() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let mut session = store
            .begin("fixture", 0)
            .expect("a session should be started");
        let process = ProcessIdentity::new(1);
        let reused_process = ProcessIdentity::new(2);

        session
            .set_collector_decision(CollectorDecision {
                requested: CollectorRequest::Auto,
                backend: CollectorBackend::Ptrace,
                fallback_reason: Some(CollectorFallbackReason::PermissionDenied),
            })
            .expect("collector decision should be stored");
        session
            .set_backend("ptrace")
            .expect("backend should be stored");
        session
            .record_process(ProcessRecord {
                identity: process,
                operating_system_id: 41_000,
                start_time_ticks: Some(81),
                parent: None,
                executable: "fixture".to_owned(),
                occurred_at_ms: 10,
                evidence: EvidenceKind::Observed,
            })
            .expect("process should be stored");
        session
            .record_process(ProcessRecord {
                identity: reused_process,
                operating_system_id: 41_000,
                start_time_ticks: Some(82),
                parent: None,
                executable: "fixture-again".to_owned(),
                occurred_at_ms: 12,
                evidence: EvidenceKind::Observed,
            })
            .expect("reused process id should be stored with a new identity");
        session
            .record_event(CollectorEvent {
                category: "filesystem",
                operation: "read",
                target: "/tmp/input".to_owned(),
                process: Some(process),
                occurred_at_ms: 11,
                evidence: EvidenceKind::Observed,
            })
            .expect("event should be stored");
        session
            .record_environment_variable(EnvironmentVariableRecord {
                name: "PATH".to_owned(),
                process,
                evidence: EvidenceKind::Observed,
            })
            .expect("observed environment access should be stored");
        session
            .set_coverage(SessionCoverage {
                processes: CategoryCoverage::complete(),
                filesystem: CategoryCoverage::partial(2),
                network: CategoryCoverage::unavailable(),
                environment: CategoryCoverage::unavailable(),
            })
            .expect("coverage should be stored");
        let database = session.paths().database().to_owned();
        session
            .finalize(SessionOutcome::exited(0))
            .expect("the session should be finalized");

        let connection = Connection::open(database).expect("the database should open");
        let process_rows: Vec<(i64, i64, i64)> = connection
            .prepare(
                "SELECT process_id, operating_system_id, start_time_ticks
                 FROM process ORDER BY process_id",
            )
            .expect("the process query should prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("the process rows should be queried")
            .collect::<Result<_, _>>()
            .expect("the process rows should be read");
        let coverage = connection
            .query_row(
                "SELECT state, lost_events FROM coverage WHERE category = 'filesystem'",
                [],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .expect("the coverage row should exist");
        let collector: (String, String, String) = connection
            .query_row(
                "SELECT collector_requested, collector_backend,
                        collector_fallback_reason
                 FROM session WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("the collector decision should exist");
        let environment_evidence: String = connection
            .query_row(
                "SELECT evidence FROM environment_variable WHERE name = 'PATH'",
                [],
                |row| row.get(0),
            )
            .expect("the environment evidence should exist");

        assert_eq!(process_rows, [(1, 41_000, 81), (2, 41_000, 82)]);
        assert_eq!(coverage, ("partial".to_owned(), 2));
        assert_eq!(
            collector,
            (
                "auto".to_owned(),
                "ptrace".to_owned(),
                "permission_denied".to_owned(),
            )
        );
        assert_eq!(environment_evidence, "observed");
        assert!(connection
            .execute(
                "UPDATE coverage SET state = 'complete', lost_events = 1
                 WHERE category = 'filesystem'",
                [],
            )
            .is_err());
    }

    #[test]
    fn finalized_findings_link_to_raw_event_evidence() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let mut session = store
            .begin("fixture", 0)
            .expect("a session should be started");
        let process = ProcessIdentity::new(1);
        session
            .record_process(ProcessRecord {
                identity: process,
                operating_system_id: 72,
                start_time_ticks: Some(90),
                parent: None,
                executable: "fixture".to_owned(),
                occurred_at_ms: 10,
                evidence: EvidenceKind::Observed,
            })
            .expect("the process should be stored");
        for (operation, occurred_at_ms) in [("open", 11), ("read", 12)] {
            session
                .record_event(CollectorEvent {
                    category: "filesystem",
                    operation,
                    target: "$HOME/.ssh/id_ed25519".to_owned(),
                    process: Some(process),
                    occurred_at_ms,
                    evidence: EvidenceKind::Observed,
                })
                .expect("the evidence event should be stored");
        }
        let database = session.paths().database().to_owned();
        session
            .finalize(SessionOutcome::exited(0))
            .expect("the session should finalize");

        let connection = Connection::open(database).expect("the database should open");
        let finding = connection
            .query_row(
                "SELECT rule_id, rule_version, severity, process_id, subject
                 FROM finding",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .expect("the finding should exist");
        let evidence: Vec<(i64, String)> = connection
            .prepare(
                "SELECT event.event_id, event.target
                 FROM finding_evidence
                 JOIN event USING (event_id)
                 ORDER BY event.event_id",
            )
            .expect("the evidence query should prepare")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .expect("the evidence should be queried")
            .collect::<Result<_, _>>()
            .expect("the evidence should be read");
        let privacy_profile: String = connection
            .query_row(
                "SELECT privacy_profile FROM session WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("the privacy profile should exist");

        assert_eq!(
            finding,
            (
                "EW-FS-001".to_owned(),
                1,
                "high".to_owned(),
                1,
                "$HOME/.ssh/id_ed25519".to_owned(),
            )
        );
        assert_eq!(
            evidence,
            [
                (1, "$HOME/.ssh/id_ed25519".to_owned()),
                (2, "$HOME/.ssh/id_ed25519".to_owned()),
            ]
        );
        assert_eq!(privacy_profile, CURRENT_PRIVACY_PROFILE);
    }

    #[cfg(unix)]
    #[test]
    fn session_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("printf", 0)
            .expect("a session should be started");

        for path in [session.paths().database(), session.paths().lock()] {
            let mode = fs::metadata(path)
                .expect("session metadata should be available")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn orphaned_running_sessions_are_recovered() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("sleep", 1)
            .expect("a session should be started");
        let database = session.paths().database().to_owned();
        let marker = session.paths().finalized().to_owned();
        drop(session);

        let recovered = store
            .recover_interrupted()
            .expect("the orphaned session should be recovered");

        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].database(), database);
        assert!(marker.exists());
        assert!(!recovered[0].lock().exists());

        let connection = Connection::open(database).expect("the database should open");
        let row = connection
            .query_row(
                "SELECT state, finalized, interruption FROM session WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .expect("the session row should exist");

        assert_eq!(
            row,
            (
                "interrupted".to_owned(),
                1,
                "runner exited before finalization".to_owned(),
            )
        );
        let coverage: Vec<(String, String, i64)> = connection
            .prepare(
                "SELECT category, state, lost_events FROM coverage
                 ORDER BY category",
            )
            .expect("coverage should be readable")
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .expect("coverage should be queried")
            .collect::<Result<_, _>>()
            .expect("coverage rows should be read");
        assert_eq!(
            coverage,
            [
                ("environment".to_owned(), "partial".to_owned(), 1),
                ("filesystem".to_owned(), "partial".to_owned(), 1),
                ("network".to_owned(), "partial".to_owned(), 1),
                ("processes".to_owned(), "partial".to_owned(), 1),
            ]
        );
    }

    #[test]
    fn interrupted_instrumented_sessions_drop_auxiliary_files_and_record_loss() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin_in_mode("node", 0, SessionMode::Instrumented)
            .expect("an instrumented session should be started");
        let database = session.paths().database().to_owned();
        let event_path = database.with_extension("node-events");
        let preload_path = database.with_extension("node-preload.cjs");
        fs::write(&event_path, "partial event stream").expect("the event file should be created");
        fs::write(&preload_path, "preload").expect("the preload file should be created");
        drop(session);

        let recovered = store
            .recover_interrupted()
            .expect("the instrumented session should be recovered");

        assert_eq!(recovered.len(), 1);
        assert!(!event_path.exists());
        assert!(!preload_path.exists());
        let connection = Connection::open(database).expect("the database should open");
        let coverage: (String, i64) = connection
            .query_row(
                "SELECT state, lost_events FROM coverage
                 WHERE category = 'node_enrichment'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the enrichment coverage should be readable");
        assert_eq!(coverage, ("partial".to_owned(), 1));
    }

    #[test]
    fn active_sessions_are_not_recovered() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("sleep", 1)
            .expect("a session should be started");

        let recovered = store
            .recover_interrupted()
            .expect("recovery should inspect the store");

        assert!(recovered.is_empty());
        assert!(!session.paths().finalized().exists());
    }

    #[cfg(unix)]
    #[test]
    fn recovery_does_not_follow_session_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let target = directory.0.join("target");
        fs::write(&target, "unchanged").expect("the target should be created");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640))
            .expect("the target permissions should be set");

        let id = SessionId::parse("0123456789abcdef0123456789abcdef")
            .expect("the session id should be valid");
        let paths = store.paths(&id);
        symlink(&target, paths.database()).expect("the database symlink should be created");
        fs::write(paths.lock(), "").expect("the lock should be created");
        symlink(
            &target,
            directory.0.join("ffffffffffffffffffffffffffffffff.lock"),
        )
        .expect("the lock symlink should be created");

        let recovered = store
            .recover_interrupted()
            .expect("recovery should skip session symlinks");

        assert!(recovered.is_empty());
        assert_eq!(
            fs::metadata(&target)
                .expect("the target metadata should exist")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            fs::read_to_string(target).expect("the target should remain readable"),
            "unchanged"
        );
        assert!(!paths.lock().exists());
        assert!(directory
            .0
            .join("ffffffffffffffffffffffffffffffff.lock")
            .is_symlink());
    }
}
