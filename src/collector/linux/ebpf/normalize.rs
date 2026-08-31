use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::ffi::OsString;
use std::io;
use std::net::SocketAddr;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Component, PathBuf};
use std::process::ExitStatus;

use super::protocol::{Event, EventKind, PathData, SocketData, SyscallOperation};
use crate::collector::{
    CollectorEvent, CollectorSink, DnsConfidence, DnsCorrelationRecord, EnvironmentVariableRecord,
    FileDeltaRecord, FileState, FileStateKind, ProcessExecRecord, ProcessExitRecord,
    ProcessIdentity, ProcessRecord,
};
use crate::limits::{
    MAX_DNS_QUERIES_PER_SOCKET, MAX_FILE_SNAPSHOTS, MAX_LIVE_PROCESSES, MAX_SOCKETS_PER_PROCESS,
    MAX_TRACKED_DESCRIPTORS_PER_PROCESS,
};
use crate::privacy::{is_valid_environment_name, PathRoots};
use crate::session::EvidenceKind;

use super::super::syscall::{parse_dns_query, parse_dns_response, parse_socket_address};

pub struct CaptureClock {
    monotonic_ns: u64,
    unix_ms: i64,
}

impl CaptureClock {
    pub fn now() -> io::Result<Self> {
        let mut monotonic = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut monotonic) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let unix_ms = super::super::unix_time_ms()?;
        let monotonic_ns = (monotonic.tv_sec as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(monotonic.tv_nsec as u64);
        Ok(Self {
            monotonic_ns,
            unix_ms,
        })
    }

    fn event_time(&self, monotonic_ns: u64) -> i64 {
        let delta_ns = i128::from(monotonic_ns) - i128::from(self.monotonic_ns);
        let value = i128::from(self.unix_ms) + delta_ns / 1_000_000;
        value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    }
}

pub struct Normalizer {
    root_pid: u32,
    root_executable: String,
    root_cwd: PathBuf,
    root_start_time_ticks: Option<u64>,
    next_identity: u64,
    processes: HashMap<u32, ProcessState>,
    threads: HashMap<u32, u32>,
    roots: PathRoots,
    inherited_environment: Vec<String>,
    ignored_paths: Vec<PathBuf>,
    mutation_paths: HashSet<PathBuf>,
    clock: CaptureClock,
}

#[derive(Clone)]
struct ProcessState {
    identity: ProcessIdentity,
    executable: String,
    cwd: PathBuf,
    descriptors: HashMap<i32, Descriptor>,
}

#[derive(Clone)]
enum Descriptor {
    File(PathBuf),
    Socket(SocketState),
}

#[derive(Clone)]
struct SocketState {
    transport: &'static str,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    listening: bool,
    dns_queries: HashMap<u16, String>,
}

#[derive(Clone, Copy)]
struct CloneClassification {
    parent: u32,
    operation: &'static str,
}

#[derive(Default)]
struct ClonePlan {
    forks: HashMap<(u64, u32), CloneClassification>,
    matched_clones: HashSet<(u64, u32, u32, i64)>,
}

impl Normalizer {
    pub fn new(
        root_pid: u32,
        root_executable: String,
        root_cwd: PathBuf,
        root_start_time_ticks: Option<u64>,
        ignored_paths: Vec<PathBuf>,
        clock: CaptureClock,
    ) -> Self {
        let roots = PathRoots::new(
            env::var_os("HOME").map(Into::into),
            Some(root_cwd.clone()),
            Some(env::temp_dir()),
        );
        let mut inherited_environment: Vec<_> = env::vars_os()
            .filter_map(|(name, _)| name.into_string().ok())
            .filter(|name| is_valid_environment_name(name))
            .collect();
        inherited_environment.sort();
        inherited_environment.dedup();
        Self {
            root_pid,
            root_executable,
            root_cwd,
            root_start_time_ticks,
            next_identity: 1,
            processes: HashMap::new(),
            threads: HashMap::new(),
            roots,
            inherited_environment,
            ignored_paths,
            mutation_paths: HashSet::new(),
            clock,
        }
    }

    pub fn replay(
        &mut self,
        mut events: Vec<Event>,
        root_status: ExitStatus,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        events.sort_by(event_order);
        let clone_plan = plan_clones(&events);
        self.register_root(sink)?;

        for event in &events {
            match event.kind {
                EventKind::Heartbeat => {}
                EventKind::ProcessFork => self.observe_fork(event, &clone_plan, sink)?,
                EventKind::ProcessExec => self.observe_exec(event, sink)?,
                EventKind::ProcessExit => self.observe_exit(event, sink)?,
                EventKind::Syscall => self.observe_syscall(event, &clone_plan, sink)?,
            }
        }
        self.finish_remaining_processes(sink)?;
        self.finish_root(root_status, sink)?;
        self.record_file_states(sink)
    }

    fn register_root(&mut self, sink: &mut dyn CollectorSink) -> io::Result<()> {
        let occurred_at_ms = self.clock.unix_ms;
        let identity = self.allocate_identity()?;
        self.processes.insert(
            self.root_pid,
            ProcessState {
                identity,
                executable: self.root_executable.clone(),
                cwd: self.root_cwd.clone(),
                descriptors: HashMap::new(),
            },
        );
        self.threads.insert(self.root_pid, self.root_pid);
        sink.record_process(ProcessRecord {
            identity,
            operating_system_id: self.root_pid,
            start_time_ticks: self.root_start_time_ticks,
            parent: None,
            executable: self.root_executable.clone(),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)?;
        self.record_event(
            "process",
            "start",
            self.root_executable.clone(),
            identity,
            occurred_at_ms,
            sink,
        )?;
        for name in &self.inherited_environment {
            sink.record_environment_variable(EnvironmentVariableRecord {
                name: name.clone(),
                process: identity,
                evidence: EvidenceKind::Derived,
            })
            .map_err(sink_error)?;
            self.record_event(
                "environment",
                "inherited",
                name.clone(),
                identity,
                occurred_at_ms,
                sink,
            )?;
        }
        Ok(())
    }

    fn observe_fork(
        &mut self,
        event: &Event,
        clone_plan: &ClonePlan,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let child = event.arguments[1] as u32;
        let Some(classification) = clone_plan.forks.get(&(event.monotonic_ns, child)).copied()
        else {
            return Ok(());
        };
        self.register_child(
            child,
            classification.parent,
            classification.operation,
            self.clock.event_time(event.monotonic_ns),
            sink,
        )
    }

    fn observe_exec(&mut self, event: &Event, sink: &mut dyn CollectorSink) -> io::Result<()> {
        let process_id = event.tgid;
        let former = event.arguments[1] as u32;
        if former != process_id {
            if let Some(process) = self.processes.remove(&former) {
                let occurred_at_ms = self.clock.event_time(event.monotonic_ns);
                sink.record_process_exit(ProcessExitRecord {
                    identity: process.identity,
                    occurred_at_ms,
                    exit_code: None,
                    termination_signal: None,
                })
                .map_err(sink_error)?;
                self.record_event(
                    "process",
                    "exit",
                    process.executable,
                    process.identity,
                    occurred_at_ms,
                    sink,
                )?;
            }
        }
        if !self.processes.contains_key(&process_id) {
            if let Some(owner) = self.threads.get(&former).copied() {
                if owner != process_id {
                    if let Some(process) = self.processes.remove(&owner) {
                        self.processes.insert(process_id, process);
                    }
                }
            }
        }
        if !self.processes.contains_key(&process_id) {
            sink.record_lost_events("processes", 1)
                .map_err(sink_error)?;
            self.register_orphan(process_id, self.clock.event_time(event.monotonic_ns), sink)?;
        }
        self.threads.insert(process_id, process_id);

        let executable = event
            .data
            .strip_suffix(&[0])
            .unwrap_or(&event.data)
            .to_vec();
        let executable = if executable.is_empty() {
            self.processes
                .get(&process_id)
                .map(|process| process.executable.clone())
                .unwrap_or_else(|| self.root_executable.clone())
        } else {
            OsString::from_vec(executable)
                .to_string_lossy()
                .into_owned()
        };
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "exec process is missing"))?;
        process.executable.clone_from(&executable);
        let identity = process.identity;
        let occurred_at_ms = self.clock.event_time(event.monotonic_ns);
        sink.record_process_exec(ProcessExecRecord {
            identity,
            executable: executable.clone(),
            occurred_at_ms,
        })
        .map_err(sink_error)?;
        self.record_event(
            "process",
            "exec",
            executable,
            identity,
            occurred_at_ms,
            sink,
        )
    }

    fn observe_exit(&mut self, event: &Event, sink: &mut dyn CollectorSink) -> io::Result<()> {
        if event.tid != event.tgid {
            self.threads.remove(&event.tid);
            if let Some(process) = self.processes.remove(&event.tid) {
                let occurred_at_ms = self.clock.event_time(event.monotonic_ns);
                sink.record_process_exit(ProcessExitRecord {
                    identity: process.identity,
                    occurred_at_ms,
                    exit_code: None,
                    termination_signal: None,
                })
                .map_err(sink_error)?;
                self.record_event(
                    "process",
                    "exit",
                    process.executable,
                    process.identity,
                    occurred_at_ms,
                    sink,
                )?;
            }
            return Ok(());
        }
        if event.tgid == self.root_pid {
            return Ok(());
        }
        let Some(process) = self.processes.remove(&event.tgid) else {
            return Ok(());
        };
        self.threads.retain(|_, owner| *owner != event.tgid);
        let occurred_at_ms = self.clock.event_time(event.monotonic_ns);
        sink.record_process_exit(ProcessExitRecord {
            identity: process.identity,
            occurred_at_ms,
            exit_code: None,
            termination_signal: None,
        })
        .map_err(sink_error)?;
        self.record_event(
            "process",
            "exit",
            process.executable,
            process.identity,
            occurred_at_ms,
            sink,
        )
    }

    fn observe_syscall(
        &mut self,
        event: &Event,
        clone_plan: &ClonePlan,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let Some(operation) = event.syscall_operation() else {
            sink.record_lost_events("processes", 1).map_err(sink_error)?;
            return Ok(());
        };
        if matches!(
            operation,
            SyscallOperation::Clone | SyscallOperation::Clone3 | SyscallOperation::Fork
        ) {
            return self.observe_clone_syscall(event, operation, clone_plan, sink);
        }
        let process_id = self.threads.get(&event.tid).copied().unwrap_or(event.tgid);
        if !self.processes.contains_key(&process_id) {
            return Ok(());
        }
        let occurred_at_ms = self.clock.event_time(event.monotonic_ns);
        self.observe_descriptor_operation(process_id, operation, event, occurred_at_ms, sink)?;
        self.observe_network(process_id, operation, event, occurred_at_ms, sink)?;
        self.observe_filesystem(process_id, operation, event, occurred_at_ms, sink)
    }

    fn observe_clone_syscall(
        &mut self,
        event: &Event,
        operation: SyscallOperation,
        clone_plan: &ClonePlan,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if event.result <= 0 {
            return Ok(());
        }
        let key = (event.monotonic_ns, event.tgid, event.tid, event.result);
        if clone_plan.matched_clones.contains(&key) {
            return Ok(());
        }
        let child = event.result as u32;
        let label = if operation == SyscallOperation::Fork {
            "fork"
        } else {
            "clone"
        };
        self.register_child(
            child,
            event.tgid,
            label,
            self.clock.event_time(event.monotonic_ns),
            sink,
        )
    }

    fn observe_descriptor_operation(
        &mut self,
        process_id: u32,
        operation: SyscallOperation,
        event: &Event,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if event.result < 0 {
            return Ok(());
        }
        match operation {
            SyscallOperation::Close => {
                if let Some(process) = self.processes.get_mut(&process_id) {
                    process.descriptors.remove(&(event.arguments[0] as i32));
                }
            }
            SyscallOperation::Duplicate => {
                self.duplicate_descriptor(
                    process_id,
                    event.arguments[0] as i32,
                    event.result as i32,
                    sink,
                )?;
            }
            SyscallOperation::Fcntl
                if matches!(
                    event.arguments[1] as i32,
                    libc::F_DUPFD | libc::F_DUPFD_CLOEXEC
                ) =>
            {
                self.duplicate_descriptor(
                    process_id,
                    event.arguments[0] as i32,
                    event.result as i32,
                    sink,
                )?;
            }
            SyscallOperation::ChangeDirectory => {
                if let Some(path) =
                    self.first_resolved_path(process_id, libc::AT_FDCWD, event, sink)?
                {
                    if let Some(process) = self.processes.get_mut(&process_id) {
                        process.cwd = path;
                    }
                }
            }
            SyscallOperation::ChangeDirectoryFd => {
                let descriptor = event.arguments[0] as i32;
                let path = self.descriptor_path(process_id, descriptor);
                if let (Some(process), Some(path)) = (self.processes.get_mut(&process_id), path) {
                    process.cwd = path;
                }
            }
            _ => {}
        }
        let _ = occurred_at_ms;
        Ok(())
    }

    fn observe_network(
        &mut self,
        process_id: u32,
        operation: SyscallOperation,
        event: &Event,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let data = event.socket_data().map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("socket event: {error}"))
        })?;
        if data.as_ref().map(|data| data.truncated).unwrap_or(false) {
            sink.record_lost_events("network", 1).map_err(sink_error)?;
        }
        match operation {
            SyscallOperation::Socket if event.result >= 0 => {
                let socket_type = event.arguments[1] as i32 & 0xf;
                let protocol = event.arguments[2] as i32;
                let transport = match (socket_type, protocol) {
                    (libc::SOCK_STREAM, 0 | libc::IPPROTO_TCP) => "tcp",
                    (libc::SOCK_DGRAM, 0 | libc::IPPROTO_UDP) => "udp",
                    (libc::SOCK_STREAM, _) => "stream",
                    (libc::SOCK_DGRAM, _) => "datagram",
                    _ => "socket",
                };
                let process = self.processes.get(&process_id).expect("process checked");
                let socket_count = process
                    .descriptors
                    .values()
                    .filter(|descriptor| matches!(descriptor, Descriptor::Socket(_)))
                    .count();
                if socket_count >= MAX_SOCKETS_PER_PROCESS
                    || process.descriptors.len() >= MAX_TRACKED_DESCRIPTORS_PER_PROCESS
                {
                    sink.record_lost_events("network", 1).map_err(sink_error)?;
                } else {
                    self.processes
                        .get_mut(&process_id)
                        .expect("process checked")
                        .descriptors
                        .insert(
                            event.result as i32,
                            Descriptor::Socket(SocketState {
                                transport,
                                local: None,
                                peer: None,
                                listening: false,
                                dns_queries: HashMap::new(),
                            }),
                        );
                }
            }
            SyscallOperation::Bind if event.result >= 0 => {
                if let Some(endpoint) = socket_endpoint(data.as_ref()) {
                    let descriptor = event.arguments[0] as i32;
                    self.update_socket_endpoint(process_id, descriptor, endpoint, false);
                    self.record_network_event(
                        process_id,
                        descriptor,
                        "bind",
                        endpoint,
                        occurred_at_ms,
                        sink,
                    )?;
                }
            }
            SyscallOperation::Connect
                if event.result >= 0 || event.result == -i64::from(libc::EINPROGRESS) =>
            {
                if let Some(endpoint) = socket_endpoint(data.as_ref()) {
                    let descriptor = event.arguments[0] as i32;
                    self.update_socket_endpoint(process_id, descriptor, endpoint, true);
                    self.record_network_event(
                        process_id,
                        descriptor,
                        "connect",
                        endpoint,
                        occurred_at_ms,
                        sink,
                    )?;
                }
            }
            SyscallOperation::Listen if event.result >= 0 => {
                let descriptor = event.arguments[0] as i32;
                if let Some(Descriptor::Socket(socket)) = self
                    .processes
                    .get_mut(&process_id)
                    .and_then(|process| process.descriptors.get_mut(&descriptor))
                {
                    socket.listening = true;
                    if let Some(endpoint) = socket.local.filter(|endpoint| endpoint.port() != 0) {
                        self.record_network_event(
                            process_id,
                            descriptor,
                            "listen",
                            endpoint,
                            occurred_at_ms,
                            sink,
                        )?;
                    }
                }
            }
            SyscallOperation::GetSocketName if event.result >= 0 => {
                if let Some(endpoint) = socket_endpoint(data.as_ref()) {
                    let descriptor = event.arguments[0] as i32;
                    let listening =
                        self.update_socket_endpoint(process_id, descriptor, endpoint, false);
                    if listening {
                        self.record_network_event(
                            process_id,
                            descriptor,
                            "listen",
                            endpoint,
                            occurred_at_ms,
                            sink,
                        )?;
                    }
                }
            }
            SyscallOperation::GetPeerName if event.result >= 0 => {
                if let Some(endpoint) = socket_endpoint(data.as_ref()) {
                    self.update_socket_endpoint(
                        process_id,
                        event.arguments[0] as i32,
                        endpoint,
                        true,
                    );
                }
            }
            SyscallOperation::Accept if event.result >= 0 => {
                let descriptor = event.arguments[0] as i32;
                let peer = socket_endpoint(data.as_ref());
                let accepted = self
                    .processes
                    .get(&process_id)
                    .and_then(|process| process.descriptors.get(&descriptor))
                    .and_then(|descriptor| match descriptor {
                        Descriptor::Socket(socket) => Some(SocketState {
                            transport: socket.transport,
                            local: socket.local,
                            peer,
                            listening: false,
                            dns_queries: HashMap::new(),
                        }),
                        Descriptor::File(_) => None,
                    });
                if let Some(socket) = accepted {
                    self.processes
                        .get_mut(&process_id)
                        .expect("process checked")
                        .descriptors
                        .insert(event.result as i32, Descriptor::Socket(socket));
                    if let Some(endpoint) = peer {
                        self.record_network_event(
                            process_id,
                            event.result as i32,
                            "accept",
                            endpoint,
                            occurred_at_ms,
                            sink,
                        )?;
                    }
                }
            }
            SyscallOperation::SendTo | SyscallOperation::Write | SyscallOperation::WriteVector
                if event.result > 0 =>
            {
                self.observe_socket_payload(process_id, event, data, true, occurred_at_ms, sink)?;
            }
            SyscallOperation::ReceiveFrom
            | SyscallOperation::Read
            | SyscallOperation::ReadVector
                if event.result > 0 =>
            {
                self.observe_socket_payload(process_id, event, data, false, occurred_at_ms, sink)?;
            }
            _ => {}
        }
        Ok(())
    }

    fn observe_socket_payload(
        &mut self,
        process_id: u32,
        event: &Event,
        data: Option<SocketData>,
        sending: bool,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let descriptor = event.arguments[0] as i32;
        let identity = self.processes[&process_id].identity;
        let Some(Descriptor::Socket(socket)) = self
            .processes
            .get_mut(&process_id)
            .and_then(|process| process.descriptors.get_mut(&descriptor))
        else {
            return Ok(());
        };
        let Some(data) = data else {
            return Ok(());
        };
        if sending {
            if let Some((transaction, hostname)) = parse_dns_query(&data.payload) {
                if !socket.dns_queries.contains_key(&transaction)
                    && socket.dns_queries.len() >= MAX_DNS_QUERIES_PER_SOCKET
                {
                    sink.record_lost_events("network", 1).map_err(sink_error)?;
                } else {
                    socket.dns_queries.insert(transaction, hostname);
                }
            }
        } else {
            let dns_events = parse_dns_response(&data.payload, &mut socket.dns_queries);
            for dns in dns_events {
                let address = dns.address.to_string();
                sink.record_dns_correlation(DnsCorrelationRecord {
                    hostname: dns.hostname.clone(),
                    address: address.clone(),
                    process: identity,
                    occurred_at_ms,
                    evidence: EvidenceKind::Observed,
                    confidence: DnsConfidence::High,
                })
                .map_err(sink_error)?;
                sink.record_event(CollectorEvent {
                    category: "network",
                    operation: "dns",
                    target: format!("{} → {address}", dns.hostname),
                    process: Some(identity),
                    occurred_at_ms,
                    evidence: EvidenceKind::Derived,
                })
                .map_err(sink_error)?;
            }
        }
        if socket.transport == "udp" {
            let endpoint = socket_endpoint(Some(&data)).or(socket.peer);
            if let Some(endpoint) = endpoint {
                let operation = if sending { "send" } else { "receive" };
                self.record_network_event(
                    process_id,
                    descriptor,
                    operation,
                    endpoint,
                    occurred_at_ms,
                    sink,
                )?;
            }
        }
        Ok(())
    }

    fn observe_filesystem(
        &mut self,
        process_id: u32,
        operation: SyscallOperation,
        event: &Event,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if event.result < 0 {
            return Ok(());
        }
        let path_data = event.path_data().map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("path event: {error}"))
        })?;
        if path_data
            .as_ref()
            .map(|data| data.truncated)
            .unwrap_or(false)
        {
            sink.record_lost_events("filesystem", 1)
                .map_err(sink_error)?;
            return Ok(());
        }
        match operation {
            SyscallOperation::OpenAt | SyscallOperation::OpenAt2 => {
                let Some(path) = self.first_resolved_path(
                    process_id,
                    event.arguments[0] as i32,
                    event,
                    sink,
                )? else {
                    return Ok(());
                };
                self.finish_open(
                    process_id,
                    path,
                    event.arguments[2] as i32,
                    event.result,
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::Open | SyscallOperation::Create => {
                let Some(path) = self.first_resolved_path(process_id, libc::AT_FDCWD, event, sink)? else {
                    return Ok(());
                };
                let flags = if operation == SyscallOperation::Create {
                    libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC
                } else {
                    event.arguments[1] as i32
                };
                self.finish_open(process_id, path, flags, event.result, occurred_at_ms, sink)?;
            }
            SyscallOperation::Read | SyscallOperation::ReadVector | SyscallOperation::ReadAt
                if event.result > 0 =>
            {
                self.record_descriptor_file(
                    process_id,
                    event.arguments[0] as i32,
                    "read",
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::Write | SyscallOperation::WriteVector | SyscallOperation::WriteAt
                if event.result > 0 =>
            {
                self.record_descriptor_file(
                    process_id,
                    event.arguments[0] as i32,
                    "write",
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::FileTruncate => {
                self.record_descriptor_file(
                    process_id,
                    event.arguments[0] as i32,
                    "truncate",
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::Truncate => {
                self.record_single_path(
                    process_id,
                    libc::AT_FDCWD,
                    event,
                    ("truncate", true),
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::StatAt | SyscallOperation::ReadLinkAt => {
                self.record_single_path(
                    process_id,
                    event.arguments[0] as i32,
                    event,
                    ("read", false),
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::Stat => {
                self.record_single_path(
                    process_id,
                    libc::AT_FDCWD,
                    event,
                    ("read", false),
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::ReadDirectory => {
                self.record_descriptor_file(
                    process_id,
                    event.arguments[0] as i32,
                    "read",
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::UnlinkAt | SyscallOperation::MakeDirectoryAt => {
                let name = if operation == SyscallOperation::UnlinkAt {
                    "unlink"
                } else {
                    "create"
                };
                self.record_single_path(
                    process_id,
                    event.arguments[0] as i32,
                    event,
                    (name, true),
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::Unlink
            | SyscallOperation::MakeDirectory
            | SyscallOperation::RemoveDirectory => {
                let name = if operation == SyscallOperation::MakeDirectory {
                    "create"
                } else {
                    "unlink"
                };
                self.record_single_path(
                    process_id,
                    libc::AT_FDCWD,
                    event,
                    (name, true),
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::RenameAt | SyscallOperation::LinkAt => {
                let name = if operation == SyscallOperation::RenameAt {
                    "rename"
                } else {
                    "link"
                };
                self.record_two_paths(
                    process_id,
                    (event.arguments[0] as i32, event.arguments[2] as i32),
                    path_data,
                    name,
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::Rename | SyscallOperation::Link => {
                let name = if operation == SyscallOperation::Rename {
                    "rename"
                } else {
                    "link"
                };
                self.record_two_paths(
                    process_id,
                    (libc::AT_FDCWD, libc::AT_FDCWD),
                    path_data,
                    name,
                    occurred_at_ms,
                    sink,
                )?;
            }
            SyscallOperation::SymlinkAt | SyscallOperation::Symlink => {
                let Some(data) = path_data else {
                    self.lose_path(sink)?;
                    return Ok(());
                };
                let link_dir = if operation == SyscallOperation::SymlinkAt {
                    event.arguments[1] as i32
                } else {
                    libc::AT_FDCWD
                };
                let Some(link) = self.resolve_bytes(process_id, link_dir, &data.second) else {
                    self.lose_path(sink)?;
                    return Ok(());
                };
                let target = PathBuf::from(OsString::from_vec(data.first));
                self.record_file_event(
                    process_id,
                    "symlink",
                    &[target, link.clone()],
                    occurred_at_ms,
                    sink,
                )?;
                self.remember_mutation_path(link, sink)?;
            }
            SyscallOperation::MemoryMap => {
                let descriptor = event.arguments[4] as i32;
                if descriptor >= 0 {
                    let protection = event.arguments[2] as i32;
                    let flags = event.arguments[3] as i32;
                    if protection & libc::PROT_READ != 0 {
                        self.record_descriptor_file(
                            process_id,
                            descriptor,
                            "read",
                            occurred_at_ms,
                            sink,
                        )?;
                    }
                    if protection & libc::PROT_WRITE != 0 && flags & libc::MAP_SHARED != 0 {
                        self.record_descriptor_file(
                            process_id,
                            descriptor,
                            "write",
                            occurred_at_ms,
                            sink,
                        )?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn finish_open(
        &mut self,
        process_id: u32,
        path: PathBuf,
        flags: i32,
        result: i64,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if let Some(process) = self.processes.get_mut(&process_id) {
            if process.descriptors.contains_key(&(result as i32))
                || process.descriptors.len() < MAX_TRACKED_DESCRIPTORS_PER_PROCESS
            {
                process
                    .descriptors
                    .insert(result as i32, Descriptor::File(path.clone()));
            } else {
                sink.record_lost_events("filesystem", 1)
                    .map_err(sink_error)?;
            }
        }
        if flags & libc::O_CREAT != 0 && flags & libc::O_EXCL != 0 {
            self.record_file_event(
                process_id,
                "create",
                std::slice::from_ref(&path),
                occurred_at_ms,
                sink,
            )?;
            self.remember_mutation_path(path.clone(), sink)?;
        }
        if flags & libc::O_TRUNC != 0 {
            self.record_file_event(
                process_id,
                "truncate",
                std::slice::from_ref(&path),
                occurred_at_ms,
                sink,
            )?;
            self.remember_mutation_path(path.clone(), sink)?;
        }
        self.record_file_event(process_id, "open", &[path], occurred_at_ms, sink)
    }

    fn record_single_path(
        &mut self,
        process_id: u32,
        directory: i32,
        event: &Event,
        action: (&'static str, bool),
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let (operation, mutation) = action;
        let Some(path) = self.first_resolved_path(process_id, directory, event, sink)? else {
            return Ok(());
        };
        self.record_file_event(
            process_id,
            operation,
            std::slice::from_ref(&path),
            occurred_at_ms,
            sink,
        )?;
        if mutation {
            self.remember_mutation_path(path, sink)?;
        }
        Ok(())
    }

    fn record_two_paths(
        &mut self,
        process_id: u32,
        directories: (i32, i32),
        data: Option<PathData>,
        operation: &'static str,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let (first_directory, second_directory) = directories;
        let Some(data) = data else {
            self.lose_path(sink)?;
            return Ok(());
        };
        let Some(first) = self.resolve_bytes(process_id, first_directory, &data.first) else {
            self.lose_path(sink)?;
            return Ok(());
        };
        let Some(second) = self.resolve_bytes(process_id, second_directory, &data.second) else {
            self.lose_path(sink)?;
            return Ok(());
        };
        self.record_file_event(
            process_id,
            operation,
            &[first.clone(), second.clone()],
            occurred_at_ms,
            sink,
        )?;
        if operation == "rename" {
            self.remember_mutation_path(first, sink)?;
        }
        self.remember_mutation_path(second, sink)?;
        Ok(())
    }

    fn first_resolved_path(
        &self,
        process_id: u32,
        directory: i32,
        event: &Event,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<Option<PathBuf>> {
        let Some(data) = event.path_data().map_err(|error| {
            io::Error::new(io::ErrorKind::InvalidData, format!("path event: {error}"))
        })? else {
            sink.record_lost_events("filesystem", 1).map_err(sink_error)?;
            return Ok(None);
        };
        let path = self.resolve_bytes(process_id, directory, &data.first);
        if path.is_none() {
            sink.record_lost_events("filesystem", 1)
                .map_err(sink_error)?;
        }
        Ok(path)
    }

    fn resolve_bytes(&self, process_id: u32, directory: i32, bytes: &[u8]) -> Option<PathBuf> {
        let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
        if path.is_absolute() {
            return Some(clean_path(path));
        }
        let process = self.processes.get(&process_id)?;
        let base = if directory == libc::AT_FDCWD {
            process.cwd.clone()
        } else {
            match process.descriptors.get(&directory)? {
                Descriptor::File(path) => path.clone(),
                Descriptor::Socket(_) => return None,
            }
        };
        Some(clean_path(base.join(path)))
    }

    fn descriptor_path(&self, process_id: u32, descriptor: i32) -> Option<PathBuf> {
        match self
            .processes
            .get(&process_id)?
            .descriptors
            .get(&descriptor)?
        {
            Descriptor::File(path) => Some(path.clone()),
            Descriptor::Socket(_) => None,
        }
    }

    fn duplicate_descriptor(
        &mut self,
        process_id: u32,
        source: i32,
        destination: i32,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let descriptor = self
            .processes
            .get(&process_id)
            .and_then(|process| process.descriptors.get(&source))
            .cloned();
        if let Some(descriptor) = descriptor {
            let loss_category = match descriptor {
                Descriptor::File(_) => "filesystem",
                Descriptor::Socket(_) => "network",
            };
            let process = self
                .processes
                .get_mut(&process_id)
                .expect("process checked");
            if !process.descriptors.contains_key(&destination)
                && process.descriptors.len() >= MAX_TRACKED_DESCRIPTORS_PER_PROCESS
            {
                sink.record_lost_events(loss_category, 1)
                    .map_err(sink_error)?;
            } else {
                process.descriptors.insert(destination, descriptor);
            }
        }
        Ok(())
    }

    fn record_descriptor_file(
        &mut self,
        process_id: u32,
        descriptor: i32,
        operation: &'static str,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let Some(path) = self.descriptor_path(process_id, descriptor) else {
            return Ok(());
        };
        self.record_file_event(
            process_id,
            operation,
            std::slice::from_ref(&path),
            occurred_at_ms,
            sink,
        )?;
        if matches!(operation, "write" | "truncate") {
            self.remember_mutation_path(path, sink)?;
        }
        Ok(())
    }

    fn remember_mutation_path(
        &mut self,
        path: PathBuf,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if self.mutation_paths.contains(&path) {
            return Ok(());
        }
        if self.mutation_paths.len() >= MAX_FILE_SNAPSHOTS {
            return sink.record_lost_events("filesystem", 1).map_err(sink_error);
        }
        self.mutation_paths.insert(path);
        Ok(())
    }

    fn record_file_event(
        &self,
        process_id: u32,
        operation: &'static str,
        paths: &[PathBuf],
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if !paths.is_empty()
            && paths
                .iter()
                .all(|path| self.ignored_paths.iter().any(|ignored| ignored == path))
        {
            return Ok(());
        }
        let target = paths
            .iter()
            .map(|path| self.roots.normalize(path))
            .collect::<Vec<_>>()
            .join(" → ");
        let identity = self.processes[&process_id].identity;
        self.record_event(
            "filesystem",
            operation,
            target,
            identity,
            occurred_at_ms,
            sink,
        )
    }

    fn record_network_event(
        &self,
        process_id: u32,
        descriptor: i32,
        operation: &'static str,
        endpoint: SocketAddr,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let Some(Descriptor::Socket(socket)) = self.processes.get(&process_id).and_then(|process| {
            process.descriptors.get(&descriptor)
        })
        else {
            return Ok(());
        };
        let identity = self.processes[&process_id].identity;
        self.record_event(
            "network",
            operation,
            format!("{} {endpoint}", socket.transport),
            identity,
            occurred_at_ms,
            sink,
        )
    }

    fn update_socket_endpoint(
        &mut self,
        process_id: u32,
        descriptor: i32,
        endpoint: SocketAddr,
        peer: bool,
    ) -> bool {
        let Some(Descriptor::Socket(socket)) = self
            .processes
            .get_mut(&process_id)
            .and_then(|process| process.descriptors.get_mut(&descriptor))
        else {
            return false;
        };
        if peer {
            socket.peer = Some(endpoint);
        } else {
            socket.local = Some(endpoint);
        }
        socket.listening
    }

    fn register_child(
        &mut self,
        child: u32,
        parent: u32,
        operation: &'static str,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if self.processes.contains_key(&child) {
            return Ok(());
        }
        if self.processes.len() >= MAX_LIVE_PROCESSES {
            for category in ["processes", "filesystem", "network", "environment"] {
                sink.record_lost_events(category, 1).map_err(sink_error)?;
            }
            return Ok(());
        }
        let Some(parent_state) = self.processes.get(&parent).cloned() else {
            sink.record_lost_events("processes", 1).map_err(sink_error)?;
            return self.register_orphan(child, occurred_at_ms, sink);
        };
        let identity = self.allocate_identity()?;
        self.processes.insert(
            child,
            ProcessState {
                identity,
                executable: parent_state.executable.clone(),
                cwd: parent_state.cwd,
                descriptors: parent_state.descriptors,
            },
        );
        self.threads.insert(child, child);
        sink.record_process(ProcessRecord {
            identity,
            operating_system_id: child,
            start_time_ticks: None,
            parent: Some(parent_state.identity),
            executable: parent_state.executable.clone(),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)?;
        self.record_event(
            "process",
            operation,
            parent_state.executable,
            identity,
            occurred_at_ms,
            sink,
        )
    }

    fn register_orphan(
        &mut self,
        process_id: u32,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let identity = self.allocate_identity()?;
        self.processes.insert(
            process_id,
            ProcessState {
                identity,
                executable: self.root_executable.clone(),
                cwd: self.root_cwd.clone(),
                descriptors: HashMap::new(),
            },
        );
        sink.record_process(ProcessRecord {
            identity,
            operating_system_id: process_id,
            start_time_ticks: None,
            parent: None,
            executable: self.root_executable.clone(),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)
    }

    fn finish_remaining_processes(&mut self, sink: &mut dyn CollectorSink) -> io::Result<()> {
        let occurred_at_ms = super::super::unix_time_ms()?;
        let remaining: Vec<_> = self
            .processes
            .iter()
            .filter(|(process_id, _)| **process_id != self.root_pid)
            .map(|(process_id, process)| (*process_id, process.clone()))
            .collect();
        if !remaining.is_empty() {
            sink.record_lost_events("processes", remaining.len() as u64)
                .map_err(sink_error)?;
        }
        for (process_id, process) in remaining {
            self.processes.remove(&process_id);
            sink.record_process_exit(ProcessExitRecord {
                identity: process.identity,
                occurred_at_ms,
                exit_code: None,
                termination_signal: None,
            })
            .map_err(sink_error)?;
            sink.record_event(CollectorEvent {
                category: "process",
                operation: "exit",
                target: process.executable,
                process: Some(process.identity),
                occurred_at_ms,
                evidence: EvidenceKind::Derived,
            })
            .map_err(sink_error)?;
        }
        Ok(())
    }

    fn finish_root(&mut self, status: ExitStatus, sink: &mut dyn CollectorSink) -> io::Result<()> {
        let Some(root) = self.processes.remove(&self.root_pid) else {
            return Err(io::Error::new(io::ErrorKind::Other, "root process is missing"));
        };
        let occurred_at_ms = super::super::unix_time_ms()?;
        sink.record_process_exit(ProcessExitRecord {
            identity: root.identity,
            occurred_at_ms,
            exit_code: status.code(),
            termination_signal: status.signal(),
        })
        .map_err(sink_error)?;
        self.record_event(
            "process",
            "exit",
            root.executable,
            root.identity,
            occurred_at_ms,
            sink,
        )
    }

    fn record_file_states(&self, sink: &mut dyn CollectorSink) -> io::Result<()> {
        let mut paths: Vec<_> = self.mutation_paths.iter().collect();
        paths.sort();
        let before = FileState {
            kind: FileStateKind::Unknown,
            size: None,
            modified_at_ns: None,
        };
        for path in paths {
            if self.ignored_paths.iter().any(|ignored| ignored == path) {
                continue;
            }
            let after = super::super::capture_file_state(path);
            let target = self.roots.normalize(path);
            sink.record_file_delta(FileDeltaRecord {
                path: target.clone(),
                before,
                after,
            })
            .map_err(sink_error)?;
            sink.record_event(CollectorEvent {
                category: "filesystem",
                operation: "state-observed",
                target,
                process: None,
                occurred_at_ms: super::super::unix_time_ms()?,
                evidence: EvidenceKind::Derived,
            })
            .map_err(sink_error)?;
        }
        Ok(())
    }

    fn record_event(
        &self,
        category: &'static str,
        operation: &'static str,
        target: String,
        process: ProcessIdentity,
        occurred_at_ms: i64,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        sink.record_event(CollectorEvent {
            category,
            operation,
            target,
            process: Some(process),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)
    }

    fn allocate_identity(&mut self) -> io::Result<ProcessIdentity> {
        let identity = ProcessIdentity::new(self.next_identity);
        self.next_identity = self
            .next_identity
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "process identity exhausted"))?;
        Ok(identity)
    }

    fn lose_path(&self, sink: &mut dyn CollectorSink) -> io::Result<()> {
        sink.record_lost_events("filesystem", 1).map_err(sink_error)
    }
}

fn socket_endpoint(data: Option<&SocketData>) -> Option<SocketAddr> {
    data.and_then(|data| parse_socket_address(&data.address))
}

fn event_order(left: &Event, right: &Event) -> std::cmp::Ordering {
    (
        left.monotonic_ns,
        event_kind_order(left.kind),
        left.tgid,
        left.tid,
        left.flags,
        left.result,
        left.arguments,
        &left.data,
    )
        .cmp(&(
            right.monotonic_ns,
            event_kind_order(right.kind),
            right.tgid,
            right.tid,
            right.flags,
            right.result,
            right.arguments,
            &right.data,
        ))
}

const fn event_kind_order(kind: EventKind) -> u8 {
    match kind {
        EventKind::ProcessFork => 0,
        EventKind::ProcessExec => 1,
        EventKind::Syscall => 2,
        EventKind::ProcessExit => 3,
        EventKind::Heartbeat => 4,
    }
}

fn plan_clones(events: &[Event]) -> ClonePlan {
    let mut plan = ClonePlan::default();
    let mut pending: HashMap<u32, VecDeque<(u64, u32)>> = HashMap::new();
    for event in events {
        if event.kind == EventKind::ProcessFork {
            pending
                .entry(event.arguments[1] as u32)
                .or_default()
                .push_back((event.monotonic_ns, event.tgid));
            continue;
        }
        let Some(operation) = event.syscall_operation() else {
            continue;
        };
        if event.result <= 0
            || !matches!(
                operation,
                SyscallOperation::Clone | SyscallOperation::Clone3 | SyscallOperation::Fork
            )
        {
            continue;
        }
        let child = event.result as u32;
        let Some(queue) = pending.get_mut(&child) else {
            continue;
        };
        let Some(position) = queue.iter().position(|(_, parent)| *parent == event.tgid) else {
            continue;
        };
        let Some((fork_time, parent)) = queue.remove(position) else {
            continue;
        };
        let operation_name = if operation == SyscallOperation::Fork {
            "fork"
        } else {
            "clone"
        };
        plan.forks.insert(
            (fork_time, child),
            CloneClassification {
                parent,
                operation: operation_name,
            },
        );
        plan.matched_clones
            .insert((event.monotonic_ns, event.tgid, event.tid, event.result));
    }
    plan
}

fn clean_path(path: PathBuf) -> PathBuf {
    let mut cleaned = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !cleaned.pop() {
                    cleaned.push(component.as_os_str());
                }
            }
            _ => cleaned.push(component.as_os_str()),
        }
    }
    cleaned
}

fn sink_error(error: crate::collector::SinkError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}
