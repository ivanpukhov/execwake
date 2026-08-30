use std::collections::HashMap;
use std::env;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus};
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

mod syscall;

use syscall::SyscallState;

use super::{
    Collector, CollectorEvent, CollectorSink, DnsConfidence, DnsCorrelationRecord,
    EnvironmentVariableRecord, FileDeltaRecord, FileState, FileStateKind, ProcessExecRecord,
    ProcessExitRecord, ProcessIdentity, ProcessRecord, SinkError,
};
use crate::privacy::{is_valid_environment_name, PathRoots};
use crate::session::{CategoryCoverage, EvidenceKind, SessionCoverage};

pub struct PtraceCollector {
    root_executable: String,
    next_identity: u64,
    processes: HashMap<libc::pid_t, TracedProcess>,
    path_roots: PathRoots,
    file_snapshots: HashMap<std::path::PathBuf, FileState>,
    inherited_environment: Vec<String>,
}

struct TracedProcess {
    identity: ProcessIdentity,
    executable: String,
    syscalls: SyscallState,
}

impl PtraceCollector {
    pub fn new(root_executable: String) -> Self {
        Self {
            root_executable,
            next_identity: 1,
            processes: HashMap::new(),
            path_roots: PathRoots::new(
                env::var_os("HOME").map(Into::into),
                env::current_dir().ok(),
                Some(env::temp_dir()),
            ),
            file_snapshots: HashMap::new(),
            inherited_environment: inherited_environment_names(),
        }
    }

    fn register_process(
        &mut self,
        process_id: libc::pid_t,
        parent_id: Option<libc::pid_t>,
        operation: &'static str,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        if self.processes.contains_key(&process_id) {
            return Ok(());
        }

        let inherited_syscalls = parent_id.and_then(|id| {
            self.processes
                .get(&id)
                .map(|process| SyscallState::child(&process.syscalls))
        });
        let parent = parent_id.and_then(|id| {
            self.processes
                .get(&id)
                .map(|process| (process.identity, process.executable.clone()))
        });
        let executable = parent
            .as_ref()
            .map(|(_, executable)| executable.clone())
            .unwrap_or_else(|| self.root_executable.clone());
        let identity = ProcessIdentity::new(self.next_identity);
        self.next_identity = self
            .next_identity
            .checked_add(1)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "process identity exhausted"))?;
        let occurred_at_ms = unix_time_ms()?;
        let start_time_ticks = process_start_time(process_id).ok();
        sink.record_process(ProcessRecord {
            identity,
            operating_system_id: process_id as u32,
            start_time_ticks,
            parent: parent.as_ref().map(|(identity, _)| *identity),
            executable: executable.clone(),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)?;
        sink.record_event(CollectorEvent {
            category: "process",
            operation,
            target: executable.clone(),
            process: Some(identity),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)?;
        if parent_id.is_none() {
            for name in &self.inherited_environment {
                sink.record_environment_variable(EnvironmentVariableRecord {
                    name: name.clone(),
                    process: identity,
                    evidence: EvidenceKind::Derived,
                })
                .map_err(sink_error)?;
                sink.record_event(CollectorEvent {
                    category: "environment",
                    operation: "inherited",
                    target: name.clone(),
                    process: Some(identity),
                    occurred_at_ms,
                    evidence: EvidenceKind::Derived,
                })
                .map_err(sink_error)?;
            }
        }
        self.processes.insert(
            process_id,
            TracedProcess {
                identity,
                executable,
                syscalls: inherited_syscalls.unwrap_or_else(SyscallState::root),
            },
        );
        Ok(())
    }

    fn record_exec(
        &mut self,
        process_id: libc::pid_t,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let executable = std::fs::read_link(format!("/proc/{process_id}/exe"))
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown executable".to_owned());
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "exec from unknown process"))?;
        process.executable.clone_from(&executable);
        sink.record_process_exec(ProcessExecRecord {
            identity: process.identity,
            executable: executable.clone(),
            occurred_at_ms: unix_time_ms()?,
        })
        .map_err(sink_error)?;
        sink.record_event(CollectorEvent {
            category: "process",
            operation: "exec",
            target: executable,
            process: Some(process.identity),
            occurred_at_ms: unix_time_ms()?,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)
    }

    fn record_exit(
        &mut self,
        process_id: libc::pid_t,
        wait_status: libc::c_int,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let Some(process) = self.processes.remove(&process_id) else {
            return Ok(());
        };
        let occurred_at_ms = unix_time_ms()?;
        let (exit_code, termination_signal) = if libc::WIFEXITED(wait_status) {
            (Some(libc::WEXITSTATUS(wait_status)), None)
        } else {
            (None, Some(libc::WTERMSIG(wait_status)))
        };
        sink.record_process_exit(ProcessExitRecord {
            identity: process.identity,
            occurred_at_ms,
            exit_code,
            termination_signal,
        })
        .map_err(sink_error)?;
        sink.record_event(CollectorEvent {
            category: "process",
            operation: "exit",
            target: process.executable,
            process: Some(process.identity),
            occurred_at_ms,
            evidence: EvidenceKind::Observed,
        })
        .map_err(sink_error)
    }

    fn record_syscall(
        &mut self,
        process_id: libc::pid_t,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<()> {
        let process = self
            .processes
            .get_mut(&process_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "syscall from unknown process"))?;
        let identity = process.identity;
        let observation = process.syscalls.observe_stop(process_id)?;
        for path in observation.mutation_paths {
            self.file_snapshots
                .entry(path.clone())
                .or_insert_with(|| capture_file_state(&path));
        }
        for event in observation.events {
            let target = event
                .paths
                .iter()
                .map(|path| self.path_roots.normalize(path))
                .collect::<Vec<_>>()
                .join(" → ");
            sink.record_event(CollectorEvent {
                category: "filesystem",
                operation: event.operation,
                target,
                process: Some(identity),
                occurred_at_ms: unix_time_ms()?,
                evidence: EvidenceKind::Observed,
            })
            .map_err(sink_error)?;
        }
        for event in observation.network_events {
            sink.record_event(CollectorEvent {
                category: "network",
                operation: event.operation,
                target: format!("{} {}", event.transport, event.endpoint),
                process: Some(identity),
                occurred_at_ms: unix_time_ms()?,
                evidence: EvidenceKind::Observed,
            })
            .map_err(sink_error)?;
        }
        for event in observation.dns_events {
            let occurred_at_ms = unix_time_ms()?;
            let address = event.address.to_string();
            sink.record_dns_correlation(DnsCorrelationRecord {
                hostname: event.hostname.clone(),
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
                target: format!("{} → {address}", event.hostname),
                process: Some(identity),
                occurred_at_ms,
                evidence: EvidenceKind::Derived,
            })
            .map_err(sink_error)?;
        }
        Ok(())
    }

    fn record_file_deltas(&self, sink: &mut dyn CollectorSink) -> io::Result<()> {
        let mut paths: Vec<_> = self.file_snapshots.iter().collect();
        paths.sort_by(|(left, _), (right, _)| left.cmp(right));
        for (path, before) in paths {
            let after = capture_file_state(path);
            let target = self.path_roots.normalize(path);
            sink.record_file_delta(FileDeltaRecord {
                path: target.clone(),
                before: *before,
                after,
            })
            .map_err(sink_error)?;
            let operation = match (before.kind, after.kind) {
                (FileStateKind::Absent, kind) if kind != FileStateKind::Absent => "state-created",
                (kind, FileStateKind::Absent) if kind != FileStateKind::Absent => "state-removed",
                _ if *before == after => "state-restored",
                _ => "state-changed",
            };
            sink.record_event(CollectorEvent {
                category: "filesystem",
                operation,
                target,
                process: None,
                occurred_at_ms: unix_time_ms()?,
                evidence: EvidenceKind::Derived,
            })
            .map_err(sink_error)?;
        }
        Ok(())
    }
}

impl Collector for PtraceCollector {
    fn backend_name(&self) -> &'static str {
        "ptrace"
    }

    fn prepare(&mut self, command: &mut Command) -> io::Result<()> {
        unsafe {
            command.pre_exec(|| {
                if libc::ptrace(
                    libc::PTRACE_TRACEME,
                    0,
                    ptr::null_mut::<libc::c_void>(),
                    ptr::null_mut::<libc::c_void>(),
                ) == -1
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }

    fn collect(
        &mut self,
        child: &mut Child,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<ExitStatus> {
        let root_id = child.id() as libc::pid_t;
        let mut wait_status = 0;
        wait_for(root_id, &mut wait_status)?;
        if !libc::WIFSTOPPED(wait_status) || libc::WSTOPSIG(wait_status) != libc::SIGTRAP {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "tracee did not enter its initial stop",
            ));
        }

        let options = libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_TRACEEXIT
            | libc::PTRACE_O_EXITKILL;
        ptrace_call(
            libc::PTRACE_SETOPTIONS,
            root_id,
            ptr::null_mut(),
            options as usize as *mut libc::c_void,
        )
        .map_err(|error| trace_error("setting ptrace options", error))?;
        self.register_process(root_id, None, "start", sink)?;
        sink.set_backend(self.backend_name()).map_err(sink_error)?;
        resume_syscall(root_id, 0).map_err(|error| trace_error("resuming root process", error))?;

        let mut root_status = None;
        while !self.processes.is_empty() {
            let process_id = wait_for(-1, &mut wait_status)?;
            if libc::WIFEXITED(wait_status) || libc::WIFSIGNALED(wait_status) {
                if process_id == root_id {
                    root_status = Some(ExitStatus::from_raw(wait_status));
                }
                self.record_exit(process_id, wait_status, sink)?;
                continue;
            }
            if !libc::WIFSTOPPED(wait_status) {
                continue;
            }

            let stop_signal = libc::WSTOPSIG(wait_status);
            let ptrace_event = wait_status >> 16;
            match ptrace_event {
                libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                    let mut child_id: libc::c_ulong = 0;
                    ptrace_call(
                        libc::PTRACE_GETEVENTMSG,
                        process_id,
                        ptr::null_mut(),
                        &mut child_id as *mut _ as *mut libc::c_void,
                    )?;
                    let operation = if ptrace_event == libc::PTRACE_EVENT_CLONE {
                        "clone"
                    } else {
                        "fork"
                    };
                    self.register_process(
                        child_id as libc::pid_t,
                        Some(process_id),
                        operation,
                        sink,
                    )?;
                    resume_syscall(process_id, 0)?;
                }
                libc::PTRACE_EVENT_EXEC => {
                    self.record_exec(process_id, sink)?;
                    resume_syscall(process_id, 0)?;
                }
                libc::PTRACE_EVENT_EXIT => resume_syscall(process_id, 0)?,
                0 => {
                    if stop_signal == (libc::SIGTRAP | 0x80) {
                        self.record_syscall(process_id, sink)?;
                    }
                    let signal = if stop_signal == libc::SIGSTOP
                        || stop_signal == libc::SIGTRAP
                        || stop_signal == (libc::SIGTRAP | 0x80)
                    {
                        0
                    } else {
                        stop_signal
                    };
                    resume_syscall(process_id, signal)?;
                }
                _ => resume_syscall(process_id, 0)?,
            }
        }

        self.record_file_deltas(sink)?;
        sink.set_coverage(SessionCoverage {
            processes: CategoryCoverage::complete(),
            filesystem: CategoryCoverage::partial(0),
            network: CategoryCoverage::partial(0),
            environment: CategoryCoverage::partial(0),
        })
        .map_err(sink_error)?;
        root_status
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "root process status missing"))
    }
}

fn wait_for(process_id: libc::pid_t, wait_status: &mut libc::c_int) -> io::Result<libc::pid_t> {
    loop {
        let result =
            unsafe { libc::waitpid(process_id, wait_status, libc::__WALL | libc::__WNOTHREAD) };
        if result >= 0 {
            return Ok(result);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn resume_syscall(process_id: libc::pid_t, signal: libc::c_int) -> io::Result<()> {
    ptrace_call(
        libc::PTRACE_SYSCALL,
        process_id,
        ptr::null_mut(),
        signal as usize as *mut libc::c_void,
    )
    .map(|_| ())
}

fn ptrace_call(
    request: libc::c_uint,
    process_id: libc::pid_t,
    address: *mut libc::c_void,
    data: *mut libc::c_void,
) -> io::Result<libc::c_long> {
    let result = unsafe { libc::ptrace(request, process_id, address, data) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn sink_error(error: SinkError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

fn trace_error(action: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

fn unix_time_ms() -> io::Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis())
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "system time is out of range"))
}

fn process_start_time(process_id: libc::pid_t) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat"))?;
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process stat"))?
        .1;
    fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "process start time missing"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))
}

fn capture_file_state(path: &std::path::Path) -> FileState {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            let kind = if file_type.is_file() {
                FileStateKind::File
            } else if file_type.is_dir() {
                FileStateKind::Directory
            } else if file_type.is_symlink() {
                FileStateKind::Symlink
            } else {
                FileStateKind::Other
            };
            let modified_at_ns = i128::from(metadata.mtime())
                .checked_mul(1_000_000_000)
                .and_then(|value| value.checked_add(i128::from(metadata.mtime_nsec())))
                .and_then(|value| i64::try_from(value).ok());
            FileState {
                kind,
                size: Some(metadata.size()),
                modified_at_ns,
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => FileState {
            kind: FileStateKind::Absent,
            size: None,
            modified_at_ns: None,
        },
        Err(_) => FileState {
            kind: FileStateKind::Unknown,
            size: None,
            modified_at_ns: None,
        },
    }
}

fn inherited_environment_names() -> Vec<String> {
    extern "C" {
        static mut environ: *mut *mut libc::c_char;
    }

    let mut names = Vec::new();
    unsafe {
        // Stop at the separator so no bytes from an environment value are read.
        let mut entry = environ;
        while !entry.is_null() && !(*entry).is_null() {
            let bytes = *entry as *const u8;
            let mut name = Vec::new();
            for index in 0..4096 {
                let byte = *bytes.add(index);
                if byte == b'=' {
                    if let Ok(name) = String::from_utf8(name) {
                        if is_valid_environment_name(&name) {
                            names.push(name);
                        }
                    }
                    break;
                }
                if byte == 0 {
                    break;
                }
                name.push(byte);
            }
            entry = entry.add(1);
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

#[cfg(test)]
mod tests {
    use super::{inherited_environment_names, process_start_time};

    #[test]
    fn reads_process_start_time_from_proc() {
        assert!(process_start_time(std::process::id() as libc::pid_t).is_ok());
    }

    #[test]
    fn inherited_environment_contains_names_only() {
        let names = inherited_environment_names();

        assert!(names.iter().any(|name| name == "PATH"));
        assert!(names.iter().all(|name| !name.contains('=')));
    }
}
