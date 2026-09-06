use std::convert::{TryFrom, TryInto};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

mod normalize;
mod protocol;

use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{Array, HashMap as BpfHashMap, MapRefMut, PerfEventArray};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;

use super::PtraceCollector;
use crate::collector::{Collector, CollectorSink};
use crate::limits::{EBPF_BUFFER_PAGES, EBPF_READ_BATCH, MAX_EBPF_QUEUED_EVENTS};
use crate::session::{
    CategoryCoverage, CollectorBackend, CollectorDecision, CollectorFallbackReason,
    CollectorRequest, SessionCoverage,
};

static CGROUP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub enum LinuxCollector {
    Ebpf {
        collector: EbpfCollector,
        requested: CollectorRequest,
    },
    Ptrace {
        collector: PtraceCollector,
        requested: CollectorRequest,
        fallback_reason: Option<CollectorFallbackReason>,
    },
}

impl LinuxCollector {
    pub fn new(root_executable: String, requested: CollectorRequest) -> io::Result<Self> {
        #[cfg(test)]
        if requested == CollectorRequest::Auto
            && std::env::var_os("EXECWAKE_FORCE_PTRACE").is_some()
        {
            return Ok(Self::Ptrace {
                collector: PtraceCollector::new(root_executable),
                requested,
                fallback_reason: None,
            });
        }

        match requested {
            CollectorRequest::Ptrace => Ok(Self::Ptrace {
                collector: PtraceCollector::new(root_executable),
                requested,
                fallback_reason: None,
            }),
            CollectorRequest::Ebpf => EbpfCollector::new(root_executable)
                .map(|collector| Self::Ebpf {
                    collector,
                    requested,
                })
                .map_err(EbpfInitializationError::into_io),
            CollectorRequest::Auto => match EbpfCollector::new(root_executable.clone()) {
                Ok(collector) => Ok(Self::Ebpf {
                    collector,
                    requested,
                }),
                Err(error) => {
                    #[cfg(test)]
                    if std::env::var_os("EXECWAKE_REQUIRE_EBPF").is_some() {
                        panic!("eBPF collector is required for this test: {error:?}");
                    }
                    Ok(Self::Ptrace {
                        collector: PtraceCollector::new(root_executable),
                        requested,
                        fallback_reason: Some(error.reason),
                    })
                }
            },
        }
    }

    pub fn decision(&self) -> CollectorDecision {
        match self {
            Self::Ebpf { requested, .. } => CollectorDecision {
                requested: *requested,
                backend: CollectorBackend::Ebpf,
                fallback_reason: None,
            },
            Self::Ptrace {
                requested,
                fallback_reason,
                ..
            } => CollectorDecision {
                requested: *requested,
                backend: CollectorBackend::Ptrace,
                fallback_reason: *fallback_reason,
            },
        }
    }

    pub fn ignore_paths(&mut self, paths: &[&Path]) {
        match self {
            Self::Ebpf { collector, .. } => collector
                .ignored_paths
                .extend(paths.iter().map(|path| path.to_path_buf())),
            Self::Ptrace { collector, .. } => collector.ignore_paths(paths),
        }
    }
}

impl Collector for LinuxCollector {
    fn backend_name(&self) -> &'static str {
        match self {
            Self::Ebpf { collector, .. } => collector.backend_name(),
            Self::Ptrace { collector, .. } => collector.backend_name(),
        }
    }

    fn prepare(&mut self, command: &mut Command) -> io::Result<()> {
        match self {
            Self::Ebpf { collector, .. } => collector.prepare(command),
            Self::Ptrace { collector, .. } => collector.prepare(command),
        }
    }

    fn collect(
        &mut self,
        child: &mut Child,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<ExitStatus> {
        match self {
            Self::Ebpf { collector, .. } => collector.collect(child, sink),
            Self::Ptrace { collector, .. } => collector.collect(child, sink),
        }
    }
}

#[derive(Debug)]
struct EbpfInitializationError {
    reason: CollectorFallbackReason,
    error: io::Error,
}

impl EbpfInitializationError {
    fn new(reason: CollectorFallbackReason, context: &str, error: impl std::fmt::Display) -> Self {
        Self {
            reason,
            error: io::Error::new(io::ErrorKind::Other, format!("{context}: {error}")),
        }
    }

    fn cgroup(error: io::Error) -> Self {
        let reason = match error.kind() {
            io::ErrorKind::NotFound => CollectorFallbackReason::CgroupUnavailable,
            io::ErrorKind::PermissionDenied => CollectorFallbackReason::PermissionDenied,
            io::ErrorKind::InvalidData | io::ErrorKind::Unsupported => {
                CollectorFallbackReason::PlatformIncompatible
            }
            _ => CollectorFallbackReason::CgroupSetupFailed,
        };
        Self::new(reason, "creating collector cgroup", error)
    }

    fn into_io(self) -> io::Error {
        self.error
    }
}

pub struct EbpfCollector {
    root_executable: String,
    root_cwd: PathBuf,
    ignored_paths: Vec<PathBuf>,
    scope: CgroupScope,
    probe: EbpfProbe,
}

impl EbpfCollector {
    fn new(root_executable: String) -> Result<Self, EbpfInitializationError> {
        let scope = CgroupScope::create().map_err(EbpfInitializationError::cgroup)?;
        let probe = EbpfProbe::load(scope.id())?;
        let root_cwd = std::env::current_dir().map_err(|error| {
            EbpfInitializationError::new(
                CollectorFallbackReason::InitializationFailed,
                "reading current directory",
                error,
            )
        })?;
        Ok(Self {
            root_executable,
            root_cwd,
            ignored_paths: Vec::new(),
            scope,
            probe,
        })
    }
}

impl Collector for EbpfCollector {
    fn backend_name(&self) -> &'static str {
        "ebpf"
    }

    fn prepare(&mut self, command: &mut Command) -> io::Result<()> {
        self.scope.configure(command)
    }

    fn collect(
        &mut self,
        child: &mut Child,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<ExitStatus> {
        let namespace_root_pid = child.id();
        let root_start_time_ticks =
            super::process_start_time(namespace_root_pid as libc::pid_t).ok();
        let clock = normalize::CaptureClock::now()?;
        let mut normalizer = normalize::Normalizer::new(
            namespace_root_pid,
            self.root_executable.clone(),
            self.root_cwd.clone(),
            root_start_time_ticks,
            self.ignored_paths.clone(),
            clock,
        );
        let run = match self.probe.start() {
            Ok(run) => run,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if let Err(error) = normalizer
            .start(sink)
            .and_then(|()| sink.set_backend(self.backend_name()).map_err(sink_error))
        {
            let _ = child.kill();
            let _ = child.wait();
            let _ = self.probe.stop(run);
            return Err(error);
        }
        let result = child.wait();
        let output = self.probe.stop(run)?;
        let status = result?;
        sink.set_coverage(ebpf_coverage(output.lost_events))
            .map_err(sink_error)?;
        normalizer.replay(output.events, status, sink)?;
        Ok(status)
    }
}

const fn ebpf_coverage(lost_events: u64) -> SessionCoverage {
    SessionCoverage {
        processes: if lost_events == 0 {
            CategoryCoverage::complete()
        } else {
            CategoryCoverage::partial(lost_events)
        },
        filesystem: CategoryCoverage::partial(lost_events),
        network: CategoryCoverage::partial(lost_events),
        environment: CategoryCoverage::partial(lost_events),
    }
}

struct CgroupScope {
    path: PathBuf,
    id: u64,
}

impl CgroupScope {
    fn create() -> io::Result<Self> {
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let current = membership
            .lines()
            .find_map(|line| line.strip_prefix("0::"))
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "cgroup v2 is unavailable"))?;
        let relative = Path::new(current.trim_start_matches('/'));
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid cgroup membership path",
            ));
        }
        let parent = Path::new("/sys/fs/cgroup").join(relative);
        for _ in 0..8 {
            let sequence = CGROUP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!("execwake-{}-{sequence}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    let id = fs::metadata(&path)?.ino();
                    return Ok(Self { path, id });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a collector cgroup",
        ))
    }

    const fn id(&self) -> u64 {
        self.id
    }

    fn configure(&self, command: &mut Command) -> io::Result<()> {
        let path = CString::new(self.path.join("cgroup.procs").as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cgroup path"))?;
        unsafe {
            command.pre_exec(move || {
                let descriptor = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
                if descriptor < 0 {
                    return Err(io::Error::last_os_error());
                }
                let result = libc::write(descriptor, b"0".as_ptr() as *const libc::c_void, 1);
                let write_error = if result == -1 {
                    Some(io::Error::last_os_error())
                } else if result != 1 {
                    Some(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "could not join collector cgroup",
                    ))
                } else {
                    None
                };
                libc::close(descriptor);
                if let Some(error) = write_error {
                    return Err(error);
                }
                Ok(())
            });
        }
        Ok(())
    }
}

impl Drop for CgroupScope {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

struct EbpfProbe {
    bpf: Bpf,
    buffers: Option<Vec<PerfEventArrayBuffer<MapRefMut>>>,
}

impl EbpfProbe {
    fn load(cgroup_id: u64) -> Result<Self, EbpfInitializationError> {
        let mut bpf = Bpf::load(aya::include_bytes_aligned!("../../../bpf/collector.bpf.o"))
            .map_err(|error| {
                EbpfInitializationError::new(
                    CollectorFallbackReason::ProgramLoadFailed,
                    "loading embedded eBPF object",
                    error,
                )
            })?;
        let mut target =
            Array::<_, u64>::try_from(bpf.map_mut("TARGET_CGROUP").map_err(|error| {
                EbpfInitializationError::new(
                    CollectorFallbackReason::ProgramLoadFailed,
                    "opening target cgroup map",
                    error,
                )
            })?)
            .map_err(|error| {
                EbpfInitializationError::new(
                    CollectorFallbackReason::ProgramLoadFailed,
                    "opening target cgroup map",
                    error,
                )
            })?;
        target.set(0, cgroup_id, 0).map_err(|error| {
            EbpfInitializationError::new(
                CollectorFallbackReason::ProgramLoadFailed,
                "configuring target cgroup map",
                error,
            )
        })?;
        drop(target);

        let mut operation_map = BpfHashMap::<_, i64, u32>::try_from(
            bpf.map_mut("SYSCALL_OPERATIONS").map_err(|error| {
                EbpfInitializationError::new(
                    CollectorFallbackReason::ProgramLoadFailed,
                    "opening syscall operation map",
                    error,
                )
            })?,
        )
        .map_err(|error| {
            EbpfInitializationError::new(
                CollectorFallbackReason::ProgramLoadFailed,
                "opening syscall operation map",
                error,
            )
        })?;
        for (number, operation) in syscall_operations() {
            operation_map
                .insert(number, operation as u32, 0)
                .map_err(|error| {
                    EbpfInitializationError::new(
                        CollectorFallbackReason::ProgramLoadFailed,
                        "configuring syscall operation map",
                        error,
                    )
                })?;
        }
        drop(operation_map);

        for event in [
            "sched_process_fork",
            "sched_process_exec",
            "sched_process_exit",
        ] {
            attach_tracepoint(&mut bpf, event, "sched", event)?;
        }
        attach_tracepoint(
            &mut bpf,
            "raw_syscalls_sys_enter",
            "raw_syscalls",
            "sys_enter",
        )?;
        attach_tracepoint(
            &mut bpf,
            "raw_syscalls_sys_exit",
            "raw_syscalls",
            "sys_exit",
        )?;

        let mut event_array = PerfEventArray::try_from(bpf.map_mut("EVENTS").map_err(|error| {
            EbpfInitializationError::new(
                CollectorFallbackReason::EventBufferUnavailable,
                "opening event buffer map",
                error,
            )
        })?)
        .map_err(|error| {
            EbpfInitializationError::new(
                CollectorFallbackReason::EventBufferUnavailable,
                "opening event buffer map",
                error,
            )
        })?;
        let mut buffers = Vec::new();
        for cpu in online_cpus().map_err(|error| {
            EbpfInitializationError::new(
                CollectorFallbackReason::EventBufferUnavailable,
                "enumerating online CPUs",
                error,
            )
        })? {
            buffers.push(
                event_array
                    .open(cpu, Some(EBPF_BUFFER_PAGES))
                    .map_err(|error| {
                        EbpfInitializationError::new(
                            CollectorFallbackReason::EventBufferUnavailable,
                            "opening per-CPU event buffer",
                            error,
                        )
                    })?,
            );
        }
        Ok(Self {
            bpf,
            buffers: Some(buffers),
        })
    }

    fn start(&mut self) -> io::Result<ProbeRun> {
        let buffers = self
            .buffers
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "eBPF probe already started"))?;
        Ok(ProbeRun::start(buffers))
    }

    fn stop(&mut self, run: ProbeRun) -> io::Result<ProbeOutput> {
        let mut output = run.stop()?;
        let losses = Array::<_, u64>::try_from(self.bpf.map_mut("LOSSES").map_err(other_error)?)
            .map_err(other_error)?;
        output.lost_events = output
            .lost_events
            .saturating_add(losses.get(&0, 0).map_err(other_error)?);
        Ok(output)
    }
}

fn attach_tracepoint(
    bpf: &mut Bpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> Result<(), EbpfInitializationError> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| {
            EbpfInitializationError::new(
                CollectorFallbackReason::ProgramLoadFailed,
                "locating eBPF program",
                program_name,
            )
        })?
        .try_into()
        .map_err(|error| {
            EbpfInitializationError::new(
                CollectorFallbackReason::ProgramLoadFailed,
                "opening eBPF tracepoint program",
                error,
            )
        })?;
    program.load().map_err(|error| {
        EbpfInitializationError::new(
            CollectorFallbackReason::ProgramLoadFailed,
            &format!("loading {program_name} eBPF program"),
            error,
        )
    })?;
    program.attach(category, event).map_err(|error| {
        EbpfInitializationError::new(
            CollectorFallbackReason::TracepointAttachFailed,
            &format!("attaching {program_name} eBPF program"),
            error,
        )
    })?;
    Ok(())
}

fn syscall_operations() -> Vec<(i64, protocol::SyscallOperation)> {
    use protocol::SyscallOperation;

    let mut operations = Vec::with_capacity(48);
    operations.extend([
        (libc::SYS_socket, SyscallOperation::Socket),
        (libc::SYS_bind, SyscallOperation::Bind),
        (libc::SYS_connect, SyscallOperation::Connect),
        (libc::SYS_listen, SyscallOperation::Listen),
        (libc::SYS_accept4, SyscallOperation::Accept),
        (libc::SYS_close, SyscallOperation::Close),
        (libc::SYS_dup, SyscallOperation::Duplicate),
        (libc::SYS_dup3, SyscallOperation::Duplicate),
        (libc::SYS_fcntl, SyscallOperation::Fcntl),
        (libc::SYS_sendto, SyscallOperation::SendTo),
        (libc::SYS_recvfrom, SyscallOperation::ReceiveFrom),
        (libc::SYS_write, SyscallOperation::Write),
        (libc::SYS_read, SyscallOperation::Read),
        (libc::SYS_getsockname, SyscallOperation::GetSocketName),
        (libc::SYS_getpeername, SyscallOperation::GetPeerName),
        (libc::SYS_openat, SyscallOperation::OpenAt),
        (libc::SYS_openat2, SyscallOperation::OpenAt2),
        (libc::SYS_readv, SyscallOperation::ReadVector),
        (libc::SYS_preadv, SyscallOperation::ReadVector),
        (libc::SYS_preadv2, SyscallOperation::ReadVector),
        (libc::SYS_writev, SyscallOperation::WriteVector),
        (libc::SYS_pwritev, SyscallOperation::WriteVector),
        (libc::SYS_pwritev2, SyscallOperation::WriteVector),
        (libc::SYS_pread64, SyscallOperation::ReadAt),
        (libc::SYS_pwrite64, SyscallOperation::WriteAt),
        (libc::SYS_truncate, SyscallOperation::Truncate),
        (libc::SYS_ftruncate, SyscallOperation::FileTruncate),
        (libc::SYS_renameat, SyscallOperation::RenameAt),
        (libc::SYS_renameat2, SyscallOperation::RenameAt),
        (libc::SYS_linkat, SyscallOperation::LinkAt),
        (libc::SYS_symlinkat, SyscallOperation::SymlinkAt),
        (libc::SYS_unlinkat, SyscallOperation::UnlinkAt),
        (libc::SYS_mkdirat, SyscallOperation::MakeDirectoryAt),
        (libc::SYS_chdir, SyscallOperation::ChangeDirectory),
        (libc::SYS_fchdir, SyscallOperation::ChangeDirectoryFd),
        (libc::SYS_mmap, SyscallOperation::MemoryMap),
        (libc::SYS_newfstatat, SyscallOperation::StatAt),
        (libc::SYS_statx, SyscallOperation::StatAt),
        (libc::SYS_readlinkat, SyscallOperation::ReadLinkAt),
        (libc::SYS_getdents64, SyscallOperation::ReadDirectory),
        (libc::SYS_clone, SyscallOperation::Clone),
        (libc::SYS_clone3, SyscallOperation::Clone3),
    ]);
    #[cfg(target_arch = "x86_64")]
    operations.extend([
        (libc::SYS_accept, SyscallOperation::Accept),
        (libc::SYS_dup2, SyscallOperation::Duplicate),
        (libc::SYS_open, SyscallOperation::Open),
        (libc::SYS_creat, SyscallOperation::Create),
        (libc::SYS_rename, SyscallOperation::Rename),
        (libc::SYS_link, SyscallOperation::Link),
        (libc::SYS_symlink, SyscallOperation::Symlink),
        (libc::SYS_unlink, SyscallOperation::Unlink),
        (libc::SYS_mkdir, SyscallOperation::MakeDirectory),
        (libc::SYS_rmdir, SyscallOperation::RemoveDirectory),
        (libc::SYS_stat, SyscallOperation::Stat),
        (libc::SYS_lstat, SyscallOperation::Stat),
        (libc::SYS_fork, SyscallOperation::Fork),
        (libc::SYS_vfork, SyscallOperation::Fork),
    ]);
    operations
}

struct ProbeRun {
    stop: Arc<AtomicBool>,
    thread: thread::JoinHandle<ProbeOutput>,
}

struct ProbeOutput {
    events: Vec<protocol::Event>,
    lost_events: u64,
}

impl ProbeRun {
    fn start(mut buffers: Vec<PerfEventArrayBuffer<MapRefMut>>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = thread::spawn(move || {
            let mut output: Vec<_> = (0..EBPF_READ_BATCH)
                .map(|_| BytesMut::with_capacity(protocol::MAX_EVENT_BYTES))
                .collect();
            let mut events = Vec::new();
            let mut lost_events = 0_u64;
            while !thread_stop.load(Ordering::Acquire) {
                drain_buffers(&mut buffers, &mut output, &mut events, &mut lost_events);
                thread::yield_now();
            }
            while drain_buffers(&mut buffers, &mut output, &mut events, &mut lost_events) > 0 {}
            ProbeOutput {
                events,
                lost_events,
            }
        });
        Self { stop, thread }
    }

    fn stop(self) -> io::Result<ProbeOutput> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "eBPF reader thread failed"))
    }
}

fn drain_buffers(
    buffers: &mut [PerfEventArrayBuffer<MapRefMut>],
    output: &mut [BytesMut],
    captured: &mut Vec<protocol::Event>,
    lost: &mut u64,
) -> usize {
    let mut drained = 0;
    for buffer in buffers.iter_mut().filter(|buffer| buffer.readable()) {
        match buffer.read_events(output) {
            Ok(events) => {
                drained += events.read;
                *lost = lost.saturating_add(events.lost as u64);
                for event in output.iter_mut().take(events.read) {
                    match protocol::decode(event) {
                        Ok(event)
                            if valid_event(&event) && captured.len() < MAX_EBPF_QUEUED_EVENTS =>
                        {
                            captured.push(event);
                        }
                        Ok(_) | Err(_) => {
                            *lost = lost.saturating_add(1);
                        }
                    }
                    event.clear();
                }
            }
            Err(_) => {
                *lost = lost.saturating_add(1);
            }
        }
    }
    drained
}

fn valid_event(event: &protocol::Event) -> bool {
    event.kind != protocol::EventKind::Syscall
        || event.syscall_operation().is_some()
            && event.socket_data().is_ok()
            && event.path_data().is_ok()
}

fn other_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

fn sink_error(error: crate::collector::SinkError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::net::TcpListener;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    use crate::session::{CollectorBackend, CollectorRequest, CoverageState};

    use super::protocol::{EventKind, SyscallOperation};
    use super::{ebpf_coverage, CgroupScope, EbpfProbe, LinuxCollector};

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn explicit_ptrace_selection_does_not_initialize_ebpf() {
        let collector = LinuxCollector::new("fixture".to_owned(), CollectorRequest::Ptrace)
            .expect("ptrace selection should not depend on eBPF availability");
        let decision = collector.decision();

        assert_eq!(decision.requested, CollectorRequest::Ptrace);
        assert_eq!(decision.backend, CollectorBackend::Ptrace);
        assert_eq!(decision.fallback_reason, None);
    }

    #[test]
    fn buffer_loss_marks_every_category_partial() {
        let coverage = ebpf_coverage(19);

        for category in [
            coverage.processes,
            coverage.filesystem,
            coverage.network,
            coverage.environment,
        ] {
            assert_eq!(category.state(), CoverageState::Partial);
            assert_eq!(category.lost_events(), 19);
        }
    }

    #[test]
    fn captures_process_lifecycle_events() {
        if std::env::var_os("EXECWAKE_REQUIRE_EBPF").is_none() {
            return;
        }

        let scope = CgroupScope::create().expect("the test cgroup should be available");
        let mut probe = EbpfProbe::load(scope.id()).expect("the eBPF probe should load");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "/bin/true & wait"]);
        scope
            .configure(&mut command)
            .expect("the command should enter the test cgroup");

        let run = probe.start().expect("the event reader should start");
        let status = command.status().expect("the fixture command should run");
        let output = probe.stop(run).expect("the event reader should stop");

        assert!(status.success());
        assert_eq!(output.lost_events, 0);
        for kind in [
            EventKind::ProcessFork,
            EventKind::ProcessExec,
            EventKind::ProcessExit,
        ] {
            assert!(
                output.events.iter().any(|event| event.kind == kind),
                "missing {kind:?} event: {:?}",
                output.events
            );
        }
    }

    #[test]
    fn captures_network_syscalls_and_payloads() {
        if std::env::var_os("EXECWAKE_REQUIRE_EBPF").is_none() {
            return;
        }

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("the listener should bind");
        let port = listener
            .local_addr()
            .expect("the listener should have an address")
            .port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("the connection should arrive");
            let mut payload = [0_u8; 4];
            stream
                .read_exact(&mut payload)
                .expect("the payload should arrive");
            assert_eq!(&payload, b"ping");
        });

        let scope = CgroupScope::create().expect("the test cgroup should be available");
        let mut probe = EbpfProbe::load(scope.id()).expect("the eBPF probe should load");
        let mut command = Command::new("/bin/bash");
        command.args(["-c", &format!("printf ping > /dev/tcp/127.0.0.1/{port}")]);
        scope
            .configure(&mut command)
            .expect("the command should enter the test cgroup");

        let run = probe.start().expect("the event reader should start");
        let status = command.status().expect("the fixture command should run");
        let output = probe.stop(run).expect("the event reader should stop");
        server.join().expect("the server should finish");

        assert!(status.success());
        assert_eq!(output.lost_events, 0);
        assert!(output.events.iter().any(|event| {
            event.syscall_operation() == Some(SyscallOperation::Connect)
                && event
                    .socket_data()
                    .ok()
                    .flatten()
                    .map(|data| !data.address.is_empty())
                    .unwrap_or(false)
        }));
        assert!(output.events.iter().any(|event| {
            event.syscall_operation() == Some(SyscallOperation::Write)
                && event
                    .socket_data()
                    .ok()
                    .flatten()
                    .map(|data| data.payload == b"ping")
                    .unwrap_or(false)
        }));
    }

    #[test]
    fn captures_filesystem_paths_and_operations() {
        if std::env::var_os("EXECWAKE_REQUIRE_EBPF").is_none() {
            return;
        }

        let sequence = TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "execwake-ebpf-files-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).expect("the fixture directory should be created");

        let scope = CgroupScope::create().expect("the test cgroup should be available");
        let mut probe = EbpfProbe::load(scope.id()).expect("the eBPF probe should load");
        let mut command = Command::new("/bin/bash");
        command
            .current_dir(&root)
            .args([
                "-c",
                "printf data > created.txt && mv created.txt renamed.txt && ln renamed.txt linked.txt && rm linked.txt",
            ]);
        scope
            .configure(&mut command)
            .expect("the command should enter the test cgroup");

        let run = probe.start().expect("the event reader should start");
        let status = command.status().expect("the fixture command should run");
        let output = probe.stop(run).expect("the event reader should stop");
        fs::remove_dir_all(&root).expect("the fixture directory should be removed");

        assert!(status.success());
        assert_eq!(output.lost_events, 0);
        assert!(has_path_event(
            &output.events,
            SyscallOperation::OpenAt,
            b"created.txt",
            b""
        ));
        assert!(has_path_event(
            &output.events,
            SyscallOperation::RenameAt,
            b"created.txt",
            b"renamed.txt"
        ));
        assert!(has_path_event(
            &output.events,
            SyscallOperation::LinkAt,
            b"renamed.txt",
            b"linked.txt"
        ));
        assert!(has_path_event(
            &output.events,
            SyscallOperation::UnlinkAt,
            b"linked.txt",
            b""
        ));
    }

    fn has_path_event(
        events: &[super::protocol::Event],
        operation: SyscallOperation,
        first: &[u8],
        second: &[u8],
    ) -> bool {
        events.iter().any(|event| {
            event.syscall_operation() == Some(operation)
                && event
                    .path_data()
                    .ok()
                    .flatten()
                    .map(|data| data.first == first && data.second == second)
                    .unwrap_or(false)
        })
    }
}
