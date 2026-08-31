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
use std::time::Duration;

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
use crate::session::{CategoryCoverage, SessionCoverage};

static CGROUP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub enum LinuxCollector {
    Ebpf(EbpfCollector),
    Ptrace(PtraceCollector),
}

impl LinuxCollector {
    pub fn new(root_executable: String) -> Self {
        match EbpfCollector::new(root_executable.clone()) {
            Ok(collector) => Self::Ebpf(collector),
            Err(_error) => {
                #[cfg(test)]
                if std::env::var_os("EXECWAKE_REQUIRE_EBPF").is_some() {
                    panic!("eBPF collector is required for this test: {_error:?}");
                }
                Self::Ptrace(PtraceCollector::new(root_executable))
            }
        }
    }

    pub fn ignore_paths(&mut self, paths: &[&Path]) {
        match self {
            Self::Ebpf(collector) => collector.ptrace.ignore_paths(paths),
            Self::Ptrace(collector) => collector.ignore_paths(paths),
        }
    }
}

impl Collector for LinuxCollector {
    fn backend_name(&self) -> &'static str {
        match self {
            Self::Ebpf(collector) => collector.backend_name(),
            Self::Ptrace(collector) => collector.backend_name(),
        }
    }

    fn prepare(&mut self, command: &mut Command) -> io::Result<()> {
        match self {
            Self::Ebpf(collector) => collector.prepare(command),
            Self::Ptrace(collector) => collector.prepare(command),
        }
    }

    fn collect(
        &mut self,
        child: &mut Child,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<ExitStatus> {
        match self {
            Self::Ebpf(collector) => collector.collect(child, sink),
            Self::Ptrace(collector) => collector.collect(child, sink),
        }
    }
}

pub struct EbpfCollector {
    ptrace: PtraceCollector,
    scope: CgroupScope,
    probe: EbpfProbe,
}

impl EbpfCollector {
    fn new(root_executable: String) -> io::Result<Self> {
        let scope = CgroupScope::create()?;
        let probe = EbpfProbe::load(scope.id())?;
        Ok(Self {
            ptrace: PtraceCollector::new(root_executable),
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
        self.scope.configure(command)?;
        self.ptrace.prepare(command)
    }

    fn collect(
        &mut self,
        child: &mut Child,
        sink: &mut dyn CollectorSink,
    ) -> io::Result<ExitStatus> {
        let run = self.probe.start()?;
        let result = self.ptrace.collect(child, sink);
        let output = run.stop()?;
        let _captured_events = output.events.len();
        sink.set_backend(self.backend_name()).map_err(sink_error)?;
        if output.lost_events > 0 {
            sink.set_coverage(coverage_after_loss(output.lost_events))
                .map_err(sink_error)?;
        }
        result
    }
}

const fn coverage_after_loss(lost_events: u64) -> SessionCoverage {
    SessionCoverage {
        processes: CategoryCoverage::partial(lost_events),
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
    _bpf: Bpf,
    buffers: Option<Vec<PerfEventArrayBuffer<MapRefMut>>>,
}

impl EbpfProbe {
    fn load(cgroup_id: u64) -> io::Result<Self> {
        let mut bpf = Bpf::load(aya::include_bytes_aligned!("../../../bpf/collector.bpf.o"))
            .map_err(other_error)?;
        let mut target =
            Array::<_, u64>::try_from(bpf.map_mut("TARGET_CGROUP").map_err(other_error)?)
                .map_err(other_error)?;
        target.set(0, cgroup_id, 0).map_err(other_error)?;
        drop(target);

        let mut operation_map = BpfHashMap::<_, i64, u32>::try_from(
            bpf.map_mut("SYSCALL_OPERATIONS").map_err(other_error)?,
        )
        .map_err(other_error)?;
        for (number, operation) in syscall_operations() {
            operation_map
                .insert(number, operation as u32, 0)
                .map_err(other_error)?;
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

        let mut event_array = PerfEventArray::try_from(bpf.map_mut("EVENTS").map_err(other_error)?)
            .map_err(other_error)?;
        let mut buffers = Vec::new();
        for cpu in online_cpus()? {
            buffers.push(
                event_array
                    .open(cpu, Some(EBPF_BUFFER_PAGES))
                    .map_err(other_error)?,
            );
        }
        Ok(Self {
            _bpf: bpf,
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
}

fn attach_tracepoint(
    bpf: &mut Bpf,
    program_name: &str,
    category: &str,
    event: &str,
) -> io::Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "eBPF program is missing"))?
        .try_into()
        .map_err(other_error)?;
    program.load().map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("loading {program_name} eBPF program: {error}"),
        )
    })?;
    program.attach(category, event).map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("attaching {program_name} eBPF program: {error}"),
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
                thread::sleep(Duration::from_millis(1));
            }
            drain_buffers(&mut buffers, &mut output, &mut events, &mut lost_events);
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
) {
    for buffer in buffers.iter_mut().filter(|buffer| buffer.readable()) {
        match buffer.read_events(output) {
            Ok(events) => {
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

    use crate::session::CoverageState;

    use super::protocol::{EventKind, SyscallOperation};
    use super::{coverage_after_loss, CgroupScope, EbpfProbe};

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn buffer_loss_marks_every_category_partial() {
        let coverage = coverage_after_loss(19);

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
        let output = run.stop().expect("the event reader should stop");

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
        let output = run.stop().expect("the event reader should stop");
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
        let output = run.stop().expect("the event reader should stop");
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
