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

use aya::maps::perf::PerfEventArrayBuffer;
use aya::maps::{Array, MapRefMut, PerfEventArray};
use aya::programs::RawTracePoint;
use aya::util::online_cpus;
use aya::Bpf;
use bytes::BytesMut;

use super::PtraceCollector;
use crate::collector::{Collector, CollectorSink};
use crate::limits::{EBPF_BUFFER_PAGES, EBPF_READ_BATCH};
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
        let lost_events = run.stop()?;
        sink.set_backend(self.backend_name()).map_err(sink_error)?;
        if lost_events > 0 {
            sink.set_coverage(coverage_after_loss(lost_events))
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

        let program: &mut RawTracePoint = bpf
            .program_mut("sys_enter")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "eBPF program is missing"))?
            .try_into()
            .map_err(other_error)?;
        program.load().map_err(other_error)?;
        program.attach("sys_enter").map_err(other_error)?;

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

struct ProbeRun {
    stop: Arc<AtomicBool>,
    lost: Arc<AtomicU64>,
    thread: thread::JoinHandle<()>,
}

impl ProbeRun {
    fn start(mut buffers: Vec<PerfEventArrayBuffer<MapRefMut>>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let lost = Arc::new(AtomicU64::new(0));
        let thread_stop = stop.clone();
        let thread_lost = lost.clone();
        let thread = thread::spawn(move || {
            let mut output: Vec<_> = (0..EBPF_READ_BATCH)
                .map(|_| BytesMut::with_capacity(16))
                .collect();
            while !thread_stop.load(Ordering::Acquire) {
                drain_buffers(&mut buffers, &mut output, &thread_lost);
                thread::sleep(Duration::from_millis(1));
            }
            drain_buffers(&mut buffers, &mut output, &thread_lost);
        });
        Self { stop, lost, thread }
    }

    fn stop(self) -> io::Result<u64> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "eBPF reader thread failed"))?;
        Ok(self.lost.load(Ordering::Acquire))
    }
}

fn drain_buffers(
    buffers: &mut [PerfEventArrayBuffer<MapRefMut>],
    output: &mut [BytesMut],
    lost: &AtomicU64,
) {
    for buffer in buffers.iter_mut().filter(|buffer| buffer.readable()) {
        match buffer.read_events(output) {
            Ok(events) => {
                lost.fetch_add(events.lost as u64, Ordering::Relaxed);
                for event in output.iter_mut().take(events.read) {
                    event.clear();
                }
            }
            Err(_) => {
                lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn other_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

fn sink_error(error: crate::collector::SinkError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

#[cfg(test)]
mod tests {
    use crate::session::CoverageState;

    use super::coverage_after_loss;

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
}
