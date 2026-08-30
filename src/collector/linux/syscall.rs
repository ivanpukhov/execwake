use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;

pub struct SyscallState {
    pending: Option<PendingFileOperation>,
    pending_network: Option<PendingNetworkOperation>,
    sockets: std::collections::HashMap<i32, SocketInformation>,
}

pub struct FileEvent {
    pub operation: &'static str,
    pub paths: Vec<PathBuf>,
}

pub struct FileObservation {
    pub events: Vec<FileEvent>,
    pub mutation_paths: Vec<PathBuf>,
    pub network_events: Vec<NetworkEvent>,
}

pub struct NetworkEvent {
    pub operation: &'static str,
    pub transport: &'static str,
    pub endpoint: SocketAddr,
}

#[derive(Clone)]
struct SocketInformation {
    transport: &'static str,
    local: Option<SocketAddr>,
}

enum PendingNetworkOperation {
    Socket {
        transport: &'static str,
    },
    Bind {
        descriptor: i32,
        endpoint: SocketAddr,
    },
    Connect {
        descriptor: i32,
        endpoint: SocketAddr,
    },
    Listen {
        descriptor: i32,
    },
    Close {
        descriptor: i32,
    },
    Duplicate {
        source: i32,
        requested: Option<i32>,
    },
}

enum PendingFileOperation {
    Open {
        path: PathBuf,
        flags: i32,
        existed: bool,
    },
    One {
        operation: &'static str,
        path: PathBuf,
        requires_data: bool,
    },
    Two {
        operation: &'static str,
        first: PathBuf,
        second: PathBuf,
    },
    Mapping {
        path: PathBuf,
        read: bool,
        write: bool,
    },
}

impl SyscallState {
    pub fn root() -> Self {
        Self {
            pending: None,
            pending_network: None,
            sockets: std::collections::HashMap::new(),
        }
    }

    pub fn child(parent: &Self) -> Self {
        Self {
            pending: None,
            pending_network: None,
            sockets: parent.sockets.clone(),
        }
    }

    pub fn observe_stop(&mut self, process_id: libc::pid_t) -> io::Result<FileObservation> {
        match read_syscall_stop(process_id)? {
            SyscallStop::Entry(registers) => {
                self.pending = decode_file_operation(process_id, &registers).unwrap_or(None);
                self.pending_network =
                    decode_network_operation(process_id, &registers).unwrap_or(None);
                let mutation_paths = self
                    .pending
                    .as_ref()
                    .map(PendingFileOperation::mutation_paths)
                    .unwrap_or_default();
                Ok(FileObservation {
                    events: Vec::new(),
                    mutation_paths,
                    network_events: Vec::new(),
                })
            }
            SyscallStop::Exit(result) => {
                let events = self
                    .pending
                    .take()
                    .filter(|_| result >= 0)
                    .map(|pending| finish_file_operation(pending, result))
                    .unwrap_or_default();
                let network_events = self
                    .pending_network
                    .take()
                    .filter(|_| result >= 0)
                    .map(|pending| {
                        finish_network_operation(process_id, pending, result, &mut self.sockets)
                    })
                    .unwrap_or_default();
                Ok(FileObservation {
                    events,
                    mutation_paths: Vec::new(),
                    network_events,
                })
            }
            SyscallStop::Other => Ok(FileObservation {
                events: Vec::new(),
                mutation_paths: Vec::new(),
                network_events: Vec::new(),
            }),
        }
    }
}

impl PendingFileOperation {
    fn mutation_paths(&self) -> Vec<PathBuf> {
        match self {
            Self::Open {
                path,
                flags,
                existed: _,
            } if flags & (libc::O_CREAT | libc::O_TRUNC) != 0 => vec![path.clone()],
            Self::One {
                operation,
                path,
                requires_data: _,
            } if matches!(*operation, "write" | "truncate" | "unlink") => vec![path.clone()],
            Self::Two {
                operation: _,
                first,
                second,
            } => vec![first.clone(), second.clone()],
            Self::Mapping {
                path,
                read: _,
                write: true,
            } => vec![path.clone()],
            _ => Vec::new(),
        }
    }
}

struct Registers {
    number: i64,
    arguments: [u64; 6],
}

enum SyscallStop {
    Entry(Registers),
    Exit(i64),
    Other,
}

fn decode_network_operation(
    process_id: libc::pid_t,
    registers: &Registers,
) -> io::Result<Option<PendingNetworkOperation>> {
    let number = registers.number;
    let arguments = registers.arguments;
    if number == libc::SYS_socket {
        let socket_type = arguments[1] as i32 & 0xf;
        let protocol = arguments[2] as i32;
        let transport = match (socket_type, protocol) {
            (libc::SOCK_STREAM, 0 | libc::IPPROTO_TCP) => "tcp",
            (libc::SOCK_DGRAM, 0 | libc::IPPROTO_UDP) => "udp",
            (libc::SOCK_STREAM, _) => "stream",
            (libc::SOCK_DGRAM, _) => "datagram",
            _ => "socket",
        };
        return Ok(Some(PendingNetworkOperation::Socket { transport }));
    }
    if number == libc::SYS_bind || number == libc::SYS_connect {
        let Some(endpoint) = read_socket_address(process_id, arguments[1], arguments[2] as usize)?
        else {
            return Ok(None);
        };
        if number == libc::SYS_bind {
            return Ok(Some(PendingNetworkOperation::Bind {
                descriptor: arguments[0] as i32,
                endpoint,
            }));
        }
        return Ok(Some(PendingNetworkOperation::Connect {
            descriptor: arguments[0] as i32,
            endpoint,
        }));
    }
    if number == libc::SYS_listen {
        return Ok(Some(PendingNetworkOperation::Listen {
            descriptor: arguments[0] as i32,
        }));
    }
    if number == libc::SYS_close {
        return Ok(Some(PendingNetworkOperation::Close {
            descriptor: arguments[0] as i32,
        }));
    }
    if number == libc::SYS_dup || number == libc::SYS_dup3 {
        let requested = (number == libc::SYS_dup3).then_some(arguments[1] as i32);
        return Ok(Some(PendingNetworkOperation::Duplicate {
            source: arguments[0] as i32,
            requested,
        }));
    }
    #[cfg(target_arch = "x86_64")]
    if number == libc::SYS_dup2 {
        return Ok(Some(PendingNetworkOperation::Duplicate {
            source: arguments[0] as i32,
            requested: Some(arguments[1] as i32),
        }));
    }
    if number == libc::SYS_fcntl
        && matches!(arguments[1] as i32, libc::F_DUPFD | libc::F_DUPFD_CLOEXEC)
    {
        return Ok(Some(PendingNetworkOperation::Duplicate {
            source: arguments[0] as i32,
            requested: None,
        }));
    }
    Ok(None)
}

fn finish_network_operation(
    process_id: libc::pid_t,
    operation: PendingNetworkOperation,
    result: i64,
    sockets: &mut std::collections::HashMap<i32, SocketInformation>,
) -> Vec<NetworkEvent> {
    match operation {
        PendingNetworkOperation::Socket { transport } => {
            sockets.insert(
                result as i32,
                SocketInformation {
                    transport,
                    local: None,
                },
            );
            Vec::new()
        }
        PendingNetworkOperation::Bind {
            descriptor,
            endpoint,
        } => {
            let Some(socket) = sockets.get_mut(&descriptor) else {
                return Vec::new();
            };
            let endpoint =
                descriptor_socket_address(process_id, descriptor, false).unwrap_or(endpoint);
            socket.local = Some(endpoint);
            vec![NetworkEvent {
                operation: "bind",
                transport: socket.transport,
                endpoint,
            }]
        }
        PendingNetworkOperation::Connect {
            descriptor,
            endpoint,
        } => sockets
            .get(&descriptor)
            .map(|socket| {
                vec![NetworkEvent {
                    operation: "connect",
                    transport: socket.transport,
                    endpoint: descriptor_socket_address(process_id, descriptor, true)
                        .unwrap_or(endpoint),
                }]
            })
            .unwrap_or_default(),
        PendingNetworkOperation::Listen { descriptor } => sockets
            .get(&descriptor)
            .and_then(|socket| {
                descriptor_socket_address(process_id, descriptor, false)
                    .or(socket.local)
                    .map(|endpoint| NetworkEvent {
                        operation: "listen",
                        transport: socket.transport,
                        endpoint,
                    })
            })
            .into_iter()
            .collect(),
        PendingNetworkOperation::Close { descriptor } => {
            sockets.remove(&descriptor);
            Vec::new()
        }
        PendingNetworkOperation::Duplicate { source, requested } => {
            if let Some(socket) = sockets.get(&source).cloned() {
                sockets.insert(requested.unwrap_or(result as i32), socket);
            }
            Vec::new()
        }
    }
}

fn descriptor_socket_address(
    process_id: libc::pid_t,
    descriptor: i32,
    peer: bool,
) -> Option<SocketAddr> {
    let process_descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, process_id, 0) } as i32;
    if process_descriptor < 0 {
        return None;
    }
    let local_descriptor =
        unsafe { libc::syscall(libc::SYS_pidfd_getfd, process_descriptor, descriptor, 0) } as i32;
    unsafe {
        libc::close(process_descriptor);
    }
    if local_descriptor < 0 {
        return None;
    }

    let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
    let mut length = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let result = unsafe {
        if peer {
            libc::getpeername(
                local_descriptor,
                storage.as_mut_ptr() as *mut libc::sockaddr,
                &mut length,
            )
        } else {
            libc::getsockname(
                local_descriptor,
                storage.as_mut_ptr() as *mut libc::sockaddr,
                &mut length,
            )
        }
    };
    unsafe {
        libc::close(local_descriptor);
    }
    if result != 0 {
        return None;
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr() as *const u8, length as usize) };
    parse_socket_address(bytes)
}

fn read_socket_address(
    process_id: libc::pid_t,
    address: u64,
    length: usize,
) -> io::Result<Option<SocketAddr>> {
    if address == 0 || length < 2 {
        return Ok(None);
    }
    let bytes = read_memory(process_id, address, length.min(128))?;
    Ok(parse_socket_address(&bytes))
}

fn parse_socket_address(bytes: &[u8]) -> Option<SocketAddr> {
    if bytes.len() < 2 {
        return None;
    }
    let family = u16::from_ne_bytes([bytes[0], bytes[1]]) as i32;
    if family == libc::AF_INET && bytes.len() >= 8 {
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let address = Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]);
        return Some(SocketAddr::V4(SocketAddrV4::new(address, port)));
    }
    if family == libc::AF_INET6 && bytes.len() >= 28 {
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut address = [0_u8; 16];
        address.copy_from_slice(&bytes[8..24]);
        let scope = u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
        return Some(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(address),
            port,
            0,
            scope,
        )));
    }
    None
}

fn decode_file_operation(
    process_id: libc::pid_t,
    registers: &Registers,
) -> io::Result<Option<PendingFileOperation>> {
    let number = registers.number;
    let arguments = registers.arguments;

    if number == libc::SYS_openat {
        return open_operation(
            process_id,
            arguments[0] as i32,
            arguments[1],
            arguments[2] as i32,
        );
    }
    if number == libc::SYS_openat2 {
        let flags = read_unsigned(process_id, arguments[2]).unwrap_or(0) as i32;
        return open_operation(process_id, arguments[0] as i32, arguments[1], flags);
    }
    if matches_number(
        number,
        &[libc::SYS_read, libc::SYS_readv, libc::SYS_pread64],
    ) {
        return fd_operation(process_id, arguments[0] as i32, "read", true);
    }
    if matches_number(
        number,
        &[libc::SYS_write, libc::SYS_writev, libc::SYS_pwrite64],
    ) {
        return fd_operation(process_id, arguments[0] as i32, "write", true);
    }
    if number == libc::SYS_ftruncate {
        return fd_operation(process_id, arguments[0] as i32, "truncate", false);
    }
    if number == libc::SYS_truncate {
        return path_operation(process_id, libc::AT_FDCWD, arguments[0], "truncate", false);
    }
    if matches_number(
        number,
        &[
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_readlinkat,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
        ],
    ) {
        return path_operation(process_id, arguments[0] as i32, arguments[1], "read", false);
    }
    if number == libc::SYS_getdents64 {
        return fd_operation(process_id, arguments[0] as i32, "read", false);
    }
    if number == libc::SYS_fstat {
        return fd_operation(process_id, arguments[0] as i32, "read", false);
    }
    if number == libc::SYS_unlinkat {
        return path_operation(
            process_id,
            arguments[0] as i32,
            arguments[1],
            "unlink",
            false,
        );
    }
    if number == libc::SYS_renameat || number == libc::SYS_renameat2 {
        return two_path_operation(
            process_id,
            arguments[0] as i32,
            arguments[1],
            arguments[2] as i32,
            arguments[3],
            "rename",
        );
    }
    if number == libc::SYS_linkat {
        return two_path_operation(
            process_id,
            arguments[0] as i32,
            arguments[1],
            arguments[2] as i32,
            arguments[3],
            "link",
        );
    }
    if number == libc::SYS_symlinkat {
        let target = PathBuf::from(read_os_string(process_id, arguments[0])?);
        let link = resolve_path(process_id, arguments[1] as i32, arguments[2])?;
        return Ok(Some(PendingFileOperation::Two {
            operation: "symlink",
            first: link,
            second: target,
        }));
    }
    if number == libc::SYS_mmap {
        let file_descriptor = arguments[4] as i32;
        if file_descriptor < 0 {
            return Ok(None);
        }
        let Some(path) = descriptor_path(process_id, file_descriptor) else {
            return Ok(None);
        };
        let protection = arguments[2] as i32;
        let flags = arguments[3] as i32;
        return Ok(Some(PendingFileOperation::Mapping {
            path,
            read: protection & libc::PROT_READ != 0,
            write: protection & libc::PROT_WRITE != 0 && flags & libc::MAP_SHARED != 0,
        }));
    }

    decode_legacy_file_operation(process_id, registers)
}

#[cfg(target_arch = "x86_64")]
fn decode_legacy_file_operation(
    process_id: libc::pid_t,
    registers: &Registers,
) -> io::Result<Option<PendingFileOperation>> {
    let number = registers.number;
    let arguments = registers.arguments;
    if number == libc::SYS_open {
        return open_operation(
            process_id,
            libc::AT_FDCWD,
            arguments[0],
            arguments[1] as i32,
        );
    }
    if number == libc::SYS_creat {
        return open_operation(
            process_id,
            libc::AT_FDCWD,
            arguments[0],
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
        );
    }
    if number == libc::SYS_unlink {
        return path_operation(process_id, libc::AT_FDCWD, arguments[0], "unlink", false);
    }
    if number == libc::SYS_symlink {
        let target = PathBuf::from(read_os_string(process_id, arguments[0])?);
        let link = resolve_path(process_id, libc::AT_FDCWD, arguments[1])?;
        return Ok(Some(PendingFileOperation::Two {
            operation: "symlink",
            first: link,
            second: target,
        }));
    }
    if number == libc::SYS_rename || number == libc::SYS_link {
        let operation = if number == libc::SYS_rename {
            "rename"
        } else {
            "link"
        };
        return two_path_operation(
            process_id,
            libc::AT_FDCWD,
            arguments[0],
            libc::AT_FDCWD,
            arguments[1],
            operation,
        );
    }
    if matches_number(
        number,
        &[
            libc::SYS_stat,
            libc::SYS_lstat,
            libc::SYS_access,
            libc::SYS_readlink,
        ],
    ) {
        return path_operation(process_id, libc::AT_FDCWD, arguments[0], "read", false);
    }
    Ok(None)
}

#[cfg(target_arch = "aarch64")]
fn decode_legacy_file_operation(
    _process_id: libc::pid_t,
    _registers: &Registers,
) -> io::Result<Option<PendingFileOperation>> {
    Ok(None)
}

fn open_operation(
    process_id: libc::pid_t,
    directory_descriptor: i32,
    pointer: u64,
    flags: i32,
) -> io::Result<Option<PendingFileOperation>> {
    let path = resolve_path(process_id, directory_descriptor, pointer)?;
    let existed = fs::symlink_metadata(&path).is_ok();
    Ok(Some(PendingFileOperation::Open {
        path,
        flags,
        existed,
    }))
}

fn path_operation(
    process_id: libc::pid_t,
    directory_descriptor: i32,
    pointer: u64,
    operation: &'static str,
    requires_data: bool,
) -> io::Result<Option<PendingFileOperation>> {
    Ok(Some(PendingFileOperation::One {
        operation,
        path: resolve_path(process_id, directory_descriptor, pointer)?,
        requires_data,
    }))
}

fn fd_operation(
    process_id: libc::pid_t,
    file_descriptor: i32,
    operation: &'static str,
    requires_data: bool,
) -> io::Result<Option<PendingFileOperation>> {
    Ok(
        descriptor_path(process_id, file_descriptor).map(|path| PendingFileOperation::One {
            operation,
            path,
            requires_data,
        }),
    )
}

fn two_path_operation(
    process_id: libc::pid_t,
    first_directory: i32,
    first_pointer: u64,
    second_directory: i32,
    second_pointer: u64,
    operation: &'static str,
) -> io::Result<Option<PendingFileOperation>> {
    Ok(Some(PendingFileOperation::Two {
        operation,
        first: resolve_path(process_id, first_directory, first_pointer)?,
        second: resolve_path(process_id, second_directory, second_pointer)?,
    }))
}

fn finish_file_operation(operation: PendingFileOperation, result: i64) -> Vec<FileEvent> {
    match operation {
        PendingFileOperation::Open {
            path,
            flags,
            existed,
        } => {
            let mut events = Vec::new();
            if flags & libc::O_CREAT != 0 && !existed {
                events.push(FileEvent {
                    operation: "create",
                    paths: vec![path.clone()],
                });
            }
            if flags & libc::O_TRUNC != 0 {
                events.push(FileEvent {
                    operation: "truncate",
                    paths: vec![path.clone()],
                });
            }
            events.push(FileEvent {
                operation: "open",
                paths: vec![path],
            });
            events
        }
        PendingFileOperation::One {
            operation,
            path,
            requires_data,
        } if !requires_data || result > 0 => vec![FileEvent {
            operation,
            paths: vec![path],
        }],
        PendingFileOperation::One { .. } => Vec::new(),
        PendingFileOperation::Two {
            operation,
            first,
            second,
        } => vec![FileEvent {
            operation,
            paths: vec![first, second],
        }],
        PendingFileOperation::Mapping { path, read, write } => {
            let mut events = Vec::new();
            if read {
                events.push(FileEvent {
                    operation: "read",
                    paths: vec![path.clone()],
                });
            }
            if write {
                events.push(FileEvent {
                    operation: "write",
                    paths: vec![path],
                });
            }
            events
        }
    }
}

fn resolve_path(
    process_id: libc::pid_t,
    directory_descriptor: i32,
    pointer: u64,
) -> io::Result<PathBuf> {
    let path = PathBuf::from(read_os_string(process_id, pointer)?);
    if path.is_absolute() {
        return Ok(path);
    }

    let base = if directory_descriptor == libc::AT_FDCWD {
        fs::read_link(format!("/proc/{process_id}/cwd"))?
    } else {
        fs::read_link(format!("/proc/{process_id}/fd/{directory_descriptor}"))?
    };
    Ok(base.join(path))
}

fn descriptor_path(process_id: libc::pid_t, file_descriptor: i32) -> Option<PathBuf> {
    let path = fs::read_link(format!("/proc/{process_id}/fd/{file_descriptor}")).ok()?;
    path.is_absolute().then_some(path)
}

fn read_os_string(process_id: libc::pid_t, address: u64) -> io::Result<OsString> {
    const MAX_PATH_BYTES: usize = 4096;

    if address == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "null path pointer",
        ));
    }
    let mut bytes = Vec::new();
    let word_size = std::mem::size_of::<libc::c_long>();
    while bytes.len() < MAX_PATH_BYTES {
        let word = peek_word(process_id, address + bytes.len() as u64)?;
        for byte in word.to_ne_bytes().iter().take(word_size) {
            if *byte == 0 {
                return Ok(OsString::from_vec(bytes));
            }
            bytes.push(*byte);
            if bytes.len() == MAX_PATH_BYTES {
                break;
            }
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "tracee path exceeds the platform limit",
    ))
}

fn read_unsigned(process_id: libc::pid_t, address: u64) -> io::Result<u64> {
    Ok(peek_word(process_id, address)? as u64)
}

fn read_memory(process_id: libc::pid_t, address: u64, length: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(length);
    let word_size = std::mem::size_of::<libc::c_long>();
    while bytes.len() < length {
        let word = peek_word(process_id, address + bytes.len() as u64)?;
        let remaining = length - bytes.len();
        bytes.extend_from_slice(&word.to_ne_bytes()[..remaining.min(word_size)]);
    }
    Ok(bytes)
}

fn peek_word(process_id: libc::pid_t, address: u64) -> io::Result<libc::c_long> {
    unsafe {
        *libc::__errno_location() = 0;
        let result = libc::ptrace(
            libc::PTRACE_PEEKDATA,
            process_id,
            address as usize as *mut libc::c_void,
            ptr::null_mut::<libc::c_void>(),
        );
        if result == -1 && *libc::__errno_location() != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }
}

fn matches_number(number: i64, candidates: &[libc::c_long]) -> bool {
    candidates.iter().any(|candidate| number == *candidate)
}

fn read_syscall_stop(process_id: libc::pid_t) -> io::Result<SyscallStop> {
    const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
    const ENTRY: u8 = 1;
    const EXIT: u8 = 2;
    const SECCOMP: u8 = 3;

    let mut information = [0_u8; 88];
    let result = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            process_id,
            information.len() as *mut libc::c_void,
            information.as_mut_ptr() as *mut libc::c_void,
        )
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    match information[0] {
        ENTRY | SECCOMP => {
            let mut arguments = [0_u64; 6];
            for (index, argument) in arguments.iter_mut().enumerate() {
                *argument = native_u64(&information, 32 + index * 8);
            }
            Ok(SyscallStop::Entry(Registers {
                number: native_u64(&information, 24) as i64,
                arguments,
            }))
        }
        EXIT => Ok(SyscallStop::Exit(native_u64(&information, 24) as i64)),
        _ => Ok(SyscallStop::Other),
    }
}

fn native_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0_u8; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_ne_bytes(value)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr};

    use super::parse_socket_address;

    #[test]
    fn parses_ipv6_socket_addresses() {
        let mut bytes = [0_u8; 28];
        bytes[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
        bytes[2..4].copy_from_slice(&7319_u16.to_be_bytes());
        bytes[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());

        assert_eq!(
            parse_socket_address(&bytes),
            Some(
                "[::1]:7319"
                    .parse::<SocketAddr>()
                    .expect("the expected address should parse")
            )
        );
    }
}
