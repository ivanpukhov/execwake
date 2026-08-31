use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;

use crate::limits::{MAX_DNS_QUERIES_PER_SOCKET, MAX_SOCKETS_PER_PROCESS};

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
    pub dns_events: Vec<DnsEvent>,
    pub lost_network_events: u64,
}

pub struct NetworkEvent {
    pub operation: &'static str,
    pub transport: &'static str,
    pub endpoint: SocketAddr,
}

pub struct DnsEvent {
    pub hostname: String,
    pub address: std::net::IpAddr,
}

#[derive(Clone)]
struct SocketInformation {
    transport: &'static str,
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
    dns_queries: std::collections::HashMap<u16, String>,
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
    Send {
        descriptor: i32,
        buffer: u64,
        length: usize,
        endpoint: Option<SocketAddr>,
    },
    Receive {
        descriptor: i32,
        buffer: u64,
        length: usize,
        endpoint: Option<(u64, u64)>,
    },
}

#[derive(Default)]
struct NetworkObservation {
    events: Vec<NetworkEvent>,
    dns_events: Vec<DnsEvent>,
    lost_events: u64,
}

enum PendingFileOperation {
    Open {
        path: PathBuf,
        flags: i32,
        existed: Option<bool>,
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

    pub fn after_exec(&mut self) {
        self.pending = None;
        self.pending_network = None;
    }

    pub fn observe_stop(&mut self, process_id: libc::pid_t) -> io::Result<FileObservation> {
        match read_syscall_stop(process_id)? {
            SyscallStop::Entry(registers) => {
                self.pending = decode_file_operation(process_id, &registers).unwrap_or(None);
                self.pending_network =
                    decode_network_operation(process_id, &registers, &self.sockets).unwrap_or(None);
                let mutation_paths = self
                    .pending
                    .as_ref()
                    .map(PendingFileOperation::mutation_paths)
                    .unwrap_or_default();
                Ok(FileObservation {
                    events: Vec::new(),
                    mutation_paths,
                    network_events: Vec::new(),
                    dns_events: Vec::new(),
                    lost_network_events: 0,
                })
            }
            SyscallStop::Exit(result) => {
                let events = self
                    .pending
                    .take()
                    .filter(|_| result >= 0)
                    .map(|pending| finish_file_operation(pending, result))
                    .unwrap_or_default();
                let network = self
                    .pending_network
                    .take()
                    .filter(|pending| pending.completed(result))
                    .map(|pending| {
                        finish_network_operation(process_id, pending, result, &mut self.sockets)
                    })
                    .unwrap_or_default();
                Ok(FileObservation {
                    events,
                    mutation_paths: Vec::new(),
                    network_events: network.events,
                    dns_events: network.dns_events,
                    lost_network_events: network.lost_events,
                })
            }
            SyscallStop::Other => Ok(FileObservation {
                events: Vec::new(),
                mutation_paths: Vec::new(),
                network_events: Vec::new(),
                dns_events: Vec::new(),
                lost_network_events: 0,
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
                operation: "rename",
                first,
                second,
            } => vec![first.clone(), second.clone()],
            Self::Two {
                operation: "link" | "symlink",
                first: _,
                second,
            } => vec![second.clone()],
            Self::Mapping {
                path,
                read: _,
                write: true,
            } => vec![path.clone()],
            _ => Vec::new(),
        }
    }
}

impl PendingNetworkOperation {
    fn completed(&self, result: i64) -> bool {
        result >= 0
            || matches!(self, Self::Connect { .. }) && result == -i64::from(libc::EINPROGRESS)
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
    sockets: &std::collections::HashMap<i32, SocketInformation>,
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
    let descriptor = arguments[0] as i32;
    if sockets.contains_key(&descriptor)
        && (number == libc::SYS_sendto || number == libc::SYS_write)
    {
        let endpoint = if number == libc::SYS_sendto {
            read_socket_address(process_id, arguments[4], arguments[5] as usize)?
        } else {
            None
        };
        return Ok(Some(PendingNetworkOperation::Send {
            descriptor,
            buffer: arguments[1],
            length: arguments[2] as usize,
            endpoint,
        }));
    }
    if sockets.contains_key(&descriptor)
        && (number == libc::SYS_recvfrom || number == libc::SYS_read)
    {
        return Ok(Some(PendingNetworkOperation::Receive {
            descriptor,
            buffer: arguments[1],
            length: arguments[2] as usize,
            endpoint: (number == libc::SYS_recvfrom).then_some((arguments[4], arguments[5])),
        }));
    }
    Ok(None)
}

fn finish_network_operation(
    process_id: libc::pid_t,
    operation: PendingNetworkOperation,
    result: i64,
    sockets: &mut std::collections::HashMap<i32, SocketInformation>,
) -> NetworkObservation {
    match operation {
        PendingNetworkOperation::Socket { transport } => {
            if !sockets.contains_key(&(result as i32)) && sockets.len() >= MAX_SOCKETS_PER_PROCESS {
                return NetworkObservation {
                    lost_events: 1,
                    ..NetworkObservation::default()
                };
            }
            sockets.insert(
                result as i32,
                SocketInformation {
                    transport,
                    local: None,
                    peer: None,
                    dns_queries: std::collections::HashMap::new(),
                },
            );
            NetworkObservation::default()
        }
        PendingNetworkOperation::Bind {
            descriptor,
            endpoint,
        } => {
            let Some(socket) = sockets.get_mut(&descriptor) else {
                return NetworkObservation::default();
            };
            let endpoint =
                descriptor_socket_address(process_id, descriptor, false).unwrap_or(endpoint);
            socket.local = Some(endpoint);
            NetworkObservation {
                events: vec![NetworkEvent {
                    operation: "bind",
                    transport: socket.transport,
                    endpoint,
                }],
                dns_events: Vec::new(),
                lost_events: 0,
            }
        }
        PendingNetworkOperation::Connect {
            descriptor,
            endpoint,
        } => sockets
            .get_mut(&descriptor)
            .map_or_else(NetworkObservation::default, |socket| {
                let endpoint =
                    descriptor_socket_address(process_id, descriptor, true).unwrap_or(endpoint);
                socket.peer = Some(endpoint);
                NetworkObservation {
                    events: vec![NetworkEvent {
                        operation: "connect",
                        transport: socket.transport,
                        endpoint,
                    }],
                    dns_events: Vec::new(),
                    lost_events: 0,
                }
            }),
        PendingNetworkOperation::Listen { descriptor } => NetworkObservation {
            events: sockets
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
            dns_events: Vec::new(),
            lost_events: 0,
        },
        PendingNetworkOperation::Close { descriptor } => {
            sockets.remove(&descriptor);
            NetworkObservation::default()
        }
        PendingNetworkOperation::Duplicate { source, requested } => {
            if let Some(socket) = sockets.get(&source).cloned() {
                let descriptor = requested.unwrap_or(result as i32);
                if sockets.contains_key(&descriptor) || sockets.len() < MAX_SOCKETS_PER_PROCESS {
                    sockets.insert(descriptor, socket);
                } else {
                    return NetworkObservation {
                        lost_events: 1,
                        ..NetworkObservation::default()
                    };
                }
            }
            NetworkObservation::default()
        }
        PendingNetworkOperation::Send {
            descriptor,
            buffer,
            length,
            endpoint,
        } => {
            let mut events = Vec::new();
            if let Some(socket) = sockets.get_mut(&descriptor) {
                let length = usize::try_from(result).unwrap_or(0).min(length).min(65_537);
                if let Ok(bytes) = read_memory(process_id, buffer, length) {
                    if let Some((transaction, hostname)) = parse_dns_query(&bytes) {
                        if !remember_dns_query(socket, transaction, hostname) {
                            return NetworkObservation {
                                lost_events: 1,
                                ..NetworkObservation::default()
                            };
                        }
                    }
                }
                if socket.transport == "udp" {
                    if let Some(endpoint) = endpoint.or(socket.peer) {
                        events.push(NetworkEvent {
                            operation: "send",
                            transport: socket.transport,
                            endpoint,
                        });
                    }
                }
            }
            NetworkObservation {
                events,
                dns_events: Vec::new(),
                lost_events: 0,
            }
        }
        PendingNetworkOperation::Receive {
            descriptor,
            buffer,
            length,
            endpoint,
        } => {
            let Some(socket) = sockets.get_mut(&descriptor) else {
                return NetworkObservation::default();
            };
            let length = usize::try_from(result).unwrap_or(0).min(length).min(65_537);
            let dns_events = read_memory(process_id, buffer, length)
                .ok()
                .map(|bytes| parse_dns_response(&bytes, &mut socket.dns_queries))
                .unwrap_or_default();
            let endpoint = endpoint
                .and_then(|(address, length)| {
                    read_socket_length(process_id, length)
                        .ok()
                        .and_then(|length| read_socket_address(process_id, address, length).ok())
                        .flatten()
                })
                .or(socket.peer);
            let events = if socket.transport == "udp" {
                endpoint
                    .map(|endpoint| NetworkEvent {
                        operation: "receive",
                        transport: socket.transport,
                        endpoint,
                    })
                    .into_iter()
                    .collect()
            } else {
                Vec::new()
            };
            NetworkObservation {
                events,
                dns_events,
                lost_events: 0,
            }
        }
    }
}

fn remember_dns_query(socket: &mut SocketInformation, transaction: u16, hostname: String) -> bool {
    if !socket.dns_queries.contains_key(&transaction)
        && socket.dns_queries.len() >= MAX_DNS_QUERIES_PER_SOCKET
    {
        return false;
    }
    socket.dns_queries.insert(transaction, hostname);
    true
}

fn read_socket_length(process_id: libc::pid_t, address: u64) -> io::Result<usize> {
    if address == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "null socket length pointer",
        ));
    }
    let bytes = peek_word(process_id, address)?.to_ne_bytes();
    let mut length = [0_u8; std::mem::size_of::<libc::socklen_t>()];
    let length_size = length.len();
    length.copy_from_slice(&bytes[..length_size]);
    Ok(libc::socklen_t::from_ne_bytes(length) as usize)
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

fn parse_dns_query(bytes: &[u8]) -> Option<(u16, String)> {
    let message = dns_message(bytes)?;
    if message.len() < 12 || u16::from_be_bytes([message[2], message[3]]) & 0x8000 != 0 {
        return None;
    }
    if u16::from_be_bytes([message[4], message[5]]) == 0 {
        return None;
    }
    let (hostname, offset) = parse_dns_name(message, 12, 0)?;
    if offset.checked_add(4)? > message.len() || hostname.is_empty() {
        return None;
    }
    Some((u16::from_be_bytes([message[0], message[1]]), hostname))
}

fn parse_dns_response(
    bytes: &[u8],
    queries: &mut std::collections::HashMap<u16, String>,
) -> Vec<DnsEvent> {
    let Some(message) = dns_message(bytes) else {
        return Vec::new();
    };
    if message.len() < 12 {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return Vec::new();
    }
    let transaction = u16::from_be_bytes([message[0], message[1]]);
    let Some(expected_hostname) = queries.remove(&transaction) else {
        return Vec::new();
    };
    let question_count = usize::from(u16::from_be_bytes([message[4], message[5]]));
    let answer_count = usize::from(u16::from_be_bytes([message[6], message[7]]));
    let mut offset = 12;
    let mut question_hostname = None;
    for index in 0..question_count {
        let Some((hostname, next)) = parse_dns_name(message, offset, 0) else {
            return Vec::new();
        };
        offset = next;
        if offset
            .checked_add(4)
            .map_or(true, |end| end > message.len())
        {
            return Vec::new();
        }
        if index == 0 {
            question_hostname = Some(hostname);
        }
        offset += 4;
    }
    if question_hostname.as_deref() != Some(expected_hostname.as_str()) {
        return Vec::new();
    }

    let mut names = vec![expected_hostname.clone()];
    let mut events = Vec::new();
    for _ in 0..answer_count {
        let Some((owner, next)) = parse_dns_name(message, offset, 0) else {
            break;
        };
        offset = next;
        if offset
            .checked_add(10)
            .map_or(true, |end| end > message.len())
        {
            break;
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let data_length = usize::from(u16::from_be_bytes([
            message[offset + 8],
            message[offset + 9],
        ]));
        offset += 10;
        let Some(data_end) = offset.checked_add(data_length) else {
            break;
        };
        if data_end > message.len() {
            break;
        }
        if class == 1 && names.contains(&owner) {
            match (record_type, data_length) {
                (1, 4) => events.push(DnsEvent {
                    hostname: expected_hostname.clone(),
                    address: std::net::IpAddr::V4(Ipv4Addr::new(
                        message[offset],
                        message[offset + 1],
                        message[offset + 2],
                        message[offset + 3],
                    )),
                }),
                (28, 16) => {
                    let mut address = [0_u8; 16];
                    address.copy_from_slice(&message[offset..data_end]);
                    events.push(DnsEvent {
                        hostname: expected_hostname.clone(),
                        address: std::net::IpAddr::V6(Ipv6Addr::from(address)),
                    });
                }
                (5, _) => {
                    if let Some((canonical, _)) = parse_dns_name(message, offset, 0) {
                        names.push(canonical);
                    }
                }
                _ => {}
            }
        }
        offset = data_end;
    }
    events
}

fn dns_message(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < 12 {
        return None;
    }
    if bytes.len() >= 14 {
        let framed_length = usize::from(u16::from_be_bytes([bytes[0], bytes[1]]));
        if framed_length == bytes.len() - 2 {
            return Some(&bytes[2..]);
        }
    }
    Some(bytes)
}

fn parse_dns_name(message: &[u8], start: usize, depth: usize) -> Option<(String, usize)> {
    if depth > 8 || start >= message.len() {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = start;
    loop {
        let length = *message.get(offset)?;
        if length == 0 {
            offset += 1;
            return Some((labels.join(".").to_ascii_lowercase(), offset));
        }
        if length & 0xc0 == 0xc0 {
            let second = *message.get(offset + 1)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, second]));
            let (suffix, _) = parse_dns_name(message, pointer, depth + 1)?;
            labels.push(suffix);
            return Some((labels.join(".").to_ascii_lowercase(), offset + 2));
        }
        if length > 63 {
            return None;
        }
        let label_start = offset + 1;
        let label_end = label_start.checked_add(usize::from(length))?;
        let label = message.get(label_start..label_end)?;
        if label.is_empty()
            || !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_'))
        {
            return None;
        }
        labels.push(std::str::from_utf8(label).ok()?.to_owned());
        if labels.iter().map(String::len).sum::<usize>() + labels.len() > 254 {
            return None;
        }
        offset = label_end;
    }
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
            first: target,
            second: link,
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
            first: target,
            second: link,
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
    let existed = match fs::symlink_metadata(&path) {
        Ok(_) => Some(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Some(false),
        Err(_) => None,
    };
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
            if flags & libc::O_CREAT != 0 && existed == Some(false) {
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
    use std::collections::HashMap;
    use std::net::{Ipv6Addr, SocketAddr};
    use std::path::PathBuf;

    use super::{
        finish_file_operation, finish_network_operation, parse_dns_query, parse_dns_response,
        parse_socket_address, remember_dns_query, PendingFileOperation, PendingNetworkOperation,
        SocketInformation,
    };
    use crate::limits::{MAX_DNS_QUERIES_PER_SOCKET, MAX_SOCKETS_PER_PROCESS};

    #[test]
    fn keeps_nonblocking_connect_attempts() {
        let operation = PendingNetworkOperation::Connect {
            descriptor: 7,
            endpoint: "127.0.0.1:7319".parse().expect("the endpoint should parse"),
        };

        assert!(operation.completed(-i64::from(libc::EINPROGRESS)));
        assert!(!operation.completed(-i64::from(libc::ECONNREFUSED)));
    }

    #[test]
    fn snapshots_only_the_created_symlink() {
        let operation = PendingFileOperation::Two {
            operation: "symlink",
            first: PathBuf::from("target"),
            second: PathBuf::from("/tmp/link"),
        };

        assert_eq!(operation.mutation_paths(), [PathBuf::from("/tmp/link")]);
    }

    #[test]
    fn does_not_infer_creation_when_prior_state_is_unknown() {
        let events = finish_file_operation(
            PendingFileOperation::Open {
                path: PathBuf::from("/unreadable/file"),
                flags: libc::O_CREAT,
                existed: None,
            },
            4,
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, "open");
    }

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

    #[test]
    fn correlates_only_matching_dns_responses() {
        let query = dns_query();
        let response = dns_response();
        let (transaction, hostname) = parse_dns_query(&query).expect("the query should parse");
        let mut queries = HashMap::new();
        queries.insert(transaction, hostname);

        let events = parse_dns_response(&response, &mut queries);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].hostname, "fixture.test");
        assert_eq!(events[0].address.to_string(), "127.0.0.7");
        assert!(parse_dns_response(&response, &mut HashMap::new()).is_empty());
    }

    #[test]
    fn bounds_socket_and_dns_tracking() {
        let mut sockets = HashMap::new();
        for descriptor in 0..MAX_SOCKETS_PER_PROCESS {
            let observation = finish_network_operation(
                std::process::id() as libc::pid_t,
                PendingNetworkOperation::Socket { transport: "tcp" },
                descriptor as i64,
                &mut sockets,
            );
            assert_eq!(observation.lost_events, 0);
        }
        let overflow = finish_network_operation(
            std::process::id() as libc::pid_t,
            PendingNetworkOperation::Socket { transport: "tcp" },
            MAX_SOCKETS_PER_PROCESS as i64,
            &mut sockets,
        );
        assert_eq!(sockets.len(), MAX_SOCKETS_PER_PROCESS);
        assert_eq!(overflow.lost_events, 1);

        let mut socket = SocketInformation {
            transport: "udp",
            local: None,
            peer: None,
            dns_queries: HashMap::new(),
        };
        for transaction in 0..MAX_DNS_QUERIES_PER_SOCKET {
            assert!(remember_dns_query(
                &mut socket,
                transaction as u16,
                format!("host-{transaction}.test"),
            ));
        }
        assert!(!remember_dns_query(
            &mut socket,
            MAX_DNS_QUERIES_PER_SOCKET as u16,
            "overflow.test".to_owned(),
        ));
        assert_eq!(socket.dns_queries.len(), MAX_DNS_QUERIES_PER_SOCKET);
    }

    fn dns_query() -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        packet.extend_from_slice(&[
            7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 4, b't', b'e', b's', b't', 0,
        ]);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet
    }

    fn dns_response() -> Vec<u8> {
        let mut packet = dns_query();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0;
        packet[7] = 1;
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 7]);
        packet
    }
}
