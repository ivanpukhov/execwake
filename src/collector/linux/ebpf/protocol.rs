use std::io;

pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 88;
pub const MAX_DATA_BYTES: usize = 384;
pub const MAX_EVENT_BYTES: usize = HEADER_BYTES + MAX_DATA_BYTES;
const SOCKET_ADDRESS_BYTES: usize = 128;
const SOCKET_PAYLOAD_OFFSET: usize = 8 + SOCKET_ADDRESS_BYTES;
const SYSCALL_OPERATION_MASK: u32 = 0xffff;
const DATA_HAS_ADDRESS: u32 = 1 << 16;
const DATA_HAS_PAYLOAD: u32 = 1 << 17;
const DATA_TRUNCATED: u32 = 1 << 18;
const DATA_HAS_FIRST_PATH: u32 = 1 << 19;
const DATA_HAS_SECOND_PATH: u32 = 1 << 20;
const PATH_BYTES: usize = 188;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EventKind {
    Heartbeat = 0,
    ProcessFork = 1,
    ProcessExec = 2,
    ProcessExit = 3,
    Syscall = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SyscallOperation {
    Socket = 1,
    Bind = 2,
    Connect = 3,
    Listen = 4,
    Accept = 5,
    Close = 6,
    Duplicate = 7,
    Fcntl = 8,
    SendTo = 9,
    ReceiveFrom = 10,
    Write = 11,
    Read = 12,
    OpenAt = 13,
    ReadVector = 14,
    WriteVector = 15,
    ReadAt = 16,
    WriteAt = 17,
    Truncate = 18,
    FileTruncate = 19,
    RenameAt = 20,
    LinkAt = 21,
    SymlinkAt = 22,
    UnlinkAt = 23,
    MakeDirectoryAt = 24,
    ChangeDirectory = 25,
    ChangeDirectoryFd = 26,
    MemoryMap = 27,
    StatAt = 28,
    ReadLinkAt = 29,
    ReadDirectory = 30,
    Open = 31,
    Create = 32,
    Rename = 33,
    Link = 34,
    Symlink = 35,
    Unlink = 36,
    MakeDirectory = 37,
    RemoveDirectory = 38,
    Stat = 39,
    OpenAt2 = 40,
}

impl SyscallOperation {
    fn parse(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::Socket),
            2 => Some(Self::Bind),
            3 => Some(Self::Connect),
            4 => Some(Self::Listen),
            5 => Some(Self::Accept),
            6 => Some(Self::Close),
            7 => Some(Self::Duplicate),
            8 => Some(Self::Fcntl),
            9 => Some(Self::SendTo),
            10 => Some(Self::ReceiveFrom),
            11 => Some(Self::Write),
            12 => Some(Self::Read),
            13 => Some(Self::OpenAt),
            14 => Some(Self::ReadVector),
            15 => Some(Self::WriteVector),
            16 => Some(Self::ReadAt),
            17 => Some(Self::WriteAt),
            18 => Some(Self::Truncate),
            19 => Some(Self::FileTruncate),
            20 => Some(Self::RenameAt),
            21 => Some(Self::LinkAt),
            22 => Some(Self::SymlinkAt),
            23 => Some(Self::UnlinkAt),
            24 => Some(Self::MakeDirectoryAt),
            25 => Some(Self::ChangeDirectory),
            26 => Some(Self::ChangeDirectoryFd),
            27 => Some(Self::MemoryMap),
            28 => Some(Self::StatAt),
            29 => Some(Self::ReadLinkAt),
            30 => Some(Self::ReadDirectory),
            31 => Some(Self::Open),
            32 => Some(Self::Create),
            33 => Some(Self::Rename),
            34 => Some(Self::Link),
            35 => Some(Self::Symlink),
            36 => Some(Self::Unlink),
            37 => Some(Self::MakeDirectory),
            38 => Some(Self::RemoveDirectory),
            39 => Some(Self::Stat),
            40 => Some(Self::OpenAt2),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketData {
    pub address: Vec<u8>,
    pub payload: Vec<u8>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathData {
    pub first: Vec<u8>,
    pub second: Vec<u8>,
    pub truncated: bool,
}

impl EventKind {
    fn parse(value: u16) -> Option<Self> {
        match value {
            0 => Some(Self::Heartbeat),
            1 => Some(Self::ProcessFork),
            2 => Some(Self::ProcessExec),
            3 => Some(Self::ProcessExit),
            4 => Some(Self::Syscall),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub kind: EventKind,
    pub monotonic_ns: u64,
    pub tgid: u32,
    pub tid: u32,
    pub result: i64,
    pub arguments: [u64; 6],
    pub flags: u32,
    pub data: Vec<u8>,
}

impl Event {
    pub fn syscall_operation(&self) -> Option<SyscallOperation> {
        (self.kind == EventKind::Syscall)
            .then(|| SyscallOperation::parse(self.flags & SYSCALL_OPERATION_MASK))
            .flatten()
    }

    pub fn socket_data(&self) -> io::Result<Option<SocketData>> {
        let has_address = self.flags & DATA_HAS_ADDRESS != 0;
        let has_payload = self.flags & DATA_HAS_PAYLOAD != 0;
        if !has_address && !has_payload {
            return Ok(None);
        }
        if self.kind != EventKind::Syscall || self.data.len() != MAX_DATA_BYTES {
            return Err(invalid_event("eBPF socket data is invalid"));
        }

        let address_length = read_u32(&self.data, 0)? as usize;
        let payload_length = read_u32(&self.data, 4)? as usize;
        if address_length > SOCKET_ADDRESS_BYTES
            || payload_length > MAX_DATA_BYTES - SOCKET_PAYLOAD_OFFSET
            || (!has_address && address_length != 0)
            || (!has_payload && payload_length != 0)
        {
            return Err(invalid_event("eBPF socket data length is invalid"));
        }
        Ok(Some(SocketData {
            address: self.data[8..8 + address_length].to_vec(),
            payload: self.data[SOCKET_PAYLOAD_OFFSET..SOCKET_PAYLOAD_OFFSET + payload_length]
                .to_vec(),
            truncated: self.flags & DATA_TRUNCATED != 0,
        }))
    }

    pub fn path_data(&self) -> io::Result<Option<PathData>> {
        let has_first = self.flags & DATA_HAS_FIRST_PATH != 0;
        let has_second = self.flags & DATA_HAS_SECOND_PATH != 0;
        if !has_first && !has_second {
            return Ok(None);
        }
        if self.kind != EventKind::Syscall || self.data.len() != MAX_DATA_BYTES {
            return Err(invalid_event("eBPF path data is invalid"));
        }

        let first_length = read_u32(&self.data, 0)? as usize;
        let second_length = read_u32(&self.data, 4)? as usize;
        if first_length >= PATH_BYTES
            || second_length >= PATH_BYTES
            || (!has_first && first_length != 0)
            || (!has_second && second_length != 0)
        {
            return Err(invalid_event("eBPF path data length is invalid"));
        }
        Ok(Some(PathData {
            first: self.data[8..8 + first_length].to_vec(),
            second: self.data[8 + PATH_BYTES..8 + PATH_BYTES + second_length].to_vec(),
            truncated: self.flags & DATA_TRUNCATED != 0,
        }))
    }
}

pub fn decode(bytes: &[u8]) -> io::Result<Event> {
    if bytes.len() < HEADER_BYTES {
        return Err(invalid_event("eBPF event header is truncated"));
    }
    let version = read_u16(bytes, 0)?;
    if version != VERSION {
        return Err(invalid_event("eBPF event version is unsupported"));
    }
    let kind = EventKind::parse(read_u16(bytes, 2)?)
        .ok_or_else(|| invalid_event("eBPF event kind is invalid"))?;
    let size = read_u32(bytes, 4)? as usize;
    let data_length = read_u32(bytes, 80)? as usize;
    if data_length > MAX_DATA_BYTES || size != HEADER_BYTES + data_length || size > bytes.len() {
        return Err(invalid_event("eBPF event size is invalid"));
    }

    let mut arguments = [0_u64; 6];
    for (index, argument) in arguments.iter_mut().enumerate() {
        *argument = read_u64(bytes, 32 + index * 8)?;
    }
    Ok(Event {
        kind,
        monotonic_ns: read_u64(bytes, 8)?,
        tgid: read_u32(bytes, 16)?,
        tid: read_u32(bytes, 20)?,
        result: read_i64(bytes, 24)?,
        arguments,
        flags: read_u32(bytes, 84)?,
        data: bytes[HEADER_BYTES..size].to_vec(),
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| invalid_event("eBPF event field is truncated"))?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| invalid_event("eBPF event field is truncated"))?;
    Ok(u32::from_le_bytes(
        value.try_into().expect("field length is fixed"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> io::Result<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| invalid_event("eBPF event field is truncated"))?;
    Ok(u64::from_le_bytes(
        value.try_into().expect("field length is fixed"),
    ))
}

fn read_i64(bytes: &[u8], offset: usize) -> io::Result<i64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| invalid_event("eBPF event field is truncated"))?;
    Ok(i64::from_le_bytes(
        value.try_into().expect("field length is fixed"),
    ))
}

fn invalid_event(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::{
        decode, EventKind, SyscallOperation, DATA_HAS_ADDRESS, DATA_HAS_FIRST_PATH,
        DATA_HAS_PAYLOAD, DATA_HAS_SECOND_PATH, HEADER_BYTES, MAX_DATA_BYTES, PATH_BYTES,
        SOCKET_PAYLOAD_OFFSET, VERSION,
    };

    #[test]
    fn decodes_a_bounded_little_endian_event() {
        let mut bytes = vec![0_u8; HEADER_BYTES + 4];
        bytes[0..2].copy_from_slice(&VERSION.to_le_bytes());
        bytes[2..4].copy_from_slice(&(EventKind::ProcessFork as u16).to_le_bytes());
        bytes[4..8].copy_from_slice(&((HEADER_BYTES + 4) as u32).to_le_bytes());
        bytes[8..16].copy_from_slice(&91_u64.to_le_bytes());
        bytes[16..20].copy_from_slice(&7_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&8_u32.to_le_bytes());
        bytes[24..32].copy_from_slice(&(-2_i64).to_le_bytes());
        bytes[32..40].copy_from_slice(&11_u64.to_le_bytes());
        bytes[80..84].copy_from_slice(&4_u32.to_le_bytes());
        bytes[84..88].copy_from_slice(&3_u32.to_le_bytes());
        bytes[88..].copy_from_slice(b"data");

        let event = decode(&bytes).expect("the event should decode");

        assert_eq!(event.kind, EventKind::ProcessFork);
        assert_eq!(event.monotonic_ns, 91);
        assert_eq!((event.tgid, event.tid), (7, 8));
        assert_eq!(event.result, -2);
        assert_eq!(event.arguments[0], 11);
        assert_eq!(event.flags, 3);
        assert_eq!(event.data, b"data");
    }

    #[test]
    fn rejects_unknown_truncated_and_oversized_events() {
        assert!(decode(&[]).is_err());

        let mut bytes = vec![0_u8; HEADER_BYTES];
        bytes[0..2].copy_from_slice(&VERSION.to_le_bytes());
        bytes[2..4].copy_from_slice(&99_u16.to_le_bytes());
        bytes[4..8].copy_from_slice(&(HEADER_BYTES as u32).to_le_bytes());
        assert!(decode(&bytes).is_err());

        bytes[2..4].copy_from_slice(&(EventKind::Heartbeat as u16).to_le_bytes());
        bytes[4..8].copy_from_slice(&((HEADER_BYTES + MAX_DATA_BYTES + 1) as u32).to_le_bytes());
        bytes[80..84].copy_from_slice(&((MAX_DATA_BYTES + 1) as u32).to_le_bytes());
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn decodes_bounded_socket_data() {
        let mut bytes = vec![0_u8; HEADER_BYTES + MAX_DATA_BYTES];
        let event_length = bytes.len() as u32;
        bytes[0..2].copy_from_slice(&VERSION.to_le_bytes());
        bytes[2..4].copy_from_slice(&(EventKind::Syscall as u16).to_le_bytes());
        bytes[4..8].copy_from_slice(&event_length.to_le_bytes());
        bytes[80..84].copy_from_slice(&(MAX_DATA_BYTES as u32).to_le_bytes());
        let flags = SyscallOperation::Connect as u32 | DATA_HAS_ADDRESS | DATA_HAS_PAYLOAD;
        bytes[84..88].copy_from_slice(&flags.to_le_bytes());
        bytes[88..92].copy_from_slice(&4_u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&3_u32.to_le_bytes());
        bytes[96..100].copy_from_slice(b"addr");
        let payload = HEADER_BYTES + SOCKET_PAYLOAD_OFFSET;
        bytes[payload..payload + 3].copy_from_slice(b"dns");

        let event = decode(&bytes).expect("the event should decode");
        let data = event
            .socket_data()
            .expect("socket data should be valid")
            .expect("socket data should be present");

        assert_eq!(event.syscall_operation(), Some(SyscallOperation::Connect));
        assert_eq!(data.address, b"addr");
        assert_eq!(data.payload, b"dns");
        assert!(!data.truncated);
    }

    #[test]
    fn decodes_two_bounded_paths() {
        let mut bytes = vec![0_u8; HEADER_BYTES + MAX_DATA_BYTES];
        let event_length = bytes.len() as u32;
        bytes[0..2].copy_from_slice(&VERSION.to_le_bytes());
        bytes[2..4].copy_from_slice(&(EventKind::Syscall as u16).to_le_bytes());
        bytes[4..8].copy_from_slice(&event_length.to_le_bytes());
        bytes[80..84].copy_from_slice(&(MAX_DATA_BYTES as u32).to_le_bytes());
        let flags = SyscallOperation::RenameAt as u32 | DATA_HAS_FIRST_PATH | DATA_HAS_SECOND_PATH;
        bytes[84..88].copy_from_slice(&flags.to_le_bytes());
        bytes[88..92].copy_from_slice(&3_u32.to_le_bytes());
        bytes[92..96].copy_from_slice(&3_u32.to_le_bytes());
        bytes[96..99].copy_from_slice(b"old");
        let second = HEADER_BYTES + 8 + PATH_BYTES;
        bytes[second..second + 3].copy_from_slice(b"new");

        let event = decode(&bytes).expect("the event should decode");
        let data = event
            .path_data()
            .expect("path data should be valid")
            .expect("path data should be present");

        assert_eq!(data.first, b"old");
        assert_eq!(data.second, b"new");
        assert!(!data.truncated);
    }
}
