use std::io;

pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 88;
pub const MAX_DATA_BYTES: usize = 384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum EventKind {
    Heartbeat = 0,
    ProcessFork = 1,
    ProcessExec = 2,
    ProcessExit = 3,
    Syscall = 4,
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
    use super::{decode, EventKind, HEADER_BYTES, MAX_DATA_BYTES, VERSION};

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
}
