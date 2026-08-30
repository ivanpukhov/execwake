use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr;

pub struct SyscallState {
    pending: Option<PendingFileOperation>,
}

pub struct FileEvent {
    pub operation: &'static str,
    pub paths: Vec<PathBuf>,
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
    pub const fn root() -> Self {
        Self { pending: None }
    }

    pub const fn child() -> Self {
        Self { pending: None }
    }

    pub fn observe_stop(&mut self, process_id: libc::pid_t) -> io::Result<Vec<FileEvent>> {
        match read_syscall_stop(process_id)? {
            SyscallStop::Entry(registers) => {
                self.pending = decode_file_operation(process_id, &registers).unwrap_or(None);
                Ok(Vec::new())
            }
            SyscallStop::Exit(result) => {
                let Some(pending) = self.pending.take() else {
                    return Ok(Vec::new());
                };
                if result < 0 {
                    return Ok(Vec::new());
                }
                Ok(finish_file_operation(pending, result))
            }
            SyscallStop::Other => Ok(Vec::new()),
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
