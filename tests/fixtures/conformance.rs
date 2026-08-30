use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const FIXTURE_TIMEOUT: Duration = Duration::from_secs(5);

fn main() {
    if let Err(error) = run() {
        eprintln!("conformance fixture failed: {error}");
        process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let mut arguments = env::args_os();
    arguments.next();

    match arguments.next().as_deref() {
        Some(mode) if mode == "--child" => {
            let root = required_path(arguments.next())?;
            let port = required_port(arguments.next())?;
            run_child(&root, port)
        }
        Some(mode) if mode == "--grandchild" => {
            let root = required_path(arguments.next())?;
            run_grandchild(&root)
        }
        Some(mode) if mode == "--short-lived" => Ok(()),
        Some(mode) if mode == "--root" => {
            let root = required_path(arguments.next())?;
            run_root(&root)
        }
        Some(_) | None => verify_fixture(),
    }
}

fn run_root(root: &Path) -> io::Result<()> {
    if env::var_os("EXECWAKE_CONFORMANCE_FLAG").is_none() {
        return Err(invalid_input("the fixture environment flag is required"));
    }

    let mut input = String::new();
    File::open(root.join("read.txt"))?.read_to_string(&mut input)?;
    if input != "fixture input\n" {
        return Err(invalid_input("read.txt has unexpected contents"));
    }

    fs::write(root.join("created.txt"), "created by root\n")?;
    OpenOptions::new()
        .append(true)
        .open(root.join("modified.txt"))?
        .write_all(b"after\n")?;
    fs::rename(root.join("rename-from.txt"), root.join("renamed.txt"))?;
    fs::write(root.join("delete-me.txt"), "temporary\n")?;
    fs::remove_file(root.join("delete-me.txt"))?;
    fs::hard_link(root.join("created.txt"), root.join("hard-link.txt"))?;

    #[cfg(unix)]
    std::os::unix::fs::symlink("created.txt", root.join("symbolic-link.txt"))?;

    let original_directory = env::current_dir()?;
    env::set_current_dir(root)?;
    let relative_write = fs::write("cwd-relative.txt", "resolved from cwd\n");
    let restore_directory = env::set_current_dir(original_directory);
    relative_write?;
    restore_directory?;

    #[cfg(unix)]
    {
        write_through_dirfd(root)?;
        write_through_mapping(root)?;
    }

    run_udp_roundtrip("127.0.0.1:0", "127.0.0.1:0")?;
    if UdpSocket::bind("[::1]:0").is_ok() {
        run_udp_roundtrip("[::1]:0", "[::1]:0")?;
    }
    run_local_dns_exchange()?;

    for _ in 0..8 {
        let mut short_lived = Command::new(env::current_exe()?)
            .arg("--short-lived")
            .spawn()?;
        wait_for_child(&mut short_lived, "short-lived child")?;
    }

    let mut flood = File::create(root.join("event-flood.txt"))?;
    for _ in 0..2_048 {
        flood.write_all(b"x")?;
    }

    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let mut child = Command::new(env::current_exe()?)
        .arg("--child")
        .arg(root)
        .arg(port.to_string())
        .spawn()?;

    let mut connection = accept_child_connection(&listener, &mut child)?;
    configure_stream(&connection)?;
    let mut request = [0_u8; 4];
    connection.read_exact(&mut request)?;
    if &request != b"ping" {
        return Err(invalid_input("child sent an unexpected request"));
    }
    connection.write_all(b"pong")?;

    wait_for_child(&mut child, "child")?;

    println!("conformance run completed");
    Ok(())
}

fn run_child(root: &Path, port: u16) -> io::Result<()> {
    fs::write(root.join("child.txt"), "created by child\n")?;

    let mut connection = connect_to_listener(port)?;
    configure_stream(&connection)?;
    connection.write_all(b"ping")?;
    let mut response = [0_u8; 4];
    connection.read_exact(&mut response)?;
    if &response != b"pong" {
        return Err(invalid_input("listener sent an unexpected response"));
    }

    let mut grandchild = Command::new(env::current_exe()?)
        .arg("--grandchild")
        .arg(root)
        .spawn()?;
    wait_for_child(&mut grandchild, "grandchild")?;

    Ok(())
}

fn run_grandchild(root: &Path) -> io::Result<()> {
    let mut input = String::new();
    File::open(root.join("read.txt"))?.read_to_string(&mut input)?;
    if input != "fixture input\n" {
        return Err(invalid_input("read.txt has unexpected contents"));
    }
    fs::write(root.join("grandchild.txt"), "created by grandchild\n")
}

fn run_udp_roundtrip(receiver_address: &str, sender_address: &str) -> io::Result<()> {
    let receiver = UdpSocket::bind(receiver_address)?;
    receiver.set_read_timeout(Some(FIXTURE_TIMEOUT))?;
    let sender = UdpSocket::bind(sender_address)?;
    sender.connect(receiver.local_addr()?)?;
    sender.send(b"datagram")?;
    let mut message = [0_u8; 8];
    let received = receiver.recv(&mut message)?;
    if received != message.len() || &message != b"datagram" {
        return Err(invalid_input("UDP payload did not round-trip"));
    }
    Ok(())
}

fn run_local_dns_exchange() -> io::Result<()> {
    let server = UdpSocket::bind("127.0.0.1:0")?;
    server.set_read_timeout(Some(FIXTURE_TIMEOUT))?;
    let server_address = server.local_addr()?;
    let server_thread = thread::spawn(move || -> io::Result<()> {
        let mut query = [0_u8; 512];
        let (length, peer) = server.recv_from(&mut query)?;
        let response = dns_response(&query[..length])?;
        server.send_to(&response, peer)?;
        Ok(())
    });

    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.set_read_timeout(Some(FIXTURE_TIMEOUT))?;
    client.connect(server_address)?;
    client.send(&dns_query())?;
    let mut response = [0_u8; 512];
    let length = client.recv(&mut response)?;
    if length < 12 || response[..2] != [0x4e, 0x57] {
        return Err(invalid_input("local DNS response was invalid"));
    }
    server_thread
        .join()
        .map_err(|_| invalid_input("local DNS server panicked"))??;
    Ok(())
}

fn dns_query() -> Vec<u8> {
    let mut packet = vec![
        0x4e, 0x57, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    packet.extend_from_slice(&[
        7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 4, b't', b'e', b's', b't', 0,
    ]);
    packet.extend_from_slice(&[0, 1, 0, 1]);
    packet
}

fn dns_response(query: &[u8]) -> io::Result<Vec<u8>> {
    if query != dns_query() {
        return Err(invalid_input("local DNS query was invalid"));
    }
    let mut packet = query.to_vec();
    packet[2] = 0x81;
    packet[3] = 0x80;
    packet[6] = 0;
    packet[7] = 1;
    packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 7]);
    Ok(packet)
}

#[cfg(unix)]
fn write_through_dirfd(root: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    let root = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| invalid_input("fixture path contains a null byte"))?;
    let name = CString::new("dirfd-relative.txt").expect("the static name is valid");
    let descriptor = unsafe { libc::open(root.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    file.write_all(b"resolved from dirfd\n")
}

#[cfg(unix)]
fn write_through_mapping(root: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let path = root.join("mapped.txt");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(4_096)?;
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4_096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if mapping == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        std::ptr::copy_nonoverlapping(b"mapped\n".as_ptr(), mapping.cast::<u8>(), 7);
    }
    let sync_result = unsafe { libc::msync(mapping, 4_096, libc::MS_SYNC) };
    let sync_error = (sync_result != 0).then(io::Error::last_os_error);
    let unmap_result = unsafe { libc::munmap(mapping, 4_096) };
    if let Some(error) = sync_error {
        return Err(error);
    }
    if unmap_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn accept_child_connection(listener: &TcpListener, child: &mut Child) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + FIXTURE_TIMEOUT;

    loop {
        match listener.accept() {
            Ok((connection, _)) => return Ok(connection),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }

        if let Some(status) = child.try_wait()? {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("child exited before connecting: {status}"),
            ));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out waiting for child connection",
            ));
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn connect_to_listener(port: u16) -> io::Result<TcpStream> {
    let mut last_error = None;

    for address in ("localhost", port).to_socket_addrs()? {
        if !address.ip().is_loopback() {
            continue;
        }

        match TcpStream::connect_timeout(&address, FIXTURE_TIMEOUT) {
            Ok(connection) => return Ok(connection),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(|| invalid_input("localhost did not resolve to loopback")))
}

fn configure_stream(connection: &TcpStream) -> io::Result<()> {
    connection.set_read_timeout(Some(FIXTURE_TIMEOUT))?;
    connection.set_write_timeout(Some(FIXTURE_TIMEOUT))
}

fn wait_for_child(child: &mut Child, name: &str) -> io::Result<()> {
    let deadline = Instant::now() + FIXTURE_TIMEOUT;

    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("{name} process failed: {status}"),
                ))
            };
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out waiting for {name} process"),
            ));
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn verify_fixture() -> io::Result<()> {
    let fixture = FixtureDirectory::new()?;
    fs::write(fixture.path().join("read.txt"), "fixture input\n")?;
    fs::write(fixture.path().join("modified.txt"), "before\n")?;
    fs::write(fixture.path().join("rename-from.txt"), "rename me\n")?;
    env::set_var("EXECWAKE_CONFORMANCE_FLAG", "present");

    run_root(fixture.path())?;

    expect_contents(&fixture.path().join("created.txt"), "created by root\n")?;
    expect_contents(&fixture.path().join("hard-link.txt"), "created by root\n")?;
    expect_contents(&fixture.path().join("modified.txt"), "before\nafter\n")?;
    expect_contents(&fixture.path().join("renamed.txt"), "rename me\n")?;
    expect_contents(
        &fixture.path().join("cwd-relative.txt"),
        "resolved from cwd\n",
    )?;
    #[cfg(unix)]
    {
        expect_contents(
            &fixture.path().join("dirfd-relative.txt"),
            "resolved from dirfd\n",
        )?;
        let mapped = fs::read(fixture.path().join("mapped.txt"))?;
        if !mapped.starts_with(b"mapped\n") {
            return Err(invalid_input("mapped.txt has unexpected contents"));
        }
        if fs::read_link(fixture.path().join("symbolic-link.txt"))? != Path::new("created.txt") {
            return Err(invalid_input("symbolic link has an unexpected target"));
        }
    }
    expect_contents(&fixture.path().join("child.txt"), "created by child\n")?;
    expect_contents(
        &fixture.path().join("grandchild.txt"),
        "created by grandchild\n",
    )?;
    expect_absent(&fixture.path().join("rename-from.txt"))?;
    expect_absent(&fixture.path().join("delete-me.txt"))?;
    if fs::metadata(fixture.path().join("event-flood.txt"))?.len() != 2_048 {
        return Err(invalid_input("event flood has an unexpected size"));
    }
    Ok(())
}

fn expect_contents(path: &Path, expected: &str) -> io::Result<()> {
    if fs::read_to_string(path)? == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} has unexpected contents", path.display()),
        ))
    }
}

fn expect_absent(path: &Path) -> io::Result<()> {
    if path.exists() {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} should not exist", path.display()),
        ))
    } else {
        Ok(())
    }
}

struct FixtureDirectory {
    path: PathBuf,
}

impl FixtureDirectory {
    fn new() -> io::Result<Self> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| invalid_input("the system clock is before the Unix epoch"))?
            .as_nanos();
        let path = env::temp_dir().join(format!("execwake-conformance-{}-{nonce}", process::id()));
        fs::create_dir(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        if self.path.parent() == Some(env::temp_dir().as_path())
            && self
                .path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map_or(false, |name| name.starts_with("execwake-conformance-"))
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn required_path(argument: Option<std::ffi::OsString>) -> io::Result<PathBuf> {
    argument
        .map(PathBuf::from)
        .ok_or_else(|| invalid_input("a fixture directory is required"))
}

fn required_port(argument: Option<std::ffi::OsString>) -> io::Result<u16> {
    argument
        .and_then(|argument| argument.to_str().and_then(|value| value.parse().ok()))
        .ok_or_else(|| invalid_input("a valid port is required"))
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
