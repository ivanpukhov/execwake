use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
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
    expect_contents(&fixture.path().join("modified.txt"), "before\nafter\n")?;
    expect_contents(&fixture.path().join("renamed.txt"), "rename me\n")?;
    expect_contents(&fixture.path().join("child.txt"), "created by child\n")?;
    expect_contents(
        &fixture.path().join("grandchild.txt"),
        "created by grandchild\n",
    )?;
    expect_absent(&fixture.path().join("rename-from.txt"))?;
    expect_absent(&fixture.path().join("delete-me.txt"))
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
