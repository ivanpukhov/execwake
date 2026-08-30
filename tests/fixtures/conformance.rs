use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{self, Child, Command};
use std::thread;
use std::time::{Duration, Instant};

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
        Some(root) => run_root(Path::new(root)),
        None => Err(invalid_input("a fixture directory is required")),
    }
}

fn run_root(root: &Path) -> io::Result<()> {
    let _ = env::var_os("EXECWAKE_CONFORMANCE_FLAG");

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
    let mut request = [0_u8; 4];
    connection.read_exact(&mut request)?;
    if &request != b"ping" {
        return Err(invalid_input("child sent an unexpected request"));
    }
    connection.write_all(b"pong")?;

    if !child.wait()?.success() {
        return Err(io::Error::new(io::ErrorKind::Other, "child process failed"));
    }

    println!("conformance run completed");
    Ok(())
}

fn run_child(root: &Path, port: u16) -> io::Result<()> {
    fs::write(root.join("child.txt"), "created by child\n")?;

    let mut connection = TcpStream::connect(("localhost", port))?;
    connection.write_all(b"ping")?;
    let mut response = [0_u8; 4];
    connection.read_exact(&mut response)?;
    if &response != b"pong" {
        return Err(invalid_input("listener sent an unexpected response"));
    }

    let status = Command::new(env::current_exe()?)
        .arg("--grandchild")
        .arg(root)
        .status()?;
    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "grandchild process failed",
        ));
    }

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
    let deadline = Instant::now() + Duration::from_secs(5);

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
