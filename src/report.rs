use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::Extension;
use axum::http::Request;
use axum::middleware::{self, Next};
use axum::response::{Html, Response};
use axum::routing::get;
use axum::Router;

const REPORT_SHELL: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>ExecWake</title></head><body><main><h1>ExecWake</h1><p>Report loading.</p></main></body></html>";

#[derive(Clone)]
struct Activity(Arc<Mutex<Instant>>);

pub struct ReportServer {
    listener: TcpListener,
    address: SocketAddr,
    activity: Activity,
    idle_timeout: Duration,
}

impl ReportServer {
    pub fn bind(idle_timeout: Duration) -> io::Result<Self> {
        if idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "idle timeout must be greater than zero",
            ));
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;

        Ok(Self {
            listener,
            address,
            activity: Activity(Arc::new(Mutex::new(Instant::now()))),
            idle_timeout,
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub async fn run(self) -> io::Result<()> {
        let app = Router::new()
            .route("/", get(index))
            .layer(middleware::from_fn(track_activity))
            .layer(Extension(self.activity.clone()));
        let shutdown = wait_for_idle(self.activity, self.idle_timeout);

        axum::Server::from_tcp(self.listener)
            .map_err(server_error)?
            .serve(app.into_make_service())
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(server_error)
    }
}

async fn index() -> Html<&'static str> {
    Html(REPORT_SHELL)
}

async fn track_activity<B>(
    Extension(activity): Extension<Activity>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    *activity.0.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
    next.run(request).await
}

async fn wait_for_idle(activity: Activity, idle_timeout: Duration) {
    loop {
        let elapsed = activity
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .elapsed();
        if elapsed >= idle_timeout {
            return;
        }
        tokio::time::sleep(idle_timeout - elapsed).await;
    }
}

fn server_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    use super::ReportServer;

    #[tokio::test]
    async fn serves_only_on_loopback_and_stops_when_idle() {
        let server =
            ReportServer::bind(Duration::from_millis(100)).expect("the report server should bind");
        let address = server.address();
        assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);

        let task = tokio::spawn(server.run());
        let mut connection = TcpStream::connect(address)
            .await
            .expect("the report server should accept a connection");
        connection
            .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("the request should be written");
        let mut response = Vec::new();
        connection
            .read_to_end(&mut response)
            .await
            .expect("the response should be read");
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the report server should stop after its idle timeout")
            .expect("the server task should finish")
            .expect("the report server should stop cleanly");
    }
}
