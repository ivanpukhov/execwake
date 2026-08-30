use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, LOCATION,
    ORIGIN, REFERRER_POLICY, SET_COOKIE, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::storage::SessionPaths;

const BODY_LIMIT: usize = 16 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const REPORT_SHELL: &str = include_str!("report/assets/index.html");
const REPORT_JAVASCRIPT: &[u8] = include_bytes!("report/assets/assets/app.js");
const REPORT_STYLES: &[u8] = include_bytes!("report/assets/assets/app.css");
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

#[derive(Clone)]
struct Activity(Arc<Mutex<Instant>>);

impl Activity {
    fn touch(&self) {
        *self.0.lock().unwrap_or_else(|error| error.into_inner()) = Instant::now();
    }

    fn elapsed(&self) -> Duration {
        self.0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .elapsed()
    }
}

#[derive(Clone)]
struct AppState {
    session: SessionPaths,
    token: Arc<str>,
    host: Arc<str>,
    origin: Arc<str>,
    activity: Activity,
}

pub struct ReportServer {
    listener: TcpListener,
    address: SocketAddr,
    state: AppState,
    idle_timeout: Duration,
}

impl ReportServer {
    pub fn bind(session: SessionPaths, idle_timeout: Duration) -> io::Result<Self> {
        if idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "idle timeout must be greater than zero",
            ));
        }
        if !session.database().is_file() || !session.finalized().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "report session is not finalized",
            ));
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let host: Arc<str> = address.to_string().into();
        let origin: Arc<str> = format!("http://{address}").into();

        Ok(Self {
            listener,
            address,
            state: AppState {
                session,
                token: random_token()?.into(),
                host,
                origin,
                activity: Activity(Arc::new(Mutex::new(Instant::now()))),
            },
            idle_timeout,
        })
    }

    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn open_url(&self) -> String {
        format!(
            "{}/open/{}?token={}",
            self.state.origin,
            self.state.session.id().as_str(),
            self.state.token
        )
    }

    pub async fn run(self) -> io::Result<()> {
        let protected = Router::new()
            .route("/session/:id", get(index))
            .route("/api/session/:id", get(session_api))
            .route("/assets/app.js", get(app_javascript))
            .route("/assets/app.css", get(app_styles))
            .route_layer(middleware::from_fn_with_state(
                self.state.clone(),
                require_token,
            ));
        let app = Router::new()
            .route("/open/:id", get(open_report))
            .merge(protected)
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .layer(middleware::from_fn(limit_request_time))
            .layer(middleware::from_fn_with_state(
                self.state.clone(),
                validate_request,
            ))
            .with_state(self.state.clone());
        let shutdown = wait_for_idle(self.state.activity, self.idle_timeout);

        axum::Server::from_tcp(self.listener)
            .map_err(server_error)?
            .http1_header_read_timeout(REQUEST_TIMEOUT)
            .serve(app.into_make_service())
            .with_graceful_shutdown(shutdown)
            .await
            .map_err(server_error)
    }
}

#[derive(Deserialize)]
struct OpenQuery {
    token: String,
}

async fn open_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<OpenQuery>,
) -> Response {
    if id != state.session.id().as_str() || !constant_time_eq(&query.token, &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    state.activity.touch();
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&format!("/session/{id}"))
            .expect("a validated session id is a valid header value"),
    );
    response.headers_mut().insert(
        SET_COOKIE,
        HeaderValue::from_str(&format!(
            "execwake_token={}; Path=/; HttpOnly; SameSite=Strict",
            state.token
        ))
        .expect("a hexadecimal token is a valid cookie value"),
    );
    response
}

async fn index(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if id == state.session.id().as_str() {
        Html(REPORT_SHELL).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn app_javascript() -> Response {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        REPORT_JAVASCRIPT,
    )
        .into_response()
}

async fn app_styles() -> Response {
    ([(CONTENT_TYPE, "text/css; charset=utf-8")], REPORT_STYLES).into_response()
}

async fn session_api(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    if id != state.session.id().as_str() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let database = state.session.database().to_owned();
    match tokio::task::spawn_blocking(move || load_report(database)).await {
        Ok(Ok(report)) => Json(report).into_response(),
        Ok(Err(_)) | Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn validate_request<B>(
    State(state): State<AppState>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    let valid_host = request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map_or(false, |host| host == state.host.as_ref());
    let valid_origin = request
        .headers()
        .get(ORIGIN)
        .map(|value| value.to_str().ok() == Some(state.origin.as_ref()))
        .unwrap_or(true);
    let valid_length = request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .map_or(true, |length| length <= BODY_LIMIT);

    let mut response = if !valid_host || !valid_origin {
        StatusCode::FORBIDDEN.into_response()
    } else if !valid_length {
        StatusCode::PAYLOAD_TOO_LARGE.into_response()
    } else {
        next.run(request).await
    };
    add_security_headers(&mut response);
    response
}

async fn require_token<B>(
    State(state): State<AppState>,
    request: Request<B>,
    next: Next<B>,
) -> Response {
    let authorized = request
        .headers()
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| cookie_value(cookies, "execwake_token"))
        .map_or(false, |token| constant_time_eq(token, &state.token));

    if !authorized {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    state.activity.touch();
    next.run(request).await
}

async fn limit_request_time<B>(request: Request<B>, next: Next<B>) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => StatusCode::REQUEST_TIMEOUT.into_response(),
    }
}

fn add_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn cookie_value<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|cookie| {
        let (cookie_name, value) = cookie.trim().split_once('=')?;
        (cookie_name == name).then_some(value)
    })
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }

    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

async fn wait_for_idle(activity: Activity, idle_timeout: Duration) {
    loop {
        let elapsed = activity.elapsed();
        if elapsed >= idle_timeout {
            return;
        }
        tokio::time::sleep(idle_timeout - elapsed).await;
    }
}

fn random_token() -> io::Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "random source unavailable"))?;

    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut token, "{byte:02x}").expect("writing to a string cannot fail");
    }
    Ok(token)
}

fn server_error(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionReport {
    id: String,
    schema_version: i64,
    mode: String,
    state: String,
    finalized: bool,
    command_name: String,
    argument_count: i64,
    started_at_ms: i64,
    ended_at_ms: Option<i64>,
    exit_code: Option<i64>,
    termination_signal: Option<i64>,
    interruption: Option<String>,
    coverage: Vec<CoverageReport>,
    processes: Vec<ProcessReport>,
    events: Vec<EventReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CoverageReport {
    category: String,
    state: String,
    lost_events: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessReport {
    process_id: i64,
    parent_process_id: Option<i64>,
    executable: String,
    started_at_ms: i64,
    ended_at_ms: Option<i64>,
    exit_code: Option<i64>,
    termination_signal: Option<i64>,
    evidence: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EventReport {
    event_id: i64,
    category: String,
    operation: String,
    target: String,
    process_id: Option<i64>,
    occurred_at_ms: i64,
    evidence: String,
}

fn load_report(database: PathBuf) -> rusqlite::Result<SessionReport> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut report = connection.query_row(
        "SELECT id, schema_version, mode, state, finalized, command_name,
                argument_count, started_at_ms, ended_at_ms, exit_code,
                termination_signal, interruption
         FROM session WHERE singleton = 1",
        [],
        |row| {
            Ok(SessionReport {
                id: row.get(0)?,
                schema_version: row.get(1)?,
                mode: row.get(2)?,
                state: row.get(3)?,
                finalized: row.get::<_, i64>(4)? == 1,
                command_name: row.get(5)?,
                argument_count: row.get(6)?,
                started_at_ms: row.get(7)?,
                ended_at_ms: row.get(8)?,
                exit_code: row.get(9)?,
                termination_signal: row.get(10)?,
                interruption: row.get(11)?,
                coverage: Vec::new(),
                processes: Vec::new(),
                events: Vec::new(),
            })
        },
    )?;

    report.coverage = query_coverage(&connection)?;
    report.processes = query_processes(&connection)?;
    report.events = query_events(&connection)?;
    Ok(report)
}

fn query_coverage(connection: &Connection) -> rusqlite::Result<Vec<CoverageReport>> {
    let mut statement = connection
        .prepare("SELECT category, state, lost_events FROM coverage ORDER BY category")?;
    let rows = statement
        .query_map([], |row| {
            Ok(CoverageReport {
                category: row.get(0)?,
                state: row.get(1)?,
                lost_events: row.get(2)?,
            })
        })?
        .collect();
    rows
}

fn query_processes(connection: &Connection) -> rusqlite::Result<Vec<ProcessReport>> {
    let mut statement = connection.prepare(
        "SELECT process_id, parent_process_id, executable, started_at_ms,
                ended_at_ms, exit_code, termination_signal, evidence
         FROM process ORDER BY started_at_ms, process_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(ProcessReport {
                process_id: row.get(0)?,
                parent_process_id: row.get(1)?,
                executable: row.get(2)?,
                started_at_ms: row.get(3)?,
                ended_at_ms: row.get(4)?,
                exit_code: row.get(5)?,
                termination_signal: row.get(6)?,
                evidence: row.get(7)?,
            })
        })?
        .collect();
    rows
}

fn query_events(connection: &Connection) -> rusqlite::Result<Vec<EventReport>> {
    let mut statement = connection.prepare(
        "SELECT event_id, category, operation, target, process_id,
                occurred_at_ms, evidence
         FROM event ORDER BY occurred_at_ms, event_id",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok(EventReport {
                event_id: row.get(0)?,
                category: row.get(1)?,
                operation: row.get(2)?,
                target: row.get(3)?,
                process_id: row.get(4)?,
                occurred_at_ms: row.get(5)?,
                evidence: row.get(6)?,
            })
        })?
        .collect();
    rows
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::ReportServer;
    use crate::storage::{SessionOutcome, SessionStore};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            Self(
                std::env::temp_dir()
                    .join(format!("execwake-report-{}-{nonce}", std::process::id())),
            )
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[tokio::test]
    async fn protects_the_report_and_stops_when_idle() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("printf", 2)
            .expect("a session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the session should finalize");
        let server = ReportServer::bind(session, Duration::from_millis(250))
            .expect("the report server should bind");
        let address = server.address();
        assert!(address.ip().is_loopback());
        let open_url = server.open_url();
        let open_path = open_url
            .strip_prefix(&format!("http://{address}"))
            .expect("the open URL should use the bound address")
            .to_owned();
        let mut task = tokio::spawn(server.run());

        let rejected = tokio::select! {
            result = &mut task => panic!("the report server stopped before accepting requests: {result:?}"),
            response = request(address, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n") => response,
        };
        assert!(rejected.starts_with("HTTP/1.1 403 Forbidden"));
        assert!(rejected.contains("content-security-policy:"));
        assert!(!rejected.contains("access-control-allow-origin"));

        let opened = request(
            address,
            &format!("GET {open_path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(opened.starts_with("HTTP/1.1 303 See Other"));
        let cookie = header(&opened, "set-cookie").expect("a token cookie should be set");
        let session_path = header(&opened, "location").expect("a report location should be set");

        let report = request(
            address,
            &format!(
                "GET /api{session_path} HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(report.starts_with("HTTP/1.1 200 OK"));
        assert!(report.contains("\"commandName\":\"printf\""));

        let asset = request(
            address,
            &format!(
                "GET /assets/app.js HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(asset.starts_with("HTTP/1.1 200 OK"));
        assert!(asset.contains("content-type: text/javascript; charset=utf-8"));

        let rejected_origin = request(
            address,
            &format!(
                "GET {session_path} HTTP/1.1\r\nHost: {address}\r\nOrigin: http://example.com\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(rejected_origin.starts_with("HTTP/1.1 403 Forbidden"));

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the report server should stop after its idle timeout")
            .expect("the server task should finish")
            .expect("the report server should stop cleanly");
    }

    async fn request(address: std::net::SocketAddr, request: &str) -> String {
        let request = request.to_owned();
        tokio::task::spawn_blocking(move || request_blocking(address, &request))
            .await
            .expect("the client task should finish")
    }

    fn request_blocking(address: std::net::SocketAddr, request: &str) -> String {
        use std::io::{Read, Write};

        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        let mut connection = loop {
            match std::net::TcpStream::connect(address) {
                Ok(connection) => break connection,
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("the report server should accept a connection: {error}"),
            }
        };
        connection
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("the client timeout should be set");
        connection
            .write_all(request.as_bytes())
            .expect("the request should be written");
        let mut response = Vec::new();
        connection
            .read_to_end(&mut response)
            .expect("the response should be read");
        String::from_utf8(response).expect("the response should be UTF-8")
    }

    fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
        response.lines().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name
                .eq_ignore_ascii_case(name)
                .then_some(value.trim())
        })
    }
}
