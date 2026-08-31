use std::fs;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path as FilePath, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{
    CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, CONTENT_TYPE, COOKIE, HOST, LOCATION,
    ORIGIN, REFERRER_POLICY, SET_COOKIE, TRANSFER_ENCODING, X_CONTENT_TYPE_OPTIONS,
};
use axum::http::{HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::display_text::sanitize;
use crate::session::CURRENT_SCHEMA_VERSION;
use crate::session_input::{canonical_session_file, check_integrity, configure_read_only};
use crate::storage::SessionPaths;

const BODY_LIMIT: usize = crate::limits::REPORT_REQUEST_BYTES;
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
    source: Arc<ReportSource>,
    token: Arc<str>,
    host: Arc<str>,
    origin: Arc<str>,
    activity: Activity,
}

#[derive(Clone)]
enum ReportSource {
    Session(SessionPaths),
    Diff(Box<crate::semantic_diff::SemanticDiff>),
}

impl ReportSource {
    fn route_id(&self) -> &str {
        match self {
            Self::Session(session) => session.id().as_str(),
            Self::Diff(_) => "diff",
        }
    }

    fn location(&self) -> String {
        match self {
            Self::Session(session) => format!("/session/{}", session.id().as_str()),
            Self::Diff(_) => "/diff".to_owned(),
        }
    }
}

pub struct ReportServer {
    listener: TcpListener,
    address: SocketAddr,
    state: AppState,
    idle_timeout: Duration,
}

impl ReportServer {
    pub fn bind(session: SessionPaths, idle_timeout: Duration) -> io::Result<Self> {
        validate_session(&session)?;
        Self::bind_source(ReportSource::Session(session), idle_timeout)
    }

    pub fn bind_diff(before: PathBuf, after: PathBuf, idle_timeout: Duration) -> io::Result<Self> {
        let report = crate::semantic_diff::compare_paths(&before, &after).map_err(server_error)?;
        Self::bind_source(ReportSource::Diff(Box::new(report)), idle_timeout)
    }

    fn bind_source(source: ReportSource, idle_timeout: Duration) -> io::Result<Self> {
        if idle_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "idle timeout must be greater than zero",
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
                source: Arc::new(source),
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
            self.state.source.route_id(),
            self.state.token
        )
    }

    pub async fn run(self) -> io::Result<()> {
        let protected = Router::new()
            .route("/session/:id", get(index))
            .route("/api/session/:id", get(session_api))
            .route("/api/session/:id/events", get(session_events_api))
            .route("/diff", get(diff_index))
            .route("/api/diff", get(diff_api))
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
            .http1_max_buf_size(BODY_LIMIT)
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
    if id != state.source.route_id() || !constant_time_eq(&query.token, &state.token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    state.activity.touch();
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&state.source.location())
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
    match state.source.as_ref() {
        ReportSource::Session(session) if id == session.id().as_str() => {
            Html(REPORT_SHELL).into_response()
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn diff_index(State(state): State<AppState>) -> Response {
    match state.source.as_ref() {
        ReportSource::Diff(_) => Html(REPORT_SHELL).into_response(),
        ReportSource::Session(_) => StatusCode::NOT_FOUND.into_response(),
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
    let database = match state.source.as_ref() {
        ReportSource::Session(session) if id == session.id().as_str() => {
            session.database().to_owned()
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    match tokio::task::spawn_blocking(move || load_report(database)).await {
        Ok(Ok(report)) => Json(report).into_response(),
        Ok(Err(_)) | Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn session_events_api(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(query): Query<EventQuery>,
) -> Response {
    let database = match state.source.as_ref() {
        ReportSource::Session(session) if id == session.id().as_str() => {
            session.database().to_owned()
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    match tokio::task::spawn_blocking(move || load_event_page(database, query)).await {
        Ok(Ok(page)) => Json(page).into_response(),
        Ok(Err(_)) | Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn diff_api(State(state): State<AppState>) -> Response {
    let report = match state.source.as_ref() {
        ReportSource::Diff(report) => report.as_ref().clone(),
        ReportSource::Session(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    Json(report).into_response()
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
    let valid_length = match request.headers().get(CONTENT_LENGTH) {
        Some(value) => value
            .to_str()
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .map_or(false, |length| length <= BODY_LIMIT),
        None => true,
    };
    let valid_encoding = !request.headers().contains_key(TRANSFER_ENCODING);

    let mut response = if !valid_host || !valid_origin {
        StatusCode::FORBIDDEN.into_response()
    } else if !valid_length || !valid_encoding {
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

fn validate_session(session: &SessionPaths) -> io::Result<()> {
    if !is_regular_file(session.database()) || !is_regular_file(session.finalized()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "report session is not finalized",
        ));
    }

    let database = canonical_session_file(session.database())?;
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(server_error)?;
    configure_read_only(&connection).map_err(server_error)?;
    if !check_integrity(&connection).map_err(server_error)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "report session database is corrupt",
        ));
    }
    let (id, schema_version, mode, state, finalized) = connection
        .query_row(
            "SELECT id, schema_version, mode, state, finalized
             FROM session WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .map_err(server_error)?;

    if id != session.id().as_str()
        || schema_version != i64::from(CURRENT_SCHEMA_VERSION)
        || mode != "observe"
        || finalized != 1
        || !matches!(state.as_str(), "finalized" | "interrupted")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "report session metadata is inconsistent",
        ));
    }

    Ok(())
}

fn is_regular_file(path: &FilePath) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
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
    process_count: i64,
    processes: Vec<ProcessReport>,
    event_count: i64,
    timeline_events: Vec<EventReport>,
    finding_count: i64,
    findings: Vec<FindingReport>,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EventQuery {
    #[serde(default)]
    offset: usize,
    category: Option<String>,
    search: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct EventPage {
    offset: usize,
    total: i64,
    events: Vec<EventReport>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct FindingReport {
    finding_id: i64,
    rule_id: String,
    rule_version: i64,
    severity: String,
    process_id: i64,
    subject: String,
    evidence_event_ids: Vec<i64>,
    evidence_truncated: bool,
}

fn load_report(database: PathBuf) -> rusqlite::Result<SessionReport> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    configure_read_only(&connection)?;
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
                command_name: sanitize(&row.get::<_, String>(5)?),
                argument_count: row.get(6)?,
                started_at_ms: row.get(7)?,
                ended_at_ms: row.get(8)?,
                exit_code: row.get(9)?,
                termination_signal: row.get(10)?,
                interruption: row
                    .get::<_, Option<String>>(11)?
                    .map(|value| sanitize(&value)),
                coverage: Vec::new(),
                process_count: 0,
                processes: Vec::new(),
                event_count: 0,
                timeline_events: Vec::new(),
                finding_count: 0,
                findings: Vec::new(),
            })
        },
    )?;

    report.coverage = query_coverage(&connection)?;
    report.process_count = query_count(&connection, "process")?;
    report.processes = query_processes(&connection)?;
    report.event_count = query_event_count(&connection)?;
    report.timeline_events = query_timeline_events(&connection, report.event_count)?;
    report.finding_count = query_count(&connection, "finding")?;
    report.findings = query_findings(&connection)?;
    Ok(report)
}

fn query_coverage(connection: &Connection) -> rusqlite::Result<Vec<CoverageReport>> {
    let mut statement = connection
        .prepare("SELECT category, state, lost_events FROM coverage ORDER BY category")?;
    let rows = statement
        .query_map([], |row| {
            Ok(CoverageReport {
                category: sanitize(&row.get::<_, String>(0)?),
                state: sanitize(&row.get::<_, String>(1)?),
                lost_events: row.get(2)?,
            })
        })?
        .collect();
    rows
}

fn query_processes(connection: &Connection) -> rusqlite::Result<Vec<ProcessReport>> {
    let mut statement = connection.prepare(&format!(
        "SELECT process_id, parent_process_id, executable, started_at_ms,
                ended_at_ms, exit_code, termination_signal, evidence
         FROM process ORDER BY started_at_ms, process_id LIMIT {}",
        crate::limits::REPORT_PROCESS_LIMIT
    ))?;
    let rows = statement
        .query_map([], |row| {
            Ok(ProcessReport {
                process_id: row.get(0)?,
                parent_process_id: row.get(1)?,
                executable: sanitize(&row.get::<_, String>(2)?),
                started_at_ms: row.get(3)?,
                ended_at_ms: row.get(4)?,
                exit_code: row.get(5)?,
                termination_signal: row.get(6)?,
                evidence: sanitize(&row.get::<_, String>(7)?),
            })
        })?
        .collect();
    rows
}

fn query_event_count(connection: &Connection) -> rusqlite::Result<i64> {
    query_count(connection, "event")
}

fn query_count(connection: &Connection, table: &str) -> rusqlite::Result<i64> {
    connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
}

fn query_timeline_events(
    connection: &Connection,
    event_count: i64,
) -> rusqlite::Result<Vec<EventReport>> {
    let limit = i64::try_from(crate::limits::REPORT_TIMELINE_EVENT_LIMIT)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let stride = event_count
        .saturating_add(limit - 1)
        .checked_div(limit)
        .unwrap_or(1)
        .max(1);
    let mut statement = connection.prepare(
        "SELECT event_id, category, operation, target, process_id,
                occurred_at_ms, evidence
         FROM event
         WHERE event_id % ?1 = 0 OR event_id = 1
         ORDER BY occurred_at_ms, event_id
         LIMIT ?2",
    )?;
    let rows = statement
        .query_map([stride, limit], event_report_from_row)?
        .collect();
    rows
}

fn load_event_page(database: PathBuf, query: EventQuery) -> rusqlite::Result<EventPage> {
    let connection = Connection::open_with_flags(
        database,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    configure_read_only(&connection)?;
    let category = match query.category {
        Some(value)
            if !matches!(
                value.as_str(),
                "process" | "filesystem" | "network" | "environment"
            ) =>
        {
            return Err(rusqlite::Error::InvalidQuery)
        }
        value => value,
    };
    let search = query.search.unwrap_or_default();
    let has_search = !search.is_empty();
    let has_category = category.is_some();
    let total = connection.query_row(
        "SELECT COUNT(*) FROM event
         WHERE (?1 = 0 OR category = ?2)
           AND (?3 = 0 OR instr(lower(target), lower(?4)) > 0
                        OR instr(lower(operation), lower(?4)) > 0)",
        rusqlite::params![has_category, category, has_search, search],
        |row| row.get(0),
    )?;
    let offset = query
        .offset
        .min(usize::try_from(total).unwrap_or(usize::MAX));
    let mut statement = connection.prepare(
        "SELECT event_id, category, operation, target, process_id,
                occurred_at_ms, evidence
         FROM event
         WHERE (?1 = 0 OR category = ?2)
           AND (?3 = 0 OR instr(lower(target), lower(?4)) > 0
                        OR instr(lower(operation), lower(?4)) > 0)
         ORDER BY event_id
         LIMIT ?5 OFFSET ?6",
    )?;
    let events = statement
        .query_map(
            rusqlite::params![
                has_category,
                category,
                has_search,
                search,
                i64::try_from(crate::limits::REPORT_EVENT_PAGE_SIZE)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                i64::try_from(offset).map_err(|_| rusqlite::Error::InvalidQuery)?,
            ],
            event_report_from_row,
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(EventPage {
        offset,
        total,
        events,
    })
}

fn event_report_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EventReport> {
    Ok(EventReport {
        event_id: row.get(0)?,
        category: sanitize(&row.get::<_, String>(1)?),
        operation: sanitize(&row.get::<_, String>(2)?),
        target: sanitize(&row.get::<_, String>(3)?),
        process_id: row.get(4)?,
        occurred_at_ms: row.get(5)?,
        evidence: sanitize(&row.get::<_, String>(6)?),
    })
}

fn query_findings(connection: &Connection) -> rusqlite::Result<Vec<FindingReport>> {
    let mut statement = connection.prepare(&format!(
        "SELECT finding_id, rule_id, rule_version, severity, process_id, subject
         FROM finding
         ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                  rule_id, rule_version, process_id, subject
         LIMIT {}",
        crate::limits::REPORT_FINDING_LIMIT
    ))?;
    let rows = statement
        .query_map([], |row| {
            Ok(FindingReport {
                finding_id: row.get(0)?,
                rule_id: sanitize(&row.get::<_, String>(1)?),
                rule_version: row.get(2)?,
                severity: sanitize(&row.get::<_, String>(3)?),
                process_id: row.get(4)?,
                subject: sanitize(&row.get::<_, String>(5)?),
                evidence_event_ids: Vec::new(),
                evidence_truncated: false,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);

    rows.into_iter()
        .map(|mut finding| {
            let mut evidence_statement = connection.prepare(&format!(
                "SELECT event_id FROM finding_evidence
                 WHERE finding_id = ?1 ORDER BY event_id LIMIT {}",
                crate::limits::REPORT_FINDING_EVIDENCE_LIMIT + 1
            ))?;
            let mut evidence_event_ids = evidence_statement
                .query_map([finding.finding_id], |row| row.get(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            finding.evidence_truncated =
                evidence_event_ids.len() > crate::limits::REPORT_FINDING_EVIDENCE_LIMIT;
            evidence_event_ids.truncate(crate::limits::REPORT_FINDING_EVIDENCE_LIMIT);
            finding.evidence_event_ids = evidence_event_ids;
            Ok(finding)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{load_event_page, load_report, EventQuery, ReportServer, BODY_LIMIT};
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

        let oversized = request(
            address,
            &format!(
                "POST / HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                BODY_LIMIT + 1
            ),
        )
        .await;
        assert!(oversized.starts_with("HTTP/1.1 413 Payload Too Large"));

        let chunked = request(
            address,
            &format!(
                "POST / HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n"
            ),
        )
        .await;
        assert!(chunked.starts_with("HTTP/1.1 413 Payload Too Large"));

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
        assert!(report.contains("\"eventCount\":0"));
        assert!(report.contains("\"findings\":[]"));

        let events = request(
            address,
            &format!(
                "GET /api{session_path}/events?offset=0 HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(events.starts_with("HTTP/1.1 200 OK"));
        assert!(events.contains("\"total\":0"));

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

    #[tokio::test]
    async fn serves_a_token_protected_diff_report() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let before = store
            .begin("npm", 2)
            .expect("the first session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the first session should finalize");
        let after = store
            .begin("npm", 2)
            .expect("the second session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the second session should finalize");
        let server = ReportServer::bind_diff(
            before.database().to_owned(),
            after.database().to_owned(),
            Duration::from_millis(200),
        )
        .expect("the diff server should bind");
        fs::remove_file(before.database()).expect("the first session file should be removable");
        fs::remove_file(after.database()).expect("the second session file should be removable");
        let address = server.address();
        let open_path = server
            .open_url()
            .strip_prefix(&format!("http://{address}"))
            .expect("the open URL should use the bound address")
            .to_owned();
        let task = tokio::spawn(server.run());

        let opened = request(
            address,
            &format!("GET {open_path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert!(opened.starts_with("HTTP/1.1 303 See Other"));
        let cookie = header(&opened, "set-cookie").expect("a token cookie should be set");
        assert_eq!(header(&opened, "location"), Some("/diff"));

        let report = request(
            address,
            &format!(
                "GET /api/diff HTTP/1.1\r\nHost: {address}\r\nCookie: {cookie}\r\nConnection: close\r\n\r\n"
            ),
        )
        .await;
        assert!(report.starts_with("HTTP/1.1 200 OK"));
        assert!(report.contains("\"whatChanged\":[\"No comparable finding changes.\"]"));

        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("the diff server should stop after its idle timeout")
            .expect("the diff server task should finish")
            .expect("the diff server should stop cleanly");
    }

    #[test]
    fn rejects_a_database_with_mismatched_session_metadata() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("printf", 0)
            .expect("a session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the session should finalize");
        let connection = rusqlite::Connection::open(session.database())
            .expect("the session database should open");
        connection
            .execute(
                "UPDATE session SET id = 'ffffffffffffffffffffffffffffffff' WHERE singleton = 1",
                [],
            )
            .expect("the session id should be changed");

        assert!(ReportServer::bind(session, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn neutralizes_hostile_report_text_without_changing_raw_evidence() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("fixture", 0)
            .expect("a session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the session should finalize");
        let hostile = format!(
            "<script>alert(1)</script><style>body{{display:none}}</style>\u{1b}]8;;https://example.test\u{7}link\u{1b}]8;;\u{7}\u{202e}{}",
            "x".repeat(20_000)
        );
        let connection = rusqlite::Connection::open(session.database())
            .expect("the session database should open");
        connection
            .execute(
                "INSERT INTO event (
                     category, operation, target, process_id, occurred_at_ms, evidence
                 ) VALUES ('filesystem', 'read', ?1, NULL, 1, 'observed')",
                [&hostile],
            )
            .expect("the hostile event should be stored");
        drop(connection);

        let report = load_report(session.database().to_owned()).expect("the report should load");
        let displayed = &report.timeline_events[0].target;

        assert!(!displayed.contains("<script>"));
        assert!(!displayed.contains("<style>"));
        assert!(!displayed.contains('\u{1b}'));
        assert!(!displayed.contains('\u{202e}'));
        assert!(displayed.contains("\\u{003c}script\\u{003e}"));
        assert!(displayed.contains("[truncated "));

        let connection = rusqlite::Connection::open(session.database())
            .expect("the session database should reopen");
        let raw: String = connection
            .query_row("SELECT target FROM event", [], |row| row.get(0))
            .expect("the raw event should remain available");
        assert_eq!(raw, hostile);
    }

    #[test]
    fn pages_and_filters_large_event_sets() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("fixture", 0)
            .expect("a session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the session should finalize");
        let mut connection = rusqlite::Connection::open(session.database())
            .expect("the session database should open");
        let transaction = connection
            .transaction()
            .expect("an event transaction should start");
        {
            let mut statement = transaction
                .prepare(
                    "INSERT INTO event (
                         category, operation, target, process_id, occurred_at_ms, evidence
                     ) VALUES (?1, ?2, ?3, NULL, ?4, 'observed')",
                )
                .expect("the insert should prepare");
            for index in 0..1_200_i64 {
                let category = if index % 2 == 0 {
                    "filesystem"
                } else {
                    "network"
                };
                statement
                    .execute(rusqlite::params![
                        category,
                        "read",
                        format!("target-{index}"),
                        index
                    ])
                    .expect("the event should be inserted");
            }
        }
        transaction.commit().expect("the events should commit");
        drop(connection);

        let first = load_event_page(
            session.database().to_owned(),
            EventQuery {
                offset: 0,
                category: None,
                search: None,
            },
        )
        .expect("the first event page should load");
        assert_eq!(first.total, 1_200);
        assert_eq!(first.offset, 0);
        assert_eq!(first.events.len(), 500);

        let filtered = load_event_page(
            session.database().to_owned(),
            EventQuery {
                offset: 0,
                category: Some("network".to_owned()),
                search: Some("target-1199".to_owned()),
            },
        )
        .expect("the filtered event page should load");
        assert_eq!(filtered.total, 1);
        assert_eq!(filtered.events[0].target, "target-1199");

        let report = load_report(session.database().to_owned()).expect("the report should load");
        assert_eq!(report.event_count, 1_200);
        assert_eq!(report.timeline_events.len(), 1_200);
    }

    #[test]
    fn bounds_processes_findings_and_evidence_in_the_report_payload() {
        let directory = TestDirectory::new();
        let store = SessionStore::at(directory.0.clone()).expect("storage should be created");
        let session = store
            .begin("fixture", 0)
            .expect("a session should start")
            .finalize(SessionOutcome::exited(0))
            .expect("the session should finalize");
        let mut connection = rusqlite::Connection::open(session.database())
            .expect("the session database should open");
        let transaction = connection
            .transaction()
            .expect("a report fixture transaction should start");
        {
            let mut process_statement = transaction
                .prepare(
                    "INSERT INTO process (
                         process_id, operating_system_id, parent_process_id, executable,
                         started_at_ms, evidence
                     ) VALUES (?1, ?1, NULL, 'fixture', ?1, 'observed')",
                )
                .expect("the process insert should prepare");
            for process_id in 1..=crate::limits::REPORT_PROCESS_LIMIT + 1 {
                let process_id = i64::try_from(process_id).expect("the process id should fit");
                process_statement
                    .execute([process_id])
                    .expect("the process should be inserted");
            }
        }
        {
            let mut event_statement = transaction
                .prepare(
                    "INSERT INTO event (
                         category, operation, target, process_id, occurred_at_ms, evidence
                     ) VALUES ('filesystem', 'read', '/tmp/input', 1, ?1, 'observed')",
                )
                .expect("the event insert should prepare");
            for occurred_at_ms in 1..=crate::limits::REPORT_FINDING_EVIDENCE_LIMIT + 1 {
                event_statement
                    .execute([i64::try_from(occurred_at_ms).expect("the timestamp should fit")])
                    .expect("the event should be inserted");
            }
        }
        {
            let mut finding_statement = transaction
                .prepare(
                    "INSERT INTO finding (
                         rule_id, rule_version, severity, process_id, subject
                     ) VALUES ('EW-FS-001', 1, 'high', 1, ?1)",
                )
                .expect("the finding insert should prepare");
            let mut evidence_statement = transaction
                .prepare("INSERT INTO finding_evidence (finding_id, event_id) VALUES (?1, ?2)")
                .expect("the evidence insert should prepare");
            for index in 0..=crate::limits::REPORT_FINDING_LIMIT {
                finding_statement
                    .execute([format!("subject-{index:05}")])
                    .expect("the finding should be inserted");
                let finding_id = transaction.last_insert_rowid();
                if index == 0 {
                    for event_id in 1..=crate::limits::REPORT_FINDING_EVIDENCE_LIMIT + 1 {
                        evidence_statement
                            .execute(rusqlite::params![
                                finding_id,
                                i64::try_from(event_id).expect("the event id should fit")
                            ])
                            .expect("the finding evidence should be inserted");
                    }
                } else {
                    evidence_statement
                        .execute(rusqlite::params![finding_id, 1_i64])
                        .expect("the finding evidence should be inserted");
                }
            }
        }
        transaction
            .commit()
            .expect("the report fixture should commit");
        drop(connection);

        let report = load_report(session.database().to_owned()).expect("the report should load");
        let first_finding = report
            .findings
            .iter()
            .find(|finding| finding.subject == "subject-00000")
            .expect("the first finding should be present");

        assert_eq!(
            report.process_count,
            i64::try_from(crate::limits::REPORT_PROCESS_LIMIT + 1)
                .expect("the process count should fit")
        );
        assert_eq!(report.processes.len(), crate::limits::REPORT_PROCESS_LIMIT);
        assert_eq!(
            report.finding_count,
            i64::try_from(crate::limits::REPORT_FINDING_LIMIT + 1)
                .expect("the finding count should fit")
        );
        assert_eq!(report.findings.len(), crate::limits::REPORT_FINDING_LIMIT);
        assert_eq!(
            first_finding.evidence_event_ids.len(),
            crate::limits::REPORT_FINDING_EVIDENCE_LIMIT
        );
        assert!(first_finding.evidence_truncated);
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
