mod database;
mod guests;
mod meetings;
mod network;
mod recovery;
mod rooms;
mod security;
mod zoom;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, DefaultBodyLimit, Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use futures_util::{SinkExt, StreamExt};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

type ApiResult<T> = Result<T, ApiError>;
#[derive(Debug)]
struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}
impl From<rusqlite::Error> for ApiError {
    fn from(_: rusqlite::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not save your changes",
        )
    }
}
fn bad(message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message)
}
fn forbidden() -> ApiError {
    ApiError(StatusCode::FORBIDDEN, "This action is not allowed")
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn token_hash(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

#[derive(Clone)]
struct App {
    db: Arc<Mutex<Connection>>,
    live: Arc<Mutex<Live>>,
    origin: String,
    passwords: Arc<Semaphore>,
    attempts: Arc<Mutex<HashMap<String, (i64, u32)>>>,
    operations: Arc<Mutex<()>>,
    connections: Arc<Semaphore>,
    dummy_password: String,
    account_connections: Arc<Mutex<HashMap<String, Weak<Semaphore>>>>,
    queued_bytes: Arc<Semaphore>,
    guests: Arc<Mutex<HashMap<String, guests::Session>>>,
}
#[derive(Default)]
struct Live {
    peers: HashMap<String, Peer>,
    calls: HashMap<String, Call>,
    rooms: HashMap<String, rooms::Room>,
}
struct Peer {
    group_client: Option<String>,
    meeting_moderation: bool,
    raise_hand: bool,
    connection: String,
    session: String,
    tx: mpsc::Sender<QueuedMessage>,
    stop: Arc<Notify>,
}
struct QueuedMessage {
    text: String,
    close: bool,
    // Retained through the write, and released on failure or connection teardown.
    _bytes: OwnedSemaphorePermit,
}
const QUEUED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct Call {
    id: String,
    caller: String,
    callee: String,
    created: i64,
    accepted: bool,
    offer: bool,
    answer: bool,
    candidates: [u16; 2],
}
#[derive(Serialize, Clone)]
struct User {
    id: String,
    username: String,
    display_name: String,
}

fn identity(user: &User) -> Value {
    let mut value = json!(user);
    if user.username.starts_with('~') {
        value["guest"] = json!(true);
        value["scoped_guest"] = json!(false);
    }
    value
}

impl App {
    fn new(path: &str, origin: String) -> Result<Self, rusqlite::Error> {
        let db = database::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL, password TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS discovery_preferences(user_id TEXT PRIMARY KEY REFERENCES users(id), enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)));
            CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS friends(sender TEXT NOT NULL REFERENCES users(id), recipient TEXT NOT NULL REFERENCES users(id), accepted INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL, PRIMARY KEY(sender,recipient), CHECK(sender<>recipient));
            CREATE TABLE IF NOT EXISTS meetings(id TEXT PRIMARY KEY, owner TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL, created INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS meeting_members(meeting_id TEXT NOT NULL REFERENCES meetings(id),user_id TEXT NOT NULL REFERENCES users(id),PRIMARY KEY(meeting_id,user_id));
            CREATE TABLE IF NOT EXISTS meeting_network(meeting_id TEXT PRIMARY KEY REFERENCES meetings(id) ON DELETE CASCADE,visible INTEGER NOT NULL DEFAULT 0 CHECK(visible IN (0,1)));
            CREATE TABLE IF NOT EXISTS meeting_speaking(meeting_id TEXT PRIMARY KEY REFERENCES meetings(id) ON DELETE CASCADE,enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)));
            CREATE TABLE IF NOT EXISTS meeting_controls(meeting_id TEXT NOT NULL,user_id TEXT NOT NULL,is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),moderator_muted INTEGER NOT NULL DEFAULT 0 CHECK(moderator_muted IN (0,1)),PRIMARY KEY(meeting_id,user_id),FOREIGN KEY(meeting_id,user_id) REFERENCES meeting_members(meeting_id,user_id) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS meeting_access(meeting_id TEXT PRIMARY KEY REFERENCES meetings(id),open_invite INTEGER NOT NULL DEFAULT 0 CHECK(open_invite IN (0,1)));
            CREATE TABLE IF NOT EXISTS meeting_blocks(meeting_id TEXT NOT NULL REFERENCES meetings(id),user_id TEXT NOT NULL REFERENCES users(id),PRIMARY KEY(meeting_id,user_id));
            CREATE INDEX IF NOT EXISTS meeting_members_user ON meeting_members(user_id);
            CREATE TABLE IF NOT EXISTS meeting_visits(meeting_id TEXT NOT NULL REFERENCES meetings(id),user_id TEXT NOT NULL REFERENCES users(id),PRIMARY KEY(meeting_id,user_id));
            CREATE INDEX IF NOT EXISTS meeting_visits_user ON meeting_visits(user_id);
            CREATE TABLE IF NOT EXISTS history(id TEXT PRIMARY KEY, caller TEXT NOT NULL REFERENCES users(id), callee TEXT NOT NULL REFERENCES users(id), started INTEGER NOT NULL, ended INTEGER NOT NULL, outcome TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS history_caller ON history(caller,started);
            CREATE INDEX IF NOT EXISTS history_callee ON history(callee,started);
            CREATE INDEX IF NOT EXISTS friends_recipient ON friends(recipient);")?;
        // Keep the two-column roster compatible with earlier server binaries.
        // Import roles if opening a development database with the interim columns.
        let columns = {
            let mut q = db.prepare("PRAGMA table_info(meeting_members)")?;
            let names = q
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()?;
            names
        };
        if columns.iter().any(|c| c == "is_admin") && columns.iter().any(|c| c == "moderator_muted")
        {
            db.execute_batch("INSERT INTO meeting_controls(meeting_id,user_id,is_admin,moderator_muted) SELECT meeting_id,user_id,is_admin,moderator_muted FROM meeting_members WHERE 1 ON CONFLICT(meeting_id,user_id) DO NOTHING;")?;
        }
        db.execute("DELETE FROM sessions WHERE expires < ?1", [now()])?;
        // Zoom-linked rooms have a live roster, not permanent reserved seats.
        db.execute("DELETE FROM meeting_members WHERE meeting_id IN (SELECT id FROM meetings WHERE owner=?1)", [zoom::OWNER])?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            live: Default::default(),
            origin,
            passwords: Arc::new(Semaphore::new(2)),
            attempts: Default::default(),
            operations: Default::default(),
            connections: Arc::new(Semaphore::new(256)),
            account_connections: Default::default(),
            queued_bytes: Arc::new(Semaphore::new(QUEUED_BYTES)),
            guests: Default::default(),
            dummy_password: Argon2::default()
                .hash_password(b"dummy-account-password", &SaltString::generate(&mut OsRng))
                .expect("password hashing available")
                .to_string(),
        })
    }
    fn limited(&self, key: String, limit: u32, seconds: i64) -> bool {
        let mut attempts = self.attempts.lock().unwrap();
        if !attempts.contains_key(&key) && attempts.len() >= 8192 {
            return true;
        }
        let entry = attempts.entry(key).or_insert((now(), 0));
        if now() - entry.0 >= seconds {
            *entry = (now(), 0);
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 > limit
    }
    fn user(&self, headers: &HeaderMap) -> ApiResult<User> {
        let token = headers
            .get("cookie")
            .and_then(|h| h.to_str().ok())
            .and_then(|c| {
                c.split(';')
                    .find_map(|part| part.trim().strip_prefix("pvp_session="))
            })
            .ok_or(ApiError(StatusCode::UNAUTHORIZED, "Please sign in"))?;
        let hash = token_hash(token);
        let db = self.db.lock().unwrap();
        let user = db.query_row("SELECT u.id,u.username,u.display_name FROM users u JOIN sessions s ON s.user_id=u.id WHERE s.token=?1 AND s.expires>?2", params![hash,now()], |r| Ok(User {id:r.get(0)?,username:r.get(1)?,display_name:r.get(2)?})).optional()?.ok_or(ApiError(StatusCode::UNAUTHORIZED, "Please sign in"))?;
        // Slide a valid session after an hour of activity; never revive expired
        // or revoked sessions. WebSocket heartbeats also authenticate here.
        db.execute(
            "UPDATE sessions SET expires=?1 WHERE token=?2 AND expires>?3 AND expires<?4",
            params![now() + 30 * 86400, hash, now(), now() + 30 * 86400 - 3600],
        )?;
        Ok(user)
    }
    fn session_cookie(&self, token: &str) -> String {
        let secure = if self.origin.starts_with("https://") {
            "; Secure"
        } else {
            ""
        };
        format!("pvp_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000{secure}")
    }

    fn participant(&self, headers: &HeaderMap) -> ApiResult<User> {
        match self.user(headers) {
            Ok(user) => Ok(user),
            Err(error) if error.0 == StatusCode::UNAUTHORIZED => guests::user(self, headers),
            Err(error) => Err(error),
        }
    }

    fn session(&self, user: &User) -> ApiResult<Response> {
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.db.lock().unwrap().execute(
            "INSERT INTO sessions VALUES(?1,?2,?3)",
            params![token_hash(&token), user.id, now() + 30 * 86400],
        )?;
        Ok((
            [("set-cookie", self.session_cookie(&token))],
            Json(identity(user)),
        )
            .into_response())
    }

    fn accepted(&self, a: &str, b: &str) -> ApiResult<bool> {
        Ok(self.db.lock().unwrap().query_row("SELECT EXISTS(SELECT 1 FROM friends WHERE accepted=1 AND ((sender=?1 AND recipient=?2) OR (sender=?2 AND recipient=?1)))", params![a,b], |r| r.get(0))?)
    }
    fn connection_permit(&self, user: &str) -> ApiResult<OwnedSemaphorePermit> {
        let mut accounts = self.account_connections.lock().unwrap();
        accounts.retain(|_, limit| limit.strong_count() > 0);
        let limit = accounts
            .get(user)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let limit = Arc::new(Semaphore::new(2));
                accounts.insert(user.to_owned(), Arc::downgrade(&limit));
                limit
            });
        limit.try_acquire_owned().map_err(|_| {
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many connections for this account",
            )
        })
    }
    fn enqueue(&self, tx: &mpsc::Sender<QueuedMessage>, value: Value) -> bool {
        let close = matches!(value["type"].as_str(), Some("replaced" | "signed-out"));
        let text = value.to_string();
        let Ok(bytes) = self
            .queued_bytes
            .clone()
            .try_acquire_many_owned(text.len() as u32)
        else {
            return false;
        };
        tx.try_send(QueuedMessage {
            text,
            close,
            _bytes: bytes,
        })
        .is_ok()
    }
    fn send(&self, user: &str, value: Value) {
        if let Some(peer) = self.live.lock().unwrap().peers.get(user) {
            // Bounded queue: close slow connections rather than lose signaling silently.
            if !self.enqueue(&peer.tx, value) {
                peer.stop.notify_one();
            }
        }
    }
    fn changed(&self, a: &str, b: &str) {
        for id in [a, b] {
            self.send(id, json!({"type":"friends-changed"}));
        }
    }
    fn presence(&self, id: &str) {
        let ids: Vec<String> = {
            let db = self.db.lock().unwrap();
            let mut q = db.prepare("SELECT CASE WHEN sender=?1 THEN recipient ELSE sender END FROM friends WHERE accepted=1 AND (sender=?1 OR recipient=?1)").unwrap();
            let rows = q.query_map([id], |r| r.get(0)).unwrap();
            rows.filter_map(Result::ok).collect()
        };
        for friend in ids {
            self.send(&friend, json!({"type":"friends-changed"}));
        }
    }
    fn end_call(&self, id: &str, outcome: &str) {
        let call = self.live.lock().unwrap().calls.remove(id);
        if let Some(call) = call {
            let outcome = if call.accepted && outcome == "missed" {
                "ended"
            } else {
                outcome
            };
            let result = self.db.lock().unwrap().execute(
                "INSERT OR IGNORE INTO history VALUES(?1,?2,?3,?4,?5,?6)",
                params![
                    call.id,
                    call.caller,
                    call.callee,
                    call.created,
                    now(),
                    outcome
                ],
            );
            if result.is_err() {
                eprintln!("Could not persist call history");
            }
            for peer in [&call.caller, &call.callee] {
                self.send(
                    peer,
                    json!({"type":"call-ended","call_id":call.id,"reason":outcome}),
                );
            }
        }
    }
}

async fn protect(State(app): State<App>, request: axum::extract::Request, next: Next) -> Response {
    let origin = request
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok());
    if ((request.method() != axum::http::Method::GET
        && request.method() != axum::http::Method::HEAD)
        || request.uri().path().ends_with("/api/ws"))
        && origin != Some(app.origin.as_str())
    {
        return security_headers(forbidden().into_response());
    }
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|i| i.0.ip().to_string())
        .unwrap_or_default();
    let key = if ip == "127.0.0.1" || ip == "::1" {
        request
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(&ip)
            .split(',')
            .next_back()
            .unwrap_or(&ip)
            .trim()
            .to_owned()
    } else {
        ip
    };
    let auth = matches!(
        request.uri().path(),
        "/api/login" | "/api/register" | "/api/guest/start" | "/recovery/api/start"
    ) || ((request.uri().path().starts_with("/api/meetings/")
        || request.uri().path().starts_with("/recovery/api/meetings/"))
        && request.uri().path().ends_with("/guest"));
    if app.limited(format!("http:{key}"), 600, 60)
        || (auth && app.limited(format!("auth:{key}"), 30, 900))
        || (request.uri().path() == "/api/zoom" && app.limited(format!("zoom:{key}"), 120, 60))
    {
        return security_headers(
            ApiError(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many attempts. Try again later",
            )
            .into_response(),
        );
    }
    if request.method() != axum::http::Method::GET && !auth {
        if let Ok(user) = app.user(request.headers()) {
            if app.limited(format!("actions:{}", user.id), 60, 60) {
                return security_headers(
                    ApiError(
                        StatusCode::TOO_MANY_REQUESTS,
                        "Too many changes. Try again later",
                    )
                    .into_response(),
                );
            }
        }
    }
    security_headers(next.run(request).await)
}
fn security_headers(mut response: Response) -> Response {
    for (key,value) in [
        ("x-content-type-options","nosniff"),
        ("referrer-policy","no-referrer"),
        ("cache-control","no-store"),
        ("permissions-policy","camera=(self), microphone=(self), display-capture=(self)"),
        ("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    ] { response.headers_mut().insert(key, value.parse().unwrap()); }
    response
}

#[derive(Deserialize)]
struct Credentials {
    username: String,
    password: String,
    #[serde(default)]
    display_name: String,
}
async fn register(State(app): State<App>, Json(input): Json<Credentials>) -> ApiResult<Response> {
    let username = input.username.trim().to_lowercase();
    let display_name = input.display_name.trim().to_owned();
    if !(3..=32).contains(&username.len())
        || !username
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(bad(
            "Use 3–32 letters, numbers, or underscores for your username",
        ));
    }
    if !(10..=128).contains(&input.password.len()) {
        return Err(bad("Use a password between 10 and 128 characters"));
    }
    if display_name.is_empty()
        || display_name.chars().count() > 60
        || display_name.chars().any(char::is_control)
    {
        return Err(bad("Enter a display name of 1–60 characters"));
    }
    let _permit = app.passwords.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Sign-in is busy. Try again shortly",
        )
    })?;
    let password = tokio::task::spawn_blocking(move || {
        let _permit = _permit;
        Argon2::default()
            .hash_password(input.password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|h| h.to_string())
    })
    .await
    .map_err(|_| bad("Try again"))?
    .map_err(|_| bad("Try again"))?;
    let user = User {
        id: Uuid::new_v4().to_string(),
        username,
        display_name,
    };
    let result = app.db.lock().unwrap().execute(
        "INSERT INTO users VALUES(?1,?2,?3,?4)",
        params![user.id, user.username, user.display_name, password],
    );
    match result {
        Ok(_) => app.session(&user),
        Err(rusqlite::Error::SqliteFailure(e, _))
            if e.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            Err(ApiError(
                StatusCode::CONFLICT,
                "That username is already taken",
            ))
        }
        Err(e) => Err(e.into()),
    }
}
async fn login(State(app): State<App>, Json(input): Json<Credentials>) -> ApiResult<Response> {
    if input.username.len() > 32 || input.password.len() > 128 {
        return Err(bad("Invalid credentials"));
    }
    // An account budget complements the IP budget: rotating addresses must
    // not multiply password guesses against the same username. Unknown names
    // use the same gate and normalization, without revealing account existence.
    let username = input.username.trim().to_lowercase();
    if app.limited(format!("login-account:{}", token_hash(&username)), 30, 900) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again later",
        ));
    }
    let found = app
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT id,username,display_name,password FROM users WHERE username=?1",
            [username],
            |r| {
                Ok((
                    User {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        display_name: r.get(2)?,
                    },
                    r.get::<_, String>(3)?,
                ))
            },
        )
        .optional()?;
    let _permit = app.passwords.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Sign-in is busy. Try again shortly",
        )
    })?;
    let dummy_password = app.dummy_password.clone();
    let valid = tokio::task::spawn_blocking(move || {
        let _permit = _permit;
        let hash = found
            .as_ref()
            .map(|f| f.1.as_str())
            .unwrap_or(&dummy_password);
        let parsed = PasswordHash::new(hash).ok()?;
        Argon2::default()
            .verify_password(input.password.as_bytes(), &parsed)
            .ok()?;
        found.map(|(user, _)| user)
    })
    .await
    .map_err(|_| bad("Try again"))?;
    app.session(&valid.ok_or(ApiError(
        StatusCode::UNAUTHORIZED,
        "Username or password is incorrect",
    ))?)
}
async fn me(
    State(app): State<App>,
    headers: HeaderMap,
    axum::extract::Query(options): axum::extract::Query<HashMap<String, String>>,
) -> ApiResult<Response> {
    let user = app.participant(&headers)?;
    if guests::is_guest(&user) {
        return Ok(Json(guests::describe(&app, &user)).into_response());
    }
    let token = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .and_then(|c| {
            c.split(';')
                .find_map(|part| part.trim().strip_prefix("pvp_session="))
        })
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "Please sign in"))?;
    if options.get("renew").is_some_and(|v| v == "1") {
        Ok((
            [
                ("set-cookie", app.session_cookie(token)),
                ("cache-control", "no-store".to_owned()),
            ],
            Json(identity(&user)),
        )
            .into_response())
    } else {
        Ok(([("cache-control", "no-store")], Json(identity(&user))).into_response())
    }
}
async fn logout(State(app): State<App>, headers: HeaderMap) -> ApiResult<Response> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    let token = headers
        .get("cookie")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .split(';')
        .find_map(|c| c.trim().strip_prefix("pvp_session="))
        .unwrap_or("");
    app.db
        .lock()
        .unwrap()
        .execute("DELETE FROM sessions WHERE token=?1", [token_hash(token)])?;
    let live = app.live.lock().unwrap();
    if let Some(peer) = live
        .peers
        .get(&user.id)
        .filter(|p| p.session == token_hash(token))
    {
        let _ = app.enqueue(&peer.tx, json!({"type":"signed-out"}));
        peer.stop.notify_one();
    }
    drop(live);
    Ok((
        [(
            "set-cookie",
            "pvp_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        )],
        Json(json!({"ok":true})),
    )
        .into_response())
}
#[derive(Deserialize)]
struct DiscoveryPreference {
    enabled: bool,
}
async fn discovery_preference(
    State(app): State<App>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let user = app.user(&headers)?;
    let enabled = app
        .db
        .lock()
        .unwrap()
        .query_row(
            "SELECT enabled FROM discovery_preferences WHERE user_id=?1",
            [&user.id],
            |r| r.get::<_, bool>(0),
        )
        .optional()?
        .unwrap_or(true);
    Ok(Json(json!({"enabled":enabled})))
}
async fn save_discovery_preference(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<DiscoveryPreference>,
) -> ApiResult<Json<Value>> {
    let user = app.user(&headers)?;
    app.db.lock().unwrap().execute("INSERT INTO discovery_preferences(user_id,enabled) VALUES(?1,?2) ON CONFLICT(user_id) DO UPDATE SET enabled=excluded.enabled", params![user.id,input.enabled])?;
    Ok(Json(json!({"enabled":input.enabled})))
}
#[derive(Deserialize)]
struct FriendSearch {
    q: String,
}
async fn search_friends(
    State(app): State<App>,
    headers: HeaderMap,
    Query(input): Query<FriendSearch>,
) -> ApiResult<Json<Value>> {
    let user = app.user(&headers)?;
    if app.limited(format!("discovery:{}", user.id), 120, 60) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many searches. Try again later",
        ));
    }
    let prefix = input.q.trim().trim_start_matches('@').to_lowercase();
    if prefix.len() < 2
        || prefix.len() > 32
        || !prefix
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_')
    {
        return Ok(Json(json!([])));
    }
    let db = app.db.lock().unwrap();
    let mut query = db.prepare("SELECT u.id,u.username,u.display_name FROM users u LEFT JOIN discovery_preferences p ON p.user_id=u.id WHERE COALESCE(p.enabled,1)=1 AND u.id<>?1 AND substr(u.username,1,length(?2))=?2 AND NOT EXISTS(SELECT 1 FROM friends f WHERE (f.sender=?1 AND f.recipient=u.id) OR (f.recipient=?1 AND f.sender=u.id)) ORDER BY u.username LIMIT 10")?;
    let users = query
        .query_map(params![user.id, prefix], |r| {
            Ok(User {
                id: r.get(0)?,
                username: r.get(1)?,
                display_name: r.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(json!(users)))
}
async fn friends(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = app.user(&headers)?;
    let db = app.db.lock().unwrap();
    let mut q=db.prepare("SELECT u.id,u.username,u.display_name,f.accepted,f.sender FROM friends f JOIN users u ON u.id=CASE WHEN f.sender=?1 THEN f.recipient ELSE f.sender END WHERE f.sender=?1 OR f.recipient=?1 ORDER BY f.accepted DESC,u.display_name COLLATE NOCASE")?;
    let rows = q.query_map([&user.id], |r| {
        Ok((
            User {
                id: r.get(0)?,
                username: r.get(1)?,
                display_name: r.get(2)?,
            },
            r.get::<_, bool>(3)?,
            r.get::<_, String>(4)?,
        ))
    })?;
    let peers = app.live.lock().unwrap();
    let mut result = Vec::new();
    for row in rows {
        let (friend, accepted, sender) = row?;
        result.push(json!({"id":friend.id,"username":friend.username,"display_name":friend.display_name,"status":if accepted{"accepted"}else if sender==user.id{"sent"}else{"received"},"online":accepted && peers.peers.contains_key(&friend.id),"voice_room":if accepted { rooms::voice_presence(&peers, &friend.id) } else { None }}));
    }
    Ok(Json(json!(result)))
}
#[derive(Deserialize)]
struct FriendRequest {
    username: String,
}
async fn request_friend(
    State(app): State<App>,
    headers: HeaderMap,
    Json(input): Json<FriendRequest>,
) -> ApiResult<Json<Value>> {
    let user = app.user(&headers)?;
    let peer: String = {
        let db = app.db.lock().unwrap();
        let peer = db
            .query_row(
                "SELECT id FROM users WHERE username=?1",
                [input.username.trim().trim_start_matches('@').to_lowercase()],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .ok_or(ApiError(
                StatusCode::NOT_FOUND,
                "No one has that username yet",
            ))?;
        if peer == user.id {
            return Err(bad("You cannot add yourself"));
        }
        let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM friends WHERE (sender=?1 AND recipient=?2) OR (sender=?2 AND recipient=?1))",params![user.id,peer],|r|r.get(0))?;
        if exists {
            return Err(ApiError(
                StatusCode::CONFLICT,
                "A friendship or request already exists",
            ));
        }
        let count: i64 = db.query_row("SELECT count(*) FROM friends WHERE sender=?1 OR recipient=?1 OR sender=?2 OR recipient=?2", params![user.id, peer], |r|r.get(0))?;
        if count >= 500 {
            return Err(bad("Friend list limit reached"));
        }
        db.execute(
            "INSERT INTO friends VALUES(?1,?2,0,?3)",
            params![user.id, peer, now()],
        )?;
        peer
    };
    app.changed(&user.id, &peer);
    Ok(Json(json!({"ok":true})))
}
async fn accept_friend(
    State(app): State<App>,
    headers: HeaderMap,
    Path(peer): Path<String>,
) -> ApiResult<Json<Value>> {
    let user = app.user(&headers)?;
    let changed = app.db.lock().unwrap().execute(
        "UPDATE friends SET accepted=1 WHERE sender=?1 AND recipient=?2 AND accepted=0",
        params![peer, user.id],
    )?;
    if changed == 0 {
        return Err(bad("No incoming request from this person"));
    }
    app.changed(&user.id, &peer);
    Ok(Json(json!({"ok":true})))
}
async fn remove_friend(
    State(app): State<App>,
    headers: HeaderMap,
    Path(peer): Path<String>,
) -> ApiResult<Json<Value>> {
    let _operation = app.operations.lock().unwrap();
    let user = app.user(&headers)?;
    app.db.lock().unwrap().execute(
        "DELETE FROM friends WHERE (sender=?1 AND recipient=?2) OR (sender=?2 AND recipient=?1)",
        params![user.id, peer],
    )?;
    let calls: Vec<_> = app
        .live
        .lock()
        .unwrap()
        .calls
        .values()
        .filter(|c| {
            (c.caller == user.id && c.callee == peer) || (c.callee == user.id && c.caller == peer)
        })
        .map(|c| c.id.clone())
        .collect();
    for call in calls {
        app.end_call(&call, "removed");
    }
    rooms::friend_removed(&app, &user.id, &peer);
    meetings::friend_removed(&app, &user.id, &peer)?;
    app.changed(&user.id, &peer);
    Ok(Json(json!({"ok":true})))
}
async fn history(State(app): State<App>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let user = app.user(&headers)?;
    let db = app.db.lock().unwrap();
    let mut q=db.prepare("SELECT h.id,u.id,u.display_name,h.started,h.ended,h.outcome,h.caller FROM history h JOIN users u ON u.id=CASE WHEN h.caller=?1 THEN h.callee ELSE h.caller END WHERE h.caller=?1 OR h.callee=?1 ORDER BY h.started DESC,h.rowid DESC LIMIT 50")?;
    let rows=q.query_map([&user.id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"peer_id":r.get::<_,String>(1)?,"display_name":r.get::<_,String>(2)?,"started":r.get::<_,i64>(3)?,"ended":r.get::<_,i64>(4)?,"outcome":r.get::<_,String>(5)?,"outgoing":r.get::<_,String>(6)?==user.id})))?;
    Ok(Json(json!(rows.collect::<Result<Vec<_>, _>>()?)))
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum ClientMessage {
    Call {
        peer_id: String,
    },
    Accept {
        call_id: String,
    },
    Decline {
        call_id: String,
    },
    Hangup {
        call_id: String,
    },
    Signal {
        call_id: String,
        payload: Value,
    },
    RoomCapabilities {
        client: String,
        #[serde(default)]
        meeting_moderation: bool,
        #[serde(default)]
        raise_hand: bool,
    },
    MeetingEnter {
        meeting_id: String,
    },
    VoiceOpen,
    VoiceJoin {
        room_id: String,
    },
    RoomCreate {
        peer_ids: Vec<String>,
    },
    RoomJoin {
        room_id: String,
    },
    RoomLeave {
        room_id: String,
    },
    RoomInvite {
        room_id: String,
        peer_id: String,
    },
    RoomSignal {
        room_id: String,
        to: String,
        generation: u8,
        payload: Value,
    },
    Pong,
}
fn handle_message(app: &App, user: &User, message: ClientMessage) -> ApiResult<()> {
    if guests::is_guest(user)
        && !matches!(
            &message,
            ClientMessage::RoomCapabilities { .. }
                | ClientMessage::MeetingEnter { .. }
                | ClientMessage::RoomLeave { .. }
                | ClientMessage::RoomSignal { .. }
                | ClientMessage::Pong
        )
    {
        return Err(forbidden());
    }
    match message {
        ClientMessage::RoomCapabilities {
            client,
            meeting_moderation,
            raise_hand,
        } => {
            if let Some(peer) = app.live.lock().unwrap().peers.get_mut(&user.id) {
                peer.raise_hand = raise_hand;
            }
            return rooms::capabilities(app, user, client, meeting_moderation);
        }
        ClientMessage::MeetingEnter { meeting_id } => {
            return meetings::enter(app, user, meeting_id)
        }
        ClientMessage::VoiceOpen => return rooms::open_voice(app, user),
        ClientMessage::VoiceJoin { room_id } => return rooms::join_voice(app, user, room_id),
        ClientMessage::RoomCreate { peer_ids } => return rooms::create(app, user, peer_ids),
        ClientMessage::RoomJoin { room_id } => return rooms::join(app, user, room_id),
        ClientMessage::RoomLeave { room_id } => {
            rooms::leave(app, &user.id, &room_id)?;
            guests::left(app, &user.id);
            return Ok(());
        }
        ClientMessage::RoomInvite { room_id, peer_id } => {
            return rooms::invite(app, user, room_id, peer_id)
        }
        ClientMessage::RoomSignal {
            room_id,
            to,
            generation,
            payload,
        } => return rooms::signal(app, user, room_id, to, generation, payload),
        ClientMessage::Pong => (),
        ClientMessage::Call { peer_id } => {
            if app.limited(format!("calls:{}", user.id), 20, 60) {
                return Err(ApiError(
                    StatusCode::TOO_MANY_REQUESTS,
                    "Too many calls. Try again later",
                ));
            }
            if !app.accepted(&user.id, &peer_id)? {
                return Err(ApiError(
                    StatusCode::FORBIDDEN,
                    "You can only call accepted friends",
                ));
            }
            let call = Call {
                id: Uuid::new_v4().to_string(),
                caller: user.id.clone(),
                callee: peer_id,
                created: now(),
                accepted: false,
                offer: false,
                answer: false,
                candidates: [0, 0],
            };
            {
                let mut live = app.live.lock().unwrap();
                if rooms::joined(&live, &call.caller)
                    || rooms::joined(&live, &call.callee)
                    || live.calls.values().any(|c| {
                        [&c.caller, &c.callee]
                            .iter()
                            .any(|id| **id == call.caller || **id == call.callee)
                    })
                {
                    return Err(ApiError(
                        StatusCode::CONFLICT,
                        "You or your friend is already in a call",
                    ));
                }
                live.calls.insert(call.id.clone(), call.clone());
            }
            app.send(
                &call.caller,
                json!({"type":"calling","call_id":call.id,"peer_id":call.callee}),
            );
            app.send(
                &call.callee,
                json!({"type":"incoming","call_id":call.id,"peer":user}),
            );
        }
        ClientMessage::Accept { call_id } => {
            let call = {
                let mut live = app.live.lock().unwrap();
                let call = live
                    .calls
                    .get_mut(&call_id)
                    .ok_or(bad("This call has ended"))?;
                if call.callee != user.id || call.accepted || now() - call.created >= 60 {
                    return Err(forbidden());
                }
                call.accepted = true;
                call.clone()
            };
            app.send(&call.caller,json!({"type":"call-accepted","call_id":call.id,"peer_id":call.callee,"initiator":true}));
            app.send(&call.callee,json!({"type":"call-accepted","call_id":call.id,"peer_id":call.caller,"initiator":false}));
        }
        ClientMessage::Decline { call_id } => {
            {
                let live = app.live.lock().unwrap();
                let call = live.calls.get(&call_id).ok_or(bad("This call has ended"))?;
                if call.callee != user.id || call.accepted {
                    return Err(forbidden());
                }
            }
            app.end_call(&call_id, "declined");
        }
        ClientMessage::Hangup { call_id } => {
            {
                let live = app.live.lock().unwrap();
                let call = live.calls.get(&call_id).ok_or(bad("This call has ended"))?;
                if call.caller != user.id && call.callee != user.id {
                    return Err(forbidden());
                }
            }
            app.end_call(&call_id, "ended");
        }
        ClientMessage::Signal { call_id, payload } => {
            if !security::valid_signal(&payload) {
                return Err(bad("Invalid or unencrypted direct-peer signal"));
            }
            let peer = {
                let mut live = app.live.lock().unwrap();
                let call = live
                    .calls
                    .get_mut(&call_id)
                    .ok_or(bad("This call has ended"))?;
                if !call.accepted {
                    return Err(forbidden());
                }
                let index = if call.caller == user.id {
                    0
                } else if call.callee == user.id {
                    1
                } else {
                    return Err(forbidden());
                };
                match payload["type"].as_str().unwrap() {
                    "offer" if index == 0 && !call.offer => call.offer = true,
                    "answer" if index == 1 && call.offer && !call.answer => call.answer = true,
                    "candidate" if call.candidates[index] < 128 => call.candidates[index] += 1,
                    _ => return Err(bad("Unexpected signal or candidate limit exceeded")),
                }
                if index == 0 {
                    call.callee.clone()
                } else {
                    call.caller.clone()
                }
            };
            app.send(
                &peer,
                json!({"type":"signal","call_id":call_id,"payload":payload}),
            );
        }
    }
    Ok(())
}
async fn websocket(
    State(app): State<App>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> ApiResult<Response> {
    let user = app.participant(&headers)?;
    let account_permit = app.connection_permit(&user.id)?;
    let permit = app
        .connections
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "Service is busy"))?;
    Ok(ws
        .max_message_size(65536)
        .max_frame_size(65536)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            let _account_permit = account_permit;
            connection(app, user, headers, socket).await
        }))
}
async fn connection(app: App, user: User, headers: HeaderMap, socket: WebSocket) {
    let id = Uuid::new_v4().to_string();
    let (tx, mut rx) = mpsc::channel(256);
    let stop = Arc::new(Notify::new());
    {
        let _operation = app.operations.lock().unwrap();
        {
            // Authentication may have been revoked while the upgrade was pending.
            if app.participant(&headers).is_err() {
                return;
            }
            let mut live = app.live.lock().unwrap();
            if let Some(previous) = live.peers.insert(
                user.id.clone(),
                Peer {
                    group_client: None,
                    meeting_moderation: false,
                    raise_hand: false,
                    connection: id.clone(),
                    session: headers
                        .get("cookie")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .split(';')
                        .find_map(|c| c.trim().strip_prefix("pvp_session="))
                        .map(token_hash)
                        .unwrap_or_default(),
                    tx: tx.clone(),
                    stop: stop.clone(),
                },
            ) {
                if !app.enqueue(&previous.tx, json!({"type":"replaced"})) {
                    previous.stop.notify_one();
                }
            }
        }
        app.send(
            &user.id,
            json!({"type":"server-capabilities","groupCalls":true,"voiceRooms":true,"permanentMeetings":true,"meetingModeration":true,"raiseHand":true,"openMeetings":true,"guestMeetings":true,"maxGroup":16}),
        );
        rooms::disconnect(&app, &user.id);
        guests::left(&app, &user.id);
        app.presence(&user.id);
        // A new window cannot inherit an established media connection.
        let active: Vec<_> = app
            .live
            .lock()
            .unwrap()
            .calls
            .values()
            .filter(|c| c.accepted && (c.caller == user.id || c.callee == user.id))
            .map(|c| c.id.clone())
            .collect();
        for call in active {
            app.end_call(&call, "disconnected");
        }
        let pending: Vec<_> = app
            .live
            .lock()
            .unwrap()
            .calls
            .values()
            .filter(|c| c.callee == user.id && !c.accepted && now() - c.created < 60)
            .cloned()
            .collect();
        for call in pending {
            let peer = app
                .db
                .lock()
                .unwrap()
                .query_row(
                    "SELECT id,username,display_name FROM users WHERE id=?1",
                    [&call.caller],
                    |r| {
                        Ok(User {
                            id: r.get(0)?,
                            username: r.get(1)?,
                            display_name: r.get(2)?,
                        })
                    },
                )
                .ok();
            app.send(
                &user.id,
                json!({"type":"incoming","call_id":call.id,"peer":peer}),
            );
        }
    }
    let (mut writer, mut reader) = socket.split();
    let mut heartbeat = tokio::time::interval(Duration::from_secs(20));
    let mut last_seen = now();
    let mut window_started = now();
    let mut messages = 0u32;
    loop {
        tokio::select! {
            _=stop.notified()=>break,
            value=rx.recv()=>match value {
                Some(value)=>{if bounded_send(&mut writer, Message::Text(value.text.clone().into())).await.is_err() || value.close {break;}},
                None=>break,
            },
            message=reader.next()=>{
                if now()-window_started>=10 { window_started=now(); messages=0; }
                messages+=1;
                let limit=if rooms::joined(&app.live.lock().unwrap(),&user.id){1024}else{256};
                if messages>limit { break; }
                match message {
                Some(Ok(Message::Text(text)))=>{
                    last_seen=now();
                    // A superseded tab cannot mutate the replacement connection's calls.
                    let _operation = app.operations.lock().unwrap();
                    if !app.live.lock().unwrap().peers.get(&user.id).is_some_and(|p|p.connection==id) {break;}
                    if app.participant(&headers).is_err() { break; }
                    match serde_json::from_str::<ClientMessage>(&text) {
                        Ok(message)=>if let Err(error)=handle_message(&app,&user,message) {if !app.enqueue(&tx,json!({"type":"error","message":error.1})){stop.notify_one();}},
                        Err(_)=>{if !app.enqueue(&tx,json!({"type":"error","message":"Invalid message"})){stop.notify_one();}},
                    }
                },
                Some(Ok(Message::Pong(_)))=>last_seen=now(),
                Some(Ok(Message::Ping(bytes)))=>{if bounded_send(&mut writer, Message::Pong(bytes)).await.is_err(){break;}},
                Some(Ok(Message::Close(_)))|None|Some(Err(_))=>break,
                _=>(),
                }
            },
            _=heartbeat.tick()=>{
                if now()-last_seen>60 || app.participant(&headers).is_err(){break;}
                if bounded_send(&mut writer, Message::Text(json!({"type":"ping"}).to_string().into())).await.is_err(){break;}
            },
        }
    }
    {
        let _operation = app.operations.lock().unwrap();
        let current = {
            let mut live = app.live.lock().unwrap();
            let current = live.peers.get(&user.id).is_some_and(|p| p.connection == id);
            if current {
                live.peers.remove(&user.id);
            }
            current
        };
        if current {
            rooms::disconnect(&app, &user.id);
            guests::left(&app, &user.id);
            let calls: Vec<_> = app
                .live
                .lock()
                .unwrap()
                .calls
                .values()
                .filter(|c| c.caller == user.id || (c.callee == user.id && c.accepted))
                .map(|c| c.id.clone())
                .collect();
            for call in calls {
                app.end_call(&call, "disconnected");
            }
            app.presence(&user.id);
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(3), writer.close()).await;
}

async fn bounded_send<S>(writer: &mut S, message: Message) -> Result<(), ()>
where
    S: futures_util::Sink<Message> + Unpin,
{
    tokio::time::timeout(Duration::from_secs(5), writer.send(message))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

fn router(app: App) -> Router {
    Router::new()
        .merge(recovery::routes())
        .route(
            "/packages/pvp-call/src/index.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../packages/pvp-call/src/index.js"),
                )
            }),
        )
        .route(
            "/packages/pvp-call/src/mesh.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../packages/pvp-call/src/mesh.js"),
                )
            }),
        )
        .route(
            "/packages/pvp-call/src/media.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../packages/pvp-call/src/media.js"),
                )
            }),
        )
        .route(
            "/packages/pvp-call/src/room.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../packages/pvp-call/src/room.js"),
                )
            }),
        )
        .route(
            "/packages/pvp-call/src/security.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../packages/pvp-call/src/security.js"),
                )
            }),
        )
        .route(
            "/packages/pvp-call/src/quality.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../packages/pvp-call/src/quality.js"),
                )
            }),
        )
        .route(
            "/packages/pvp-call/src/inspector.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../packages/pvp-call/src/inspector.js"),
                )
            }),
        )
        .route(
            "/",
            get(|| async {
                if std::env::var("PVP_RECOVERY").as_deref() == Ok("1") {
                    Html(include_str!("../../recovery/index.html"))
                } else {
                    Html(include_str!("../../web/index.html"))
                }
            }),
        )
        .route(
            "/meetings.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/meetings.js"),
                )
            }),
        )
        .route(
            "/ui.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/ui.js"),
                )
            }),
        )
        .route(
            "/polish.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../../web/polish.css"),
                )
            }),
        )
        .route(
            "/icons.svg",
            get(|| async {
                (
                    [("content-type", "image/svg+xml; charset=utf-8")],
                    include_str!("../../web/icons.svg"),
                )
            }),
        )
        .route(
            "/meeting-join.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/meeting-join.js"),
                )
            }),
        )
        .route(
            "/meeting-route.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/meeting-route.js"),
                )
            }),
        )
        .route(
            "/meeting-mobile.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../../web/meeting-mobile.css"),
                )
            }),
        )
        .route(
            "/playback.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/playback.js"),
                )
            }),
        )
        .route(
            "/motion.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/motion.js"),
                )
            }),
        )
        .route(
            "/motion.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../../web/motion.css"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/app.js"),
                )
            }),
        )
        .route(
            "/group-calls.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/group-calls.js"),
                )
            }),
        )
        .route(
            "/meeting-chat.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/meeting-chat.js"),
                )
            }),
        )
        .route(
            "/bandwidth.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/bandwidth.js"),
                )
            }),
        )
        .route(
            "/group-quality.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/group-quality.js"),
                )
            }),
        )
        .route(
            "/group-video.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/group-video.js"),
                )
            }),
        )
        .route(
            "/security.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/security.js"),
                )
            }),
        )
        .route(
            "/trust.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/trust.js"),
                )
            }),
        )
        .route(
            "/media-health.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/media-health.js"),
                )
            }),
        )
        .route(
            "/call-stage.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/call-stage.js"),
                )
            }),
        )
        .route(
            "/inspector.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/inspector.js"),
                )
            }),
        )
        .route(
            "/styles.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../../web/styles.css"),
                )
            }),
        )
        .route(
            "/room-scene.svg",
            get(|| async {
                (
                    [("content-type", "image/svg+xml")],
                    include_bytes!("../../web/room-scene.svg").as_slice(),
                )
            }),
        )
        .route(
            "/fonts/Manrope.ttf",
            get(|| async {
                (
                    [("content-type", "font/ttf")],
                    include_bytes!("../../web/fonts/Manrope.ttf").as_slice(),
                )
            }),
        )
        .route(
            "/fonts/InstrumentSerif-Regular.ttf",
            get(|| async {
                (
                    [("content-type", "font/ttf")],
                    include_bytes!("../../web/fonts/InstrumentSerif-Regular.ttf").as_slice(),
                )
            }),
        )
        .route(
            "/brand-tokens.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../../web/brand-tokens.css"),
                )
            }),
        )
        .route(
            "/icon.svg",
            get(|| async {
                (
                    [("content-type", "image/svg+xml")],
                    include_str!("../../web/icon.svg"),
                )
            }),
        )
        .route(
            "/manifest.webmanifest",
            get(|| async {
                (
                    [("content-type", "application/manifest+json")],
                    include_str!("../../web/manifest.webmanifest"),
                )
            }),
        )
        .route(
            "/health",
            get(|| async {
                Json(
                    json!({"status":"ok","version":env!("CARGO_PKG_VERSION"),"media":"direct-p2p"}),
                )
            }),
        )
        .route("/api/network", get(network::snapshot))
        .route("/api/meetings/{id}/network", post(meetings::set_network))
        .route(
            "/network.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../../web/network.js"),
                )
            }),
        )
        .route(
            "/network.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../../web/network.css"),
                )
            }),
        )
        .route("/api/register", post(register))
        .route("/api/login", post(login))
        .route("/api/logout", post(logout))
        .route("/api/guest/logout", post(guests::logout))
        .route("/api/guest/start", post(guests::start))
        .route("/api/zoom", post(zoom::open))
        .route("/api/me", get(me))
        .route(
            "/api/discovery",
            get(discovery_preference).post(save_discovery_preference),
        )
        .route("/api/friends/search", get(search_friends))
        .route("/api/friends", get(friends))
        .route("/api/friends/request", post(request_friend))
        .route("/api/friends/{peer}/accept", post(accept_friend))
        .route("/api/friends/{peer}", delete(remove_friend))
        .route("/api/meetings", get(meetings::list).post(meetings::create))
        .route("/api/meetings/{id}/preview", get(meetings::preview))
        .route("/api/meetings/{id}/guest", post(guests::create))
        .route(
            "/api/meetings/{id}",
            get(meetings::get).delete(meetings::revoke),
        )
        .route("/api/meetings/{id}/members", post(meetings::add))
        .route(
            "/api/meetings/{id}/members/{peer}",
            delete(meetings::remove),
        )
        .route(
            "/api/meetings/{id}/members/{peer}/admin",
            post(meetings::set_admin),
        )
        .route(
            "/api/meetings/{id}/members/{peer}/mute",
            post(meetings::set_mute),
        )
        .route("/api/meetings/{id}/speaking", post(meetings::set_speaking))
        .route("/api/meetings/{id}/hand", post(meetings::set_hand))
        .route(
            "/api/meetings/{id}/members/{peer}/speak",
            post(meetings::set_speaker),
        )
        .route("/api/history", get(history))
        .route("/api/ws", get(websocket))
        .layer(DefaultBodyLimit::max(16384))
        .layer(middleware::from_fn_with_state(app.clone(), protect))
        .with_state(app)
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let origin = std::env::var("PVP_ORIGIN").unwrap_or_else(|_| "http://localhost:8787".into());
    let path = std::env::var("PVP_DATABASE").unwrap_or_else(|_| "pvp.sqlite".into());
    let bind = std::env::var("PVP_BIND").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let app = App::new(&path, origin.clone())?;
    let cleanup = app.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            cleanup
                .attempts
                .lock()
                .unwrap()
                .retain(|_, (start, _)| now() - *start < 900);
            rooms::expire(&cleanup);
            guests::expire(&cleanup);
            let expired: Vec<_> = cleanup
                .live
                .lock()
                .unwrap()
                .calls
                .values()
                .filter(|c| !c.accepted && now() - c.created >= 60)
                .map(|c| c.id.clone())
                .collect();
            for call in expired {
                cleanup.end_call(&call, "missed");
            }
            let _ = cleanup
                .db
                .lock()
                .unwrap()
                .execute("DELETE FROM sessions WHERE expires<?1", [now()]);
        }
    });
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("PVP signaling on {bind}, origin {origin}. Media travels directly between peers.");
    axum::serve(
        listener,
        router(app).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn discovery_respects_account_preference_and_friendships() {
        let (app, a, b) = fixture();
        let headers_for = |user: &User, token: String| {
            app.db
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO sessions VALUES(?1,?2,?3)",
                    params![token_hash(&token), user.id, now() + 3600],
                )
                .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert("cookie", format!("pvp_session={token}").parse().unwrap());
            headers
        };
        let a_headers = headers_for(&a, "a".repeat(64));
        let b_headers = headers_for(&b, "b".repeat(64));
        let search = || {
            search_friends(
                State(app.clone()),
                a_headers.clone(),
                Query(FriendSearch { q: "@BO".into() }),
            )
        };
        assert_eq!(search().await.unwrap().0[0]["username"], "bob");
        assert!(search_friends(
            State(app.clone()),
            HeaderMap::new(),
            Query(FriendSearch { q: "bo".into() })
        )
        .await
        .is_err());
        let _ = save_discovery_preference(
            State(app.clone()),
            b_headers.clone(),
            Json(DiscoveryPreference { enabled: false }),
        )
        .await
        .unwrap();
        assert_eq!(
            discovery_preference(State(app.clone()), b_headers.clone())
                .await
                .unwrap()
                .0["enabled"],
            false
        );
        assert_eq!(search().await.unwrap().0, json!([]));
        let _ = save_discovery_preference(
            State(app.clone()),
            b_headers,
            Json(DiscoveryPreference { enabled: true }),
        )
        .await
        .unwrap();
        assert_eq!(search().await.unwrap().0.as_array().unwrap().len(), 1);
        app.db
            .lock()
            .unwrap()
            .execute("INSERT INTO friends VALUES('a','b',0,0)", [])
            .unwrap();
        assert_eq!(search().await.unwrap().0, json!([]));
        app.db
            .lock()
            .unwrap()
            .execute("UPDATE friends SET accepted=1", [])
            .unwrap();
        assert_eq!(search().await.unwrap().0, json!([]));
        assert_eq!(
            search_friends(
                State(app.clone()),
                a_headers,
                Query(FriendSearch { q: "b_".into() })
            )
            .await
            .unwrap()
            .0,
            json!([])
        );
    }
    fn fixture() -> (App, User, User) {
        let app = App::new(":memory:", "http://localhost:8787".into()).unwrap();
        let a = User {
            id: "a".into(),
            username: "alice".into(),
            display_name: "Alice".into(),
        };
        let b = User {
            id: "b".into(),
            username: "bob".into(),
            display_name: "Bob".into(),
        };
        for user in [&a, &b] {
            app.db
                .lock()
                .unwrap()
                .execute(
                    "INSERT INTO users VALUES(?1,?2,?3,'hash')",
                    params![user.id, user.username, user.display_name],
                )
                .unwrap();
        }
        (app, a, b)
    }
    #[test]
    fn one_account_cannot_exhaust_connection_capacity() {
        let (app, user, other) = fixture();
        let first = app.connection_permit(&user.id).unwrap();
        let second = app.connection_permit(&user.id).unwrap();
        assert!(app.connection_permit(&user.id).is_err());
        assert!(app.connection_permit(&other.id).is_ok());
        drop(first);
        assert!(app.connection_permit(&user.id).is_ok());
        drop(second);
        assert!(app.connection_permit(&user.id).is_ok());
    }
    #[test]
    fn queued_signaling_has_a_global_byte_budget_and_releases_on_drop() {
        let (app, _, _) = fixture();
        let (tx, rx) = mpsc::channel(256);
        let payload = json!({"sdp":"x".repeat(60000)});
        let size = payload.to_string().len();
        let mut count = 0;
        while app.enqueue(&tx, payload.clone()) {
            count += 1;
        }
        assert!(count < 256);
        assert_eq!(
            app.queued_bytes.available_permits(),
            QUEUED_BYTES - count * size
        );
        drop(rx);
        assert_eq!(app.queued_bytes.available_permits(), QUEUED_BYTES);
        assert!(!app.enqueue(&tx, payload));
        assert_eq!(app.queued_bytes.available_permits(), QUEUED_BYTES);
    }
    #[tokio::test]
    async fn only_explicit_renewal_sets_a_secure_persistent_cookie() {
        let (mut app, user, _) = fixture();
        app.origin = "https://lopixel.space".into();
        let token = "b".repeat(64);
        app.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO sessions VALUES(?1,?2,?3)",
                params![token_hash(&token), user.id, now() + 86400],
            )
            .unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("pvp_session={token}").parse().unwrap());
        let bootstrap = me(
            State(app.clone()),
            headers.clone(),
            axum::extract::Query(HashMap::new()),
        )
        .await
        .unwrap();
        assert!(!bootstrap.headers().contains_key("set-cookie"));
        let renewed = me(
            State(app),
            headers,
            axum::extract::Query(HashMap::from([("renew".into(), "1".into())])),
        )
        .await
        .unwrap();
        let cookie = renewed
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cookie.contains("HttpOnly; SameSite=Strict; Max-Age=2592000; Secure"));
        assert_eq!(renewed.headers().get("cache-control").unwrap(), "no-store");
    }
    #[test]
    fn sessions_slide_with_activity_but_never_revive_expired_or_revoked_tokens() {
        let (app, user, _) = fixture();
        let token = "a".repeat(64);
        let hash = token_hash(&token);
        let mut headers = HeaderMap::new();
        headers.insert("cookie", format!("pvp_session={token}").parse().unwrap());
        app.db
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO sessions VALUES(?1,?2,?3)",
                params![hash, user.id, now() + 60],
            )
            .unwrap();
        assert_eq!(app.user(&headers).unwrap().id, user.id);
        let expires: i64 = app
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT expires FROM sessions WHERE token=?1",
                [&hash],
                |r| r.get(0),
            )
            .unwrap();
        assert!(expires >= now() + 30 * 86400 - 2);
        assert!(app
            .session_cookie(&token)
            .contains("HttpOnly; SameSite=Strict; Max-Age=2592000"));
        app.db
            .lock()
            .unwrap()
            .execute("UPDATE sessions SET expires=?1", [now() - 1])
            .unwrap();
        assert!(app.user(&headers).is_err());
        app.db
            .lock()
            .unwrap()
            .execute("DELETE FROM sessions", [])
            .unwrap();
        assert!(app.user(&headers).is_err());
    }
    #[test]
    fn mutual_acceptance_required_for_call() {
        let (app, a, b) = fixture();
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Call {
                peer_id: b.id.clone()
            }
        )
        .is_err());
        app.db
            .lock()
            .unwrap()
            .execute("INSERT INTO friends VALUES('a','b',0,0)", [])
            .unwrap();
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Call {
                peer_id: b.id.clone()
            }
        )
        .is_err());
        app.db
            .lock()
            .unwrap()
            .execute("UPDATE friends SET accepted=1", [])
            .unwrap();
        assert!(handle_message(&app, &a, ClientMessage::Call { peer_id: b.id }).is_ok());
        assert_eq!(app.live.lock().unwrap().calls.len(), 1);
    }
    #[test]
    fn only_callee_accepts_and_only_participants_signal() {
        let (app, a, b) = fixture();
        app.db
            .lock()
            .unwrap()
            .execute("INSERT INTO friends VALUES('a','b',1,0)", [])
            .unwrap();
        handle_message(
            &app,
            &a,
            ClientMessage::Call {
                peer_id: b.id.clone(),
            },
        )
        .unwrap_or_else(|_| panic!());
        let id = app
            .live
            .lock()
            .unwrap()
            .calls
            .keys()
            .next()
            .unwrap()
            .clone();
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Accept {
                call_id: id.clone()
            }
        )
        .is_err());
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Signal {
                call_id: id.clone(),
                payload: json!({"type":"offer"})
            }
        )
        .is_err());
        assert!(handle_message(
            &app,
            &b,
            ClientMessage::Accept {
                call_id: id.clone()
            }
        )
        .is_ok());
        let stranger = User {
            id: "x".into(),
            username: "x".into(),
            display_name: "X".into(),
        };
        assert!(handle_message(
            &app,
            &stranger,
            ClientMessage::Signal {
                call_id: id.clone(),
                payload: json!({"type":"offer"})
            }
        )
        .is_err());
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Signal {
                call_id: id.clone(),
                payload: json!({"type":"candidate","candidate":"candidate:1 typ relay"})
            }
        )
        .is_err());
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Signal {
                call_id: id,
                payload: json!({"type":"candidate","candidate":{"candidate":"candidate:1 1 udp 2122260223 127.0.0.1 12345 typ host","sdpMid":"0","sdpMLineIndex":0}})
            }
        )
        .is_ok());
    }
    #[test]
    fn expired_calls_cannot_be_accepted_before_cleanup_tick() {
        let (app, a, b) = fixture();
        app.db
            .lock()
            .unwrap()
            .execute("INSERT INTO friends VALUES('a','b',1,0)", [])
            .unwrap();
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Call {
                peer_id: b.id.clone()
            }
        )
        .is_ok());
        let id = {
            let mut live = app.live.lock().unwrap();
            let call = live.calls.values_mut().next().unwrap();
            call.created = now() - 60;
            call.id.clone()
        };
        assert!(handle_message(&app, &b, ClientMessage::Accept { call_id: id }).is_err());
    }
    #[test]
    fn missed_call_persists_and_releases_busy_state() {
        let (app, a, b) = fixture();
        app.db
            .lock()
            .unwrap()
            .execute("INSERT INTO friends VALUES('a','b',1,0)", [])
            .unwrap();
        assert!(handle_message(
            &app,
            &a,
            ClientMessage::Call {
                peer_id: b.id.clone()
            }
        )
        .is_ok());
        assert!(handle_message(&app, &b, ClientMessage::Call { peer_id: a.id }).is_err());
        let id = app
            .live
            .lock()
            .unwrap()
            .calls
            .keys()
            .next()
            .unwrap()
            .clone();
        app.end_call(&id, "missed");
        assert!(app.live.lock().unwrap().calls.is_empty());
        let outcome: String = app
            .db
            .lock()
            .unwrap()
            .query_row("SELECT outcome FROM history", [], |r| r.get(0))
            .unwrap();
        assert_eq!(outcome, "missed");
    }
}
