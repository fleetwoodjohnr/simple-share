//! The HTTPS server phones talk to while sharing is on.
//!
//! Access works like this: the QR code on the computer carries a token that
//! works for one scan. Opening it creates a *pending* device, shows the same
//! 6-digit code on the phone and the computer, and gives the browser a secret
//! cookie; nothing more is possible until the person at the computer allows
//! that device. A device allowed with "Remember" keeps its cookie, and the
//! computer keeps only its SHA-256, so it is let in again in later sessions.
//! Every request must use our exact `name.local:PORT` or `IP:PORT` as its Host
//! (no DNS rebinding), state-changing requests need a custom header (no CSRF),
//! and no CORS headers are ever sent.

use crate::save;
use crate::tls::Ca;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use axum::{Json, Router};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// How long a device may wait for an answer before it is turned away.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
/// `__Host-`: the browser only accepts it from this exact host, over HTTPS.
const COOKIE: &str = "__Host-ss";
/// The longest a browser keeps a cookie (Chrome's cap). Refreshed each session.
const COOKIE_DAYS: u64 = 400;
const CSRF_HEADER: &str = "x-simple-share";

#[derive(Debug, Clone)]
pub struct Config {
    /// Shown on the phone page.
    pub name: String,
    pub dest: PathBuf,
    pub max_upload: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Pending,
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: u64,
    /// "iPhone", "Android phone"… from the User-Agent; only a hint.
    pub label: String,
    pub ip: IpAddr,
    pub status: Status,
    /// Shown on the phone and on the computer while it waits, so the right device is allowed.
    pub code: String,
    /// The `Known` id, for a remembered device.
    pub known: Option<String>,
}

/// A device allowed with "Remember". The app stores these; only the phone has the secret.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Known {
    pub id: String,
    pub label: String,
    /// SHA-256 of the device's cookie secret.
    pub hash: String,
    /// Unix seconds.
    pub added: u64,
    pub last_used: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Offer {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub mime: String,
    #[serde(skip)]
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    DeviceRequest {
        device: Device,
    },
    DeviceExpired {
        id: u64,
    },
    /// Allowed with "Remember": the app should store it.
    Remembered {
        known: Known,
    },
    /// A remembered device connected; no approval was needed.
    Returned {
        device: Device,
    },
    Progress {
        upload: u64,
        device: String,
        name: String,
        done: u64,
        total: u64,
    },
    Saved {
        upload: u64,
        device: String,
        path: PathBuf,
        size: u64,
        sha256: String,
    },
    Failed {
        upload: u64,
        device: String,
        name: String,
        error: String,
    },
    /// Every byte of an offered file went out to the phone. Whether the phone
    /// then kept it is up to the phone.
    Sent {
        offer: String,
        device: String,
        name: String,
    },
}

struct Inner {
    /// `label.local:port`, the address phones normally use.
    local_host: String,
    /// `ip:port`, for phones that cannot look up `.local` names.
    ip_host: String,
    token: Mutex<String>,
    ca_der: Vec<u8>,
    config: Mutex<Config>,
    /// Keyed by cookie secret. Lock order: `devices`, then `known`.
    devices: Mutex<HashMap<String, Device>>,
    known: Mutex<Vec<Known>>,
    offers: Mutex<Vec<Offer>>,
    events: mpsc::UnboundedSender<Event>,
    changed: watch::Sender<bool>, // value: session ended
    last_activity: Mutex<Instant>,
    next_id: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).expect("the OS random number generator failed");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sha256_hex(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn code() -> String {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).expect("the OS random number generator failed");
    let n = u32::from_le_bytes(b) % 1_000_000;
    format!("{:03} {:03}", n / 1000, n % 1000)
}

fn cookie(secret: &str) -> HeaderValue {
    let v = format!("{COOKIE}={secret}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}", COOKIE_DAYS * 86_400);
    HeaderValue::from_str(&v).expect("hex is a valid header value")
}

/// Constant-time comparison for secrets.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The address of the interface that carries the default route. No packet is
/// sent: connecting a UDP socket only picks a route.
pub fn lan_ip() -> Option<IpAddr> {
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("192.0.2.1:9").ok()?;
    s.local_addr().ok().map(|a| a.ip()).filter(|ip| !ip.is_unspecified() && !ip.is_loopback())
}

/// Listen on `ip:port`. macOS lets ordinary apps use ports below 1024 (443)
/// only when listening on every address; `OnlyTo` then turns away connections
/// that were not sent to `ip`, such as over a VPN.
fn listen(ip: IpAddr, port: u16) -> std::io::Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind((ip, port));
    #[cfg(target_os = "macos")]
    if matches!(&listener, Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied) {
        let any: IpAddr = if ip.is_ipv4() { std::net::Ipv4Addr::UNSPECIFIED.into() } else { std::net::Ipv6Addr::UNSPECIFIED.into() };
        return std::net::TcpListener::bind((any, port));
    }
    listener
}

/// Drops connections that did not arrive at the shared address, before TLS.
#[derive(Clone, Copy)]
struct OnlyTo(IpAddr);

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for OnlyTo {
    type Stream = tokio::net::TcpStream;
    type Service = S;
    type Future = std::future::Ready<std::io::Result<(Self::Stream, S)>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let to_us = stream.local_addr().is_ok_and(|a| a.ip() == self.0);
        std::future::ready(if to_us { Ok((stream, service)) } else { Err(std::io::ErrorKind::PermissionDenied.into()) })
    }
}

/// A running share session. Dropping it does not stop the server; call `stop`.
pub struct Share {
    inner: Arc<Inner>,
    handle: axum_server::Handle,
    pub addr: SocketAddr,
}

impl Share {
    /// Start serving on `ip:port` as `label.local`, letting in the `known`
    /// devices without asking. Returns the session and its event stream.
    pub fn start(
        ca: &Ca,
        ip: IpAddr,
        port: u16,
        config: Config,
        known: Vec<Known>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<Event>), Error> {
        let tls = ca.server_config(ip)?;
        let listener = listen(ip, port)?;
        listener.set_nonblocking(true)?;
        let addr = SocketAddr::new(ip, listener.local_addr()?.port());
        // Browsers leave out the standard HTTPS port, in the address and in Host.
        let host = |h: String| h.strip_suffix(":443").map_or(h.clone(), str::to_owned);
        let (events, rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            local_host: host(format!("{}:{}", crate::tls::local_name(ca.label()), addr.port())),
            ip_host: host(addr.to_string()),
            token: Mutex::new(random_hex(16)),
            ca_der: ca.der.clone(),
            config: Mutex::new(config),
            devices: Mutex::new(HashMap::new()),
            known: Mutex::new(known),
            offers: Mutex::new(Vec::new()),
            events,
            changed: watch::channel(false).0,
            last_activity: Mutex::new(Instant::now()),
            next_id: AtomicU64::new(1),
        });
        let app = router(inner.clone());
        let handle = axum_server::Handle::new();
        let tls =
            axum_server::tls_rustls::RustlsAcceptor::new(axum_server::tls_rustls::RustlsConfig::from_config(tls)).acceptor(OnlyTo(ip));
        let server = axum_server::from_tcp(listener).acceptor(tls).handle(handle.clone());
        tokio::spawn(async move {
            if let Err(e) = server.serve(app.into_make_service_with_connect_info::<SocketAddr>()).await {
                tracing::error!(error = %e, "share server stopped");
            }
        });
        Ok((Self { inner, handle, addr }, rx))
    }

    /// What the QR code encodes. The token inside works for one scan.
    pub fn join_url(&self) -> String {
        format!("https://{}/j/{}", self.inner.local_host, lock(&self.inner.token))
    }

    /// The same, by IP address, for phones that cannot look up `.local` names.
    pub fn ip_join_url(&self) -> String {
        format!("https://{}/j/{}", self.inner.ip_host, lock(&self.inner.token))
    }

    /// Answer a waiting device. With `remember`, it is let in without asking
    /// from now on, and `Event::Remembered` carries what to store.
    pub fn decide(&self, id: u64, allow: bool, remember: bool) {
        let mut devices = lock(&self.inner.devices);
        let Some((secret, d)) = devices.iter_mut().find(|(_, d)| d.id == id && d.status == Status::Pending) else { return };
        d.status = if allow { Status::Allowed } else { Status::Denied };
        let known = (allow && remember).then(|| Known {
            id: random_hex(8),
            label: d.label.clone(),
            hash: sha256_hex(secret),
            added: now(),
            last_used: now(),
        });
        d.known = known.as_ref().map(|k| k.id.clone());
        drop(devices);
        if let Some(known) = known {
            lock(&self.inner.known).push(known.clone());
            let _ = self.inner.events.send(Event::Remembered { known });
        }
        self.inner.changed.send_modify(|_| ());
    }

    /// Turn away a device that was allowed earlier, and forget it if it was
    /// remembered. Returns the `Known` id that was forgotten.
    pub fn revoke(&self, id: u64) -> Option<String> {
        let mut devices = lock(&self.inner.devices);
        let known = devices.values().find(|d| d.id == id).and_then(|d| d.known.clone());
        devices.retain(|_, d| d.id != id);
        drop(devices);
        if let Some(k) = &known {
            lock(&self.inner.known).retain(|x| &x.id != k);
        }
        self.inner.changed.send_modify(|_| ());
        known
    }

    /// Replace the remembered devices. Connected devices that are no longer
    /// on the list lose access at once.
    pub fn set_known(&self, known: Vec<Known>) {
        let ids: Vec<String> = known.iter().map(|k| k.id.clone()).collect();
        *lock(&self.inner.known) = known;
        lock(&self.inner.devices).retain(|_, d| d.known.as_ref().is_none_or(|k| ids.contains(k)));
        self.inner.changed.send_modify(|_| ());
    }

    pub fn devices(&self) -> Vec<Device> {
        let mut v: Vec<_> = lock(&self.inner.devices).values().cloned().collect();
        v.sort_by_key(|d| d.id);
        v
    }

    /// Make a file on this computer available to allowed devices.
    pub fn offer(&self, path: PathBuf) -> std::io::Result<Offer> {
        let meta = std::fs::metadata(&path)?;
        if !meta.is_file() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "only files can be shared"));
        }
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let offer = Offer { id: random_hex(8), mime: mime_for(&name).into(), name, size: meta.len(), path };
        lock(&self.inner.offers).push(offer.clone());
        self.inner.changed.send_modify(|_| ());
        Ok(offer)
    }

    pub fn withdraw(&self, id: &str) {
        lock(&self.inner.offers).retain(|o| o.id != id);
        self.inner.changed.send_modify(|_| ());
    }

    pub fn offers(&self) -> Vec<Offer> {
        lock(&self.inner.offers).clone()
    }

    pub fn set_config(&self, config: Config) {
        *lock(&self.inner.config) = config;
        self.inner.changed.send_modify(|_| ());
    }

    /// Time since a phone last made any request.
    pub fn idle(&self) -> Duration {
        lock(&self.inner.last_activity).elapsed()
    }

    /// End the session: phones are told, every cookie stops working, the port closes.
    pub fn stop(&self) {
        lock(&self.inner.devices).clear();
        self.inner.changed.send_replace(true);
        self.handle.graceful_shutdown(Some(Duration::from_secs(2)));
    }
}

fn router(inner: Arc<Inner>) -> Router {
    Router::new()
        .route("/", get(|| async { asset(include_str!("../web/index.html"), "text/html; charset=utf-8") }))
        .route("/app.js", get(|| async { asset(include_str!("../web/app.js"), "text/javascript; charset=utf-8") }))
        .route("/app.css", get(|| async { asset(include_str!("../web/app.css"), "text/css; charset=utf-8") }))
        .route("/icon.svg", get(|| async { asset(include_str!("../web/icon.svg"), "image/svg+xml") }))
        .route("/ca.cer", get(ca_cert))
        .route("/j/{token}", get(join))
        .route("/api/state", get(state))
        .route("/api/events", get(events))
        .route("/api/upload", put(upload))
        .route("/api/files/{id}", get(download))
        .layer(middleware::from_fn_with_state(inner.clone(), guard))
        .with_state(inner)
}

/// Runs on every request: Host check, remembered devices, activity time,
/// security headers.
async fn guard(State(s): State<Arc<Inner>>, req: Request, next: Next) -> Response {
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let local = host == s.local_host;
    if !local && host != s.ip_host {
        return (StatusCode::MISDIRECTED_REQUEST, "Wrong address.").into_response();
    }
    *lock(&s.last_activity) = Instant::now();
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let returned = peer.and_then(|ip| let_in_remembered(&s, req.headers(), ip));
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    if let Some(secret) = returned {
        h.append(header::SET_COOKIE, cookie(&secret));
    }
    if local {
        // Browsers ignore this over a connection with a certificate warning and
        // for IP addresses, so it only binds phones that verified us (paired):
        // for them, a forged certificate becomes a hard stop with no "continue".
        h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    }
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; \
             form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    resp
}

fn asset(body: &'static str, kind: &'static str) -> Response {
    ([(header::CONTENT_TYPE, kind)], body).into_response()
}

async fn ca_cert(State(s): State<Arc<Inner>>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/x-x509-ca-cert"), (header::CONTENT_DISPOSITION, "attachment; filename=\"Simple-Share.cer\"")],
        s.ca_der.clone(),
    )
        .into_response()
}

fn cookie_secret(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .find_map(|kv| kv.trim().strip_prefix(&format!("{COOKIE}=")).map(str::to_string))
}

/// A remembered device's first request this session: let it in as allowed.
/// Returns its secret, so the cookie's lifetime can be renewed.
fn let_in_remembered(s: &Inner, headers: &HeaderMap, ip: IpAddr) -> Option<String> {
    let secret = cookie_secret(headers)?;
    let mut devices = lock(&s.devices);
    if devices.keys().any(|k| same(k, &secret)) {
        return None;
    }
    let hash = sha256_hex(&secret);
    let mut known = lock(&s.known);
    let k = known.iter_mut().find(|k| same(&k.hash, &hash))?;
    k.last_used = now();
    let d = Device {
        id: s.next_id.fetch_add(1, Ordering::Relaxed),
        label: k.label.clone(),
        ip,
        status: Status::Allowed,
        code: String::new(),
        known: Some(k.id.clone()),
    };
    drop(known);
    devices.insert(secret.clone(), d.clone());
    drop(devices);
    let _ = s.events.send(Event::Returned { device: d });
    s.changed.send_modify(|_| ());
    Some(secret)
}

fn device(s: &Inner, headers: &HeaderMap) -> Option<Device> {
    let secret = cookie_secret(headers)?;
    let devices = lock(&s.devices);
    devices.iter().find(|(k, _)| same(k, &secret)).map(|(_, d)| d.clone())
}

fn allowed(s: &Inner, headers: &HeaderMap) -> Result<Device, (StatusCode, &'static str)> {
    match device(s, headers) {
        Some(d) if d.status == Status::Allowed => Ok(d),
        Some(_) => Err((StatusCode::FORBIDDEN, "Not allowed yet.")),
        None => Err((StatusCode::UNAUTHORIZED, "Scan the code on the computer.")),
    }
}

fn label(headers: &HeaderMap) -> String {
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let kind = [
        ("iPhone", "iPhone"),
        ("iPad", "iPad"),
        ("Android", "Android device"),
        ("Macintosh", "Mac or iPad"),
        ("Windows", "Windows PC"),
        ("CrOS", "Chromebook"),
        ("Linux", "Linux computer"),
    ]
    .iter()
    .find(|(k, _)| ua.contains(k))
    .map_or("Browser", |(_, v)| v);
    kind.to_string()
}

async fn join(
    State(s): State<Arc<Inner>>,
    Path(token): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let home = [(header::LOCATION, HeaderValue::from_static("/"))];
    match device(&s, &headers) {
        Some(d) if d.status != Status::Denied => return (StatusCode::SEE_OTHER, home).into_response(),
        // Denied earlier: a fresh scan asks again, as a new device.
        Some(d) => lock(&s.devices).retain(|_, x| x.id != d.id),
        None => {}
    }
    {
        // One scan per code: whoever opens it first uses it up, and the
        // computer shows a new one. A photo of the screen is worthless.
        let mut current = lock(&s.token);
        if !same(&token, &current) {
            return (StatusCode::NOT_FOUND, "This code has been used. Scan the code on the computer again.").into_response();
        }
        *current = random_hex(16);
    }
    let secret = random_hex(32);
    let d = Device {
        id: s.next_id.fetch_add(1, Ordering::Relaxed),
        label: label(&headers),
        ip: peer.ip(),
        status: Status::Pending,
        code: code(),
        known: None,
    };
    lock(&s.devices).insert(secret.clone(), d.clone());
    let _ = s.events.send(Event::DeviceRequest { device: d.clone() });
    s.changed.send_modify(|_| ());
    // Unanswered requests are turned away.
    let s2 = s.clone();
    tokio::spawn(async move {
        tokio::time::sleep(APPROVAL_TIMEOUT).await;
        let mut devices = lock(&s2.devices);
        if let Some(dev) = devices.values_mut().find(|x| x.id == d.id && x.status == Status::Pending) {
            dev.status = Status::Denied;
            drop(devices);
            let _ = s2.events.send(Event::DeviceExpired { id: d.id });
            s2.changed.send_modify(|_| ());
        }
    });
    let mut resp = (StatusCode::SEE_OTHER, home).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie(&secret));
    resp
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StateView {
    name: String,
    status: Status,
    /// While pending: the code the computer shows too.
    code: Option<String>,
    remembered: bool,
    offers: Vec<Offer>,
    max_upload: u64,
}

async fn state(State(s): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    let Some(d) = device(&s, &headers) else {
        return (StatusCode::UNAUTHORIZED, "Scan the code on the computer.").into_response();
    };
    let cfg = lock(&s.config).clone();
    let offers = if d.status == Status::Allowed { lock(&s.offers).clone() } else { Vec::new() };
    Json(StateView {
        name: cfg.name,
        status: d.status,
        code: (d.status == Status::Pending).then_some(d.code),
        remembered: d.known.is_some(),
        offers,
        max_upload: cfg.max_upload,
    })
    .into_response()
}

/// Server-sent events: "changed" whenever the phone should refetch its state,
/// "ended" when the session stops.
async fn events(State(s): State<Arc<Inner>>, headers: HeaderMap) -> Response {
    if device(&s, &headers).is_none() {
        return (StatusCode::UNAUTHORIZED, "Scan the code on the computer.").into_response();
    }
    let rx = s.changed.subscribe();
    let stream = futures_util::stream::unfold(Some((rx, true)), |st| async move {
        let (mut rx, first) = st?;
        if !first && rx.changed().await.is_err() {
            return None;
        }
        let ended = *rx.borrow_and_update();
        let ev = SseEvent::default().data(if ended { "ended" } else { "changed" });
        Some((Ok::<_, std::convert::Infallible>(ev), (!ended).then_some((rx, false))))
    });
    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

#[derive(Deserialize)]
struct UploadQuery {
    name: String,
}

/// Deletes a partial upload unless it was finished.
struct Partial(Option<PathBuf>);
impl Drop for Partial {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

async fn upload(State(s): State<Arc<Inner>>, headers: HeaderMap, Query(q): Query<UploadQuery>, body: Body) -> Response {
    let d = match allowed(&s, &headers) {
        Ok(d) => d,
        Err(r) => return r.into_response(),
    };
    if headers.get(CSRF_HEADER).is_none() {
        return (StatusCode::FORBIDDEN, "Missing request header.").into_response();
    }
    let Some(total) = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok()).and_then(|v| v.parse::<u64>().ok()) else {
        return (StatusCode::LENGTH_REQUIRED, "Missing file size.").into_response();
    };
    let cfg = lock(&s.config).clone();
    if total > cfg.max_upload {
        return (StatusCode::PAYLOAD_TOO_LARGE, "This file is larger than the computer accepts.").into_response();
    }
    let name = save::safe_file_name(&q.name).unwrap_or_else(|| "file".into());
    let id = s.next_id.fetch_add(1, Ordering::Relaxed);
    let fail = |code: StatusCode, error: String| {
        let _ = s.events.send(Event::Failed { upload: id, device: d.label.clone(), name: name.clone(), error: error.clone() });
        (code, error).into_response()
    };
    if let Err(e) = tokio::fs::create_dir_all(&cfg.dest).await {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, format!("The receive folder is not available: {e}"));
    }
    let tmp = cfg.dest.join(format!(".simple-share-partial-{}", random_hex(8)));
    let mut guard = Partial(Some(tmp.clone()));
    let mut file = match tokio::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).await {
        Ok(f) => f,
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not create the file: {e}")),
    };
    let mut hash = Sha256::new();
    let mut done = 0u64;
    let mut last = Instant::now();
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return fail(StatusCode::BAD_REQUEST, "The upload was interrupted.".into());
        };
        done += chunk.len() as u64;
        if done > total {
            return fail(StatusCode::BAD_REQUEST, "The upload was longer than announced.".into());
        }
        hash.update(&chunk);
        if let Err(e) = file.write_all(&chunk).await {
            let code = if e.raw_os_error() == Some(28) { StatusCode::INSUFFICIENT_STORAGE } else { StatusCode::INTERNAL_SERVER_ERROR };
            return fail(code, format!("Could not save: {e}"));
        }
        if last.elapsed() > Duration::from_millis(250) {
            last = Instant::now();
            *lock(&s.last_activity) = last;
            let _ = s.events.send(Event::Progress { upload: id, device: d.label.clone(), name: name.clone(), done, total });
        }
    }
    if done != total {
        return fail(StatusCode::BAD_REQUEST, "The upload ended early.".into());
    }
    // On disk for real before anyone is told it is saved.
    if let Err(e) = file.sync_all().await {
        return fail(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not save: {e}"));
    }
    drop(file);
    let dest = cfg.dest.clone();
    let final_name = name.clone();
    let tmp2 = tmp.clone();
    let path = match tokio::task::spawn_blocking(move || save::finalize(&tmp2, &dest, &final_name)).await {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => return fail(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not save: {e}")),
        Err(e) => return fail(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    guard.0 = None;
    let sha256 = format!("{:x}", hash.finalize());
    let _ = s.events.send(Event::Saved { upload: id, device: d.label, path: path.clone(), size: done, sha256: sha256.clone() });
    let saved_as = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Json(serde_json::json!({ "name": saved_as, "size": done, "sha256": sha256 })).into_response()
}

async fn download(State(s): State<Arc<Inner>>, Path(id): Path<String>, headers: HeaderMap) -> Response {
    let d = match allowed(&s, &headers) {
        Ok(d) => d,
        Err(r) => return r.into_response(),
    };
    let Some(offer) = lock(&s.offers).iter().find(|o| same(&o.id, &id)).cloned() else {
        return (StatusCode::NOT_FOUND, "This file is no longer shared.").into_response();
    };
    let file = match tokio::fs::File::open(&offer.path).await {
        Ok(f) => f,
        Err(_) => return (StatusCode::GONE, "This file is no longer on the computer.").into_response(),
    };
    let done = Event::Sent { offer: offer.id.clone(), device: d.label, name: offer.name.clone() };
    if offer.size == 0 {
        let _ = s.events.send(done.clone());
    }
    // "Sent" fires as the last byte is handed to the connection. (hyper stops
    // polling once Content-Length is reached, so this cannot wait for the end.)
    let (events, total) = (s.events.clone(), offer.size);
    let mut handed = 0u64;
    let body = tokio_util::io::ReaderStream::new(file).inspect(move |chunk| {
        if let Ok(c) = chunk {
            handed += c.len() as u64;
            if handed == total {
                let _ = events.send(done.clone());
            }
        }
    });
    let disposition = format!("attachment; filename=\"{}\"; filename*=UTF-8''{}", ascii_fallback(&offer.name), pct_encode(&offer.name));
    let mut resp = Body::from_stream(body).into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_str(&offer.mime).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(offer.size));
    if let Ok(v) = HeaderValue::from_str(&disposition) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

fn ascii_fallback(name: &str) -> String {
    name.chars().map(|c| if c.is_ascii_graphic() && c != '"' && c != '\\' || c == ' ' { c } else { '_' }).collect()
}

/// RFC 5987 percent-encoding for `filename*`.
fn pct_encode(name: &str) -> String {
    name.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

fn mime_for(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "heif" => "image/heif",
        "mov" => "video/quicktime",
        "mp4" | "m4v" => "video/mp4",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    //! Real HTTPS on 127.0.0.1 as `testlabel.local`, with a client that trusts only our CA.
    use super::*;
    use reqwest::header::{CONTENT_LENGTH, HOST};

    const LABEL: &str = "testlabel";

    struct Fixture {
        share: Share,
        events: mpsc::UnboundedReceiver<Event>,
        ca: Ca,
        dest: PathBuf,
        base: String,
    }

    fn root(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("simple-share-srv-{tag}-{}", std::process::id()))
    }

    fn start(ca: Ca, dest: PathBuf, max_upload: u64, known: Vec<Known>) -> Fixture {
        let cfg = Config { name: "Test PC".into(), dest: dest.clone(), max_upload };
        let (share, events) = Share::start(&ca, "127.0.0.1".parse().expect("ip"), 0, cfg, known).expect("start");
        let base = format!("https://{LABEL}.local:{}", share.addr.port());
        Fixture { share, events, ca, dest, base }
    }

    fn fixture(tag: &str, max_upload: u64) -> Fixture {
        let root = root(tag);
        let _ = std::fs::remove_dir_all(&root);
        let ca = Ca::create(&root.join("ca"), LABEL).expect("ca");
        start(ca, root.join("in"), max_upload, Vec::new())
    }

    fn builder(f: &Fixture) -> reqwest::ClientBuilder {
        reqwest::Client::builder()
            .use_rustls_tls()
            .tls_built_in_root_certs(false)
            .add_root_certificate(reqwest::Certificate::from_der(&f.ca.der).expect("cert"))
            // Stands in for mDNS: the port comes from the URL.
            .resolve(&format!("{LABEL}.local"), f.share.addr)
            .cookie_store(true)
    }

    fn client(f: &Fixture) -> reqwest::Client {
        builder(f).build().expect("client")
    }

    /// Scan the QR code: returns the device the computer was asked about.
    async fn join(f: &mut Fixture, c: &reqwest::Client) -> Device {
        let r = c.get(f.share.join_url()).send().await.expect("join");
        assert_eq!(r.status(), 200, "redirected to the page");
        match f.events.recv().await {
            Some(Event::DeviceRequest { device }) => device,
            other => panic!("expected a device request, got {other:?}"),
        }
    }

    async fn state(c: &reqwest::Client, f: &Fixture) -> (u16, serde_json::Value) {
        let r = c.get(format!("{}/api/state", f.base)).send().await.expect("state");
        let code = r.status().as_u16();
        (code, r.json().await.unwrap_or_default())
    }

    async fn put(c: &reqwest::Client, f: &Fixture, name: &str, body: Vec<u8>) -> reqwest::Response {
        c.put(format!("{}/api/upload", f.base)).query(&[("name", name)]).header(CSRF_HEADER, "1").body(body).send().await.expect("put")
    }

    fn partials(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir).map(|d| d.flatten().filter(|e| e.file_name().to_string_lossy().contains("partial")).count()).unwrap_or(0)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn strangers_get_nothing() {
        let f = fixture("strangers", 1 << 20);
        let c = client(&f);
        assert_eq!(state(&c, &f).await.0, 401);
        assert_eq!(c.get(format!("{}/j/{}", f.base, "0".repeat(32))).send().await.expect("join").status(), 404);
        let wrong_host = c.get(format!("{}/", f.base)).header(HOST, "attacker.example").send().await.expect("rebind");
        assert_eq!(wrong_host.status(), 421, "DNS rebinding is refused");
        assert_eq!(put(&c, &f, "a.txt", b"x".to_vec()).await.status(), 401);
        let page = c.get(format!("{}/", f.base)).send().await.expect("page");
        let h = page.headers();
        let csp = h.get("content-security-policy").expect("csp").to_str().expect("str").to_string();
        assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
        assert_eq!(h.get("referrer-policy").expect("referrer"), "no-referrer");
        assert_eq!(h.get("strict-transport-security").expect("hsts"), "max-age=31536000");
        assert_eq!(h.get("cross-origin-resource-policy").expect("corp"), "same-origin");
        assert!(h.get("access-control-allow-origin").is_none());

        // The IP address works too, without HSTS (browsers ignore it for IPs).
        let by_ip = c.get(format!("https://{}/", f.share.addr)).send().await.expect("ip");
        assert_eq!(by_ip.status(), 200);
        assert!(by_ip.headers().get("strict-transport-security").is_none());
        f.share.stop();
    }

    #[tokio::test]
    async fn connections_to_other_addresses_are_dropped() {
        use axum_server::accept::Accept;
        // Listening on every address, as on macOS for port 443; the share is on 127.0.0.1.
        let l = tokio::net::TcpListener::bind("0.0.0.0:0").await.expect("bind");
        let port = l.local_addr().expect("addr").port();
        for (to, ok) in [("127.0.0.1", true), ("127.0.0.2", false)] {
            let _c = tokio::net::TcpStream::connect((to, port)).await.expect("connect");
            let (s, _) = l.accept().await.expect("accept");
            assert_eq!(OnlyTo("127.0.0.1".parse().expect("ip")).accept(s, ()).await.is_ok(), ok, "{to}");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn tls_1_2_is_refused() {
        let f = fixture("tls12", 1 << 20);
        let old = builder(&f).max_tls_version(reqwest::tls::Version::TLS_1_2).build().expect("client");
        assert!(old.get(format!("{}/", f.base)).send().await.is_err(), "TLS 1.3 only");
        assert_eq!(client(&f).get(format!("{}/", f.base)).send().await.expect("1.3").status(), 200);
        f.share.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_code_works_for_one_scan_and_shows_a_matching_number() {
        let mut f = fixture("token", 1 << 20);
        let used = f.share.join_url();
        let (phone, other) = (client(&f), client(&f));
        let d = join(&mut f, &phone).await;
        let (_, s) = state(&phone, &f).await;
        assert_eq!(s["status"], "pending");
        assert_eq!(s["code"], d.code, "the phone shows the code the computer shows");
        assert_eq!(d.code.len(), 7);
        assert_eq!(other.get(&used).send().await.expect("again").status(), 404, "a used code is worthless");
        assert_ne!(f.share.join_url(), used, "the computer shows a new one");

        // Denied, then a fresh scan asks again.
        f.share.decide(d.id, false, false);
        assert_eq!(state(&phone, &f).await.1["status"], "denied");
        let again = join(&mut f, &phone).await;
        assert_ne!(again.id, d.id);
        f.share.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn approved_device_uploads_are_saved_safely() {
        let mut f = fixture("upload", 8 << 20);
        let c = client(&f);
        let d = join(&mut f, &c).await;
        assert_eq!(put(&c, &f, "a.txt", b"x".to_vec()).await.status(), 403, "pending devices cannot upload");

        f.share.decide(d.id, true, false);
        let no_csrf = c.put(format!("{}/api/upload?name=a.txt", f.base)).body("x").send().await.expect("put");
        assert_eq!(no_csrf.status(), 403, "custom header required");

        // 3 MB: bigger than axum's default body limit, streamed to disk.
        let big = vec![7u8; 3 << 20];
        let r = put(&c, &f, "IMG_0001.HEIC", big.clone()).await;
        assert_eq!(r.status(), 200);
        let j: serde_json::Value = r.json().await.expect("json");
        assert_eq!(j["name"], "IMG_0001.HEIC");
        assert_eq!(j["sha256"], format!("{:x}", Sha256::digest(&big)));
        assert_eq!(std::fs::read(f.dest.join("IMG_0001.HEIC")).expect("saved"), big);

        let again: serde_json::Value = put(&c, &f, "IMG_0001.HEIC", b"second".to_vec()).await.json().await.expect("json");
        assert_eq!(again["name"], "IMG_0001 (1).HEIC", "never overwrites");
        let evil: serde_json::Value = put(&c, &f, "../../../evil.sh", b"#!".to_vec()).await.json().await.expect("json");
        assert_eq!(evil["name"], "evil.sh");
        assert!(f.dest.join("evil.sh").exists());
        assert_eq!(partials(&f.dest), 0);
        f.share.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remembered_devices_come_back_without_asking() {
        let mut f = fixture("remember", 1 << 20);
        let (phone, guest) = (client(&f), client(&f));
        let d = join(&mut f, &phone).await;
        f.share.decide(d.id, true, true);
        let known = match f.events.recv().await {
            Some(Event::Remembered { known }) => known,
            other => panic!("expected remembered, got {other:?}"),
        };
        assert_eq!(known.label, d.label);
        assert_eq!(known.hash.len(), 64, "only a hash is kept");
        let (_, s) = state(&phone, &f).await;
        assert_eq!((s["status"].as_str(), s["remembered"].as_bool()), (Some("allowed"), Some(true)));
        let g = join(&mut f, &guest).await;
        f.share.decide(g.id, true, false);
        f.share.stop();

        // Next session: new port, no QR code, no question.
        let Fixture { ca, dest, .. } = f;
        let mut f = start(ca, dest, 1 << 20, vec![known.clone()]);
        let page = phone.get(format!("{}/", f.base)).send().await.expect("page");
        assert!(page.headers().get("set-cookie").is_some_and(|v| v.to_str().is_ok_and(|v| v.contains("Max-Age="))), "cookie renewed");
        match f.events.recv().await {
            Some(Event::Returned { device }) => assert_eq!(device.known.as_deref(), Some(known.id.as_str())),
            other => panic!("expected returned, got {other:?}"),
        }
        assert_eq!(state(&phone, &f).await.1["status"], "allowed");
        assert_eq!(state(&guest, &f).await.0, 401, "allowed once is not remembered");

        // Forgetting cuts it off at once.
        f.share.set_known(Vec::new());
        assert_eq!(state(&phone, &f).await.0, 401);
        f.share.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn removing_a_remembered_device_forgets_it() {
        let mut f = fixture("revoke", 1 << 20);
        let phone = client(&f);
        let d = join(&mut f, &phone).await;
        f.share.decide(d.id, true, true);
        let Some(Event::Remembered { known }) = f.events.recv().await else { panic!("remembered") };
        assert_eq!(f.share.revoke(d.id), Some(known.id));
        assert_eq!(state(&phone, &f).await.0, 401, "not let back in");
        f.share.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn oversize_and_broken_uploads_leave_nothing_behind() {
        let mut f = fixture("limits", 1000);
        let c = client(&f);
        let d = join(&mut f, &c).await;
        f.share.decide(d.id, true, false);
        assert_eq!(put(&c, &f, "big.bin", vec![0u8; 2000]).await.status(), 413);

        // Announce 1000 bytes, send 900, then hang up.
        let short = futures_util::stream::iter([Ok::<_, std::io::Error>(vec![1u8; 900])]);
        let _ = c
            .put(format!("{}/api/upload?name=short.bin", f.base))
            .header(CSRF_HEADER, "1")
            .header(CONTENT_LENGTH, "1000")
            .body(reqwest::Body::wrap_stream(short))
            .send()
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!f.dest.join("short.bin").exists(), "an incomplete upload is never saved");
        assert_eq!(partials(&f.dest), 0, "and its temp file is gone");
        f.share.stop();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn only_offered_files_download_and_stop_ends_access() {
        let mut f = fixture("download", 1 << 20);
        let shared = f.dest.parent().expect("root").join("report.pdf");
        std::fs::write(&shared, b"%PDF-1.7 hello").expect("file");
        let offer = f.share.offer(shared).expect("offer");

        let c = client(&f);
        let d = join(&mut f, &c).await;
        let url = format!("{}/api/files/{}", f.base, offer.id);
        assert_eq!(c.get(&url).send().await.expect("get").status(), 403, "pending devices see nothing");
        f.share.decide(d.id, true, false);
        let r = c.get(&url).send().await.expect("get");
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers().get("content-type").expect("ct"), "application/pdf");
        assert!(r.headers().get("content-disposition").expect("cd").to_str().expect("s").starts_with("attachment;"));
        assert_eq!(r.bytes().await.expect("body").as_ref(), b"%PDF-1.7 hello");
        assert!(matches!(f.events.recv().await, Some(Event::Sent { .. })));
        assert_eq!(c.get(format!("{}/api/files/0123456789abcdef", f.base)).send().await.expect("get").status(), 404);
        assert_eq!(c.get(format!("{}/api/files/..%2F..%2Fetc%2Fpasswd", f.base)).send().await.expect("get").status(), 404);

        // The phone hears the session end, then its cookie is worthless.
        let mut sse = c.get(format!("{}/api/events", f.base)).send().await.expect("sse");
        let first = sse.chunk().await.expect("chunk").expect("data");
        assert!(String::from_utf8_lossy(&first).contains("changed"));
        f.share.stop();
        let mut got = String::new();
        while let Ok(Some(chunk)) = sse.chunk().await {
            got.push_str(&String::from_utf8_lossy(&chunk));
        }
        assert!(got.contains("ended"), "{got}");
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(c.get(format!("{}/api/state", f.base)).send().await.is_err(), "the port is closed");
    }
}
