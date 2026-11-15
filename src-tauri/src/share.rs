//! A sharing session as the desktop app sees it: start and stop the server and
//! its `.local` name, pass device requests to the UI, remember devices, record
//! transfers in History.

use crate::firewall::{self, Firewall};
use crate::store::{self, HistoryEntry, HistoryFile, Settings};
use serde::Serialize;
use simple_share_core::mdns;
use simple_share_core::server::{self, Config, Device, Event, Known, Offer, Share};
use simple_share_core::tls::{self, Ca};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Remembered devices unused for this long are forgotten.
const KNOWN_EXPIRY_SECS: u64 = 365 * 86_400;

struct Session {
    share: Share,
    generation: u64,
    /// Answers for `label.local` until dropped.
    _mdns: Option<mdns::Announcement>,
    /// Why phones should use the IP address instead of the name, if they should.
    name_problem: Arc<Mutex<Option<String>>>,
}

pub struct App {
    pub handle: AppHandle,
    pub dir: PathBuf,
    pub settings: Mutex<Settings>,
    pub history: Mutex<Vec<HistoryEntry>>,
    pub known: Mutex<Vec<Known>>,
    pub ca: Mutex<Ca>,
    session: Mutex<Option<Session>>,
    generation: Mutex<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub on: bool,
    pub url: Option<String>,
    /// SVG markup of the QR code for `url`.
    pub qr: Option<String>,
    /// The same by IP address, for phones that can't look up `.local` names.
    pub ip_url: Option<String>,
    pub ip_qr: Option<String>,
    /// Why the code uses the IP address, when it does.
    pub notice: Option<String>,
    pub devices: Vec<Device>,
    pub offers: Vec<Offer>,
    pub firewall: Firewall,
}

impl App {
    pub fn new(handle: AppHandle, dir: PathBuf) -> Result<Self, String> {
        let mut settings: Settings = store::load(&dir.join("settings.json"));
        if settings.host_name.is_empty() {
            settings.host_name = tls::new_label();
            store::save(&dir.join("settings.json"), &settings)?;
        }
        let ca = Ca::load_or_create(&dir, &settings.host_name).map_err(|e| format!("Could not set up the security certificate: {e}"))?;
        let mut known: Vec<Known> = store::load(&dir.join("devices.json"));
        known.retain(|k| store::now().saturating_sub(k.last_used) < KNOWN_EXPIRY_SECS);
        Ok(Self {
            settings: Mutex::new(settings),
            history: Mutex::new(store::load(&dir.join("history.json"))),
            known: Mutex::new(known),
            ca: Mutex::new(ca),
            handle,
            dir,
            session: Mutex::new(None),
            generation: Mutex::new(0),
        })
    }

    pub fn with_share<T>(&self, f: impl FnOnce(&Share) -> T) -> Option<T> {
        lock(&self.session).as_ref().map(|s| f(&s.share))
    }

    pub fn view(&self) -> View {
        let port = lock(&self.settings).port;
        let firewall = firewall::check(port);
        match lock(&self.session).as_ref() {
            Some(s) => {
                let (local, ip) = (s.share.join_url(), s.share.ip_join_url());
                let notice = lock(&s.name_problem).clone();
                // When the name doesn't work, the main code is the IP address.
                let (url, fallback) = if notice.is_some() { (ip, None) } else { (local, Some(ip)) };
                View {
                    on: true,
                    qr: qr_svg(&url),
                    url: Some(url),
                    ip_qr: fallback.as_deref().and_then(qr_svg),
                    ip_url: fallback,
                    notice,
                    devices: s.share.devices(),
                    offers: s.share.offers(),
                    firewall,
                }
            }
            None => View {
                on: false,
                url: None,
                qr: None,
                ip_url: None,
                ip_qr: None,
                notice: None,
                devices: Vec::new(),
                offers: Vec::new(),
                firewall,
            },
        }
    }

    /// The one place sharing state is broadcast: the window and the tray.
    pub fn emit_view(&self) {
        let view = self.view();
        crate::tray::refresh(&self.handle, view.on, view.devices.iter().filter(|d| d.status == server::Status::Allowed).count());
        let _ = self.handle.emit("view", &view);
    }

    pub fn add_history(&self, entry: HistoryEntry) {
        let mut h = lock(&self.history);
        h.insert(0, entry);
        h.truncate(store::HISTORY_CAP);
        let _ = store::save(&self.dir.join("history.json"), &*h);
        let _ = self.handle.emit("history", ());
    }

    /// Change the remembered devices, save them, and cut off any that are gone.
    pub fn update_known(&self, f: impl FnOnce(&mut Vec<Known>)) {
        let list = {
            let mut k = lock(&self.known);
            f(&mut k);
            let _ = store::save(&self.dir.join("devices.json"), &*k);
            k.clone()
        };
        self.with_share(|s| s.set_known(list));
        let _ = self.handle.emit("known", ());
    }

    pub fn notify(&self, title: &str, body: &str) {
        if lock(&self.settings).notifications {
            let _ = self.handle.notification().builder().title(title).body(body).show();
        }
    }

    pub fn config(&self) -> Config {
        let s = lock(&self.settings);
        Config { name: s.device_name.clone(), dest: s.receive_dir.clone(), max_upload: s.max_upload_mb << 20 }
    }
}

fn qr_svg(url: &str) -> Option<String> {
    let code = qrcode::QrCode::new(url.as_bytes()).ok()?;
    Some(code.render::<qrcode::render::svg::Color<'_>>().min_dimensions(240, 240).quiet_zone(true).build())
}

/// Start sharing. Must run inside the async runtime (the server spawns tasks).
pub fn start(app: &Arc<App>) -> Result<View, String> {
    if lock(&app.session).is_some() {
        return Ok(app.view());
    }
    let ip = server::lan_ip().ok_or("This computer is not connected to a network.")?;
    if !tls::is_permitted(ip) {
        return Err(format!(
            "This computer's address ({ip}) is a public internet address, so sharing stays off for safety. Connect to a home or office network."
        ));
    }
    let port = lock(&app.settings).port;
    let known = lock(&app.known).clone();
    let ca = lock(&app.ca);
    // The standard HTTPS port keeps the port number out of the address. Linux
    // reserves it for system services, so there the port from Settings is used,
    // as it is elsewhere when another program already has 443.
    let first = if cfg!(target_os = "linux") { port } else { 443 };
    let started = Share::start(&ca, ip, first, app.config(), known.clone());
    let started = if started.is_err() && first != port { Share::start(&ca, ip, port, app.config(), known) } else { started };
    let (share, mut events) = started.map_err(|e| {
        if e.to_string().contains("in use") {
            format!("Port {port} is already in use. Choose another port in Settings.")
        } else {
            format!("Could not start sharing: {e}")
        }
    })?;
    let label = ca.label().to_string();
    drop(ca);
    let name = tls::local_name(&label);

    // Answer for the .local name. If that fails, or another device claims the
    // name, phones use the IP address instead.
    let name_problem = Arc::new(Mutex::new(None));
    let (problem, a) = (name_problem.clone(), app.clone());
    let conflict = format!(
        "Another device on this network is answering to {name}, so the code uses this computer's IP address. \
         If this keeps happening, choose New address in Settings."
    );
    let announcement = mdns::announce(&label, ip, share.addr.port(), move || {
        *lock(&problem) = Some(conflict.clone());
        a.emit_view();
    })
    .map_err(|e| {
        tracing::warn!(error = %e, "could not announce the .local name");
        *lock(&name_problem) = Some(format!("Phones can't find {name} on this network, so the code uses this computer's IP address."));
    })
    .ok();

    let generation = {
        let mut g = lock(&app.generation);
        *g += 1;
        *g
    };
    *lock(&app.session) = Some(Session { share, generation, _mdns: announcement, name_problem });

    // Events from phones: to the UI, notifications, remembered devices and History.
    let a = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            let _ = a.handle.emit("share-event", &event);
            match event {
                Event::DeviceRequest { device } => {
                    a.notify("Simple Share", &format!("{} at {} wants to connect. Code {}", device.label, device.ip, device.code));
                    if let Some(w) = a.handle.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                    a.emit_view();
                }
                Event::DeviceExpired { .. } => a.emit_view(),
                Event::Remembered { known } => a.update_known(|k| k.push(known)),
                Event::Returned { device } => {
                    let now = store::now();
                    a.update_known(|k| k.iter_mut().filter(|k| device.known.as_ref() == Some(&k.id)).for_each(|k| k.last_used = now));
                    a.notify("Simple Share", &format!("{} connected. You allowed it before.", device.label));
                    a.emit_view();
                }
                Event::Saved { device, path, size, sha256, .. } => {
                    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    a.notify("File received", &format!("{name} from {device}"));
                    a.add_history(HistoryEntry {
                        at: store::now(),
                        direction: "received".into(),
                        peer: device,
                        files: vec![HistoryFile { name, size, path: Some(path), sha256: Some(sha256) }],
                        result: "saved".into(),
                        error: None,
                    });
                }
                Event::Failed { device, name, error, .. } => a.add_history(HistoryEntry {
                    at: store::now(),
                    direction: "received".into(),
                    peer: device,
                    files: vec![HistoryFile { name, size: 0, path: None, sha256: None }],
                    result: "failed".into(),
                    error: Some(error),
                }),
                Event::Sent { offer, device, name } => {
                    let size = a.with_share(|s| s.offers().into_iter().find(|o| o.id == offer).map(|o| o.size)).flatten().unwrap_or(0);
                    a.add_history(HistoryEntry {
                        at: store::now(),
                        direction: "sent".into(),
                        peer: device,
                        files: vec![HistoryFile { name, size, path: None, sha256: None }],
                        result: "sent".into(),
                        error: None,
                    });
                }
                Event::Progress { .. } => {}
            }
        }
    });

    // Switch off after a quiet spell, so the port is never left open by accident.
    let a = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let limit = Duration::from_secs(lock(&a.settings).idle_minutes.max(1) * 60);
            let idle = match lock(&a.session).as_ref() {
                Some(s) if s.generation == generation => s.share.idle(),
                _ => return,
            };
            if idle > limit {
                stop(&a);
                a.notify("Simple Share", "Sharing stopped after a period without activity.");
                return;
            }
        }
    });
    app.emit_view();
    Ok(app.view())
}

pub fn stop(app: &App) {
    // Taken out first so the name's goodbye (up to a second) runs unlocked.
    let session = lock(&app.session).take();
    if let Some(s) = session {
        s.share.stop();
    }
    app.emit_view();
}

/// Forget these remembered devices; any that are connected lose access at once.
pub fn forget(app: &App, ids: &[String]) {
    app.update_known(|k| k.retain(|x| !ids.contains(&x.id)));
    app.emit_view();
}
