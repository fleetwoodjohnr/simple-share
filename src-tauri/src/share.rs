//! A sharing session as the desktop app sees it: start and stop the server,
//! pass device requests to the UI, record transfers in History.

use crate::firewall::{self, Firewall};
use crate::store::{self, HistoryEntry, HistoryFile, Settings};
use serde::Serialize;
use simple_share_core::server::{self, Config, Device, Event, Offer, Share};
use simple_share_core::tls::{self, Ca};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_notification::NotificationExt;

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub struct App {
    pub handle: AppHandle,
    pub dir: PathBuf,
    pub settings: Mutex<Settings>,
    pub history: Mutex<Vec<HistoryEntry>>,
    pub ca: Mutex<Ca>,
    session: Mutex<Option<(Share, u64)>>,
    generation: Mutex<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    pub on: bool,
    pub url: Option<String>,
    /// SVG markup of the QR code for `url`.
    pub qr: Option<String>,
    pub devices: Vec<Device>,
    pub offers: Vec<Offer>,
    pub firewall: Firewall,
}

impl App {
    pub fn new(handle: AppHandle, dir: PathBuf) -> Result<Self, String> {
        let ca = Ca::load_or_create(&dir).map_err(|e| format!("Could not set up the security certificate: {e}"))?;
        Ok(Self {
            settings: Mutex::new(store::load(&dir.join("settings.json"))),
            history: Mutex::new(store::load(&dir.join("history.json"))),
            ca: Mutex::new(ca),
            handle,
            dir,
            session: Mutex::new(None),
            generation: Mutex::new(0),
        })
    }

    pub fn with_share<T>(&self, f: impl FnOnce(&Share) -> T) -> Option<T> {
        lock(&self.session).as_ref().map(|(s, _)| f(s))
    }

    pub fn view(&self) -> View {
        let port = lock(&self.settings).port;
        let firewall = firewall::check(port);
        match lock(&self.session).as_ref() {
            Some((s, _)) => {
                let url = s.join_url();
                View { on: true, qr: qr_svg(&url), url: Some(url), devices: s.devices(), offers: s.offers(), firewall }
            }
            None => View { on: false, url: None, qr: None, devices: Vec::new(), offers: Vec::new(), firewall },
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
    let (share, mut events) = Share::start(&lock(&app.ca), ip, port, app.config()).map_err(|e| {
        if e.to_string().contains("in use") {
            format!("Port {port} is already in use. Choose another port in Settings.")
        } else {
            format!("Could not start sharing: {e}")
        }
    })?;
    let generation = {
        let mut g = lock(&app.generation);
        *g += 1;
        *g
    };
    *lock(&app.session) = Some((share, generation));

    // Events from phones: to the UI, notifications and History.
    let a = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = events.recv().await {
            let _ = a.handle.emit("share-event", &event);
            match event {
                Event::DeviceRequest { device } => {
                    a.notify("Simple Share", &format!("{} at {} wants to connect.", device.label, device.ip));
                    if let Some(w) = a.handle.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.unminimize();
                        let _ = w.set_focus();
                    }
                    a.emit_view();
                }
                Event::DeviceExpired { .. } => a.emit_view(),
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
                Some((s, g)) if *g == generation => s.idle(),
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
    if let Some((share, _)) = lock(&app.session).take() {
        share.stop();
    }
    app.emit_view();
}
