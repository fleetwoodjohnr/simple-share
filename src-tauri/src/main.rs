// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod firewall;
mod share;
mod store;
mod tray;

use share::{App, View, lock};
use simple_share_core::tls::Ca;
use std::path::PathBuf;
use std::sync::Arc;
use store::{FirewallRule, HistoryEntry, Settings};
use tauri::{Manager, State};
use tauri_plugin_autostart::ManagerExt as _;

type AppState<'a> = State<'a, Arc<App>>;

#[tauri::command]
async fn view(app: AppState<'_>) -> Result<View, String> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || app.view()).await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn start_sharing(app: AppState<'_>) -> Result<View, String> {
    share::start(app.inner())
}

#[tauri::command]
fn stop_sharing(app: AppState<'_>) {
    share::stop(&app);
}

#[tauri::command]
fn decide(app: AppState<'_>, id: u64, allow: bool) {
    app.with_share(|s| s.decide(id, allow));
    app.emit_view();
}

#[tauri::command]
fn revoke(app: AppState<'_>, id: u64) {
    app.with_share(|s| s.revoke(id));
    app.emit_view();
}

#[tauri::command]
fn offer_files(app: AppState<'_>, paths: Vec<PathBuf>) -> Result<(), String> {
    let mut errors = Vec::new();
    for p in paths {
        match app.with_share(|s| s.offer(p.clone())) {
            Some(Ok(_)) => {}
            Some(Err(e)) => errors.push(format!("{}: {e}", p.display())),
            None => return Err("Start sharing first.".into()),
        }
    }
    app.emit_view();
    if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
}

#[tauri::command]
fn withdraw(app: AppState<'_>, id: String) {
    app.with_share(|s| s.withdraw(&id));
    app.emit_view();
}

#[tauri::command]
fn get_settings(app: AppState<'_>) -> Settings {
    lock(&app.settings).clone()
}

#[tauri::command]
fn save_settings(app: AppState<'_>, settings: Settings) -> Result<Settings, String> {
    let name = settings.device_name.trim();
    if name.is_empty() || name.chars().count() > 63 {
        return Err("Use a name of 1 to 63 characters.".into());
    }
    if settings.port < 1024 {
        return Err("Use a port from 1024 to 65535.".into());
    }
    if !(1..=240).contains(&settings.idle_minutes) || !(1..=65_536).contains(&settings.max_upload_mb) {
        return Err("That value is out of range.".into());
    }
    // The firewall rule is only ever changed by its own buttons.
    let mut settings = settings;
    settings.firewall_rule = lock(&app.settings).firewall_rule.clone();
    store::save(&app.dir.join("settings.json"), &settings)?;
    *lock(&app.settings) = settings.clone();
    app.with_share(|s| s.set_config(app.config()));
    Ok(settings)
}

#[tauri::command]
fn history(app: AppState<'_>) -> Vec<HistoryEntry> {
    lock(&app.history).clone()
}

#[tauri::command]
fn clear_history(app: AppState<'_>) -> Result<(), String> {
    lock(&app.history).clear();
    store::save(&app.dir.join("history.json"), &Vec::<HistoryEntry>::new())
}

#[tauri::command]
fn fingerprint(app: AppState<'_>) -> String {
    lock(&app.ca).fingerprint()
}

/// New certificate: every paired phone sees the warning again until re-paired.
#[tauri::command]
fn reset_certificate(app: AppState<'_>) -> Result<String, String> {
    share::stop(&app);
    let ca = Ca::create(&app.dir).map_err(|e| e.to_string())?;
    let fp = ca.fingerprint();
    *lock(&app.ca) = ca;
    Ok(fp)
}

#[tauri::command]
async fn allow_firewall(app: AppState<'_>) -> Result<View, String> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let port = lock(&app.settings).port;
        if let firewall::Firewall::Blocked { zone } = firewall::check(port) {
            firewall::allow(&zone, port)?;
            let mut s = lock(&app.settings);
            s.firewall_rule = Some(FirewallRule { zone, port });
            store::save(&app.dir.join("settings.json"), &*s)?;
        }
        Ok(app.view())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn remove_firewall_rule(app: AppState<'_>) -> Result<Settings, String> {
    let app = app.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let rule = lock(&app.settings).firewall_rule.clone();
        if let Some(r) = rule {
            firewall::remove(&r.zone, r.port)?;
        }
        let saved = {
            let mut s = lock(&app.settings);
            s.firewall_rule = None;
            store::save(&app.dir.join("settings.json"), &*s)?;
            s.clone()
        };
        app.emit_view();
        Ok(saved)
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn get_autostart(handle: tauri::AppHandle) -> bool {
    handle.autolaunch().is_enabled().unwrap_or(false)
}

#[tauri::command]
fn set_autostart(handle: tauri::AppHandle, enabled: bool) -> Result<bool, String> {
    let a = handle.autolaunch();
    if enabled { a.enable() } else { a.disable() }.map_err(|e| e.to_string())?;
    Ok(a.is_enabled().unwrap_or(false))
}

/// Launched at login with "Start in the tray": stay out of the way.
const MINIMIZED_ARG: &str = "--minimized";

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec![MINIMIZED_ARG])))
        .setup(|app| {
            let dir = app.path().app_config_dir()?;
            let state = Arc::new(App::new(app.handle().clone(), dir)?);
            let start_in_tray = lock(&state.settings).start_in_tray;
            app.manage(state);
            tray::build(app.handle())?;
            // The window starts hidden (tauri.conf.json) so it never flashes.
            let quiet =
                start_in_tray && std::env::args().any(|a| a == MINIMIZED_ARG) && app.try_state::<tray::Tray>().is_some_and(|t| t.available);
            if !quiet {
                tray::show_window(app.handle());
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event
                && tray::hide_on_close(window)
            {
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            view,
            start_sharing,
            stop_sharing,
            decide,
            revoke,
            offer_files,
            withdraw,
            get_settings,
            save_settings,
            history,
            clear_history,
            fingerprint,
            reset_certificate,
            allow_firewall,
            remove_firewall_rule,
            get_autostart,
            set_autostart,
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("simple-share: {e}");
            std::process::exit(1);
        })
        .run(|handle, event| {
            // Never leave the port open after the app is gone.
            if let tauri::RunEvent::Exit = event
                && let Some(app) = handle.try_state::<Arc<App>>()
            {
                share::stop(&app);
            }
        });
}
