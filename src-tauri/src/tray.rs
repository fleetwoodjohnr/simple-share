//! The tray icon (notification area on Windows, menu bar on macOS, AppIndicator
//! on Linux): shows whether sharing is on and offers Open / Start-Stop / Quit.

use crate::share::{self, App};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

const ID: &str = "main";

/// Held so the Start/Stop label can follow the sharing state.
pub struct Tray {
    toggle: MenuItem<Wry>,
    /// Is anything actually showing tray icons? (Some Linux desktops don't.)
    pub available: bool,
    told_hidden: AtomicBool,
}

fn icon(on: bool) -> Image<'static> {
    let bytes: &'static [u8] = match (cfg!(target_os = "macos"), on) {
        (true, false) => include_bytes!("../icons/tray/template-idle.png"),
        (true, true) => include_bytes!("../icons/tray/template-active.png"),
        (false, false) => include_bytes!("../icons/tray/idle.png"),
        (false, true) => include_bytes!("../icons/tray/active.png"),
    };
    Image::from_bytes(bytes).expect("tray icons are valid PNGs built into the app")
}

/// Linux shows tray icons only where a StatusNotifier host runs (KDE, most
/// desktops, GNOME with the AppIndicator extension). Without one, hiding the
/// window would leave the app unreachable, so closing must quit instead.
fn host_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        let check = || -> zbus::Result<bool> {
            let conn = zbus::blocking::Connection::session()?;
            let dbus = zbus::blocking::fdo::DBusProxy::new(&conn)?;
            Ok(dbus.name_has_owner("org.kde.StatusNotifierWatcher".try_into()?)?)
        };
        check().unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    true
}

pub fn show_window(handle: &AppHandle) {
    if let Some(w) = handle.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

pub fn build(handle: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(handle, "open", "Open Simple Share", true, None::<&str>)?;
    let toggle = MenuItem::with_id(handle, "toggle", "Start sharing", true, None::<&str>)?;
    let quit = MenuItem::with_id(handle, "quit", "Quit Simple Share", true, None::<&str>)?;
    let menu = Menu::with_items(handle, &[&open, &toggle, &PredefinedMenuItem::separator(handle)?, &quit])?;
    TrayIconBuilder::with_id(ID)
        .icon(icon(false))
        .icon_as_template(cfg!(target_os = "macos"))
        .tooltip("Simple Share: sharing off")
        .menu(&menu)
        // Windows: left click opens the window, right click the menu.
        // macOS and Linux: the menu, as on those systems' own status icons.
        .show_menu_on_left_click(!cfg!(windows))
        .on_menu_event(|h, event| match event.id.as_ref() {
            "open" => show_window(h),
            "toggle" => toggle_sharing(h),
            "quit" => {
                if let Some(app) = h.try_state::<Arc<App>>() {
                    share::stop(&app);
                }
                h.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                show_window(tray.app_handle());
            }
        })
        .build(handle)?;
    handle.manage(Tray { toggle, available: host_available(), told_hidden: AtomicBool::new(false) });
    Ok(())
}

fn toggle_sharing(handle: &AppHandle) {
    let Some(app) = handle.try_state::<Arc<App>>().map(|s| s.inner().clone()) else { return };
    if app.with_share(|_| ()).is_some() {
        share::stop(&app);
    } else {
        // The server spawns tasks, so start it on the async runtime.
        tauri::async_runtime::spawn(async move {
            if let Err(e) = share::start(&app) {
                app.notify("Sharing did not start", &e);
                show_window(&app.handle);
            }
        });
    }
}

/// Follow the sharing state: icon, tooltip and menu label.
pub fn refresh(handle: &AppHandle, on: bool, allowed: usize) {
    if let Some(tray) = handle.tray_by_id(ID) {
        let _ = tray.set_icon(Some(icon(on)));
        let _ = tray.set_icon_as_template(cfg!(target_os = "macos"));
        let tip = match (on, allowed) {
            (false, _) => "Simple Share: sharing off".to_string(),
            (true, 0) => "Simple Share: sharing on".to_string(),
            (true, 1) => "Simple Share: sharing on, 1 device".to_string(),
            (true, n) => format!("Simple Share: sharing on, {n} devices"),
        };
        let _ = tray.set_tooltip(Some(tip));
    }
    if let Some(t) = handle.try_state::<Tray>() {
        let _ = t.toggle.set_text(if on { "Stop sharing" } else { "Start sharing" });
    }
}

/// Closing the window hides it to the tray when there is a tray to come back
/// from. Returns whether the close was turned into a hide.
pub fn hide_on_close(window: &tauri::Window) -> bool {
    let handle = window.app_handle();
    let Some(tray) = handle.try_state::<Tray>() else { return false };
    if !tray.available {
        return false;
    }
    let _ = window.hide();
    if !tray.told_hidden.swap(true, Ordering::Relaxed)
        && let Some(app) = handle.try_state::<Arc<App>>()
    {
        app.notify("Simple Share is still running", "It's in the tray. Choose Quit there to close it completely.");
    }
    true
}
