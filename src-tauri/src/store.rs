//! Settings and history: small JSON files in the app's config folder.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};

pub fn load<T: DeserializeOwned + Default>(path: &Path) -> T {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

/// Write-then-rename, so a crash never leaves a half-written file.
pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    // Only this user may read them: device keys' hashes, folders, history.
    simple_share_core::tls::write_private(&tmp, &json).and_then(|()| std::fs::rename(&tmp, path)).map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    /// Shown on phones as "Send to …".
    pub device_name: String,
    /// Phones reach this computer at `host_name.local`. Random, made once.
    pub host_name: String,
    pub receive_dir: PathBuf,
    pub port: u16,
    /// Sharing stops after this long without any phone activity.
    pub idle_minutes: u64,
    pub max_upload_mb: u64,
    pub notifications: bool,
    pub theme: String,
    /// When launched at login, stay in the tray instead of opening the window.
    pub start_in_tray: bool,
    /// Check GitHub for updates at startup and daily. Installing always asks.
    pub check_updates: bool,
    /// The firewall rule Simple Share added, so exactly that can be removed again.
    pub firewall_rule: Option<FirewallRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRule {
    pub zone: String,
    pub port: u16,
    /// Simple Share also allowed mDNS, so phones can look up the `.local` name.
    #[serde(default)]
    pub mdns: bool,
}

impl Default for Settings {
    fn default() -> Self {
        let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .or_else(|| std::env::var("COMPUTERNAME").ok())
            .map(|h| h.trim().to_string())
            .unwrap_or_default();
        let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_default();
        Self {
            device_name: if host.is_empty() { "this computer".into() } else { host },
            host_name: String::new(),
            receive_dir: home.join("Downloads"),
            port: 47645,
            idle_minutes: 15,
            max_upload_mb: 4096,
            notifications: true,
            theme: "system".into(),
            start_in_tray: false,
            check_updates: true,
            firewall_rule: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryFile {
    pub name: String,
    pub size: u64,
    pub path: Option<PathBuf>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub at: u64,
    /// "received" or "sent".
    pub direction: String,
    pub peer: String,
    pub files: Vec<HistoryFile>,
    /// "saved", "sent" or "failed".
    pub result: String,
    pub error: Option<String>,
}

pub const HISTORY_CAP: usize = 500;

pub fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
