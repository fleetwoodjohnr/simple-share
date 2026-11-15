//! Answering for `label.local` on the network while sharing is on, so phones
//! reach this computer by name (multicast DNS, RFC 6762) instead of by an IP
//! address that can change.

use mdns_sd::{DaemonEvent, IfKind, RRType, ServiceDaemon, ServiceInfo};
use std::net::IpAddr;
use std::time::Duration;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// Answers for the name until dropped.
pub struct Announcement {
    daemon: ServiceDaemon,
    fullname: String,
}

/// Answer for `label.local` with `ip`, only on the network that has `ip`.
/// `on_conflict` runs if another device on the network claims the same name.
pub fn announce(label: &str, ip: IpAddr, port: u16, on_conflict: impl Fn() + Send + 'static) -> Result<Announcement, Error> {
    let daemon = ServiceDaemon::new()?;
    daemon.disable_interface(IfKind::All)?;
    daemon.enable_interface(IfKind::Addr(ip))?;
    // mdns-sd answers name lookups for the host of a registered service. The
    // instance is the random label too, so nothing personal is announced and two
    // Simple Share computers never clash on it.
    let info = ServiceInfo::new(
        "_https._tcp.local.",
        label,
        &format!("{label}.local."),
        ip,
        port,
        None::<std::collections::HashMap<String, String>>,
    )?;
    let fullname = info.get_fullname().to_string();
    let events = daemon.monitor()?;
    daemon.register(info)?;
    std::thread::spawn(move || {
        while let Ok(event) = events.recv() {
            if let DaemonEvent::NameChange(c) = event
                && matches!(c.rr_type, RRType::A | RRType::AAAA)
            {
                tracing::warn!(name = %c.original, "another device answers to this computer's .local name");
                on_conflict();
            }
        }
    });
    Ok(Announcement { daemon, fullname })
}

impl Drop for Announcement {
    fn drop(&mut self) {
        // The goodbye packets make phones forget the name at once.
        if let Ok(done) = self.daemon.unregister(&self.fullname) {
            let _ = done.recv_timeout(Duration::from_secs(1));
        }
        let _ = self.daemon.shutdown();
    }
}
