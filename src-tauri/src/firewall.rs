//! Letting phones reach the share port through firewalld (Fedora, RHEL, openSUSE…).
//!
//! Nothing here changes anything until the person clicks "Allow". Then one
//! polkit password prompt adds this single TCP port to the zone of the network
//! interface, now and permanently. "Remove firewall rule" undoes exactly that.
//! Other systems need nothing: Windows and macOS ask by themselves the first
//! time the app listens, and most other Linux setups have no firewall running.

use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum Firewall {
    /// No firewalld (or not Linux): nothing for Simple Share to do.
    NotManaged,
    Open,
    Blocked {
        zone: String,
    },
}

/// Is `port` allowed by these zone settings? Pure, so it is tested.
pub fn port_allowed(target: &str, ports: &[(String, String)], port: u16) -> bool {
    target.eq_ignore_ascii_case("ACCEPT")
        || ports.iter().any(|(p, proto)| {
            proto == "tcp"
                && match p.split_once('-') {
                    Some((a, b)) => a.parse::<u16>().is_ok_and(|a| a <= port) && b.parse::<u16>().is_ok_and(|b| port <= b),
                    None => p.parse::<u16>().is_ok_and(|p| p == port),
                }
        })
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Firewall, port_allowed};
    use std::collections::HashMap;
    use zbus::blocking::{Connection, Proxy};
    use zbus::proxy::MethodFlags;
    use zbus::zvariant::{OwnedObjectPath, OwnedValue};

    const DEST: &str = "org.fedoraproject.FirewallD1";
    const PATH: &str = "/org/fedoraproject/FirewallD1";

    fn zone_api(conn: &Connection) -> zbus::Result<Proxy<'_>> {
        Proxy::new(conn, DEST, PATH, "org.fedoraproject.FirewallD1.zone")
    }

    /// The interface carrying the default IPv4 route, i.e. the one phones reach us on.
    fn default_iface() -> Option<String> {
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        routes
            .lines()
            .skip(1)
            .map(|l| l.split_whitespace().collect::<Vec<_>>())
            .find(|f| f.get(1) == Some(&"00000000"))
            .and_then(|f| f.first().map(|s| s.to_string()))
    }

    fn zone(conn: &Connection) -> zbus::Result<String> {
        let api = zone_api(conn)?;
        if let Some(iface) = default_iface() {
            let z: String = api.call("getZoneOfInterface", &(iface,))?;
            if !z.is_empty() {
                return Ok(z);
            }
        }
        Proxy::new(conn, DEST, PATH, "org.fedoraproject.FirewallD1")?.call("getDefaultZone", &())
    }

    pub fn check(port: u16) -> Firewall {
        let Ok(conn) = Connection::system() else { return Firewall::NotManaged };
        let state = (|| -> zbus::Result<Firewall> {
            let zone = zone(&conn)?;
            let settings: HashMap<String, OwnedValue> = zone_api(&conn)?.call("getZoneSettings2", &(zone.as_str(),))?;
            let target = settings.get("target").and_then(|v| String::try_from(v.try_clone().ok()?).ok()).unwrap_or_default();
            let ports = settings.get("ports").and_then(|v| Vec::<(String, String)>::try_from(v.try_clone().ok()?).ok()).unwrap_or_default();
            Ok(if port_allowed(&target, &ports, port) { Firewall::Open } else { Firewall::Blocked { zone } })
        })();
        // An error here almost always means firewalld is not running.
        state.unwrap_or(Firewall::NotManaged)
    }

    fn auth_call(p: &Proxy<'_>, method: &str, body: &(impl serde::Serialize + zbus::zvariant::DynamicType)) -> Result<(), String> {
        p.call_with_flags::<_, _, OwnedValue>(method, MethodFlags::AllowInteractiveAuth.into(), body)
            .map(|_| ())
            .or_else(|e| {
                // Already there (or already gone) is the outcome we wanted.
                let msg = e.to_string();
                if msg.contains("ALREADY_ENABLED") || msg.contains("NOT_ENABLED") { Ok(()) } else { Err(msg) }
            })
            .map_err(|e| if e.contains("NotAuthorized") || e.contains("AccessDenied") { "Permission was not given.".into() } else { e })
    }

    fn config_zone<'a>(conn: &'a Connection, zone: &str) -> Result<Proxy<'a>, String> {
        let config = Proxy::new(conn, DEST, "/org/fedoraproject/FirewallD1/config", "org.fedoraproject.FirewallD1.config")
            .map_err(|e| e.to_string())?;
        let path: OwnedObjectPath = config.call("getZoneByName", &(zone,)).map_err(|e| e.to_string())?;
        Proxy::new(conn, DEST, path, "org.fedoraproject.FirewallD1.config.zone").map_err(|e| e.to_string())
    }

    /// Open `port`/tcp in `zone`, for now and after reboots.
    pub fn allow(zone: &str, port: u16) -> Result<(), String> {
        let conn = Connection::system().map_err(|e| e.to_string())?;
        let p = port.to_string();
        auth_call(&zone_api(&conn).map_err(|e| e.to_string())?, "addPort", &(zone, p.as_str(), "tcp", 0i32))?;
        auth_call(&config_zone(&conn, zone)?, "addPort", &(p.as_str(), "tcp"))
    }

    pub fn remove(zone: &str, port: u16) -> Result<(), String> {
        let conn = Connection::system().map_err(|e| e.to_string())?;
        let p = port.to_string();
        auth_call(&zone_api(&conn).map_err(|e| e.to_string())?, "removePort", &(zone, p.as_str(), "tcp"))?;
        auth_call(&config_zone(&conn, zone)?, "removePort", &(p.as_str(), "tcp"))
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::Firewall;
    pub fn check(_: u16) -> Firewall {
        Firewall::NotManaged
    }
    pub fn allow(_: &str, _: u16) -> Result<(), String> {
        Ok(())
    }
    pub fn remove(_: &str, _: u16) -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{allow, check, remove};

#[cfg(test)]
mod tests {
    use super::port_allowed;

    #[test]
    fn port_rules() {
        let p = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        assert!(port_allowed("ACCEPT", &[], 47645), "trusted zone");
        assert!(port_allowed("default", &p(&[("1025-65535", "tcp")]), 47645), "Fedora Workstation's stock range");
        assert!(port_allowed("default", &p(&[("47645", "tcp")]), 47645));
        assert!(!port_allowed("default", &p(&[("47645", "udp")]), 47645));
        assert!(!port_allowed("default", &p(&[("1025-2000", "tcp")]), 47645));
        assert!(!port_allowed("default", &[], 47645), "your current zones");
    }
}
