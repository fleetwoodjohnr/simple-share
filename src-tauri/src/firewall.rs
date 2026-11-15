//! Letting phones reach the share port through firewalld (Fedora, RHEL, openSUSE…).
//!
//! Nothing here changes anything until the person clicks "Allow". Then one
//! polkit password prompt adds this single TCP port, and mDNS if it is not
//! allowed yet (phones need it to look up the `.local` name), to the zone of the
//! network interface, now and permanently. "Remove firewall rule" undoes exactly
//! that.
//! Other systems need nothing: Windows and macOS ask by themselves the first
//! time the app listens, and most other Linux setups have no firewall running.

use crate::store::FirewallRule;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "camelCase")]
pub enum Firewall {
    /// No firewalld (or not Linux): nothing for Simple Share to do.
    NotManaged,
    Open,
    Blocked {
        zone: String,
        /// The share port needs opening.
        port: bool,
        /// mDNS needs opening.
        mdns: bool,
    },
}

/// Is `port`/`proto` allowed by these zone settings? Pure, so it is tested.
pub fn port_allowed(target: &str, ports: &[(String, String)], port: u16, proto: &str) -> bool {
    target.eq_ignore_ascii_case("ACCEPT")
        || ports.iter().any(|(p, pr)| {
            pr == proto
                && match p.split_once('-') {
                    Some((a, b)) => a.parse::<u16>().is_ok_and(|a| a <= port) && b.parse::<u16>().is_ok_and(|b| port <= b),
                    None => p.parse::<u16>().is_ok_and(|p| p == port),
                }
        })
}

/// Can phones send mDNS lookups (UDP 5353) to us?
pub fn mdns_allowed(target: &str, ports: &[(String, String)], services: &[String]) -> bool {
    services.iter().any(|s| s == "mdns") || port_allowed(target, ports, 5353, "udp")
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{Firewall, FirewallRule, mdns_allowed, port_allowed};
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
            let services = settings.get("services").and_then(|v| Vec::<String>::try_from(v.try_clone().ok()?).ok()).unwrap_or_default();
            let (port_ok, mdns_ok) = (port_allowed(&target, &ports, port, "tcp"), mdns_allowed(&target, &ports, &services));
            Ok(if port_ok && mdns_ok { Firewall::Open } else { Firewall::Blocked { zone, port: !port_ok, mdns: !mdns_ok } })
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

    /// Open `port`/tcp in `zone`, and mDNS with `mdns`, for now and after reboots.
    pub fn allow(zone: &str, port: u16, mdns: bool) -> Result<(), String> {
        let conn = Connection::system().map_err(|e| e.to_string())?;
        let (runtime, config) = (zone_api(&conn).map_err(|e| e.to_string())?, config_zone(&conn, zone)?);
        let p = port.to_string();
        auth_call(&runtime, "addPort", &(zone, p.as_str(), "tcp", 0i32))?;
        auth_call(&config, "addPort", &(p.as_str(), "tcp"))?;
        if mdns {
            auth_call(&runtime, "addService", &(zone, "mdns", 0i32))?;
            auth_call(&config, "addService", &("mdns",))?;
        }
        Ok(())
    }

    pub fn remove(rule: &FirewallRule) -> Result<(), String> {
        let conn = Connection::system().map_err(|e| e.to_string())?;
        let (runtime, config) = (zone_api(&conn).map_err(|e| e.to_string())?, config_zone(&conn, &rule.zone)?);
        let p = rule.port.to_string();
        auth_call(&runtime, "removePort", &(rule.zone.as_str(), p.as_str(), "tcp"))?;
        auth_call(&config, "removePort", &(p.as_str(), "tcp"))?;
        if rule.mdns {
            auth_call(&runtime, "removeService", &(rule.zone.as_str(), "mdns"))?;
            auth_call(&config, "removeService", &("mdns",))?;
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use super::{Firewall, FirewallRule};
    pub fn check(_: u16) -> Firewall {
        Firewall::NotManaged
    }
    pub fn allow(_: &str, _: u16, _: bool) -> Result<(), String> {
        Ok(())
    }
    pub fn remove(_: &FirewallRule) -> Result<(), String> {
        Ok(())
    }
}

pub use imp::{allow, check, remove};

#[cfg(test)]
mod tests {
    use super::{mdns_allowed, port_allowed};

    fn p(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn port_rules() {
        assert!(port_allowed("ACCEPT", &[], 47645, "tcp"), "trusted zone");
        assert!(port_allowed("default", &p(&[("1025-65535", "tcp")]), 47645, "tcp"), "Fedora Workstation's stock range");
        assert!(port_allowed("default", &p(&[("47645", "tcp")]), 47645, "tcp"));
        assert!(!port_allowed("default", &p(&[("47645", "udp")]), 47645, "tcp"));
        assert!(!port_allowed("default", &p(&[("1025-2000", "tcp")]), 47645, "tcp"));
        assert!(!port_allowed("default", &[], 47645, "tcp"), "your FedoraWorkstation zone");
    }

    #[test]
    fn mdns_rules() {
        let svc = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(mdns_allowed("default", &[], &svc(&["ssh", "mdns"])), "your work zone");
        assert!(mdns_allowed("default", &p(&[("5353", "udp")]), &[]));
        assert!(mdns_allowed("ACCEPT", &[], &[]));
        assert!(!mdns_allowed("default", &p(&[("1025-65535", "tcp")]), &svc(&["dhcpv6-client"])), "TCP ranges don't cover it");
        assert!(!mdns_allowed("default", &[], &svc(&["dhcpv6-client"])), "your FedoraWorkstation zone");
    }
}
