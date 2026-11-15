# Real-device testing

Automated tests (`cargo test --workspace`) cover the TLS chain and name constraints,
TLS 1.3-only, access control, one-scan codes, remembered devices, uploads, downloads
and session end over real HTTPS on 127.0.0.1 as a `.local` name.
They cannot prove how a real phone behaves. Record real results here; a test that
was not run stays NOT RUN.

| # | Test | Device / OS | Result | Notes |
|---|------|-------------|--------|-------|
| 1 | Firewall: Allow button opens the port and mDNS; Remove closes them | Fedora 44 | NOT RUN | FedoraWorkstation zone lacks both |
| 2 | Guest: scan QR, warning, Allow on computer, page loads | iPhone, iOS 26 | NOT RUN | |
| 3 | Upload one photo; saved name + SHA-256 match on both screens | iPhone, iOS 26 | NOT RUN | HEIC kept or converted? |
| 4 | Upload several photos and a video at once | iPhone, iOS 26 | NOT RUN | |
| 5 | Upload a ~1 GB video; note time (MB/s) | iPhone, iOS 26 | NOT RUN | |
| 6 | Cancel mid-upload; no `.simple-share-partial-*` left | iPhone, iOS 26 | NOT RUN | |
| 7 | Download a shared PDF; "Sent to iPhone" shown | iPhone, iOS 26 | NOT RUN | |
| 8 | Get for Photos → Save to Photos on an image and a video | iPhone, iOS 26 | NOT RUN | |
| 9 | Pair: install certificate, trust it, fingerprint matches Settings | iPhone, iOS 26 | NOT RUN | |
| 10 | After pairing: no warning on the next session | iPhone, iOS 26 | NOT RUN | |
| 11 | Deny a device; it sees "Not allowed" | iPhone, iOS 26 | NOT RUN | |
| 12 | Stop sharing while connected; phone shows "Sharing has ended" | iPhone, iOS 26 | NOT RUN | |
| 13 | Idle auto-stop after the set time | Fedora 44 | NOT RUN | |
| 14 | Idle CPU/memory while sharing | Fedora 44 | NOT RUN | |
| 15 | Tray icon registered; menu Open / Start sharing / Quit; Start switches label to Stop and icon to the green-dot variant; port 47645 listens on the LAN IP | Fedora 44 (GNOME + AppIndicator), v0.1.0 release build | PASS (2026-11-14) | driven through the tray's D-Bus menu (same path as a click), not by mouse |
| 16a | Quit from the tray exits and closes the port | Fedora 44, release build | PASS (2026-11-14) | `ss -ltn` showed no 47645 after Quit |
| 16b | Closing the window hides to the tray; Open brings it back | Fedora 44 | NOT RUN | |
| 17 | Launch at login + Start in the tray | Fedora 44 | NOT RUN | |
| 18 | Installed v0.1.0 offers v0.1.1 and installs it after "Install and restart" | each OS | NOT RUN | needs a second release |
| 19 | Windows installer and tray (built by CI) | Windows 11 | NOT RUN | built, not device-tested |
| 20 | macOS DMG, Open Anyway, menu-bar icon (built by CI) | macOS 13+ | NOT RUN | built, not device-tested |
| 21 | `.local` name resolves and serves while sharing; gone after Stop | Fedora 44 (Avahi), scratch build | PASS (2026-11-15) | `avahi-resolve` + `getent` gave the LAN IP; verified TLS 1.3 by name; TLS 1.2 refused; HSTS only by name; name and port gone after stop |
| 22 | QR opens `https://<code>.local:47645` (Linux) in Safari | iPhone, iOS 26 | NOT RUN | |
| 23 | Codes match on phone and computer; Allow with Remember | iPhone, iOS 26 | NOT RUN | |
| 24 | Stop, start again: bookmark opens with no approval; "connected" notification | iPhone, iOS 26 | NOT RUN | |
| 25 | Forget in Settings cuts off a connected phone at once | iPhone, iOS 26 | NOT RUN | |
| 26 | Paired phone: no warning on `.local`; after Reset certificate it refuses (HSTS) and the IP code works | iPhone, iOS 26 | NOT RUN | |
| 27 | Android 12+ opens the `.local` code; older Android uses the IP code | Android | NOT RUN | |
| 28 | A used QR code shows "This code has been used" on a second phone | any | NOT RUN | |
| 29 | macOS asks for Local Network access; name resolves after Allow | macOS 15 | NOT RUN | built, not device-tested |
| 30 | Windows and macOS: the code is `https://<code>.local` with no port (443); with 443 taken, it falls back to `:47645`. macOS: a connection to another of the Mac's addresses (e.g. a VPN) is dropped | Windows 11, macOS 15 | NOT RUN | dropping is unit-tested on Linux |
