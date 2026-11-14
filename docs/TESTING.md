# Real-device testing

Automated tests (`cargo test --workspace`) cover the TLS chain and name constraints,
access control, uploads, downloads and session end over real HTTPS on 127.0.0.1.
They cannot prove how a real phone behaves. Record real results here; a test that
was not run stays NOT RUN.

| # | Test | Device / OS | Result | Notes |
|---|------|-------------|--------|-------|
| 1 | Firewall: Allow button opens the port; Remove closes it | Fedora 44 | NOT RUN | |
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
