# Simple Share

Send and receive files between this computer and any phone, tablet or computer on
your network — in the browser, with no app to install on the phone and no cloud
service. Part of Simple Suite.

1. **Start sharing** on the computer. A QR code appears.
2. Scan it with the phone's camera. The computer asks: **Allow this iPhone?**
3. The phone can now send photos, videos and files to the computer, and download
   anything you drop into Simple Share.

## Security

- **Encrypted, always.** Every connection is HTTPS (TLS 1.2/1.3).
- **Verified, once paired.** Phones you install the computer's certificate on get a
  verified connection with no warning, so nobody else on the network can intercept
  or alter transfers. The certificate is *name-constrained*: it can only vouch for
  private network addresses, never for a website, so installing it cannot be used
  to spy on the phone's other traffic (enforced by the phone, and covered by tests).
  Guests who haven't paired still get an encrypted connection after tapping
  through the browser's warning once.
- **Nothing without your OK.** The QR code holds a one-session secret; each device
  that uses it must then be allowed on the computer (denied after 2 minutes).
  Stopping sharing ends every device's access.
- **Hardened server.** Exact Host check (no DNS rebinding), CSRF header on uploads,
  no CORS, strict Content-Security-Policy, no-referrer, no-store.
- **Safe saving.** File names are reduced to a bare, safe name; nothing is ever
  overwritten (`photo (1).jpg`); uploads stream to a hidden temp file, are synced
  to disk, and only then reported as saved — with their SHA-256 on both screens.
  Incomplete or oversized uploads leave nothing behind.
- **Only what you choose.** Phones can download only files you added, by random id.
- **Closed when idle.** Nothing listens until you start; sharing stops itself after
  15 minutes without activity.
- **Firewall.** On Fedora and other firewalld systems Simple Share offers to open its
  one port (one password prompt) and can remove that rule again. Nothing changes
  without your click.
- No accounts, no telemetry.

## Tray and updates

- Simple Share sits in the system tray (menu bar on macOS): Open, Start/Stop sharing,
  Quit. Closing the window keeps it running there; on Linux desktops without a tray
  host, closing quits instead. Settings has Launch at login and Start in the tray.
- Updates come from this repository's GitHub Releases. The app checks at startup and
  daily (can be turned off), and installs only when you choose — and only if the
  update's signature matches the Simple Share release key built into the app.
- Builds are not signed with Microsoft or Apple developer certificates: Windows shows
  SmartScreen once (More info → Run anyway); macOS needs System Settings → Privacy &
  Security → Open Anyway on first launch. In-app updates don't prompt again.

## Releasing

Push a tag `vX.Y.Z` matching the version in `package.json`, `Cargo.toml` and
`src-tauri/tauri.conf.json`. GitHub Actions builds Windows, macOS and Linux (x64 and
ARM64), verifies every signature, and publishes the release with `latest.json`.
The signing key lives in `.release-keys/` (never committed) and in the repository
secrets `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`.
Keep a backup of `.release-keys/`: without it, installed copies can never be updated.

## Limits

- Both devices must be on the same network. Guest/hotel Wi-Fi with "client
  isolation" blocks this.
- Unpaired phones see a "not private" warning once per session. That is how browsers
  treat local devices; pairing removes it.
- iOS may convert HEIC photos to JPEG when picking from the photo library.

## Build

Requires Rust (1.90+) and Node 20+, plus the Tauri system packages for your OS.

```sh
npm install
npm run tauri dev      # run
npm run tauri build    # packages: deb/rpm/AppImage, MSI/NSIS, DMG
cargo test --workspace # security and protocol tests
```

## License

MIT OR Apache-2.0.
