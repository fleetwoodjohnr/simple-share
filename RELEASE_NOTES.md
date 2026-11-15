**New in 0.2.0:**
- **Phones you allow are remembered.** Leave "Remember this device" ticked and that phone connects by itself whenever sharing is on, from a bookmark or the QR code, with no question. See and forget them in Settings → Allowed devices.
- **A `.local` address.** Each computer gets its own random name, like `https://k7m3x9p2q.local`, that stays the same when its IP address changes. On Linux it includes a port number (`:47645`). Phones that can't open `.local` names use "Phone can't open it? Use the IP address".
- **Even more secure:** TLS 1.3 only; each QR code works for one scan; both screens show the same 6-digit code before you allow a device; paired phones refuse any other certificate for this address outright (HSTS); the certificate can only vouch for this computer's name and private addresses.
- **Pair your phones once more.** The certificate now names this computer's `.local` address, so phones paired with 0.1 need to install the new one (Settings → Pairing shows the new fingerprint). On Fedora, Simple Share may ask once more to open the firewall, for mDNS.

Simple Share lets any phone, tablet or computer on your network send files to this computer and download files from it, in the browser, with no app to install on the phone.

**Security:** every connection is HTTPS (TLS 1.3). Each device must be allowed on the computer before it can do anything, after you check a matching code; only phones you choose to remember connect again by themselves, and nothing listens unless sharing is on. Phones you pair (install the computer's certificate once) get a verified connection with no warning; that certificate can only vouch for private network addresses, never websites. Received files are never overwritten and are reported as saved only once they are on disk, with a SHA-256 shown on both screens. No account, cloud service or telemetry.

**Install** (x64 and ARM64):
- **Windows:** run the matching `setup.exe`. It is not signed with a Microsoft certificate, so SmartScreen may say "Windows protected your PC": choose More info → Run anyway. Windows 10 22H2+ or 11 (ARM64: Windows 11).
- **macOS:** open the matching DMG and drag Simple Share to Applications. It is not notarised by Apple, so the first launch is blocked: open System Settings → Privacy & Security and choose **Open Anyway**. Allow it to find devices on your local network when asked. macOS 13 or later.
- **Linux:** install the DEB or RPM for your distribution, or use the AppImage. Needs GTK/WebKitGTK 4.1 (Ubuntu 22.04+, Debian 12+, Fedora 38+). On Fedora and other firewalld systems Simple Share offers to open its one port (and mDNS) for you.

**Updates:** Simple Share checks this page at startup and daily (Settings → About & updates to turn it off) and installs only when you choose Install and restart. Every update is verified against Simple Share's release-signing key before it is installed, on every system. Linux DEB/RPM updates ask for your password.

**Tray:** Simple Share lives in the system tray (menu bar on macOS) so sharing can keep running with the window closed; choose Quit there to exit. Some Linux desktops need an AppIndicator extension to show tray icons; without one, closing the window quits.
