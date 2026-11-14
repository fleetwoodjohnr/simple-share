**New in 0.1.1:** Settings looks right again. The "Stop sharing after", "Largest file accepted", "Theme" and "Port" boxes no longer stretch across the whole row and squeeze their labels into a narrow column.

Simple Share lets any phone, tablet or computer on your network send files to this computer and download files from it, in the browser, with no app to install on the phone.

**Security:** every connection is HTTPS. Each device must be allowed on the computer before it can do anything, and access ends when sharing stops. Phones you pair (install the computer's certificate once) get a verified connection with no warning; that certificate can only vouch for private network addresses, never websites. Received files are never overwritten and are reported as saved only once they are on disk, with a SHA-256 shown on both screens. No account, cloud service or telemetry.

**Install** (x64 and ARM64):
- **Windows:** run the matching `setup.exe`. It is not signed with a Microsoft certificate, so SmartScreen may say "Windows protected your PC": choose More info → Run anyway. Windows 10 22H2+ or 11 (ARM64: Windows 11).
- **macOS:** open the matching DMG and drag Simple Share to Applications. It is not notarised by Apple, so the first launch is blocked: open System Settings → Privacy & Security and choose **Open Anyway**. macOS 13 or later.
- **Linux:** install the DEB or RPM for your distribution, or use the AppImage. Needs GTK/WebKitGTK 4.1 (Ubuntu 22.04+, Debian 12+, Fedora 38+). On Fedora and other firewalld systems Simple Share offers to open its one port for you.

**Updates:** Simple Share checks this page at startup and daily (Settings → About & updates to turn it off) and installs only when you choose Install and restart. Every update is verified against Simple Share's release-signing key before it is installed, on every system. Linux DEB/RPM updates ask for your password.

**Tray:** Simple Share lives in the system tray (menu bar on macOS) so sharing can keep running with the window closed; choose Quit there to exit. Some Linux desktops need an AppIndicator extension to show tray icons; without one, closing the window quits.
