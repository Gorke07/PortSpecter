# Installation and packaging

[Back to README](../README.md)

## Build from source

Install stable Rust (1.99 or newer). On Windows install Visual Studio C++ Build Tools and a Windows SDK. On Ubuntu 24.04 install `build-essential pkg-config libfontconfig1-dev libxkbcommon-dev libwayland-dev libx11-dev libxrandr-dev libxi-dev libxcursor-dev libgl1-mesa-dev libdbus-1-dev iproute2 iputils-ping`. macOS requires Xcode command line tools.

```sh
cargo run --locked -p portspecter-desktop
```

Release executable:

```sh
cargo build --release --locked -p portspecter-desktop
```

Nothing is scanned on application startup. Enter your targets, choose a scan method and common or custom ports, and click **Start scan** once. Input validation and hostname resolution happen automatically before scanning; invalid input is shown without a second confirmation step. **Open ports only** is enabled by default and can be unchecked to inspect all targets. This filter affects the results view, not which targets are scanned. All results and settings stay in the local application data directory. Fonts and the MACLookup snapshot are embedded; no cloud account or runtime vendor API is required.

The **Well-known ports** checkbox is selected by default and uses 11 common TCP ports: `21,22,53,80,135,139,443,445,3389,5900,8080`. Select **Extended port scan** for the previous 34-port list, including email, databases and additional web services. A /24 with 254 hosts therefore schedules 2,794 TCP checks by default instead of 8,636; retries and discovery are additional work. Uncheck it to enter your own ports or ranges. Switching it back on preserves your custom input for the current workspace. Saved profiles and queued scans retain their exact selected port list; older 34-port presets load with extended scanning selected.

Keyboard: `F5` validates targets and starts the scan with one press. `F8` pauses/resumes; `F9` stops. `F12` saves a developer screenshot of this application only to `artifacts/portspecter-current.png`.

## Native packages

Native packaging requires Python 3.11+ and runs on the target OS:

```sh
python3 scripts/package.py --check
python3 scripts/package.py
```

The second command builds the release binary and writes packages to `artifacts/packages/`. It does not install anything or grant permissions on the build machine. `--binary <path>` can package an existing native binary; CI uses its debug executable for development packaging smoke checks.

**Linux (Debian/Ubuntu):** install the normal build prerequisites plus `dpkg-dev`; the output is a `.deb`. ELF dependencies are generated with `dpkg-shlibdeps`, and libpcap/windowing runtime dependencies are included explicitly. Install with `sudo apt install ./portspecter_<version>_<architecture>.deb`. No capture capability is granted by installation. For optional IPv4 SYN:

```sh
sudo portspecter-packet-access enable
portspecter-packet-access status
sudo portspecter-packet-access disable
```

The enable command grants only `CAP_NET_RAW` to the root-owned `/usr/bin/portspecter` executable; it does not run the GUI as root. The grant applies to any local user who can execute that binary. It validates file ownership and permissions and refuses to replace unrelated capabilities. Package upgrades replace the binary and may clear the capability: run status and explicitly enable it again if needed. RPM/AppImage packaging is not implemented.

**macOS 14+:** the `.dmg` contains `PortSpecter.app`, an Applications shortcut, setup notes and `Optional SYN Packet Access.pkg`. Drag the app into Applications for normal TCP connect/UDP use. Only install the optional package when SYN is needed. It requests administrator authorization and adds the currently logged-in desktop user to the shared `access_bpf` group. A root launch daemon grants that group read/write access to existing `/dev/bpf*` devices at startup and every 30 seconds, including nodes created later. Log out and back in after setup. This is user-level packet capture/injection access, not an app-only permission; no Npcap or new kernel driver is installed. The installer only targets the currently running system and requires a normal desktop user to be logged in.

Remove the optional macOS setup with:

```sh
sudo '/Library/Application Support/PortSpecter/PacketAccess/packet-access' remove
```

Removal unloads the PortSpecter daemon and removes only group memberships this installer added. Pre-existing membership, the shared group and device permissions used by other capture programs are retained. Log out and back in to refresh group membership; removing membership can also affect other capture apps used by that same user.

macOS development builds are ad-hoc signed. To use your own signing certificates, set `PORTSPECTER_SIGN_IDENTITY` (Developer ID Application) and `PORTSPECTER_INSTALLER_IDENTITY` (Developer ID Installer). The script does not upload or notarize artifacts. A public macOS release still requires appropriate signing, notarization and native installation/runtime verification; no Gatekeeper bypass is included.

Packaging CI builds development packages on Ubuntu, Apple Silicon macOS and Intel macOS and uploads them as workflow artifacts. These steps are configured, not evidence of a successful remote CI run. Local Windows validation covers source checks, shell syntax, Python compilation and plist structure; actual package creation, installation, removal and SYN access must be tested on the target OS.

## Application icons

The Windows EXE embeds `assets/icons/portspecter.ico` through the desktop build script. The ICO contains 16, 24, 32, 48, 64, 128 and 256 pixel images. The native window uses the same PNG artwork for its window/taskbar icon. After replacing the master PNG, regenerate the ICO on Windows with `./scripts/build-windows-icon.ps1`, then rebuild. macOS packaging generates its `.icns` from the same master using `sips` and `iconutil`.
