# PortSpecter

Native Rust / Iced network scanning workspace. Community development build, with an independent TCP/UDP engines, multi-subnet target plans and offline MAC vendor identification.

## Run

Install stable Rust (1.99 or newer). On Windows install Visual Studio C++ Build Tools and a Windows SDK. On Ubuntu 24.04 install `build-essential pkg-config libfontconfig1-dev libxkbcommon-dev libwayland-dev libx11-dev libxrandr-dev libxi-dev libxcursor-dev libgl1-mesa-dev libdbus-1-dev iproute2 iputils-ping`. macOS requires Xcode command line tools.

```sh
cargo run -p portspecter-desktop
```

Release executable:

```sh
cargo build --release -p portspecter-desktop
```

Nothing is scanned on application startup. Enter your targets, choose a scan method and common or custom ports, and click **Start scan** once. Input validation and hostname resolution happen automatically before scanning; invalid input is shown without a second confirmation step. **Open ports only** is enabled by default and can be unchecked to inspect all targets. This filter affects the results view, not which targets are scanned. All results and settings stay in the local application data directory. Fonts and the MACLookup snapshot are embedded; no cloud account or runtime vendor API is required.

The **Well-known ports** checkbox is selected by default and uses 11 common TCP ports: `21,22,53,80,135,139,443,445,3389,5900,8080`. Select **Extended port scan** for the previous 34-port list, including email, databases and additional web services. A /24 with 254 hosts therefore schedules 2,794 TCP checks by default instead of 8,636; retries and discovery are additional work. Uncheck it to enter your own ports or ranges. Switching it back on preserves your custom input for the current workspace. Saved profiles and queued scans retain their exact selected port list; older 34-port presets load with extended scanning selected.

Keyboard: `F5` validates targets and starts the scan with one press. `F8` pauses/resumes; `F9` stops. `F12` saves a developer screenshot of this application only to `artifacts/portspecter-current.png`.

## Multiple subnets / VLANs

One target per line; IPs, CIDRs, ranges and hostnames are accepted. Labels and VLAN IDs are optional:

Both `192.168.2.1-255` and `192.168.2.1-192.168.2.255` select the inclusive range from `.1` to `.255`. A host address with CIDR, such as `192.168.2.1/24`, selects the network `192.168.2.0/24` and its 254 usable host addresses (`.1`–`.254`).

```text
192.168.10.0/24 | Workstations | 10
192.168.20.0/24 | Servers | 20
10.10.30.1-10.10.30.50 | Management | 30
```

VLAN IDs are user labels. The application uses existing OS/VPN routes and never configures a switch or creates a VLAN. Overlapping targets are scanned once and keep all their group memberships. Source IP binding is available under Advanced options; it is not a guarantee of physical interface selection.

Import `.txt` or `.csv` using the UI. CSV has a required `target` column and optional `name` and `vlan_id` columns. Exclusions accept IPs and CIDRs. A session is limited to 65,536 unique hosts and 10 million host/port checks. IPv6 link-local addresses requiring a scope ID are currently rejected explicitly.

## Features in this build

- TCP connect, UDP and native IPv4 SYN; bounded concurrency, rate limiting, timeout/retry, pause/cancel and subnet controls.
- Live device results, IP/MAC/vendor/service search, subnet filters and port inspection.
- Local neighbor MAC observations, credential-free NetBIOS MAC queries for responding IPv4 targets, and offline longest-prefix vendor matching (24/28/36-bit).
- Banner, HTTP and TLS inspection; port-number hints are marked `?`.
- ICMP reachability discovery; reverse DNS, NetBIOS and on-link mDNS/LLMNR name discovery.
- SQLite history and scope-aware comparison of devices and ports; different scan methods are not compared.
- Saved target/port profiles, persistent scan queue, completion banner and taskbar/dock attention.
- CSV and versioned JSON export, including ICMP observations.
- Custom title bar with minimize, maximize/restore, close and resize controls.
- Turkish / English interface and dark / light themes.

MACs are read from the exact local neighbor entry, not inferred from a routed destination's gateway. Local/private MACs have no inferred vendor. A cache entry is not proof that a host is currently reachable. Linux MAC lookup requires `iproute2`; macOS uses the system `arp`/`ndp` tools without invoking a shell. Windows uses IP Helper directly.

Selecting a device displays its current source/interface/next-hop route and explains missing MAC information for routed or VPN destinations. Route diagnostics describe the current connection, not the historical route of a saved scan. A read-only diagnostic is also available: `cargo run -p portspecter-platform --example inspect_network -- <IP>`. It reads local neighbor and routing tables without sending scan packets.

When no local MAC is cached, each responding non-loopback IPv4 host receives at most one unicast NetBIOS node-status query (UDP 137), using the scan's source address, rate budget, cancellation and bounded job pool. A valid target-reported UNIT_ID is stored with `netbios_node_status` provenance and vendor lookup. NetBIOS must be enabled and reachable; timeouts, malformed responses and zero MACs leave the MAC unknown, without changing TCP port results. This is a MAC enrichment query, not UDP port scanning. Router/SNMP and remote-agent integrations remain separate future options. Protocol: [RFC 1002](https://datatracker.ietf.org/doc/html/rfc1002); comparable behavior: [SoftPerfect](https://www.softperfect.com/contact/knowledgebase.php?article=45).

The queue runs only after an explicit start, including after reopening the application. Closing cancels active work and waits for backend persistence. Route/interface changes pause a running scan for review; route monitoring samples one destination from each of up to 32 target blocks every five seconds.

ICMP is enabled for new scan settings. A missing ping reply is not treated as proof that a device is offline. The default open-port filter remains enabled; use the responding-devices filter to include ICMP-only devices. Windows uses its native ICMP API; Linux and macOS use their system ping programs. Name discovery can be disabled separately; mDNS and LLMNR enrichment is restricted to directly connected targets.

The custom title bar uses Iced window APIs. macOS has separate right/bottom resize grips because the underlying window library does not implement programmatic native drag-resize there. Native macOS validation remains required.

## UDP and native SYN

Choose **TCP connect**, **UDP**, or **TCP SYN** in the scan form. A session uses one method; save separate profiles or queue entries to scan multiple methods. Older profiles default to TCP connect. History/JSON retain the method; CSV includes protocol and scan_method.

UDP presets cover 5 ports (`53,123,137,161,5353`) or 11 extended ports. DNS and NTP receive a small protocol query; other ports receive an empty datagram. A UDP response means open, a reported port-unreachable means closed, and silence means open-or-filtered. This is not complete UDP service identification. TCP banner/TLS inspection is disabled in UDP and SYN mode.

The SYN motor is Rust code using dynamically loaded Npcap/libpcap, with one capture thread per source interface. It builds IPv4/TCP checksums, correlates replies using addresses, ports and randomized sequence numbers, recognizes SYN-ACK/RST and quoted ICMP errors, and sends RST after an open response. It uses the OS route and ARP to resolve the next hop on Ethernet. Next-hop MACs are for packet delivery only, never assigned to remote devices as their identity. Route changes invalidate raw capture workers. Cancelled requests are removed and capture handles close when the session ends.

- Windows requires a separately installed [Npcap](https://npcap.com/guide/npcap-devguide.html); its installation policy may require Administrator capture access. No driver is installed or bundled automatically.
- Linux requires libpcap (for example Ubuntu's `libpcap0.8t64`) and capture/injection permissions.
- macOS uses system libpcap and requires access to `/dev/bpf` capture devices.
- Supported link formats: Ethernet, NULL/LOOP and raw IPv4. Unsupported VPN/tunnel link formats report an error; there is no silent TCP-connect fallback.
- SYN currently supports IPv4 only. Use TCP connect for IPv6. SYN capture/injection is experimental until native testing with the driver is completed on each platform.

Name enrichment is separate from port probing: when enabled, it can use ICMP, NetBIOS, mDNS and LLMNR (including a TCP PTR request on 5355). Local names can be queried even when the first scanned port does not respond. Valid on-link name responses count in the responding-devices filter; reverse DNS alone does not prove reachability.

Protocol references: [LLMNR RFC 4795](https://www.rfc-editor.org/info/rfc4795/), [mDNS RFC 6762](https://www.rfc-editor.org/rfc/rfc6762.html), [SYN response states](https://nmap.org/book/synscan.html), [UDP response states](https://nmap.org/book/scan-methods-udp-scan.html). Nmap is not a runtime dependency.

## Application icons

The Windows EXE embeds `assets/icons/portspecter.ico` through the desktop build script. The ICO contains 16, 24, 32, 48, 64, 128 and 256 pixel images. The native window uses the same PNG artwork for its window/taskbar icon. After replacing the master PNG, regenerate the ICO on Windows with `./scripts/build-windows-icon.ps1`, then rebuild. macOS packaging generates its `.icns` from the same master using `sips` and `iconutil`.

## Linux and macOS packages

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

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Integration tests bind only loopback services. With the capture driver and permissions available, run the explicit native SYN test: `cargo test -p portspecter-platform native_loopback -- --ignored`. It checks open/closed responses and that no TCP handshake completes. See [development status](docs/STATUS.md) for verified platforms and remaining milestones. No claim of macOS/Linux runtime validation is made from a Windows build.

## Data and licensing

Community code: Apache-2.0. Enterprise features are not implemented in this repository. MACLookup data and embedded fonts retain their own terms; see `NOTICE` and `assets/data/SOURCE.json`. The vendor snapshot can be refreshed using `scripts/update-vendors.ps1`; refresh is an explicit development action, never an automatic startup request.
## Camera discovery and shared folders

In **Settings → Device and share discovery**, enable **ONVIF** and/or **Hikvision SADP** before starting a scan. These optional IPv4 multicast probes run once per relevant local interface (approximately three seconds), merge both protocols into the existing IP device record, and retain protocol-specific evidence. Results outside the target/exclusion scope are discarded. Normal multicast does not cross routed VLANs or most VPNs. Turn off the open-port-only filter to see discovered devices whose selected ports did not open.

The identity tab shows advertised ONVIF name/hardware/service endpoints and SADP model, serial, firmware, MAC and activation state when present. This is read-only discovery: no activation, network configuration, password changes, authenticated ONVIF device calls or video retrieval. Advertised URLs are not fetched automatically. Physical-camera/firmware interoperability still needs testing.

**List SMB shares (including hidden)** is enabled by default. An open **TCP 445** during a **TCP connect** scan triggers a bounded, read-only share enumeration. The identity tab lists disk shares, comments, copyable paths and a hidden marker for names ending in `$`, including administrative shares returned by the server. IPC and printer shares are omitted. Enumeration permission is separate from permission to read files; denied, unavailable, timeout and empty results are shown separately. Explicit source-IP selection disables SMB enumeration because the OS SMB client cannot honor that binding.

- Windows: native `NetShareEnum` level 1, using the current user identity, in a disposable helper process with an eight-second deadline. No extra installation.
- Linux: `smbclient` (included as a Debian package dependency), using anonymous enumeration and SMB2/3.
- macOS: `smbclient`, for example from `brew install samba`; Homebrew's ARM/Intel executable paths are detected. No automatic installation or credential collection.

Camera/share results survive history reload and appear in JSON (schema 3) and the CSV JSON columns. SQLite schema 4 migrates previous databases without deleting observations.

Protocol references: [ONVIF Core](https://www.onvif.org/specs/2312/ONVIF-Core-Spec-v2312.pdf), [SADP tooling implementation](https://github.com/cameronnewman/hikvision-tooling), [NetShareEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareenum), [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1).

## Dahua, DNS-SD, SSDP and device types

Enable the three optional protocols under **Settings → Device and share discovery**. They use source-bound IPv4 UDP sockets on relevant local interfaces and only accept devices inside the scan target/exclusion scope. No capture driver is required. The protocols run alongside ONVIF/SADP discovery; DNS-SD has a four-second window and SSDP allows a further four seconds for bounded description reads. These multicast mechanisms do not automatically traverse VLANs or VPNs.

- **Dahua:** DHIP `DHDiscover.search` multicast on UDP 37810. Parses framed device-info responses with IP correlation, serial/MAC, device class, model, advertised HTTP endpoint and available version fields. No initialization or configuration changes.
- **DNS-SD / Bonjour:** legacy-unicast mDNS browse queries on UDP 5353; common services plus `_services._dns-sd._udp.local` enumeration. Resolves PTR → SRV/TXT → A across separate responses. Service instances require an address record matching the responding target; proxy-advertised services belonging to other hosts are conservatively omitted. Advertised ports remain distinct from confirmed open ports. Work is bounded to 192 questions and 4,096 retained records per source interface, so very large service inventories may be partial.
- **SSDP / UPnP:** `M-SEARCH` on UDP 1900, deduplication by UDN, and same-target HTTP(S) description reads for name, manufacturer, model and device type. Foreign-IP/hostname locations, credentials and fragments are rejected; redirects and system proxies are disabled. TLS certificates are validated. At most 32 distinct descriptions are fetched per interface, four concurrently, with 128 KiB and deadline limits. Unavailable descriptions retain the discovery evidence and an explanation.
- **Device type filters:** camera, NVR/DVR, printer, router, switch, file server/NAS, media device, computer and unknown. Types are inferred from explicit device/service evidence rather than open ports or vendor names alone. Multiple roles can match one device. Unsupported device classes remain unknown; a switch or computer is not guaranteed to advertise a recognizable class. Existing open-port/subnet/search filters still apply independently.

The identity panel shows the source protocol and classification evidence. Names/MACs reported by discovery can fill the display when DNS/neighbor data is absent. Records persist in SQLite schema 5 and JSON schema 4, with a `device_advertisements_json` CSV column; even devices without any completed port observations get a CSV row with empty port/state fields.

Implemented and tested with bounded packet fixtures and local UDP/HTTP responders. Physical Dahua firmware, Bonjour and UPnP interoperability and native Linux/macOS runtime checks are still required. Protocol references: [DNS-SD RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763), [mDNS RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762), [OCF UPnP](https://openconnectivity.org/foundation/faq/upnp-faq/), [DHIP framing reference](https://github.com/OpenIPC/python-dhip/blob/master/dahua/discovery.py).
