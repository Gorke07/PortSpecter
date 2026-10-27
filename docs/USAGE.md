# User guide

[Back to README](../README.md)

## Device details and workspace

After a scan starts or a saved session loads, scan controls collapse into a compact summary. Use **Edit / new scan** to reopen them; pause/stop remain available during scanning.

| Tab | Contents |
| --- | --- |
| Overview | Device type/evidence, name and MAC sources, current route and target scope |
| Ports | Confirmed results, optional other states and expandable service evidence |
| Discovery | Expandable protocol records, advertised endpoints and metadata |
| Shares | SMB disk shares, hidden markers, paths and enumeration status |

Port-number hints are marked `?`. Reported service ports are not confirmed open ports. Route details describe the current OS connection, including when viewing saved history.

## Performance, history and exports

Worker threads can be configured from 1 to 256. Worker count, global/per-host concurrency, attempt rate, timeouts and retries are separate limits. More threads do not guarantee a faster scan; start with defaults and measure a small scope.

History compares common scope between sessions using the same method; an untested port is not treated as closed. Profiles preserve exact port lists. Queue entries are snapshots and require an explicit start after restart. Closing the application cancels work and waits for persistence.

SQLite stores sessions/settings in the OS application-data directory. `PORTSPECTER_DATA_DIR` overrides it for isolated development. Close the app before backing up the database and its WAL sidecars. Do not publish real databases or exports in bug reports.

Current formats: SQLite schema **5**, JSON export schema **4**. Discovery-only devices can have empty CSV port/state fields. See [Troubleshooting](TROUBLESHOOTING.md) for missing names/MACs, discovery and share permissions.

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

## Camera discovery and shared folders

In **Settings → Device and share discovery**, enable **ONVIF** and/or **Hikvision SADP** before starting a scan. These optional IPv4 multicast probes run once per relevant local interface (approximately three seconds), merge both protocols into the existing IP device record, and retain protocol-specific evidence. Results outside the target/exclusion scope are discarded. Normal multicast does not cross routed VLANs or most VPNs. Turn off the open-port-only filter to see discovered devices whose selected ports did not open.

The Discovery tab shows advertised ONVIF name/hardware/service endpoints and SADP model, serial, firmware, MAC and activation state when present. This is read-only discovery: no activation, network configuration, password changes, authenticated ONVIF device calls or video retrieval. Advertised URLs are not fetched automatically. Physical-camera/firmware interoperability still needs testing.

**List SMB shares (including hidden)** is enabled by default. An open **TCP 445** during a **TCP connect** scan triggers a bounded, read-only share enumeration. The Shares tab lists disk shares, comments, copyable paths and a hidden marker for names ending in `$`, including administrative shares returned by the server. IPC and printer shares are omitted. Enumeration permission is separate from permission to read files; denied, unavailable, timeout and empty results are shown separately. Explicit source-IP selection disables SMB enumeration because the OS SMB client cannot honor that binding.

- Windows: native `NetShareEnum` level 1, using the current user identity, in a disposable helper process with an eight-second deadline. No extra installation.
- Linux: `smbclient` (included as a Debian package dependency), using anonymous enumeration and SMB2/3.
- macOS: `smbclient`, for example from `brew install samba`; Homebrew's ARM/Intel executable paths are detected. No automatic installation or credential collection.

Camera/share results survive history reload and appear in JSON (schema 4) and the CSV JSON columns. SQLite schema 5 migrates previous databases without deleting observations.

Protocol references: [ONVIF Core](https://www.onvif.org/specs/2312/ONVIF-Core-Spec-v2312.pdf), [SADP tooling implementation](https://github.com/cameronnewman/hikvision-tooling), [NetShareEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmshare/nf-lmshare-netshareenum), [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1).

## Dahua, DNS-SD, SSDP and device types

Enable the three optional protocols under **Settings → Device and share discovery**. They use source-bound IPv4 UDP sockets on relevant local interfaces and only accept devices inside the scan target/exclusion scope. No capture driver is required. The protocols run alongside ONVIF/SADP discovery; DNS-SD has a four-second window and SSDP allows a further four seconds for bounded description reads. These multicast mechanisms do not automatically traverse VLANs or VPNs.

- **Dahua:** DHIP `DHDiscover.search` multicast on UDP 37810. Parses framed device-info responses with IP correlation, serial/MAC, device class, model, advertised HTTP endpoint and available version fields. No initialization or configuration changes.
- **DNS-SD / Bonjour:** legacy-unicast mDNS browse queries on UDP 5353; common services plus `_services._dns-sd._udp.local` enumeration. Resolves PTR → SRV/TXT → A across separate responses. Service instances require an address record matching the responding target; proxy-advertised services belonging to other hosts are conservatively omitted. Advertised ports remain distinct from confirmed open ports. Work is bounded to 192 questions and 4,096 retained records per source interface, so very large service inventories may be partial.
- **SSDP / UPnP:** `M-SEARCH` on UDP 1900, deduplication by UDN, and same-target HTTP(S) description reads for name, manufacturer, model and device type. Foreign-IP/hostname locations, credentials and fragments are rejected; redirects and system proxies are disabled. TLS certificates are validated. At most 32 distinct descriptions are fetched per interface, four concurrently, with 128 KiB and deadline limits. Unavailable descriptions retain the discovery evidence and an explanation.
- **Device type filters:** camera, NVR/DVR, printer, router, switch, file server/NAS, media device, computer and unknown. Types are inferred from explicit device/service evidence rather than open ports or vendor names alone. Multiple roles can match one device. Unsupported device classes remain unknown; a switch or computer is not guaranteed to advertise a recognizable class. Existing open-port/subnet/search filters still apply independently.

The Overview and Discovery tabs show the source protocol and classification evidence. Names/MACs reported by discovery can fill the display when DNS/neighbor data is absent. Records persist in SQLite schema 5 and JSON schema 4, with a `device_advertisements_json` CSV column; even devices without any completed port observations get a CSV row with empty port/state fields.

Implemented and tested with bounded packet fixtures and local UDP/HTTP responders. Physical Dahua firmware, Bonjour and UPnP interoperability and native Linux/macOS runtime checks are still required. Protocol references: [DNS-SD RFC 6763](https://datatracker.ietf.org/doc/html/rfc6763), [mDNS RFC 6762](https://datatracker.ietf.org/doc/html/rfc6762), [OCF UPnP](https://openconnectivity.org/foundation/faq/upnp-faq/), [DHIP framing reference](https://github.com/OpenIPC/python-dhip/blob/master/dahua/discovery.py).
