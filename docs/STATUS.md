# Implementation status

This is the first working implementation milestone, not the completed release roadmap.

## Implemented

Six-crate workspace; native Iced desktop; one-action scan startup; open-port filter enabled by default; TCP engine; configurable 1-256 scan worker threads with independently scheduled probe tasks; OS reverse DNS and NetBIOS device names with provenance, persistence and export; multi-subnet planning; exclusion and overlapping-CIDR handling; per-host/global budgets; pause and cancel; local MAC observations; credential-free unicast NetBIOS MAC fallback for responding IPv4 hosts; embedded vendor lookup; basic banner/HTTP/TLS evidence; local SQLite history; saved profiles; CSV/JSON export; Turkish/English UI.

## Current milestone

Custom frameless title bar, minimize/maximize/restore/close, resize grips and graceful backend shutdown. Windows/Linux use native drag-resize; macOS uses right/bottom grips with an explicit resize fallback because Winit does not implement drag-resize on macOS.

The five accepted roadmap items now have implementations:

1. Cancellable rate reservations, pause handling and network-change monitoring. Interface and route snapshots are compared every five seconds for one representative from each of up to 32 target blocks; changes pause scanning.
2. Persisted ICMP discovery, filters and inspector/export support. Windows native IPv4/IPv6 echo; Linux/macOS bounded system ping processes. No reply is not an offline verdict.
3. On-link mDNS PTR and LLMNR TCP PTR enrichment after reverse DNS/NetBIOS, with strict packet parsing and recorded provenance.
4. History comparison limited to common scope, distinguishing closed ports from no longer observed ports and warning about incomplete or different scan scopes.
5. Saved target/port profiles, persistent queue snapshots, explicit queue start, completion banner and OS attention request. This is not an OS toast notification.

## Remaining release work

- Native macOS/Linux desktop runtime validation, accessibility checks and installer packages.
- Real network mDNS/LLMNR interoperability and physical VPN/route transition testing.
- Large-session GUI memory measurements, fully streamed exports and maximum-scale stress tests.
- Scoped IPv6 link-local targets, IPv6 SYN, broader raw-link/VPN support, standalone ARP discovery and remote agents remain future work.

## Current verification

Windows workspace: 47 tests and Clippy with warnings denied passed. Tests include ICMP IPv4/IPv6 loopback, cancellation while paused, queue state recovery, scope-aware comparisons, and malformed/compressed DNS packets. SQLite schema version 3 adds ICMP observations while preserving older sessions.

The platform crate passes locked cross-target checks for Linux x64, macOS Apple Silicon and macOS Intel. This is not a complete desktop cross-build or native runtime test. CI covers Windows, Ubuntu, Apple Silicon macOS and Intel macOS; remote CI execution has not been observed.

Release benchmark: planning 65,534 hosts took 13-14 ms. A bounded 2,048-port loopback scan persisted every observation to SQLite WAL. At 1/4/24/128/256 workers, elapsed times were 4530/4506/4531/4542/4539 ms and sampled peak working sets were 21.82/21.94/22.38/24.88/27.73 MiB. This single-host timeout/concurrency-bound workload is not a LAN throughput estimate or a GUI memory measurement. There is no before/after baseline. Reproduce with `cargo run --release -p portspecter-core --example benchmark -- 24`; its only network target is loopback.

## Platform evidence

Windows x64: native application built and opened; initial/scan-plan/live-result screenshots inspected. A loopback TCP scan was started from the GUI and its completed 34/34 observations verified in SQLite. Workspace tests (28), including one-action startup, invalid-input recovery, abbreviated IPv4 ranges, CIDR host-bit normalization and NetBIOS response validation, and Clippy with warnings denied passed. Later source changes are rechecked before handoff.

Cross-platform CI is configured but has not run remotely. macOS/Linux runtime behavior, remote-VLAN routing, screen-reader behavior and large-session performance remain unverified.

MAC diagnostics: the native Windows reader and route lookup were checked against local IP Helper data. A directly connected gateway returned its MAC and offline vendor; a VPN-routed target returned no MAC and its correct next hop. Device details now explain that difference and show the current route without changing historical scan observations.

The independent NetBIOS implementation was tested with a real loopback UDP responder, wrong transaction IDs, malformed/truncated packets, zero and multicast MAC values. Two explicitly investigated VPN targets did not return a valid NetBIOS MAC during a bounded query; this is not evidence that every routed target supports this method. NetBIOS support/firewall access is required; router management integration is not implemented.

Thread count is saved in local settings and profiles, and applies to the next scan runtime. Older profiles use the logical CPU count (bounded to 1-256). Hostname resolution uses the OS resolver with eight bounded native calls and a per-query deadline, followed by unicast NetBIOS when needed. Names require a configured reverse record or an answering NetBIOS device; empty results are retained as unknown. Existing databases migrate to version 3 without removing scan data.

Settings now groups scan performance, appearance, local data and network interfaces. Worker threads use a 1-256 slider with numeric feedback and quick choices; dragging saves on release, and active scans retain their original configuration.

Settings refinement: compact thread controls, connection/per-device/rate/timeout/retry/source fields and service inspection. Scan defaults can be validated and saved for startup, restored to recommended values, and edited without changing the running plan. Network interfaces are collapsed initially.

Scan workspace refinement: local IPv4 subnet picker appends targets without starting scans or replacing drafts; compact scan action bar; open TCP port numbers with full hover details; device inspector opens only after selection; empty filter recovery. PORTSPECTER_DATA_DIR can isolate validation workspaces from the active user database.

Device inspector refinement: fixed heading and tabs, open-port-first view, optional other port states, expandable evidence/TLS cards, structured identity and current-route sections, clipboard actions for names, open ports and fingerprints. Historical sessions can be opened with --session <UUID> and an optional --device <IP>; this reads observations without starting a scan.

Window validation on Windows: custom maximize/restore/minimize worked in an isolated preview; close-request handling exited cleanly. Adding a scan to the queue persisted it without starting a session. Horizontal workspace padding was reduced from 24 to 12 logical pixels and Windows/Linux outer resize gutters from 4 to 2. Native macOS/Linux behavior still requires validation.

Port presets: new scans default to 11 TCP ports; an optional extended checkbox selects the previous 34. Profiles and queue snapshots preserve their exact lists, including legacy presets. Subnet planning, custom-port retention and preset restoration are covered by a regression test; the Windows release UI was captured and inspected.

Native scan methods: UDP and IPv4 SYN now share the existing bounded scan scheduler, cancellation, retries, persistence and exports. UDP uses connected sockets and only marks ports open on a datagram response; silence remains open-or-filtered. SYN dynamically loads Npcap/libpcap and uses per-source workers, raw packet construction/checksums, randomized sequence correlation, SYN-ACK/RST/ICMP parsing and Ethernet next-hop ARP. It never silently falls back to connect. Unsupported link formats report an error. TCP service inspection is disabled for UDP/SYN.

mDNS/LLMNR: query paths now have real loopback UDP/TCP transport tests, in addition to malformed-packet tests. Local names may be queried without a responsive first port; validated local-name responses count as responding, unlike reverse DNS alone. Physical-device multicast interoperability remains unverified.

Verification for native scans: 47 normal tests pass; one explicit native SYN integration test is ignored by default because it requires capture permissions and a driver. This Windows machine has no Npcap installed, so raw SYN injection/reception has NOT been runtime-validated. The new platform code passes Linux x64 and macOS ARM64/Intel cross-target checks. Native Linux/macOS desktop/capture runtime validation is still outstanding. No driver or Nmap was installed or bundled.

Linux/macOS packaging sources are now implemented in scripts/package.py and packaging/. Debian package dependency generation uses dpkg-shlibdeps plus explicit dlopen dependencies. Linux CAP_NET_RAW is an explicit enable/disable step, never a package-install side effect. The macOS DMG includes a separate BPF-access package for the console user, a periodic launch daemon and a removal command preserving pre-existing group membership. Signing identities are optional build inputs; development defaults are not a notarized release. CI now includes native development-package builds and artifact upload. Windows source/plist checks, POSIX-mode shell syntax and Python compilation passed. No .deb/.dmg was created on Windows, no system permission was changed, and native installer/runtime checks are still outstanding.

Windows icon integration: seven-size ICO embedded through winresource; release EXE resource inspection confirmed seven icon frames and application metadata. An isolated native preview confirmed both small window and large taskbar icon handles. The misplaced southwest resize grip was moved to the bottom row, removing the extra left gutter; the resulting layout was visually checked. Clippy passed, and the release binary was updated at target/release/portspecter.exe.
Device protocols and shares (2026-10-27): optional ONVIF WS-Discovery and Hikvision SADP IPv4 discovery, scoped to planned targets and relevant local interfaces, with bounded XML parsing, response correlation for ONVIF, duplicate merging and read-only advertised metadata. Camera evidence and SMB disk-share results persist in SQLite schema 4; JSON schema 3 and CSV include both. Protocol settings survive defaults/profiles/queues. Camera/share-bearing devices open the identity tab automatically, with source-specific information and permission/timeout/unavailable states.

SMB enumeration includes hidden dollar-suffix disk shares, excluding IPC and printers. Windows uses native NetShareEnum level 1 in a short-lived, cancellable helper; Unix uses optional smbclient anonymously with SMB2 minimum. Debian packaging now depends on smbclient; macOS detects Homebrew paths. Queries require an open TCP 445 from a connect scan; explicit source-IP binding skips SMB with an explanation because the native client cannot honor it. No credentials are collected, shares mounted or files read.

Validation: 52 tests passed across workspace and the final desktop regression run; one pre-existing live SYN test remains ignored. Clippy with warnings denied and packaging source validation passed. Platform cross-checks passed Linux x64 and macOS ARM64/Intel (not native GUI/runtime tests). A real Windows localhost NetShareEnum helper successfully returned administrative hidden shares. Windows release previews exercised persisted camera/share fixtures and settings; physical ONVIF/SADP multicast devices and Unix smbclient runtime remain unverified. Updated release executable: target/release/portspecter.exe.

Dahua / DNS-SD / SSDP and type filters (2026-10-27): all three optional local IPv4 protocols now share the interface-scoped discovery phase with ONVIF/SADP. New structured advertisements preserve identity, manufacturer/model, serial/MAC, service target/port, protocol and bounded properties. Dahua validates DHIP framing and sender IP. DNS-SD performs peer-bound legacy-unicast browse/follow-ups and joins PTR/SRV/TXT/A across packets. SSDP deduplicates UDNs and reads matching device descriptions from the same literal IP with proxies/redirects disabled, verified TLS, size/count/concurrency and deadline bounds. Reported ports never create open-port observations.

Device classification supports multiple roles with displayed evidence, including printers, recorders, file servers and media devices; unsupported classes remain unknown. Type filters compose with existing subnet/search/responding/open-port filters. Advertisements persist in SQLite schema 5 and JSON schema 4; CSV includes them even when there are no completed port observations. Settings/profile/queue loading preserves the new options; old settings default them off.

Validation: 61 workspace tests passed, one pre-existing native SYN test ignored; all-target Clippy with warnings denied and packaging source checks passed. Tests cover split DNS-SD records over real loopback UDP, custom service enumeration, DHIP truncation/sender rejection, SSDP UDP deduplication and URL checks, bounded HTTP reads/no redirect following, classification/filter behavior, persistence and discovery-only CSV rows. Windows release UI was inspected with explicitly synthetic NVR/printer/media records. Physical Dahua/Bonjour/UPnP interoperability remains unverified. Cross-target probe checks were attempted on Windows but blocked by missing target C compilers for ring; Linux/macOS native build/runtime validation remains outstanding (the existing CI matrix covers those platforms but was not run remotely).


Inspector and scan workspace (2026-10-27): replaced the long identity/network panel with Overview, Ports, Discovery and Shares tabs. Protocol records expand individually; long endpoints/IDs wrap, protocol MACs can be copied, and discovered names retain their source in the overview. Device changes reset detail state and tab changes reset scrolling. Loading/starting a session collapses target/port settings into a session-derived summary; settings can be reopened and pause/stop remain visible. Native Windows preview with synthetic records confirmed substantially more vertical room for results and details. Desktop tests: 14 passed; Clippy warnings denied passed. Native Linux/macOS GUI validation remains outstanding.
