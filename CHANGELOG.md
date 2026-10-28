# Changelog

User-visible changes are recorded here. The current application version is `0.1.0` in the workspace manifest; this does not imply a published stable release.

## Unreleased

### Added

- Response-based service/product/version detection, source-aware identity conflicts, an explicit network health test and device actions (web, SSH, RDP, SMB and Wake-on-LAN).
- Rust/Iced desktop workspace with Turkish/English, dark/light themes and custom window controls.
- Multi-subnet planning, CIDR/range parsing, exclusions and VLAN labels.
- TCP connect, UDP and experimental native IPv4 SYN scanning with pause/cancel and bounded concurrency.
- ICMP, DNS/NetBIOS/mDNS/LLMNR identity discovery and offline MAC vendor data.
- ONVIF, Hikvision SADP, Dahua, DNS-SD and SSDP device discovery.
- SMB disk-share listing, including hidden shares returned by the server.
- SQLite history, comparisons, saved profiles, queue and CSV/JSON exports.
- Platform packaging scripts, CI matrix, contribution guides and GitHub issue/PR templates.

### Improved

- Flatter device inspector with aligned identity fields, expandable sources, quieter tabs and persistent footer actions.
- Default TCP preset reduced to 11 ports, with optional 34-port extended scanning.
- Configurable worker count from 1 to 256.
- Compact scan summary and Overview/Ports/Discovery/Shares device inspector.
- Expandable discovery records, long-field wrapping and source-aware name/MAC presentation.

### Known limitations

- Native Linux/macOS runtime, installer and physical-device interoperability checks remain outstanding.
- SYN is IPv4-only and needs packet capture permissions; its native integration test is opt-in.
- Scoped IPv6 link-local targets and automatic cross-VLAN multicast discovery are not supported.
