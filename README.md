<p align="center"><img src="assets/icons/portspecter-macos.png" alt="PortSpecter icon" width="112"></p>
<h1 align="center">PortSpecter</h1>
<p align="center">Discover devices. Inspect ports. Understand your network.</p>

[![Rust checks](https://github.com/Gorke07/PortSpecter/actions/workflows/ci.yml/badge.svg)](https://github.com/Gorke07/PortSpecter/actions/workflows/ci.yml)
[![Apache-2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
![Rust 1.99+](https://img.shields.io/badge/Rust-1.99%2B-orange.svg)

PortSpecter is a native **Rust + Iced** desktop application for multi-subnet discovery and port scanning. Inspect device identity, service evidence, camera discovery and shared folders in one local workspace, with Turkish/English interfaces and dark/light themes.

**Development preview:** Windows has been exercised locally. Linux/macOS support and packaging are implemented; native runtime and installer verification remain release work. IPv4 SYN is experimental. See [current status](docs/STATUS.md).

[User guide](docs/USAGE.md) | [Installation](docs/INSTALLATION.md) | [Roadmap](docs/ROADMAP.md) | [Turkish guide](README.tr.md)

## Features

| Area | Capabilities |
| --- | --- |
| Scan | TCP connect, UDP, native IPv4 SYN; rate/concurrency limits, retries, pause and stop |
| Plan | Multiple subnets, hostnames, IPv4 ranges, exclusions, deduplication and VLAN labels |
| Identify | ICMP, reverse DNS, NetBIOS, mDNS/LLMNR, observed MACs and offline vendor lookup |
| Discover | ONVIF, Hikvision SADP, Dahua, DNS-SD/Bonjour and SSDP/UPnP |
| Inspect | Service evidence, device metadata, current routes and SMB shares including hidden shares |
| Organize | SQLite history, scope-aware comparisons, profiles, persistent queue and CSV/JSON exports |
| Navigate | Search and type filters; Overview, Ports, Discovery and Shares tabs; compact scan controls |
| Diagnose | On-demand route/DHCP configuration, DNS/TCP checks and five-sample ICMP latency/loss/jitter |
| Act | Open web/SSH/RDP/SMB clients and send a Wake-on-LAN packet |

No cloud account or Nmap installation is needed. Scan data stays local. Optional SSDP discovery reads device descriptions from the same target; network activity follows configured scan and discovery settings.

## Getting started

Install stable Rust **1.99+** and the [platform prerequisites](docs/INSTALLATION.md#build-from-source), then:

```sh
git clone https://github.com/Gorke07/PortSpecter.git
cd PortSpecter
cargo run --locked -p portspecter-desktop
```

Enter targets, choose a method and ports, then select **Start scan**. Startup does not initiate a scan. The default TCP preset has 11 common ports; extended scanning uses 34, or enter your own list. **Open ports only** is enabled by default; disable it to inspect discovery-only devices.

```text
192.168.10.1/24 | Workstations | 10
192.168.20.1-255 | Cameras | 20
10.10.30.10-10.10.30.50 | Servers | 30
```

Host-bit CIDRs are normalized: `192.168.10.1/24` selects usable addresses in `192.168.10.0/24`. VLAN labels do not configure network equipment; scanning follows existing OS/VPN routes. Use PortSpecter on networks you own or have permission to assess.

## Platform support

| Capability | Windows | Linux | macOS |
| --- | --- | --- | --- |
| Desktop / TCP connect / UDP | Locally exercised | Runtime validation pending | Runtime validation pending |
| IPv4 SYN | Npcap + capture permission | libpcap + capture/injection permission | System libpcap + BPF access |
| SMB enumeration | Native API | `smbclient` | `smbclient` |
| Packaging | Build EXE from source | Debian package script | App/DMG and optional BPF setup script |

Npcap is installed separately and is not bundled. Native SYN, physical-device interoperability, macOS signing/notarization and native installer testing remain release gates. [Installation and permissions](docs/INSTALLATION.md)

## Understand the results

- An advertised service is separate from a confirmed open port.
- UDP silence means **open or filtered**, not definitely open or offline.
- MAC addresses require local neighbor access or a target-reported identity. A gateway MAC is never assigned to a remote host.
- Multicast discovery generally stays on the local subnet; routed scanning does not make multicast cross VLANs or VPNs.
- Hidden shares appear only when the server permits enumeration. Listing a share does not grant file access.

## Documentation

| Document | Purpose |
| --- | --- |
| [User guide](docs/USAGE.md) | Targets, protocols, device details, settings and exports |
| [Installation](docs/INSTALLATION.md) | Dependencies, packages and optional SYN access |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Missing devices, identities, permissions and scan speed |
| [Architecture](docs/ARCHITECTURE.md) | Workspace responsibilities and scan data flow |
| [Roadmap](docs/ROADMAP.md) | Release gates and future work |
| [Changelog](CHANGELOG.md) | Changes in the development version |
| [Contributing](CONTRIBUTING.md) | Workflow, checks and pull requests |
| [Community conduct](CODE_OF_CONDUCT.md) | Participation and moderation expectations |
| [Security](SECURITY.md) | Security reporting and data handling |
| [Support](SUPPORT.md) | Questions and useful bug reports |

## Development

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python scripts/package.py --check
```

Latest local Windows validation: **72 tests passed**, one permission-dependent native SYN test ignored. The live CI badge and [status](docs/STATUS.md) distinguish remote and local evidence.

## License and credits

Application code: [Apache-2.0](LICENSE). [MACLookup vendor data](assets/data/SOURCE.json), Inter and JetBrains Mono retain their own terms; see [NOTICE](NOTICE) and bundled font licenses. The application license does not relicense third-party datasets.
