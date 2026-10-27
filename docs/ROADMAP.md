# Roadmap

[Back to README](../README.md)

This document records priorities, not release dates or commitments. Implemented functionality is listed in the [README](../README.md); verification evidence is in [STATUS.md](STATUS.md).

## Before a stable release

- [ ] Run native Windows/Linux/macOS end-to-end checks, including resize, keyboard navigation, themes and graceful shutdown.
- [ ] Verify Debian installation/upgrades/removal and macOS app/optional BPF package installation/removal.
- [ ] Complete macOS distribution signing and notarization workflow.
- [ ] Exercise native SYN open/closed/filter behavior with supported capture drivers and links on each platform.
- [ ] Validate ONVIF/SADP/Dahua, Bonjour and UPnP against physical hardware and document firmware differences.
- [ ] Test VPN/route changes, multicast restrictions and SMB permissions on representative networks.
- [ ] Measure large-session GUI memory, responsiveness, cancellation and export behavior.
- [ ] Publish validated packages with checksums and release notes.

## Candidate future work

- Scoped IPv6 link-local targets and IPv6 SYN.
- Broader raw-link/VPN support and standalone ARP discovery.
- Streamed large exports and additional large-network performance work.
- Router/SNMP or remote-agent discovery where local protocols cannot reach.

These items are not currently implemented features. Propose concrete use cases through [feature requests](https://github.com/Gorke07/PortSpecter/issues/new/choose), including platform and network constraints.
