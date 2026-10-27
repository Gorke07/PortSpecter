# Troubleshooting

[Back to README](../README.md)

## A device is missing

Disable **Open ports only** first. This filter is enabled by default and hides devices whose selected ports were not confirmed open, even when another discovery method received a reply. Check subnet/type/search filters and that the target is not excluded. A missing ping reply does not prove the host is offline.

For a routed target, inspect the current source/interface/next hop in device details. PortSpecter uses existing routes; a VLAN label does not configure routing. VPNs and firewalls can block traffic or change the selected source interface.

## MAC or device name is unavailable

Neighbor-table MACs normally exist only for directly connected devices. A remote gateway MAC is not the target MAC. NetBIOS or device discovery may return a target-reported address, but there is no universal MAC retrieval across routed networks.

Names depend on reverse DNS or responses to supported name/discovery protocols. Enable name discovery and check the reported source. mDNS/LLMNR and multicast device discovery generally require local-subnet reachability. Devices may not implement the protocols or may refuse queries.

## Cameras, printers or media devices are not discovered

Enable the appropriate optional protocol in Settings before scanning. Include the device address in the target scope and check multicast/firewall reachability. Turn off the open-port-only filter. Multicast normally does not cross routers or VPNs. A device-type filter requires explicit supported classification evidence; an unknown class can still be a valid device.

Report protocol, model/firmware and local/routed context with sanitized evidence. Physical-device interoperability is still being validated.

## SMB shares are absent or access is denied

Share listing requires an open TCP 445 during a TCP connect scan and the share option enabled. Explicit source-IP selection disables enumeration because the OS SMB client cannot honor it. Linux/macOS need `smbclient`; Windows uses the current user identity.

The server can deny anonymous or current-user enumeration. Hidden administrative shares are included only if returned by the server. Empty, denied, unavailable and timeout states have different meanings; listing does not grant file access.

## SYN reports a driver or permission error

Windows requires separately installed Npcap. Linux requires libpcap and capture/injection permissions. macOS requires BPF access. Use the [documented optional setup](INSTALLATION.md#native-packages); normal TCP connect/UDP use does not need that setup.

SYN currently supports IPv4. Unsupported VPN/tunnel link types return an error; the application does not silently substitute TCP connect. The ignored native test requires the same driver and privileges.

## Scans take longer than expected

Check port count, retries, timeout and attempt-rate limits. Silent targets commonly consume the timeout. The default TCP preset has 11 ports; extended mode has 34. Optional device discovery adds bounded work beyond port probing.

Threads, global/per-host concurrency and rate limits are independent. Increasing the worker slider to 256 does not guarantee more throughput. Change one setting at a time and measure a small authorized scope. Route changes can pause active scans for review.

## Collect a useful report

Include commit/version, OS/architecture, scan method, settings, steps and expected/actual result. `F12` saves an app screenshot under `artifacts/`; inspect and redact it before uploading. Use a synthetic reproduction rather than sending your database. See [Support](../SUPPORT.md) and [Security](../SECURITY.md).
