# Security policy

## Supported versions

PortSpecter is in development. Security fixes target the current `main` branch; there is no maintained stable release line or guaranteed response SLA yet.

## Reporting a vulnerability

Do not post exploit details, credentials or sensitive network data in a public issue. If GitHub displays **Security → Report a vulnerability**, use that private reporting channel. Otherwise, open a minimal issue requesting a private contact method, without disclosing the vulnerability, and wait for the maintainer to provide one. No dedicated security email address is currently published.

Include the affected commit/platform, impact, minimal reproduction and relevant sanitized evidence in the private report. Report vulnerabilities in PortSpecter here; issues in third-party software should also go to its maintainers.

## Security boundaries

- Network replies and device metadata are untrusted input. Parsers and description fetches must remain bounded and scoped to planned targets.
- Native SYN requires packet capture/injection privileges. Npcap is not bundled. Optional Linux/macOS setup changes packet-access permissions; read the [installation guide](docs/INSTALLATION.md) before enabling it.
- SMB enumeration uses current Windows identity or anonymous `smbclient` on Unix. It does not bypass server permissions or grant file access.
- Scan history and exports may reveal network topology, device identifiers and share names. Protect the local data directory and sanitize attachments.
- Current storage is a local SQLite database; application-level database encryption is not implemented.

Only scan networks for which you have authorization.
