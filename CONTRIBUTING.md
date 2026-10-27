# Contributing to PortSpecter

Bug reports, protocol interoperability results, translations and focused patches are welcome. English and Turkish reports are both welcome. Read the [roadmap](docs/ROADMAP.md) before proposing a large feature.

Participation follows the [community conduct guidelines](CODE_OF_CONDUCT.md).

## Development setup

1. Fork and clone the repository.
2. Install the [platform prerequisites](docs/INSTALLATION.md).
3. Create a branch for one focused change.
4. Run `cargo run --locked -p portspecter-desktop`.

Keep `Cargo.lock` committed. Use `PORTSPECTER_DATA_DIR` to isolate development data from your normal scans. Never commit real scan databases, credentials, exports or private network screenshots; `.gitignore` excludes local artifacts.

## Required checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python scripts/package.py --check
```

Use Python 3.11+ for packaging checks. Protocol tests should use bounded fixtures and loopback responders. Do not make tests scan a developer's LAN or require internet access. The native SYN test is intentionally ignored by default; run `cargo test -p portspecter-platform native_loopback -- --ignored` only with the required capture driver and permissions.

## Implementation expectations

- Preserve cancellation, rate limits, target/exclusion scope and bounded packet parsing.
- Keep platform-specific APIs behind the platform layer. State which platforms you actually tested.
- Distinguish observations from port-number hints or advertised services.
- Add migrations for persisted schema changes; preserve old sessions and profiles.
- Update both `assets/locales/en.ftl` and `assets/locales/tr.ftl` for visible strings.
- Include tests for changed behavior and regressions; do not add real-network dependencies to CI.
- Retain source/observed-time information where the data model supports it.

## Pull requests

Explain the problem, final behavior and validation. Include sanitized screenshots for visual changes and mention untested platforms or hardware. Keep unrelated formatting and refactors out of the patch. Use meaningful commit messages such as `fix: preserve discovery names in device details`.

Contributions use the repository's Apache-2.0 license; third-party assets must retain their own license and attribution. No additional contributor agreement is currently required. Be respectful, keep discussion technical and avoid publishing another person's private information.
