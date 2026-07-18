# Releasing Crypton Sweep

Crypton Sweep is distributed through three channels:

1. **crates.io** for Rust users: `cargo install crypton-sweep`.
2. **GitHub Releases** for users who want a compiled binary.
3. **Git source** for contributors: `cargo install --git ...` or a normal clone.

## Publish To crates.io

Configure the repository metadata in `Cargo.toml`, authenticate once, verify the package, and
publish from a clean release commit:

```bash
cargo login
cargo package --locked
cargo publish --dry-run --locked
cargo publish --locked
```

The package name `crypton-sweep` must be available on crates.io. Publishing is permanent for a
version; increment `version` before a subsequent release.

## Publish A GitHub Release

Push the release commit and create a semantic-version tag:

```bash
git switch main
git pull --ff-only origin main
git tag -a v0.1.0 -m "Crypton Sweep v0.1.0"
git push origin v0.1.0
```

The tagged-release workflow builds native archives for Linux, macOS, and Windows and attaches them
to the GitHub Release.

## Release Rules

- Use tags in the form `vMAJOR.MINOR.PATCH`.
- Run `cargo fmt --check`, `cargo check --all-targets`, and `cargo test` before tagging.
- Do not include `reports/`, `target/`, credentials, scan results, or client data in a release.
- Treat network scan output as potentially sensitive and keep it outside public releases.
- Verify the startup animation in a terminal and `--no-animation` in CI before tagging.
- Open a generated HTML report and test browser print-to-PDF before tagging.
