# Crypton Sweep Features

Crypton Sweep is an authorized cryptographic exposure and post-quantum migration intelligence
CLI. It combines live network evidence with CycloneDX software and cryptographic inventories.

## Implemented

### Network Discovery

- Authorized TCP service discovery.
- Single IPv4 target scanning.
- IPv4 CIDR scanning, such as `192.168.1.0/24`.
- Explicit IPv4 ranges, such as `192.168.1.1-192.168.1.38`.
- LAN shorthand ranges, such as `192.168.1.1-38`.
- Selected port lists and port ranges.
- Full TCP port scanning with `--all-ports`.
- Bounded target expansion to reduce accidental oversized scans.
- Parallel port checks with configurable connection timeout.

### TLS and Cryptographic Evidence

- Optional OpenSSL TLS probing.
- TLS version evidence.
- Cipher suite evidence.
- Key-exchange evidence.
- Signature-algorithm evidence.
- Certificate and PQC-group fields in the report model.
- Explicit distinction between successful TLS evidence, failed probes, and no probe requested.
- Detection signals for RSA, ECDSA, X25519, ML-KEM/Kyber, ML-DSA/Dilithium, and Falcon.
- Classical-only, PQC-capable, hybrid, and unknown cryptographic states.

### MQTT and Brownfield Assessment

- Recognition of conventional MQTT port `1883`.
- Recognition of MQTT-over-TLS port `8883`.
- High-risk finding for an observed plain MQTT listener.
- Brownfield proxy candidate recommendations.
- Recommendations distinguish observed exposure from uncharacterized services.

### CycloneDX SBOM and CBOM

- CycloneDX JSON validation.
- CycloneDX SBOM component inventory import.
- CycloneDX CBOM-style crypto component import.
- Crypto signal extraction from component names, properties, and metadata.
- CycloneDX SBOM export.
- CycloneDX CBOM export.
- Combined software, service, and crypto evidence export.
- Component relationships and crypto algorithm dependencies.
- Evidence provenance through `crypton.*` properties.

### Risk and Migration Intelligence

- Explainable risk scores.
- Finding codes, severity, titles, and details.
- Per-asset remediation recommendations.
- Proxy candidate count.
- Classical cryptography exposure count.
- PQC-ready asset count.
- Collection limitations and evidence-source metadata.

### Reports and Visualization

- Full machine-readable JSON evidence reports.
- Offline self-contained HTML reports.
- Exposure profile visualization.
- Cryptographic knowledge graph visualization.
- Priority action and risk register.
- Migration posture section.
- Asset inventory table.
- Inline monochrome Crypton Sweep SVG logo.
- Browser `Save to PDF` support with print CSS.
- Local Python server for browser viewing without third-party Python dependencies.
- Native Rust `serve` command for installed-crate browser viewing without Python.

### CLI and Distribution

- Rust crate and executable CLI.
- Interactive no-subcommand terminal workspace.
- Full command mode, such as `crypton-sweep discover ...`.
- Slash command mode, such as `/discover ...` and `/dashboard ...`.
- Built-in command palette with `/help`, `/clear`, and `/exit`.
- Readline editing, cursor movement, and command history.
- Digital local-session clock in the terminal workspace.
- Copilot-style monochrome terminal welcome panel.
- Interactive startup animation for terminal sessions.
- `--no-animation` mode for CI and scripts.
- `NO_COLOR=1` compatibility.
- GitHub source installation with `cargo install --git`.
- crates.io publication workflow.
- GitHub Release workflow for Linux, macOS, and Windows binaries.
- Release installer for supported Unix platforms.

## Evidence Boundaries

- A TCP connection proves reachability, not encryption or authentication.
- A failed TLS probe is not proof of a vulnerability.
- SBOM/CBOM evidence describes inventory; it does not prove runtime negotiation.
- The scanner runs from its execution vantage point and cannot see inaccessible VLANs, filtered
  ports, loopback-only services, or hosts outside the authorized scope.
- Reports are local by default; scan results are not uploaded automatically.

## Planned

- Protocol-aware MQTT, SSH, HTTP, and Crypton probes.
- Authenticated host and firmware collection agent.
- Passive PCAP/TAP/SPAN evidence ingestion.
- Historical scan comparison and migration trend tracking.
- SPDX import/export.
- SARIF output for CI security workflows.
- Dedicated structured CBOM object parsing.
- Signed report manifests.
- Optional enterprise dashboard and controlled evidence sharing.
