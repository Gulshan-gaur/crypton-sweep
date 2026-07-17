# Crypton Sweep

Crypton Sweep is an open-source, authorized **network cipher sweeper** and PQC migration report generator. It discovers reachable services, records cryptographic signals, imports CycloneDX inventories, and creates a self-contained HTML report with risk posture, migration actions, and a cryptographic knowledge graph.

It is intentionally separate from Crypton's proprietary protocol and proxy implementation.

## Quick Start

```bash
cargo run -- discover --target 127.0.0.1 --ports 22,80,443,8443 --tls --out reports/scan.json
cargo run -- report reports/scan.json --out reports/scan.html
```

Open `reports/scan.html` locally. The report has no runtime server or external JavaScript dependency.

Import a CycloneDX JSON SBOM:

```bash
cargo run -- inventory examples/sample.cdx.json --out reports/inventory.json
cargo run -- report reports/inventory.json --out reports/inventory.html
```

## Output Model

- Network assets and reachable services
- TLS version, cipher, key exchange, and signature evidence when `openssl` is available
- Classical versus PQC algorithm signals
- Risk score and finding codes
- Brownfield proxy candidate count
- CycloneDX-derived component inventory
- HTML report with KPI cards, algorithm profile, asset-to-algorithm graph, risk register, and migration posture

## Safety Boundary

Use only against systems you own or are explicitly authorized to assess. This tool is a discovery and migration-planning utility, not a vulnerability exploit framework or certification decision engine.

## Roadmap

- CycloneDX CBOM export with cryptographic component properties
- SPDX import/export
- SARIF output for CI systems
- Better TLS certificate parsing and expiry checks
- PCAP-backed packet segmentation and retransmission evidence
- Optional authenticated collection agent for firmware and gateway inventories
- Signed report manifests for enterprise evidence chains

