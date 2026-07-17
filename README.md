# Crypton Sweep

Crypton Sweep is an open-source, authorized **network cipher sweeper** and PQC migration report generator. It discovers reachable services, records cryptographic signals, imports CycloneDX inventories, and creates a self-contained HTML report with risk posture, migration actions, and a cryptographic knowledge graph.

It is intentionally separate from Crypton's proprietary protocol and proxy implementation.

## Quick Start

```bash
cargo run -- discover --target 127.0.0.1 --ports 22,80,443,8443 --tls --out reports/scan.json
cargo run -- report reports/scan.json --out reports/scan.html
```

Open `reports/scan.html` locally. The report has no runtime server or external JavaScript dependency.

The scanner runs from the network vantage point where the command is executed. It does not
magically see services behind a firewall, on another VLAN, bound only to loopback, or on ports
not included in `--ports`. For a client pilot, run the binary on an approved jump host inside the
client network, or use the inventory command on a supplied CycloneDX file.

Example for the Crypton MQTT pilot:

```bash
cargo run -- discover \
  --target 192.168.1.38 \
  --ports 1883,8883,443,8443 \
  --tls \
  --out reports/client-network.json
cargo run -- report reports/client-network.json --out reports/client-network.html
```

`1883` is treated as plain MQTT and will produce a high-risk brownfield/proxy candidate finding.
`8883` is the conventional MQTT-over-TLS port. A reachable service without TLS evidence is
reported as **not characterized**, not as secure and not as proof of compromise.

To scan every TCP port on one authorized host, use the bounded parallel scanner:

```bash
cargo run -- discover \
  --target 192.168.1.38 \
  --all-ports \
  --timeout-ms 300 \
  --out reports/full-host.json
```

`--all-ports` means ports `1-65535` on the specified target. It does not scan the whole LAN;
provide each approved host with another `--target` argument. Use `--tls` when you want the tool
to attempt TLS characterization on every reachable port:

```bash
cargo run -- discover --target 192.168.1.38 --all-ports --tls \
  --timeout-ms 300 --out reports/full-host-tls.json
```

`TLS services` counts only services where the OpenSSL handshake produced usable TLS evidence.
An open TCP port alone is not a TLS service. If the target has no TLS listener, the value remains
zero even though the scan found other services.

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

## How This Maps To Industry Collection

Production exposure-management tools combine several evidence sources rather than relying on one
port scan:

1. **Active discovery** from a permitted network vantage point finds reachable services and latency.
2. **Protocol-aware probes** inspect TLS versions, cipher suites, certificates, key exchange, and signature signals.
3. **Authenticated collectors** inspect hosts, processes, firmware, configuration, and local-only services.
4. **Passive collection** from a TAP, SPAN port, or approved PCAP identifies traffic that an active scan cannot reach.
5. **Software inventories** such as SBOM/CycloneDX and future CBOM input connect deployed components to cryptographic dependencies.
6. **Historical comparison** tracks newly exposed services, algorithm changes, and migration progress over time.

This repository currently implements active TCP discovery, optional OpenSSL TLS evidence, and
CycloneDX software inventory. The report records collection limits so a client can distinguish
"not observed from this location" from "secure". Authenticated collection, passive traffic
evidence, and historical diffs are the next production-readiness layers.

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
