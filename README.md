# Crypton Sweep

Crypton Sweep is an open-source, authorized **network cipher sweeper** and PQC migration report generator. It discovers reachable services, records cryptographic signals, imports CycloneDX inventories, and creates a self-contained HTML report with risk posture, migration actions, and a cryptographic knowledge graph.

It is intentionally separate from Crypton's proprietary protocol and proxy implementation.

## Install

Install from crates.io after publication:

```bash
cargo install crypton-sweep
```

Install the current source directly from GitHub:

```bash
cargo install --git https://github.com/Gulshan-gaur/crypton-sweep.git --branch main
```

For users without Rust, download a compiled binary from GitHub Releases. The tagged release
workflow publishes archives for Linux, macOS, and Windows.

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Gulshan-gaur/crypton-sweep/releases/latest/download/crypton-sweep-installer.sh | sh
```

The installer places the binary in `~/.local/bin`. Review downloaded scripts before executing
them in a controlled enterprise environment.

## Project Structure

```text
src/main.rs                  Rust CLI, scanner, inventory, exporter
templates/report.html        Offline report dashboard template
scripts/serve_report.py      Local-only static dashboard server
scripts/install.sh           Unix release installer
examples/                    Sample CycloneDX input
docs/features.md             Implemented and planned feature reference
docs/                        Architecture and release documentation
.github/workflows/           CI and tagged release automation
```

See the complete capability reference in [docs/features.md](docs/features.md).

The Rust binary performs scanning and report generation. Python only serves an already generated
HTML file locally; it is not a runtime dependency of the scanner.

Every interactive command starts with a short Crypton Sweep terminal sequence. For CI, scripts,
or plain logs, disable it explicitly:

```bash
crypton-sweep --no-animation discover --target 127.0.0.1 --ports 443
NO_COLOR=1 crypton-sweep report reports/scan.json --out reports/scan.html
```

The HTML report contains an inline Crypton Sweep SVG mark and an `Export PDF` action. Select
that action in a browser and choose **Save to PDF**; no external logo or network connection is
required.

## Quick Start

```bash
cargo run -- discover --target 127.0.0.1 --ports 22,80,443,8443 --tls --out reports/scan.json
cargo run -- report reports/scan.json --out reports/scan.html
```

Open `reports/scan.html` locally. The report has no runtime server or external JavaScript dependency.

For the browser workflow, use the native `serve` command after installation:

```bash
# Generates reports/scan.html and starts the local browser server
crypton-sweep serve reports/scan.json --out-dir reports
```

The command opens the report at `http://127.0.0.1:8765/scan.html`. Stop it with `Ctrl+C`.
Use `--no-browser` when running on a remote server:

```bash
crypton-sweep serve reports/scan.json --out-dir reports --no-browser
```

The Python server remains available for a source checkout, but it is not required for an installed
crate. For manual generation without starting a server:

```bash
crypton-sweep dashboard reports/scan.json --out-dir reports

# Optional source-checkout server
python3 scripts/serve_report.py --report scan.html
```

The Rust crate performs scanning, parsing, normalization, and HTML generation. The Python script
only serves the already-generated static report on `127.0.0.1`; it is not part of the scanning or
cryptographic logic and has no third-party dependency.

## Interactive CLI

Running the binary without a subcommand opens the interactive terminal workspace:

```bash
crypton-sweep
```

It shows the Crypton wordmark, subordinate `sweep` label, current digital clock, command prompt,
and command palette. The prompt supports cursor movement, Home/End, Ctrl+A/Ctrl+E, and Up/Down
command history. Both command styles are supported:

```text
crypton-sweep > discover --target 192.168.1.1-38 --ports 443,1883 --tls --out reports/range.json
crypton-sweep > /discover --target 192.168.1.1-38 --ports 443,1883 --tls --out reports/range.json
crypton-sweep > /dashboard reports/range.json --out-dir reports
crypton-sweep > /exit
```

Available slash commands include `/discover`, `/inventory`, `/report`, `/dashboard`, `/serve`,
`/export-cyclonedx`, `/help`, `/clear`, and `/exit`. Direct subcommands remain available for
automation and CI. Use `--no-animation` or `NO_COLOR=1` for plain terminal output.

`/dashboard` generates the HTML and returns to the prompt. `/serve` generates the HTML and starts
the local HTTP server, so that terminal is occupied while the server runs. To keep the interactive
shell available, use a second terminal:

```text
# Terminal 1
crypton-sweep
crypton-sweep > /dashboard reports/scan.json --out-dir reports

# Terminal 2
crypton-sweep serve reports/scan.json --out-dir reports
```

The browser opens at `http://127.0.0.1:8765/scan.html`. Stop the server with `Ctrl+C` in Terminal 2.

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

Target ranges are supported for authorized IPv4 networks:

```bash
# CIDR notation, inclusive of every address in the block
cargo run -- discover --target 192.168.1.0/24 --ports 1883,8883,443 --tls \
  --out reports/subnet.json

# Inclusive address range
cargo run -- discover --target 192.168.1.10-192.168.1.50 --ports 1-10000 \
  --out reports/range.json
```

The default expansion limit is 4,096 hosts. Change it explicitly with `--max-targets` only
after confirming the authorized scope. A `/24` with `--all-ports` represents more than 16 million
TCP connection attempts, so start with a focused port list and expand in stages.

Import a CycloneDX JSON SBOM:

```bash
cargo run -- inventory examples/sample.cdx.json --out reports/inventory.json
cargo run -- report reports/inventory.json --out reports/inventory.html
```

CycloneDX CBOM-style JSON is imported through the same command. The current inventory parser
reads the `components` array and detects cryptographic signals such as RSA, ECDSA, X25519,
ML-KEM/Kyber, ML-DSA/Dilithium, and Falcon from component names, properties, and metadata:

```bash
cargo run -- inventory client-sbom.cdx.json --out reports/sbom-inventory.json
cargo run -- inventory client-cbom.cdx.json --out reports/cbom-inventory.json
cargo run -- report reports/cbom-inventory.json --out reports/cbom-report.html
```

The output keeps the evidence source as `software_inventory` and marks runtime negotiation as
unverified. This is deliberate: an SBOM/CBOM describes declared or collected software evidence,
while active discovery describes reachable network services. Use both reports for a client
assessment. SPDX import and a dedicated structured CBOM asset parser are planned next.

Export a normalized Crypton Sweep report back to CycloneDX:

```bash
# Software components only
cargo run -- export-cyclonedx reports/inventory.json \
  --kind sbom --out reports/crypton-sbom.cdx.json

# Cryptographic/network evidence only
cargo run -- export-cyclonedx reports/industry-scan.json \
  --kind cbom --out reports/crypton-cbom.cdx.json

# Combined software, service, and cryptographic evidence
cargo run -- export-cyclonedx reports/industry-scan.json \
  --kind combined --out reports/crypton-combined.cdx.json
```

The exporter emits CycloneDX JSON 1.5 with standard `components`, `dependencies`, metadata, and
properties. Cryptographic assets are represented with explicit `crypton.asset_type` and
`crypton.crypto_algorithm` properties so the output remains interoperable while retaining the
tool's evidence provenance. It does not claim that an observed algorithm was negotiated when the
source report only contains an inventory or an unknown observation.

## Output Model

- Network assets and reachable services
- TLS version, cipher, key exchange, and signature evidence when `openssl` is available
- Classical versus PQC algorithm signals
- Risk score and finding codes
- Brownfield proxy candidate count
- CycloneDX-derived component inventory
- HTML report with KPI cards, algorithm profile, asset-to-algorithm graph, risk register, and migration posture

### Full JSON Evidence

The discovery JSON is designed as an evidence export. A full scan contains:

| Field | Meaning |
|---|---|
| `scan_id` | Unique identifier for correlating the JSON and HTML report. |
| `started_at`, `completed_at`, `duration_ms` | Scan execution timing. |
| `scope` | Authorized targets and collection mode. |
| `collection` | Port specification, attempted/reachable counts, worker count, timeout, TLS policy, and limitations. |
| `summary` | Aggregated exposure and migration counts. |
| `assets` | One record per reachable service. Closed or filtered ports are represented by collection counts, not by thousands of empty records. |
| `connection` | TCP connection attempt outcome, latency, tool, and error. |
| `service_detection` | Service name, detection method, confidence, and whether a banner was observed. |
| `tls_probe` | Whether TLS probing was requested, successful, failed, timed out, and which tool produced the evidence. |
| `tls` | Parsed TLS version, cipher, key exchange, signature, certificate, PQC group, and raw evidence when the handshake succeeds. |
| `crypto` | Observed algorithms, PQC/hybrid flags, quantum-vulnerability signal, and evidence source. |
| `risk`, `findings`, `recommendation` | Explainable risk posture and migration action. |
| `relationships` | Knowledge-graph edges from assets to services, algorithms, or evidence states. |

Generate a complete evidence export for one authorized host:

```bash
cargo run -- discover \
  --target 192.168.1.38 \
  --all-ports \
  --tls \
  --timeout-ms 300 \
  --out reports/industry-scan.json
```

Inspect the full file with:

```bash
jq . reports/industry-scan.json
jq '.assets[] | {id, connection, tls_probe, service_detection, crypto, risk, findings}' reports/industry-scan.json
jq '{scan_id, duration_ms, collection, summary}' reports/industry-scan.json
```

The current file is a real active-scan export, not synthetic client data. A failed TLS probe
means that OpenSSL could not establish TLS from this vantage point; it is not proof that the
service is vulnerable. For production client assessments, combine this network evidence with
authenticated host collection, passive traffic evidence, and SBOM/CBOM inventory.

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
