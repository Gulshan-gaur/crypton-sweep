use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "crypton-sweep",
    version,
    about = "Authorized network cipher sweeper and PQC migration report generator"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandKind,
}

#[derive(Subcommand)]
enum CommandKind {
    /// Probe authorized hosts and selected TCP ports.
    Discover {
        #[arg(short, long, required = true)]
        target: Vec<String>,
        #[arg(short, long, default_value = "22,80,443,1883,1884,8443,7878")]
        ports: String,
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,
        #[arg(long)]
        tls: bool,
        #[arg(short, long, default_value = "scan.json")]
        out: PathBuf,
    },
    /// Convert a CycloneDX SBOM into a cryptographic inventory report.
    Inventory {
        input: PathBuf,
        #[arg(short, long, default_value = "scan.json")]
        out: PathBuf,
    },
    /// Render a JSON report as a self-contained offline HTML dashboard.
    Report {
        input: PathBuf,
        #[arg(short, long, default_value = "report.html")]
        out: PathBuf,
        #[arg(long, value_enum, default_value_t = ReportFormat::Html)]
        format: ReportFormat,
    },
}

#[derive(Clone, ValueEnum)]
enum ReportFormat {
    Html,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScanReport {
    schema_version: String,
    tool: String,
    generated_at: String,
    scope: Scope,
    #[serde(default)]
    collection: Collection,
    summary: Summary,
    assets: Vec<Asset>,
    relationships: Vec<Relationship>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Collection {
    method: String,
    attempted_ports: Vec<u16>,
    timeout_ms: Option<u64>,
    tls_probe_requested: bool,
    limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Scope {
    mode: String,
    authorized: bool,
    targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Summary {
    assets: usize,
    services: usize,
    reachable: usize,
    tls_services: usize,
    pqc_ready: usize,
    classical_only: usize,
    high_risk: usize,
    proxy_candidates: usize,
    certificates_expiring_soon: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Asset {
    id: String,
    host: String,
    port: u16,
    #[serde(default)]
    service: String,
    protocol: String,
    reachable: bool,
    latency_ms: Option<f64>,
    tls: Option<TlsObservation>,
    crypto: CryptoProfile,
    risk: Risk,
    findings: Vec<Finding>,
    recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TlsObservation {
    version: Option<String>,
    cipher: Option<String>,
    key_exchange: Option<String>,
    signature_algorithm: Option<String>,
    certificate_algorithm: Option<String>,
    certificate_key_bits: Option<u32>,
    certificate_expires: Option<String>,
    pqc_group: Option<String>,
    raw_evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CryptoProfile {
    algorithms: Vec<String>,
    key_bits: Vec<u32>,
    pqc_supported: bool,
    hybrid_supported: bool,
    quantum_vulnerable: bool,
    #[serde(default)]
    encryption_observed: bool,
    #[serde(default)]
    evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Risk {
    score: u8,
    level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Finding {
    code: String,
    severity: String,
    title: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Relationship {
    source: String,
    target: String,
    kind: String,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        CommandKind::Discover {
            target,
            ports,
            timeout_ms,
            tls,
            out,
        } => {
            println!(
                "[crypton-sweep] scanning {} target(s), ports: {} (timeout: {} ms)",
                target.len(),
                ports,
                timeout_ms
            );
            let report = discover(&target, &ports, timeout_ms, tls)?;
            write_json(&out, &report)?;
            println!(
                "[crypton-sweep] found {} reachable service(s); wrote {}",
                report.assets.len(),
                out.display()
            );
            if report.assets.is_empty() {
                println!("[crypton-sweep] no selected ports were reachable. Check the host, port list, firewall, and that the service is running.");
            }
        }
        CommandKind::Inventory { input, out } => {
            let report = inventory(&input)?;
            write_json(&out, &report)?;
            println!(
                "[crypton-sweep] imported {} inventory component(s); wrote {}",
                report.assets.len(),
                out.display()
            );
            if report.assets.is_empty() {
                println!("[crypton-sweep] the CycloneDX document has no top-level components.");
            }
        }
        CommandKind::Report { input, out, format } => {
            let report: ScanReport = serde_json::from_slice(&fs::read(&input)?)
                .with_context(|| format!("invalid scan report {}", input.display()))?;
            match format {
                ReportFormat::Html => fs::write(&out, render_html(&report))?,
                ReportFormat::Json => write_json(&out, &report)?,
            }
            println!(
                "[crypton-sweep] report ready: {} assets, {} high-risk, {} PQC-capable",
                report.summary.assets, report.summary.high_risk, report.summary.pqc_ready
            );
            println!("[crypton-sweep] wrote {}", out.display());
            if matches!(format, ReportFormat::Html) {
                println!("[crypton-sweep] open it with: xdg-open {}", out.display());
            }
        }
    }
    Ok(())
}

fn discover(targets: &[String], ports: &str, timeout_ms: u64, use_tls: bool) -> Result<ScanReport> {
    let ports: Vec<u16> = ports
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect();
    if ports.is_empty() {
        anyhow::bail!("no valid ports supplied; use values such as --ports 1883,443,8443");
    }
    let mut assets = Vec::new();
    for host in targets {
        println!("[scan] target={host}");
        for port in &ports {
            let started = Instant::now();
            let address = format!("{host}:{port}");
            let reachable = address
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .and_then(|addr| {
                    TcpStream::connect_timeout(&addr, Duration::from_millis(timeout_ms)).ok()
                })
                .is_some();
            if !reachable {
                continue;
            }
            println!(
                "[open] {address} reachable in {:.2} ms",
                started.elapsed().as_secs_f64() * 1000.0
            );
            let tls_observation = if use_tls && matches!(*port, 443 | 8443 | 7878) {
                println!("[tls] probing {address} with openssl");
                probe_openssl(&address).ok()
            } else {
                None
            };
            let crypto = crypto_from_tls(tls_observation.as_ref());
            let (risk, findings, recommendation) = assess(&crypto, tls_observation.as_ref(), *port);
            assets.push(Asset {
                id: format!("{host}:{port}"),
                host: host.clone(),
                port: *port,
                service: service_for_port(*port).into(),
                protocol: if tls_observation.is_some() {
                    "TLS".into()
                } else {
                    service_for_port(*port).into()
                },
                reachable: true,
                latency_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
                tls: tls_observation,
                crypto,
                risk,
                findings,
                recommendation,
            });
        }
    }
    Ok(finalize_report(
        "network",
        true,
        targets.to_vec(),
        assets,
        Collection {
            method: "active TCP reachability scan".into(),
            attempted_ports: ports,
            timeout_ms: Some(timeout_ms),
            tls_probe_requested: use_tls,
            limitations: vec![
                "Closed or filtered ports are not included as assets.".into(),
                "A reachable non-TLS service does not reveal its application cryptography without a protocol-aware probe or host agent.".into(),
            ],
        },
    ))
}

fn probe_openssl(address: &str) -> Result<TlsObservation> {
    let output = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            address,
            "-brief",
            "-servername",
            address.split(':').next().unwrap_or(address),
        ])
        .stdin(Stdio::null())
        .output()
        .context("openssl is required for TLS probing")?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut observation = TlsObservation::default();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with("Protocol version:") {
            observation.version = Some(after_colon(line));
        }
        if line.starts_with("Ciphersuite:") {
            observation.cipher = Some(after_colon(line));
        }
        if line.starts_with("Peer signature type:") {
            observation.signature_algorithm = Some(after_colon(line));
        }
        if line.starts_with("Server Temp Key:") {
            observation.key_exchange = Some(after_colon(line));
        }
        observation.raw_evidence.push(line.to_string());
    }
    Ok(observation)
}

fn inventory(path: &PathBuf) -> Result<ScanReport> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("invalid CycloneDX JSON {}", path.display()))?;
    let mut assets = Vec::new();
    let mut targets = Vec::new();
    if let Some(components) = value.get("components").and_then(Value::as_array) {
        for component in components {
            let name = component
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let version = component
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let text = serde_json::to_string(component)?.to_lowercase();
            let mut crypto = CryptoProfile::default();
            for (needle, algorithm) in [
                ("rsa", "RSA"),
                ("ecdsa", "ECDSA"),
                ("x25519", "X25519"),
                ("ml-kem", "ML-KEM"),
                ("kyber", "Kyber"),
                ("ml-dsa", "ML-DSA"),
                ("dilithium", "Dilithium"),
                ("falcon", "Falcon"),
            ] {
                if text.contains(needle) {
                    crypto.algorithms.push(algorithm.into());
                }
            }
            crypto.pqc_supported = crypto.algorithms.iter().any(|a| {
                ["ML-KEM", "Kyber", "ML-DSA", "Dilithium", "Falcon"].contains(&a.as_str())
            });
            crypto.quantum_vulnerable = crypto
                .algorithms
                .iter()
                .any(|a| ["RSA", "ECDSA", "X25519"].contains(&a.as_str()));
            crypto.evidence = "software_inventory".into();
            let (risk, findings, recommendation) = assess(&crypto, None, 0);
            let id = format!("component:{name}:{version}");
            targets.push(id.clone());
            assets.push(Asset {
                id,
                host: name.into(),
                port: 0,
                service: "software component".into(),
                protocol: "component".into(),
                reachable: true,
                latency_ms: None,
                tls: None,
                crypto,
                risk,
                findings,
                recommendation,
            });
        }
    }
    Ok(finalize_report(
        "cyclonedx",
        true,
        targets,
        assets,
        Collection {
            method: "CycloneDX component inventory".into(),
            tls_probe_requested: false,
            limitations: vec![
                "Software inventory signals do not prove runtime negotiation.".into(),
                "Validate deployed endpoints with an active or authenticated collection method."
                    .into(),
            ],
            ..Collection::default()
        },
    ))
}

fn assess(
    crypto: &CryptoProfile,
    tls: Option<&TlsObservation>,
    port: u16,
) -> (Risk, Vec<Finding>, String) {
    let mut score = 0u8;
    let mut findings = Vec::new();
    if crypto.quantum_vulnerable {
        score = score.saturating_add(45);
        findings.push(Finding { code: "PQC-001".into(), severity: "high".into(), title: "Classical cryptography detected".into(), detail: "RSA, elliptic-curve, or finite-field key exchange remains exposed to a future cryptographically relevant quantum computer.".into() });
    }
    if tls.is_some() && !crypto.pqc_supported {
        score = score.saturating_add(25);
        findings.push(Finding {
            code: "PQC-002".into(),
            severity: "medium".into(),
            title: "No PQC signal observed".into(),
            detail: "The TLS observation did not identify a post-quantum or hybrid group.".into(),
        });
    }
    if port == 1883 {
        score = score.saturating_add(70);
        findings.push(Finding {
            code: "MQTT-001".into(),
            severity: "high".into(),
            title: "Plain MQTT listener observed".into(),
            detail: "TCP port 1883 conventionally carries MQTT without TLS. This scan cannot verify payload confidentiality or device identity on this endpoint.".into(),
        });
    } else if tls.is_none() && port != 0 {
        score = score.saturating_add(10);
        findings.push(Finding {
            code: "CRYPTO-UNKNOWN".into(),
            severity: "medium".into(),
            title: "Cryptography not characterized".into(),
            detail: "Reachability proves that a service accepted TCP, but it does not prove encryption, authentication, or PQC support. Use a protocol-aware probe or authenticated agent.".into(),
        });
    }
    if port != 0 && tls.is_none() && matches!(port, 443 | 8443) {
        score = score.saturating_add(15);
        findings.push(Finding {
            code: "TLS-001".into(),
            severity: "medium".into(),
            title: "TLS probe unavailable".into(),
            detail:
                "The service is reachable but was not successfully characterized by the TLS probe."
                    .into(),
        });
    }
    let level = if score >= 60 {
        "high"
    } else if score >= 30 {
        "medium"
    } else {
        "low"
    };
    let recommendation = if port == 1883 {
        "Protect this brownfield MQTT path with MQTT over TLS/PQC or a Crypton proxy; then verify the secured listener."
    } else if crypto.quantum_vulnerable {
        "Prioritize discovery and evaluate a Crypton proxy or SDK migration path."
    } else if crypto.pqc_supported {
        "Validate algorithm policy and add interoperability evidence."
    } else if tls.is_none() && port != 0 {
        "Run a protocol-aware probe or deploy an authenticated collector before declaring this service secure."
    } else {
        "Collect more cryptographic evidence before migration planning."
    };
    (
        Risk {
            score,
            level: level.into(),
        },
        findings,
        recommendation.into(),
    )
}

fn crypto_from_tls(tls: Option<&TlsObservation>) -> CryptoProfile {
    let mut crypto = CryptoProfile::default();
    crypto.evidence = if tls.is_some() {
        "tls_observation".into()
    } else {
        "not_observed".into()
    };
    if let Some(tls) = tls {
        let text = format!(
            "{} {} {}",
            tls.cipher.clone().unwrap_or_default(),
            tls.key_exchange.clone().unwrap_or_default(),
            tls.signature_algorithm.clone().unwrap_or_default()
        )
        .to_lowercase();
        for (needle, algorithm) in [
            ("rsa", "RSA"),
            ("ecdsa", "ECDSA"),
            ("x25519", "X25519"),
            ("mlkem", "ML-KEM"),
            ("kyber", "Kyber"),
            ("mldsa", "ML-DSA"),
            ("dilithium", "Dilithium"),
            ("falcon", "Falcon"),
        ] {
            if text.contains(needle) {
                crypto.algorithms.push(algorithm.into());
            }
        }
    }
    crypto.pqc_supported = crypto
        .algorithms
        .iter()
        .any(|a| ["ML-KEM", "Kyber", "ML-DSA", "Dilithium", "Falcon"].contains(&a.as_str()));
    crypto.hybrid_supported =
        crypto.algorithms.iter().any(|a| a == "X25519") && crypto.pqc_supported;
    crypto.quantum_vulnerable = crypto
        .algorithms
        .iter()
        .any(|a| ["RSA", "ECDSA", "X25519"].contains(&a.as_str()));
    crypto.encryption_observed = tls.is_some();
    crypto
}

fn service_for_port(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        80 => "HTTP",
        443 | 8443 => "HTTPS/TLS",
        1883 => "MQTT",
        8883 => "MQTT over TLS",
        7878 => "Crypton/secure channel candidate",
        _ => "TCP service",
    }
}

fn finalize_report(
    mode: &str,
    authorized: bool,
    targets: Vec<String>,
    assets: Vec<Asset>,
    collection: Collection,
) -> ScanReport {
    let mut summary = Summary {
        assets: assets.len(),
        ..Summary::default()
    };
    for asset in &assets {
        summary.services += usize::from(asset.port != 0);
        summary.reachable += usize::from(asset.reachable);
        summary.tls_services += usize::from(asset.tls.is_some());
        summary.pqc_ready += usize::from(asset.crypto.pqc_supported);
        summary.classical_only +=
            usize::from(asset.crypto.quantum_vulnerable && !asset.crypto.pqc_supported);
        summary.high_risk += usize::from(asset.risk.level == "high");
        summary.proxy_candidates += usize::from(
            (asset.crypto.quantum_vulnerable && !asset.crypto.pqc_supported)
                || asset
                    .findings
                    .iter()
                    .any(|finding| finding.code == "MQTT-001"),
        );
    }
    let relationships = assets
        .iter()
        .flat_map(|asset| {
            asset
                .crypto
                .algorithms
                .iter()
                .map(move |algorithm| Relationship {
                    source: asset.id.clone(),
                    target: format!("algorithm:{algorithm}"),
                    kind: "uses".into(),
                })
        })
        .collect();
    ScanReport {
        schema_version: "crypton-sweep/v1".into(),
        tool: format!("crypton-sweep/{VERSION}"),
        generated_at: Utc::now().to_rfc3339(),
        scope: Scope {
            mode: mode.into(),
            authorized,
            targets,
        },
        collection,
        summary,
        assets,
        relationships,
    }
}

fn after_colon(value: &str) -> String {
    value
        .split_once(':')
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

fn write_json(path: &PathBuf, report: &ScanReport) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, serde_json::to_vec_pretty(report)?)?;
    Ok(())
}

fn render_html(report: &ScanReport) -> String {
    let json = serde_json::to_string(report).expect("report is serializable");
    include_str!("../templates/report.html").replace("__REPORT_JSON__", &json)
}
