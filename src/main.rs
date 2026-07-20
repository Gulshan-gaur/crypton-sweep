use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser)]
#[command(
    name = "crypton-sweep",
    version,
    about = "Authorized network cipher sweeper and PQC migration report generator",
    after_help = "Global option: --no-animation disables the interactive startup sequence."
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
        /// Scan TCP ports 1 through 65535. Overrides --ports.
        #[arg(long)]
        all_ports: bool,
        /// Maximum expanded target count for CIDR/range input.
        #[arg(long, default_value_t = 4096)]
        max_targets: usize,
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
    /// Generate a browser dashboard with the same filename stem as the JSON input.
    Dashboard {
        input: PathBuf,
        #[arg(long, default_value = "reports")]
        out_dir: PathBuf,
    },
    /// Generate and serve the dashboard locally in a browser.
    Serve {
        input: PathBuf,
        #[arg(long, default_value = "reports")]
        out_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(short, long, default_value_t = 8765)]
        port: u16,
        #[arg(long)]
        no_browser: bool,
    },
    /// Export a normalized scan or inventory report as CycloneDX JSON.
    ExportCyclonedx {
        input: PathBuf,
        #[arg(short, long, default_value = "cyclonedx.json")]
        out: PathBuf,
        #[arg(long, value_enum, default_value_t = CycloneDxKind::Combined)]
        kind: CycloneDxKind,
    },
}

#[derive(Clone, ValueEnum)]
enum ReportFormat {
    Html,
    Json,
}

#[derive(Clone, Copy, ValueEnum)]
enum CycloneDxKind {
    Sbom,
    Cbom,
    Combined,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ScanReport {
    scan_id: String,
    schema_version: String,
    tool: String,
    started_at: String,
    completed_at: String,
    duration_ms: f64,
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
    port_spec: String,
    attempted_ports: Vec<u16>,
    attempted_port_count: usize,
    reachable_port_count: usize,
    worker_count: usize,
    timeout_ms: Option<u64>,
    tls_probe_requested: bool,
    tls_probe_timeout_ms: u64,
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
    #[serde(default)]
    connection: ProbeEvidence,
    #[serde(default)]
    tls_probe: ProbeEvidence,
    #[serde(default)]
    service_detection: ServiceDetection,
    tls: Option<TlsObservation>,
    crypto: CryptoProfile,
    risk: Risk,
    findings: Vec<Finding>,
    recommendation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ProbeEvidence {
    attempted: bool,
    outcome: String,
    duration_ms: Option<f64>,
    tool: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ServiceDetection {
    name: String,
    method: String,
    confidence: String,
    banner_observed: bool,
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

#[derive(Debug, Clone, Serialize)]
struct CycloneDxBom {
    #[serde(rename = "bomFormat")]
    bom_format: String,
    #[serde(rename = "specVersion")]
    spec_version: String,
    version: u32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<CycloneDxDependency>,
}

#[derive(Debug, Clone, Serialize)]
struct CycloneDxMetadata {
    timestamp: String,
    tools: Vec<CycloneDxTool>,
    properties: Vec<CycloneDxProperty>,
}

#[derive(Debug, Clone, Serialize)]
struct CycloneDxTool {
    vendor: String,
    name: String,
    version: String,
}

#[derive(Debug, Clone, Serialize)]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    component_type: String,
    name: String,
    version: String,
    #[serde(rename = "bom-ref")]
    bom_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    purl: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    properties: Vec<CycloneDxProperty>,
}

#[derive(Debug, Clone, Serialize)]
struct CycloneDxProperty {
    name: String,
    value: String,
}

#[derive(Debug, Clone, Serialize)]
struct CycloneDxDependency {
    #[serde(rename = "ref")]
    ref_: String,
    #[serde(rename = "dependsOn")]
    depends_on: Vec<String>,
}

fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().collect();
    let no_animation = raw_args.iter().skip(1).any(|arg| arg == "--no-animation");
    let commandless =
        raw_args.len() == 1 || raw_args.iter().skip(1).all(|arg| arg == "--no-animation");
    if commandless {
        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            return interactive_shell(no_animation);
        }
        Cli::parse_from([raw_args[0].clone(), "--help".into()]);
    }
    let clap_args: Vec<String> = raw_args
        .into_iter()
        .filter(|arg| arg != "--no-animation")
        .collect();
    let cli = Cli::parse_from(clap_args);
    startup_animation(no_animation);
    run_command(cli.command)
}

fn run_command(command: CommandKind) -> Result<()> {
    match command {
        CommandKind::Discover {
            target,
            ports,
            all_ports,
            max_targets,
            timeout_ms,
            tls,
            out,
        } => {
            println!(
                "[crypton-sweep] scanning {} target(s), ports: {} (timeout: {} ms)",
                target.len(),
                if all_ports { "1-65535" } else { &ports },
                timeout_ms
            );
            let port_spec = if all_ports { "1-65535" } else { &ports };
            let expanded_targets = expand_targets(&target, max_targets)?;
            println!(
                "[crypton-sweep] expanded {} target specification(s) to {} host(s)",
                target.len(),
                expanded_targets.len()
            );
            let report = discover(&expanded_targets, port_spec, timeout_ms, tls)?;
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
        CommandKind::Dashboard { input, out_dir } => {
            let report: ScanReport = serde_json::from_slice(&fs::read(&input)?)
                .with_context(|| format!("invalid scan report {}", input.display()))?;
            let out = dashboard_path(&input, &out_dir)?;
            fs::create_dir_all(&out_dir)?;
            fs::write(&out, render_html(&report))?;
            println!("[crypton-sweep] dashboard ready: {}", out.display());
            println!(
                "[crypton-sweep] serve it with: python3 scripts/serve_report.py --report {}",
                out.file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("report.html")
            );
        }
        CommandKind::Serve {
            input,
            out_dir,
            host,
            port,
            no_browser,
        } => {
            serve_dashboard(&input, &out_dir, &host, port, !no_browser)?;
        }
        CommandKind::ExportCyclonedx { input, out, kind } => {
            let report: ScanReport = serde_json::from_slice(&fs::read(&input)?)
                .with_context(|| format!("invalid Crypton Sweep report {}", input.display()))?;
            let bom = export_cyclonedx(&report, kind);
            write_cyclonedx(&out, &bom)?;
            println!(
                "[crypton-sweep] exported CycloneDX {} with {} component(s) to {}",
                bom_kind_label(&bom),
                bom.components.len(),
                out.display()
            );
        }
    }
    Ok(())
}

fn interactive_shell(no_animation: bool) -> Result<()> {
    if !no_animation && std::env::var_os("NO_COLOR").is_none() {
        for status in [
            "opening local workspace",
            "loading cryptographic policy",
            "ready",
        ] {
            print!("\x1b[38;5;245m  · {status:<34}\x1b[0m\r");
            io::stdout().flush().ok();
            thread::sleep(Duration::from_millis(120));
        }
        println!();
    }
    print_shell_header();
    println!("  Type a command directly or use a slash command. Type /help for examples.\n");
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        print!("\x1b[38;5;245mcrypton-sweep\x1b[0m \x1b[38;5;255m>\x1b[0m ");
        io::stdout().flush().ok();
        let Some(line) = lines.next() else {
            break;
        };
        let line = line?;
        let input = line.trim();
        if input.is_empty() {
            continue;
        }
        if matches!(input, "/exit" | "/quit" | "exit" | "quit") {
            println!("Goodbye.");
            break;
        }
        if input == "/clear" {
            print!("\x1b[2J\x1b[H");
            print_shell_header();
            continue;
        }
        if input == "/help" || input == "help" {
            print_shell_help();
            continue;
        }
        let command_args = shell_command_args(input)?;
        let parsed = match Cli::try_parse_from(
            std::iter::once("crypton-sweep".to_string()).chain(command_args),
        ) {
            Ok(cli) => cli,
            Err(error) => {
                println!("{error}");
                continue;
            }
        };
        if let Err(error) = run_command(parsed.command) {
            eprintln!("error: {error:#}");
        }
    }
    Ok(())
}

fn shell_command_args(input: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let command = input.strip_prefix('/').unwrap_or(input);
    for character in command.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '\'' | '"' if quote == Some(character) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(character),
            character if character.is_whitespace() && quote.is_none() => {
                if !current.is_empty() {
                    args.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if escaped {
        current.push('\\');
    }
    if quote.is_some() {
        anyhow::bail!("unclosed quote in command");
    }
    if !current.is_empty() {
        args.push(current);
    }
    args.retain(|value| value != "--no-animation");
    if args
        .first()
        .is_some_and(|value| value == "crypton-sweep" || value.ends_with("/crypton-sweep"))
    {
        args.remove(0);
    }
    if args.is_empty() {
        anyhow::bail!("enter a command after the prompt; use /help for examples");
    }
    Ok(args)
}

fn print_shell_header() {
    let white = "\x1b[38;5;255m";
    let muted = "\x1b[38;5;245m";
    let panel = "\x1b[48;5;235m";
    let reset = "\x1b[0m";
    let clock = chrono::Local::now().format("%H:%M:%S");
    println!("{panel}{white}  ╭──────────────────────────────────────────────────────────────────────╮{reset}");
    for line in [
        " ██████╗  ██████╗ ██╗   ██╗ ██████╗ ████████╗ ██████╗ ███╗   ██╗",
        "██╔════╝ ██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗████╗  ██║",
        "██║      ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██╔██╗ ██║",
        "██║      ██╔══██╗  ╚██╔╝  ██╔══██╗   ██║   ██║   ██║██║╚██╗██║",
        "╚██████╗ ██║  ██║   ██║   ██║  ██║   ██║   ╚██████╔╝██║ ╚████║",
        " ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝",
    ] {
        println!("{panel}{white}  │{line:<70}│{reset}");
    }
    println!(
        "{panel}{muted}  │                              sweep                         │{reset}"
    );
    println!(
        "{panel}{muted}  │                    cryptographic exposure intelligence     │{reset}"
    );
    println!("{panel}{white}  ├──────────────────────────────────────────────────────────────────────┤{reset}");
    println!(
        "{panel}{muted}  │  local session                                      {clock}  │{reset}"
    );
    println!("{panel}{white}  ╰──────────────────────────────────────────────────────────────────────╯{reset}\n");
}

fn print_shell_help() {
    println!(
        "\nCommands\n  discover ...          Scan authorized network targets\n  inventory <file>      Read a CycloneDX SBOM/CBOM\n  dashboard <file>      Generate the browser report\n  serve <file>          Generate and open the report locally\n  report <file>         Render JSON or HTML output\n  export-cyclonedx ...  Export SBOM, CBOM, or combined BOM\n\nSlash aliases\n  /discover ...  /inventory ...  /dashboard ...  /serve ...\n  /report ...    /export-cyclonedx ...  /help  /clear  /exit\n\nExamples\n  /discover --target 192.168.1.1-38 --ports 443,1883 --tls --out reports/range.json\n  /serve reports/range.json --out-dir reports\n"
    );
}

fn expand_targets(specs: &[String], max_targets: usize) -> Result<Vec<String>> {
    if max_targets == 0 {
        anyhow::bail!("--max-targets must be greater than zero");
    }
    let mut expanded = Vec::new();
    for spec in specs {
        if let Some((address, prefix)) = spec.split_once('/') {
            let ip: Ipv4Addr = address
                .parse()
                .with_context(|| format!("invalid IPv4 CIDR address: {address}"))?;
            let prefix: u8 = prefix
                .parse()
                .with_context(|| format!("invalid CIDR prefix: {prefix}"))?;
            if prefix > 32 {
                anyhow::bail!("invalid CIDR prefix /{prefix}; expected /0 through /32");
            }
            let count = 1u64 << (32 - prefix);
            if count > max_targets as u64 {
                anyhow::bail!(
                    "target {spec} expands to {count} hosts; increase --max-targets or use a smaller range"
                );
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = u32::from(ip) & mask;
            for offset in 0..count {
                expanded.push(Ipv4Addr::from(network + offset as u32).to_string());
            }
            continue;
        }

        if let Some((first, last)) = spec.split_once('-') {
            if let (Ok(first), Ok(last)) = (first.parse::<Ipv4Addr>(), last.parse::<Ipv4Addr>()) {
                let first = u32::from(first);
                let last = u32::from(last);
                append_target_range(&mut expanded, first, last, spec, max_targets)?;
                continue;
            }

            // Accept the convenient LAN shorthand: 192.168.1.1-38.
            if let (Ok(first), Ok(last_octet)) = (first.parse::<Ipv4Addr>(), last.parse::<u8>()) {
                let first = u32::from(first);
                let subnet = first & 0xffffff00;
                let last = subnet + u32::from(last_octet);
                append_target_range(&mut expanded, first, last, spec, max_targets)?;
                continue;
            }

            anyhow::bail!(
                "invalid target range {spec}; use 192.168.1.1-192.168.1.38 or 192.168.1.1-38"
            );
        }

        if spec.contains('/') {
            anyhow::bail!("unsupported target format {spec}; use an IPv4 address, CIDR, or range");
        }
        expanded.push(spec.clone());
    }
    expanded.sort();
    expanded.dedup();
    if expanded.len() > max_targets {
        anyhow::bail!(
            "target list expands to {} hosts; maximum is {}",
            expanded.len(),
            max_targets
        );
    }
    Ok(expanded)
}

fn append_target_range(
    expanded: &mut Vec<String>,
    first: u32,
    last: u32,
    spec: &str,
    max_targets: usize,
) -> Result<()> {
    if first > last {
        anyhow::bail!("invalid target range {spec}; start must not exceed end");
    }
    let count = u64::from(last - first) + 1;
    if count > max_targets as u64 {
        anyhow::bail!(
            "target {spec} expands to {count} hosts; increase --max-targets or use a smaller range"
        );
    }
    for value in first..=last {
        expanded.push(Ipv4Addr::from(value).to_string());
    }
    Ok(())
}

fn discover(targets: &[String], ports: &str, timeout_ms: u64, use_tls: bool) -> Result<ScanReport> {
    let scan_started_at = Utc::now().to_rfc3339();
    let scan_timer = Instant::now();
    let ports = parse_ports(ports)?;
    if ports.is_empty() {
        anyhow::bail!("no valid ports supplied; use values such as --ports 1883,443,8443");
    }
    let attempted_port_count = targets.len() * ports.len();
    let worker_count = ports.len().clamp(1, 64);
    let mut assets = Vec::new();
    for host in targets {
        println!("[scan] target={host}");
        assets.extend(scan_host(host, &ports, timeout_ms, use_tls)?);
    }
    let reachable_port_count = assets.len();
    Ok(finalize_report(
        "network",
        true,
        targets.to_vec(),
        assets,
        Collection {
            method: "active TCP reachability scan".into(),
            port_spec: ports_to_spec(&ports),
            attempted_ports: ports,
            attempted_port_count,
            reachable_port_count,
            worker_count,
            timeout_ms: Some(timeout_ms),
            tls_probe_requested: use_tls,
            tls_probe_timeout_ms: 3000,
            limitations: vec![
                "Closed or filtered ports are not included as assets.".into(),
                "A reachable non-TLS service does not reveal its application cryptography without a protocol-aware probe or host agent.".into(),
            ],
        },
        scan_started_at,
        scan_timer.elapsed().as_secs_f64() * 1000.0,
    ))
}

fn ports_to_spec(ports: &[u16]) -> String {
    if ports.len() == 65_535 && ports.first() == Some(&1) && ports.last() == Some(&65_535) {
        "1-65535".into()
    } else {
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for item in spec
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        if let Some((first, last)) = item.split_once('-') {
            let first: u16 = first
                .trim()
                .parse()
                .with_context(|| format!("invalid port range start: {first}"))?;
            let last: u16 = last
                .trim()
                .parse()
                .with_context(|| format!("invalid port range end: {last}"))?;
            if first == 0 || last == 0 || first > last {
                anyhow::bail!("invalid port range {item}; expected 1-65535");
            }
            ports.extend(first..=last);
        } else {
            let port: u16 = item
                .parse()
                .with_context(|| format!("invalid port: {item}"))?;
            if port == 0 {
                anyhow::bail!("port 0 is not a TCP service port");
            }
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn dashboard_path(input: &PathBuf, out_dir: &PathBuf) -> Result<PathBuf> {
    let stem = input
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .with_context(|| format!("cannot derive dashboard name from {}", input.display()))?;
    Ok(out_dir.join(format!("{stem}.html")))
}

fn scan_host(host: &str, ports: &[u16], timeout_ms: u64, use_tls: bool) -> Result<Vec<Asset>> {
    let address = format!("{host}:0");
    let ip = address
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve target {host}"))?
        .next()
        .map(|addr| addr.ip())
        .with_context(|| format!("target {host} resolved to no address"))?;
    let ports = Arc::new(ports.to_vec());
    let next = Arc::new(AtomicUsize::new(0));
    let results = Arc::new(Mutex::new(Vec::new()));
    let workers = ports.len().clamp(1, 64);
    let completed = Arc::new(AtomicUsize::new(0));

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let ports = Arc::clone(&ports);
            let next = Arc::clone(&next);
            let results = Arc::clone(&results);
            let completed = Arc::clone(&completed);
            scope.spawn(move || loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= ports.len() {
                    break;
                }
                let port = ports[index];
                let started = Instant::now();
                let socket = std::net::SocketAddr::new(ip, port);
                let reachable =
                    TcpStream::connect_timeout(&socket, Duration::from_millis(timeout_ms)).is_ok();
                let connection_duration_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if done % 1000 == 0 && ports.len() > 2000 {
                    println!("[scan] {host}: {done}/{} ports checked", ports.len());
                }
                if !reachable {
                    continue;
                }
                let endpoint = format!("{host}:{port}");
                println!(
                    "[open] {endpoint} reachable in {:.2} ms",
                    started.elapsed().as_secs_f64() * 1000.0
                );
                let (tls_observation, tls_probe) = if use_tls {
                    println!("[tls] probing {endpoint} with openssl");
                    let probe_started = Instant::now();
                    match probe_openssl(&endpoint) {
                        Ok(observation) => (
                            Some(observation),
                            ProbeEvidence {
                                attempted: true,
                                outcome: "success".into(),
                                duration_ms: Some(probe_started.elapsed().as_secs_f64() * 1000.0),
                                tool: Some("openssl s_client -brief".into()),
                                error: None,
                            },
                        ),
                        Err(error) => (
                            None,
                            ProbeEvidence {
                                attempted: true,
                                outcome: "failed".into(),
                                duration_ms: Some(probe_started.elapsed().as_secs_f64() * 1000.0),
                                tool: Some("openssl s_client -brief".into()),
                                error: Some(error.to_string()),
                            },
                        ),
                    }
                } else {
                    (
                        None,
                        ProbeEvidence {
                            attempted: false,
                            outcome: "not_requested".into(),
                            ..ProbeEvidence::default()
                        },
                    )
                };
                let crypto = crypto_from_tls(tls_observation.as_ref());
                let (risk, findings, recommendation) =
                    assess(&crypto, tls_observation.as_ref(), port);
                results
                    .lock()
                    .expect("scan results mutex poisoned")
                    .push(Asset {
                        id: endpoint,
                        host: host.to_string(),
                        port,
                        service: service_for_port(port).into(),
                        protocol: if tls_observation.is_some() {
                            "TLS".into()
                        } else {
                            service_for_port(port).into()
                        },
                        reachable: true,
                        latency_ms: connection_duration_ms,
                        connection: ProbeEvidence {
                            attempted: true,
                            outcome: "reachable".into(),
                            duration_ms: connection_duration_ms,
                            tool: Some("TCP connect".into()),
                            error: None,
                        },
                        tls_probe,
                        service_detection: ServiceDetection {
                            name: service_for_port(port).into(),
                            method: "well_known_port_mapping".into(),
                            confidence: if known_service_port(port) {
                                "medium".into()
                            } else {
                                "low".into()
                            },
                            banner_observed: false,
                        },
                        tls: tls_observation,
                        crypto,
                        risk,
                        findings,
                        recommendation,
                    });
            });
        }
    });
    let mut assets = Arc::try_unwrap(results)
        .expect("scan results still referenced")
        .into_inner()
        .expect("scan results mutex poisoned");
    assets.sort_by_key(|asset| asset.port);
    Ok(assets)
}

fn probe_openssl(address: &str) -> Result<TlsObservation> {
    let mut child = Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            address,
            "-brief",
            "-servername",
            address.split(':').next().unwrap_or(address),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("openssl is required for TLS probing")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            child.kill().ok();
            child.wait().ok();
            anyhow::bail!("TLS probe timed out after 3 seconds");
        }
        thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output()?;
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
    if observation.version.is_none()
        && observation.cipher.is_none()
        && observation.key_exchange.is_none()
        && observation.signature_algorithm.is_none()
    {
        anyhow::bail!("OpenSSL did not complete a TLS handshake");
    }
    Ok(observation)
}

fn inventory(path: &PathBuf) -> Result<ScanReport> {
    let value: Value = serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("invalid CycloneDX JSON {}", path.display()))?;
    let bom_format = value
        .get("bomFormat")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !bom_format.eq_ignore_ascii_case("CycloneDX") {
        anyhow::bail!(
            "unsupported inventory format in {}; expected CycloneDX JSON with bomFormat=CycloneDX",
            path.display()
        );
    }
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
                connection: ProbeEvidence {
                    attempted: false,
                    outcome: "not_applicable".into(),
                    ..ProbeEvidence::default()
                },
                tls_probe: ProbeEvidence {
                    attempted: false,
                    outcome: "not_applicable".into(),
                    ..ProbeEvidence::default()
                },
                service_detection: ServiceDetection {
                    name: "software component".into(),
                    method: "cyclonedx_component".into(),
                    confidence: "inventory".into(),
                    banner_observed: false,
                },
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
            port_spec: "not_applicable".into(),
            attempted_port_count: 0,
            reachable_port_count: 0,
            worker_count: 0,
            tls_probe_requested: false,
            tls_probe_timeout_ms: 0,
            limitations: vec![
                "Software inventory signals do not prove runtime negotiation.".into(),
                "Validate deployed endpoints with an active or authenticated collection method."
                    .into(),
            ],
            ..Collection::default()
        },
        Utc::now().to_rfc3339(),
        0.0,
    ))
}

fn export_cyclonedx(report: &ScanReport, kind: CycloneDxKind) -> CycloneDxBom {
    let include_software = matches!(kind, CycloneDxKind::Sbom | CycloneDxKind::Combined);
    let include_crypto = matches!(kind, CycloneDxKind::Cbom | CycloneDxKind::Combined);
    let mut components = Vec::new();
    let mut dependencies = Vec::new();

    for asset in &report.assets {
        let is_software = asset.port == 0 || asset.protocol == "component";
        let is_network = asset.port != 0;
        let has_crypto_evidence = !asset.crypto.algorithms.is_empty();
        let include_asset = (is_software
            && (include_software || (include_crypto && has_crypto_evidence)))
            || (is_network && include_crypto);
        if !include_asset {
            continue;
        }

        let reference = asset_ref(&asset.id);
        let mut properties = vec![
            property(
                "crypton.asset_type",
                if is_network {
                    "network_service"
                } else {
                    "software_component"
                },
            ),
            property("crypton.evidence_source", &asset.crypto.evidence),
            property("crypton.reachable", &asset.reachable.to_string()),
            property("crypton.risk_level", &asset.risk.level),
            property("crypton.risk_score", &asset.risk.score.to_string()),
        ];
        if is_network {
            properties.push(property("crypton.host", &asset.host));
            properties.push(property("crypton.port", &asset.port.to_string()));
            properties.push(property("crypton.protocol", &asset.protocol));
        }
        for algorithm in &asset.crypto.algorithms {
            properties.push(property("crypton.crypto_algorithm", algorithm));
        }
        if asset.crypto.algorithms.is_empty() {
            properties.push(property(
                "crypton.crypto_observation",
                if asset.crypto.encryption_observed {
                    "encryption_observed_algorithm_unknown"
                } else {
                    "not_observed"
                },
            ));
        }
        components.push(CycloneDxComponent {
            component_type: "library".into(),
            name: if is_network {
                asset.service.clone()
            } else {
                asset.host.clone()
            },
            version: if is_network {
                "runtime-observed".into()
            } else {
                asset.id.rsplit(':').next().unwrap_or("unknown").into()
            },
            bom_ref: reference.clone(),
            purl: None,
            properties,
        });

        let mut depends_on = Vec::new();
        if include_crypto {
            for algorithm in &asset.crypto.algorithms {
                let algorithm_ref = algorithm_ref(algorithm);
                if !components
                    .iter()
                    .any(|component| component.bom_ref == algorithm_ref)
                {
                    components.push(CycloneDxComponent {
                        component_type: "library".into(),
                        name: algorithm.clone(),
                        version: "observed".into(),
                        bom_ref: algorithm_ref.clone(),
                        purl: None,
                        properties: vec![
                            property("crypton.asset_type", "cryptographic_algorithm"),
                            property("crypton.algorithm", algorithm),
                            property("crypton.evidence_source", &asset.crypto.evidence),
                        ],
                    });
                }
                depends_on.push(algorithm_ref);
            }
        }
        if !depends_on.is_empty() {
            dependencies.push(CycloneDxDependency {
                ref_: reference,
                depends_on,
            });
        }
    }

    let kind_label = match kind {
        CycloneDxKind::Sbom => "sbom",
        CycloneDxKind::Cbom => "cbom",
        CycloneDxKind::Combined => "combined",
    };
    CycloneDxBom {
        bom_format: "CycloneDX".into(),
        spec_version: "1.5".into(),
        version: 1,
        metadata: CycloneDxMetadata {
            timestamp: Utc::now().to_rfc3339(),
            tools: vec![CycloneDxTool {
                vendor: "Crypton".into(),
                name: "Crypton Sweep".into(),
                version: VERSION.into(),
            }],
            properties: vec![
                property("crypton.bom_kind", kind_label),
                property("crypton.source_report", &report.scan_id),
                property("crypton.evidence_model", "network_and_software_inventory"),
            ],
        },
        components,
        dependencies,
    }
}

fn property(name: &str, value: &str) -> CycloneDxProperty {
    CycloneDxProperty {
        name: name.into(),
        value: value.into(),
    }
}

fn asset_ref(id: &str) -> String {
    format!("crypton:asset:{id}")
}

fn algorithm_ref(algorithm: &str) -> String {
    format!("crypton:algorithm:{algorithm}")
}

fn bom_kind_label(bom: &CycloneDxBom) -> &str {
    bom.metadata
        .properties
        .iter()
        .find(|property| property.name == "crypton.bom_kind")
        .map(|property| property.value.as_str())
        .unwrap_or("combined")
}

fn write_cyclonedx(path: &PathBuf, bom: &CycloneDxBom) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, serde_json::to_vec_pretty(bom)?)?;
    Ok(())
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

fn known_service_port(port: u16) -> bool {
    matches!(port, 22 | 80 | 443 | 1883 | 1884 | 7878 | 8443 | 8883)
}

fn finalize_report(
    mode: &str,
    authorized: bool,
    targets: Vec<String>,
    assets: Vec<Asset>,
    collection: Collection,
    started_at: String,
    duration_ms: f64,
) -> ScanReport {
    let completed_at = Utc::now().to_rfc3339();
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
    let mut relationships = Vec::new();
    for asset in &assets {
        let service = if asset.service.is_empty() {
            &asset.protocol
        } else {
            &asset.service
        };
        relationships.push(Relationship {
            source: asset.id.clone(),
            target: format!("service:{service}"),
            kind: "exposes".into(),
        });
        if asset.crypto.algorithms.is_empty() {
            relationships.push(Relationship {
                source: asset.id.clone(),
                target: format!("evidence:{}", asset.crypto.evidence),
                kind: "evidence".into(),
            });
        } else {
            for algorithm in &asset.crypto.algorithms {
                relationships.push(Relationship {
                    source: asset.id.clone(),
                    target: format!("algorithm:{algorithm}"),
                    kind: "uses".into(),
                });
            }
        }
    }
    ScanReport {
        scan_id: format!("sweep-{}", Utc::now().timestamp_millis()),
        schema_version: "crypton-sweep/v1".into(),
        tool: format!("crypton-sweep/{VERSION}"),
        started_at,
        completed_at: completed_at.clone(),
        duration_ms,
        generated_at: completed_at,
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
    include_str!("../templates/report.html")
        .replace("__REPORT_JSON__", &json)
        .replace(
            "__CRYPTON_LOGO_SVG__",
            include_str!("../assets/crypton-sweep-logo.svg"),
        )
}

fn serve_dashboard(
    input: &PathBuf,
    out_dir: &PathBuf,
    host: &str,
    port: u16,
    open_browser: bool,
) -> Result<()> {
    let report: ScanReport = serde_json::from_slice(&fs::read(input)?)
        .with_context(|| format!("invalid scan report {}", input.display()))?;
    let output = dashboard_path(input, out_dir)?;
    fs::create_dir_all(out_dir)?;
    fs::write(&output, render_html(&report))?;

    let listener = TcpListener::bind((host, port))
        .with_context(|| format!("failed to bind dashboard server {host}:{port}"))?;
    let actual_port = listener.local_addr()?.port();
    let file_name = output
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("report.html")
        .to_string();
    let url = format!("http://{host}:{actual_port}/{file_name}");
    println!("[crypton-sweep] dashboard generated: {}", output.display());
    println!("[crypton-sweep] serving at {url}");
    println!("[crypton-sweep] press Ctrl+C to stop");

    if open_browser {
        open_browser_url(&url);
    }
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if let Err(error) = serve_http_connection(stream, &file_name, &output) {
                    eprintln!("[crypton-sweep] browser request failed: {error}");
                }
            }
            Err(error) => eprintln!("[crypton-sweep] server connection failed: {error}"),
        }
    }
    Ok(())
}

fn serve_http_connection(mut stream: TcpStream, file_name: &str, output: &PathBuf) -> Result<()> {
    let mut request = [0u8; 8192];
    let bytes_read = stream.read(&mut request)?;
    let request = String::from_utf8_lossy(&request[..bytes_read]);
    let request_path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");
    let expected_path = format!("/{file_name}");
    let body = if request_path == "/" || request_path == expected_path {
        fs::read(output)?
    } else {
        let body = b"Not found".to_vec();
        write_http_response(&mut stream, "404 Not Found", "text/plain", &body)?;
        return Ok(());
    };
    write_http_response(&mut stream, "200 OK", "text/html; charset=utf-8", &body)
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

fn open_browser_url(url: &str) {
    let command = if cfg!(target_os = "macos") {
        "open"
    } else if cfg!(target_os = "windows") {
        "cmd"
    } else {
        "xdg-open"
    };
    let result = if cfg!(target_os = "windows") {
        Command::new(command).args(["/C", "start", "", url]).spawn()
    } else {
        Command::new(command).arg(url).spawn()
    };
    if result.is_err() {
        println!("[crypton-sweep] open this URL manually: {url}");
    }
}

fn startup_animation(disabled: bool) {
    if disabled || std::env::var_os("NO_COLOR").is_some() || !io::stdout().is_terminal() {
        println!("Crypton Sweep v{VERSION} | PQC exposure intelligence");
        return;
    }

    let white = "\x1b[38;5;255m";
    let muted = "\x1b[38;5;245m";
    let panel = "\x1b[48;5;235m";
    let reset = "\x1b[0m";
    let logo = [
        "             /\\             ",
        "        ____/  \\____        ",
        "       /    \\  /    \\       ",
        "       \\____/\\/____/       ",
        "       /    /  \\    \\       ",
        "       \\___/____\\___/       ",
        "           \\____/           ",
    ];

    print!("\x1b[?25l\n{panel}");
    println!("{white}  ╭────────────────────────────────────────────────╮{reset}");
    for line in logo {
        println!("{panel}{white}  │              {line}              │{reset}");
    }
    println!("{panel}{white}  │   C R Y P T O N   S W E E P                    │{reset}");
    println!("{panel}{muted}  │   post-quantum exposure intelligence             │{reset}");
    println!("{panel}{white}  ├────────────────────────────────────────────────┤{reset}");

    let frames = [
        ("◐", "initializing evidence engine"),
        ("◓", "loading cryptographic policy"),
        ("◑", "arming network observability"),
        ("◒", "preparing migration workspace"),
    ];
    for (spinner, message) in frames {
        print!("{panel}{white}  │   {spinner} {muted}{message:<42}{white}│{reset}\r");
        io::stdout().flush().ok();
        thread::sleep(Duration::from_millis(110));
    }
    println!("{panel}{white}  │   ✓ {white}ready{muted}  ·  authorized local analysis       {white}│{reset}");
    println!(
        "{white}  ╰────────────────────────────────────────────────╯{reset}\n{reset}\x1b[?25h"
    );
}

#[cfg(test)]
mod tests {
    use super::{dashboard_path, expand_targets, parse_ports, shell_command_args};
    use std::path::PathBuf;

    #[test]
    fn expands_cidr_and_deduplicates_targets() {
        let targets = expand_targets(
            &["192.168.1.0/30".into(), "192.168.1.1-192.168.1.2".into()],
            16,
        )
        .unwrap();
        assert_eq!(
            targets,
            vec!["192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"]
        );
    }

    #[test]
    fn rejects_target_expansion_above_limit() {
        let error = expand_targets(&["10.0.0.0/24".into()], 32).unwrap_err();
        assert!(error.to_string().contains("expands to 256 hosts"));
    }

    #[test]
    fn parses_port_ranges() {
        assert_eq!(
            parse_ports("80,443,8000-8002,443").unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
    }

    #[test]
    fn expands_multiple_shorthand_ranges() {
        let targets =
            expand_targets(&["192.168.1.1-2".into(), "192.168.1.10-11".into()], 16).unwrap();
        assert_eq!(
            targets,
            vec!["192.168.1.1", "192.168.1.10", "192.168.1.11", "192.168.1.2"]
        );
    }

    #[test]
    fn dashboard_uses_json_stem() {
        let path = dashboard_path(&"reports/industry-scan.json".into(), &"reports".into()).unwrap();
        assert_eq!(path, PathBuf::from("reports/industry-scan.html"));
    }

    #[test]
    fn shell_accepts_slash_and_full_command_forms() {
        assert_eq!(
            shell_command_args("/discover --target 192.168.1.1-38 --ports 443").unwrap(),
            vec!["discover", "--target", "192.168.1.1-38", "--ports", "443"]
        );
        assert_eq!(
            shell_command_args("crypton-sweep dashboard 'reports/a.json'").unwrap(),
            vec!["dashboard", "reports/a.json"]
        );
    }
}
