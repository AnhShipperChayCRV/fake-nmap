use crate::cli::{ScanConfig, ScanType, timing_params};
use crate::osdetect::{OsHints, OsMatch, detect_os};
use crate::services::{VersionInfo, detect_version, known_service, top_ports};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn label(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
}

impl PortState {
    pub fn label(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open|filtered",
            PortState::ClosedFiltered => "closed|filtered",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub proto: Proto,
    pub state: PortState,
    pub service: String,
    pub reason: String,
    pub version: Option<VersionInfo>,
    pub extra: String,
}

#[derive(Debug, Clone)]
pub struct HostResult {
    pub ip: IpAddr,
    pub hostname: String,
    pub up: bool,
    pub latency_ms: Option<f64>,
    pub ttl_hint: Option<u8>,
    pub ports: Vec<PortResult>,
    pub os_match: Option<OsMatch>,
}

pub struct ScanReport {
    pub hosts: Vec<HostResult>,
    pub start: Instant,
    pub elapsed: Duration,
    pub started_at_str: String,
}

/// Expand targets + ports, run every requested scan type, and build a report.
pub fn run(cfg: &ScanConfig) -> ScanReport {
    let start = Instant::now();
    let started_at_str = now_string();

    let mut ip_set: Vec<IpAddr> = Vec::new();
    for tok in &cfg.targets {
        let before = ip_set.len();
        crate::targets::expand_target(tok, &mut ip_set);
        if cfg.verbose {
            println!(
                "Expanded {tok} into {} address(es).",
                ip_set.len() - before
            );
        }
    }
    // Deduplicate and honour --exclude.
    let mut seen: HashSet<IpAddr> = HashSet::new();
    let mut excluded: Vec<IpAddr> = Vec::new();
    for tok in &cfg.exclude {
        crate::targets::expand_target(tok, &mut excluded);
    }
    let ip_set: Vec<IpAddr> = ip_set
        .into_iter()
        .filter(|ip| {
            if excluded.contains(ip) {
                false
            } else {
                seen.insert(*ip)
            }
        })
        .collect();

    if ip_set.is_empty() {
        eprintln!("ERROR: No target machine specified for Scan.");
    }

    let ports = select_ports(cfg);
    let (timeout_ms, workers) = timing_params(cfg.timing);

    // ------------------------------------------------------------------
    // Phase: host discovery (unless -Pn / -sP relies on it too).
    // ------------------------------------------------------------------
    let mut hosts: Vec<HostResult> = Vec::new();
    if cfg.no_ping {
        for ip in &ip_set {
            hosts.push(HostResult {
                ip: *ip,
                hostname: String::new(),
                up: true,
                latency_ms: None,
                ttl_hint: None,
                ports: Vec::new(),
                os_match: None,
            });
        }
    } else {
        if cfg.verbose {
            println!("Initiating Parallel DNS resolution of {n} host(s).", n = ip_set.len());
        }
        let probe_ports: Vec<u16> = vec![80, 443, 22, 445];
        let results = par_for(ip_set.clone(), workers, move |ip| {
            let (ping_ok, latency, ttl) = ping_probe(ip);
            let up = ping_ok
                || probe_ports
                    .iter()
                    .any(|p| try_connect(ip, *p, Duration::from_millis(300)).is_some());
            (ip, up, latency, ttl)
        });
        for (ip, up, latency, ttl) in results {
            hosts.push(HostResult {
                ip,
                hostname: String::new(),
                up,
                latency_ms: latency,
                ttl_hint: ttl,
                ports: Vec::new(),
                os_match: None,
            });
        }
    }

    if !cfg.ping_scan {
        // ----------------------------------------------------------------
        // Phase: port scanning.
        // ----------------------------------------------------------------
        let syn_available = crate::rawscan::syn_supported();
        if cfg.verbose {
            if syn_available {
                println!("Raw sockets available: using SYN scan.");
            } else if cfg.scan_types.iter().any(|s| *s == ScanType::TcpSyn) {
                eprintln!("Note: Raw sockets unavailable (SYN scan typically needs root/admin).");
                eprintln!("      Falling back to TCP connect scan for -sS/-sN/-sF/-sX/-sA.");
            }
        }

        let udp_ports: Vec<u16> = if cfg.scan_udp {
            ports.iter().cloned().collect()
        } else {
            Vec::new()
        };
        let tcp_ports: Vec<u16> = ports.iter().cloned().collect();
        let version_detect = cfg.version_detect;

        for host in hosts.iter_mut() {
            if !host.up {
                continue;
            }
            let ip = host.ip;
            let mut all: Vec<PortResult> = Vec::new();

            // TCP scans.
            let want_syn = cfg.scan_types.contains(&ScanType::TcpSyn)
                && !cfg.scan_types.contains(&ScanType::TcpConnect);
            let res = par_for(tcp_ports.clone(), workers, move |port| {
                if syn_available && want_syn {
                    scan_one_port_syn(ip, port, timeout_ms)
                } else {
                    scan_one_port_connect(ip, port, timeout_ms, version_detect)
                }
            });
            all.extend(res);

            // UDP scans.
            if cfg.scan_udp {
                let res = par_for(udp_ports.clone(), workers, move |port| {
                    scan_one_port_udp(ip, port, timeout_ms)
                });
                all.extend(res);
            }

            all.sort_by(|a, b| {
                (a.proto.label(), a.port).cmp(&(b.proto.label(), b.port))
            });
            host.ports = all;

            if cfg.dns_lookup {
                host.hostname = crate::scan::hostname_of(ip).unwrap_or_default();
            }

            if cfg.os_detect {
                let hints = OsHints {
                    ttl: host.ttl_hint,
                    open_tcp: host
                        .ports
                        .iter()
                        .filter(|p| p.proto == Proto::Tcp && p.state == PortState::Open)
                        .map(|p| (p.port, p.version.clone()))
                        .collect(),
                };
                host.os_match = detect_os(ip, &hints);
            }
        }

        // Re-discover hosts whose ports are all filtered: they are still "up"
        // because a ping succeeded, but this is where a firewall might hide them.
    }

    // Nmap reports hosts with no open ports as up only if discovery succeeded;
    // -Pn marks everything up.
    let elapsed = start.elapsed();
    ScanReport {
        hosts,
        start,
        elapsed,
        started_at_str,
    }
}

fn select_ports(cfg: &ScanConfig) -> Vec<u16> {
    if !cfg.ports.is_empty() {
        return cfg.ports.iter().cloned().collect();
    }
    if cfg.fast {
        return top_ports(100);
    }
    if cfg.top_ports > 0 {
        return top_ports(cfg.top_ports);
    }
    if cfg.ping_scan {
        return Vec::new();
    }
    // Nmap's default: the 1000 most common ports. We ship a curated list.
    top_ports(1000)
}

/// Generic parallel worker pool using a shared work queue.
pub fn par_for<T: Send + 'static, R: Send + 'static>(
    items: Vec<T>,
    workers: usize,
    f: impl Fn(T) -> R + Sync + Send + 'static,
) -> Vec<R> {
    let n = workers.max(1);
    let queue: Arc<Mutex<VecDeque<T>>> = Arc::new(Mutex::new(items.into_iter().collect()));
    let out: Arc<Mutex<Vec<R>>> = Arc::new(Mutex::new(Vec::new()));
    let f = Arc::new(f);
    let mut handles = Vec::new();
    for _ in 0..n {
        let queue = queue.clone();
        let out = out.clone();
        let f = f.clone();
        handles.push(thread::spawn(move || loop {
            let item = { queue.lock().unwrap().pop_front() };
            match item {
                Some(t) => {
                    let r = f(t);
                    out.lock().unwrap().push(r);
                }
                None => break,
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    let mut guard = out.lock().unwrap();
    std::mem::take(&mut *guard)
}

fn try_connect(ip: IpAddr, port: u16, timeout: Duration) -> Option<Duration> {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => Some(started.elapsed()),
        Err(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Ping / host discovery.
// ---------------------------------------------------------------------------

fn ping_probe(ip: IpAddr) -> (bool, Option<f64>, Option<u8>) {
    if ip.is_ipv6() {
        return (false, None, None);
    }
    let out = {
        #[cfg(windows)]
        {
            std::process::Command::new("ping")
                .args(["-n", "1", "-w", "900"])
                .arg(ip.to_string())
                .output()
        }
        #[cfg(unix)]
        {
            std::process::Command::new("ping")
                .args(["-c", "1", "-W", "1"])
                .arg(ip.to_string())
                .output()
        }
    };
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let lower = text.to_lowercase();
            let ttl = extract_ttl(&text);
            let latency = extract_latency(&lower);
            (true, latency, ttl)
        }
        _ => (false, None, None),
    }
}

fn extract_ttl(text: &str) -> Option<u8> {
    let lower = text.to_lowercase();
    if let Some(pos) = lower.find("ttl=") {
        let rest = &lower[pos + 4..];
        let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        return num.parse().ok();
    }
    None
}

fn extract_latency(text: &str) -> Option<f64> {
    for marker in ["time=", "time<", "time ="] {
        if let Some(pos) = text.find(marker) {
            let rest = &text[pos + marker.len()..];
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
                .collect();
            let parsed: f64 = num.replace(',', ".").parse().unwrap_or(0.0);
            return Some(parsed);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// TCP connect scan.
// ---------------------------------------------------------------------------

fn scan_one_port_connect(ip: IpAddr, port: u16, timeout_ms: u64, version: bool) -> PortResult {
    let service = known_service(port, true).to_string();
    let timeout = Duration::from_millis(timeout_ms);
    match try_connect(ip, port, timeout) {
        Some(_elapsed) => {
            let mut pr = PortResult {
                port,
                proto: Proto::Tcp,
                state: PortState::Open,
                service,
                reason: "syn-ack".into(),
                version: None,
                extra: String::new(),
            };
            if version {
                pr.version = banner_grab(ip, port);
            }
            pr
        }
        None => {
            // We must distinguish filtered/rejected vs closed. Since connect()
            // gives no direct reason, treat logical "connection refused" errors
            // as closed and everything else (timeouts, unreachable) as filtered.
            match TcpStream::connect((ip, port)) {
                Ok(_) => PortResult {
                    port,
                    proto: Proto::Tcp,
                    state: PortState::Open,
                    service,
                    reason: "syn-ack".into(),
                    version: if version { banner_grab(ip, port) } else { None },
                    extra: String::new(),
                },
                Err(e) => {
                    let refused = e.kind() == std::io::ErrorKind::ConnectionRefused;
                    PortResult {
                        port,
                        proto: Proto::Tcp,
                        state: if refused { PortState::Closed } else { PortState::Filtered },
                        service,
                        reason: if refused { "conn-refused" } else { "no-response" }.into(),
                        version: None,
                        extra: String::new(),
                    }
                }
            }
        }
    }
}

/// Bulk version grabbing: reconnect to the open port and run probes.
fn banner_grab(ip: IpAddr, port: u16) -> Option<VersionInfo> {
    let send_fn: Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, String> + Send> =
        Box::new(move |payload| {
            let addr = SocketAddr::new(ip, port);
            // Short, relaxed timeout for the banner round.
            let stream = TcpStream::connect_timeout(&addr, Duration::from_millis(1500))
                .map_err(|e| e.to_string())?;
            let mut stream = stream;
            stream.set_read_timeout(Some(Duration::from_millis(900))).ok();
            if !payload.is_empty() {
                let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                let _ = stream.write_all(payload);
            }
            let mut buf = vec![0u8; 4096];
            let mut total = Vec::new();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        total.extend_from_slice(&buf[..n]);
                        if total.len() >= 2048 {
                            break;
                        }
                    }
                }
                // Single pass is enough for banners.
                break;
            }
            Ok(total)
        });
    detect_version(port, true, send_fn)
}

// ---------------------------------------------------------------------------
// TCP SYN scan.
// ---------------------------------------------------------------------------

fn scan_one_port_syn(ip: IpAddr, port: u16, timeout_ms: u64) -> PortResult {
    let service = known_service(port, true).to_string();
    match crate::rawscan::syn_probe(ip, port, Duration::from_millis(timeout_ms)) {
        Some(true) => PortResult {
            port,
            proto: Proto::Tcp,
            state: PortState::Open,
            service,
            reason: "syn-ack".into(),
            version: None,
            extra: String::new(),
        },
        Some(false) => PortResult {
            port,
            proto: Proto::Tcp,
            state: PortState::Closed,
            service,
            reason: "reset".into(),
            version: None,
            extra: String::new(),
        },
        None => PortResult {
            port,
            proto: Proto::Tcp,
            state: PortState::Filtered,
            service,
            reason: "no-response".into(),
            version: None,
            extra: String::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// UDP scan.
// ---------------------------------------------------------------------------

fn scan_one_port_udp(ip: IpAddr, port: u16, timeout_ms: u64) -> PortResult {
    use std::net::UdpSocket;
    let service = known_service(port, false).to_string();
    let timeout = Duration::from_millis(timeout_ms);
    let src_port = 20000u16 + (port % 20000);

    let out = UdpSocket::bind(("0.0.0.0", 0));
    let socket = match out {
        Ok(s) => s,
        Err(_) => {
            return PortResult {
                port,
                proto: Proto::Udp,
                state: PortState::OpenFiltered,
                service,
                reason: "udp-response".into(),
                version: None,
                extra: String::new(),
            }
        }
    };
    let _ = socket.connect((ip, port));
    let _ = socket.set_read_timeout(Some(timeout));

    // A specific payload for a handful of protocols helps trigger replies.
    let payload: &[u8] = match port {
        53 => &[0x00, 0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        161 => &[0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,
            0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00],
        137 => &[0x21, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x20, 0x43, 0x4b, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x00, 0x00, 0x21, 0x00, 0x01],
        _ => &[],
    };
    let _ = socket.send(payload);

    let mut buf = [0u8; 2048];
    match socket.recv(&mut buf) {
        Ok(_) => {
            let mut pr = PortResult {
                port,
                proto: Proto::Udp,
                state: PortState::Open,
                service,
                reason: "udp-response".into(),
                version: None,
                extra: String::new(),
            };
            if crate::rawscan::udp_supported() {
                if let Some(info) = crate::rawscan::udp_icmp_check(ip, port, src_port, timeout_ms)
                {
                    if info {
                        pr.extra = "ICMP port unreachable".into();
                    }
                }
            }
            pr
        }
        Err(_) => {
            // On systems with raw ICMP access we can detect "closed" properly.
            if crate::rawscan::udp_supported() {
                let _ = src_port;
                if let Some(closed) =
                    crate::rawscan::udp_icmp_check(ip, port, src_port, timeout_ms)
                {
                    if closed {
                        return PortResult {
                            port,
                            proto: Proto::Udp,
                            state: PortState::Closed,
                            service,
                            reason: "port-unreach".into(),
                            version: None,
                            extra: String::new(),
                        };
                    }
                }
            }
            PortResult {
                port,
                proto: Proto::Udp,
                state: PortState::OpenFiltered,
                service,
                reason: "no-response".into(),
                version: None,
                extra: String::new(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Reverse DNS.
// ---------------------------------------------------------------------------

pub fn hostname_of(ip: IpAddr) -> Option<String> {
    crate::rawscan::reverse_dns(ip)
}

/// Human readable local time, e.g. "2026-09-12 14:33:21".
fn now_string() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86400;
    let time = secs % 86400;
    let (y, m, d) = civil_from_days(days as i64);
    let (h, mi, s) = (time / 3600, (time % 3600) / 60, time % 60);
    format!("{y:04}-{m:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[allow(dead_code)]
pub fn now_string_hms() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let time = secs % 86400;
    let (h, mi, s) = (time / 3600, (time % 3600) / 60, time % 60);
    format!("{h:02}:{mi:02}:{s:02}")
}