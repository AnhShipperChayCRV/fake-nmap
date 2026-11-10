use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScanType {
    TcpSyn,
    TcpConnect,
    Udp,
    Ping,
    Null,
    Fin,
    Xmas,
    Ack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutFormat {
    Normal,
    Grepable,
    Json,
    Xml,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub scan_types: Vec<ScanType>,
    pub targets: Vec<String>,
    pub ports: BTreeSet<u16>,
    pub no_ping: bool,
    pub ping_scan: bool,
    pub dns_lookup: bool,
    pub verbose: bool,
    pub timing: i32,
    pub top_ports: usize,
    pub fast: bool,
    pub version_detect: bool,
    pub os_detect: bool,
    pub aggressive: bool,
    pub open_only: bool,
    pub exclude: Vec<String>,
    pub outputs: Vec<(OutFormat, String)>,
    pub help: bool,
    pub scan_udp: bool,
    pub raw_args: Vec<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        ScanConfig {
            scan_types: vec![ScanType::TcpSyn],
            targets: Vec::new(),
            ports: BTreeSet::new(),
            no_ping: false,
            ping_scan: false,
            dns_lookup: true,
            verbose: false,
            timing: 3,
            top_ports: 0,
            fast: false,
            version_detect: false,
            os_detect: false,
            aggressive: false,
            open_only: false,
            exclude: Vec::new(),
            outputs: Vec::new(),
            help: false,
            scan_udp: false,
            raw_args: Vec::new(),
        }
    }
}

pub fn usage() -> String {
    let mut s = String::new();
    s.push_str("Fake Nmap 1.0.0 ( https://fakenmap.local )\n");
    s.push_str("Usage: fakenmap [Scan Type(s)] [Options] {target specification}\n\n");
    s.push_str("SCAN TYPES:\n");
    s.push_str("  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans\n");
    s.push_str("  -sU:             UDP scan\n");
    s.push_str("  -sN/sF/sX:       TCP Null, FIN, and Xmas scans\n");
    s.push_str("  -sP/-sn:         Ping scan (host discovery only)\n");
    s.push_str("  -sV:             Version detection\n");
    s.push_str("  -A:              Enable OS detection, version detection, script scanning\n\n");
    s.push_str("OPTIONS:\n");
    s.push_str("  -p <port ranges> Port(s) to scan, e.g. 22,80,443 or 1-1000 or -p-\n");
    s.push_str("  -F:              Fast mode (scan only the 100 most common ports)\n");
    s.push_str("  --top-ports <n>: Scan the n most common ports\n");
    s.push_str("  -O:              Enable OS detection\n");
    s.push_str("  -n/-R:           Never/Always do DNS resolution\n");
    s.push_str("  -Pn:             Treat all hosts as online (skip host discovery)\n");
    s.push_str("  -T<0-5>:         Set timing template (higher is faster)\n");
    s.push_str("  -v:              Increase verbosity level\n");
    s.push_str("  --open:          Only show open (or possibly open) ports\n");
    s.push_str("  -iL <file>:      Input from list of hosts/networks\n");
    s.push_str("  --exclude <hosts> Exclude hosts/networks from the scan\n");
    s.push_str("  -oN/-oG/-oJ/-oX <file>: Output in normal/grepable/JSON/XML formats\n\n");
    s
}

fn take_value(args: &[String], i: &mut usize, flag: &str, out: &mut Vec<String>) {
    *i += 1;
    if *i < args.len() {
        out.push(args[*i].clone());
    } else {
        eprintln!("ERROR: {flag} requires an argument.");
    }
}

pub fn parse(args: &[String]) -> ScanConfig {
    let mut cfg = ScanConfig {
        scan_types: vec![],
        raw_args: args.to_vec(),
        ..Default::default()
    };
    let mut i = 0;
    let mut include_file_targets = Vec::new();
    let mut explicitly_scan = false;

    while i < args.len() {
        let a = args[i].clone();
        match a.as_str() {
            "-h" | "-help" | "--help" => {
                cfg.help = true;
                return cfg;
            }
            "-sS" => {
                cfg.scan_types.push(ScanType::TcpSyn);
                explicitly_scan = true;
            }
            "-sT" => {
                cfg.scan_types.push(ScanType::TcpConnect);
                explicitly_scan = true;
            }
            "-sU" => {
                cfg.scan_types.push(ScanType::Udp);
                cfg.scan_udp = true;
                explicitly_scan = true;
            }
            "-sP" | "-sn" => {
                cfg.scan_types.push(ScanType::Ping);
                cfg.ping_scan = true;
                explicitly_scan = true;
            }
            "-sN" => {
                cfg.scan_types.push(ScanType::Null);
                explicitly_scan = true;
            }
            "-sF" => {
                cfg.scan_types.push(ScanType::Fin);
                explicitly_scan = true;
            }
            "-sX" => {
                cfg.scan_types.push(ScanType::Xmas);
                explicitly_scan = true;
            }
            "-sA" => {
                cfg.scan_types.push(ScanType::Ack);
                explicitly_scan = true;
            }
            "-sW" | "-sM" | "-sC" | "-sZ" => {
                // Accepted as aliases; behaviour follows TCP connect.
                cfg.scan_types.push(ScanType::TcpConnect);
                explicitly_scan = true;
            }
            "-sV" => cfg.version_detect = true,
            "-O" => cfg.os_detect = true,
            "-A" => {
                cfg.aggressive = true;
                cfg.os_detect = true;
                cfg.version_detect = true;
            }
            "-Pn" | "-P0" | "-PN" | "--no-ping" => cfg.no_ping = true,
            "-n" => cfg.dns_lookup = false,
            "-R" => cfg.dns_lookup = true,
            "-F" => cfg.fast = true,
            "-v" | "--verbose" => cfg.verbose = true,
            "-vv" => cfg.verbose = true,
            "--open" => cfg.open_only = true,
            "-p" | "-ports" => {
                i += 1;
                if i < args.len() {
                    parse_port_spec(&args[i], &mut cfg.ports);
                } else {
                    eprintln!("ERROR: -p requires a port specification.");
                }
            }
            "-p-" => {
                for p in 1..=65535u16 {
                    cfg.ports.insert(p);
                }
            }
            "--top-ports" => {
                i += 1;
                if i < args.len() {
                    cfg.top_ports = args[i].parse().unwrap_or(100);
                }
            }
            "--exclude" => {
                i += 1;
                if i < args.len() {
                    for t in args[i].split(',') {
                        cfg.exclude.push(t.to_string());
                    }
                }
            }
            "-iL" => {
                i += 1;
                if i < args.len() {
                    if let Ok(contents) = std::fs::read_to_string(&args[i]) {
                        for line in contents.lines() {
                            let line = line.trim();
                            if !line.is_empty() && !line.starts_with('#') {
                                include_file_targets.push(line.to_string());
                            }
                        }
                    }
                }
            }
            "-oN" | "-oG" | "-oJ" | "-oX" => {
                let fmt = match a.as_str() {
                    "-oN" => OutFormat::Normal,
                    "-oG" => OutFormat::Grepable,
                    "-oJ" => OutFormat::Json,
                    _ => OutFormat::Xml,
                };
                take_value(args, &mut i, &a, &mut Vec::new());
                if i < args.len() {
                    cfg.outputs.push((fmt, args[i].clone()));
                }
            }
            _ => {
                if let Some(rest) = a.strip_prefix("-T") {
                    if let Ok(t) = rest.parse::<i32>() {
                        if (0..=5).contains(&t) {
                            cfg.timing = t;
                        } else {
                            eprintln!("Warning: illegal timing template {t}; using T0");
                            cfg.timing = 0;
                        }
                    } else {
                        eprintln!("Warning: unrecognized timing template \"{a}\"");
                    }
                } else if a.starts_with("-T") && a.len() == 2 {
                    eprintln!("Warning: timing template requires a digit (T0-T5)");
                } else if a.starts_with('-') && a != "-" {
                    eprintln!("Warning: Unknown option {a}");
                } else {
                    // Must be a target. Check whether it contains further parser
                    // characters (a comma, whitespace, or colon) and split it.
                    for tok in split_targets(&a) {
                        cfg.targets.push(tok);
                    }
                }
            }
        }
        i += 1;
    }

    for t in include_file_targets {
        cfg.targets.extend(split_targets(&t));
    }
    if cfg.targets.is_empty() {
        eprintln!("ERROR: No target machine specified for Scan.");
        eprintln!();
    }

    if !explicitly_scan && !cfg.ping_scan {
        // Nmap default is -sS when run as root, -sT otherwise.
        if has_root() {
            cfg.scan_types.push(ScanType::TcpSyn);
        } else {
            cfg.scan_types.push(ScanType::TcpConnect);
        }
    }
    if cfg.scan_types.is_empty() {
        cfg.scan_types.push(ScanType::TcpSyn);
    }

    cfg
}

// Split a token like "host1,host2 localhost" or "192.168.1.1/24,scanme" on
// commas and whitespace into individual target specs.
fn split_targets(tok: &str) -> Vec<String> {
    tok.split([',', ' ', '\t'])
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

pub fn parse_port_spec(spec: &str, out: &mut BTreeSet<u16>) {
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part == "-" {
            for p in 1..=65535u16 {
                out.insert(p);
            }
            continue;
        }
        // "T:21,22 U:53" style protocol prefixes.
        let (lo, hi) = if part.contains('-') {
            let (a, b) = part.split_once('-').unwrap();
            (a, b)
        } else {
            (part, part)
        };
        let lo_num = match parse_port_token(lo) {
            Some(n) => n,
            None => continue,
        };
        let hi_num = match parse_port_token(hi) {
            Some(n) => n,
            None => continue,
        };
        if lo_num <= hi_num && hi_num <= 65535 {
            for p in lo_num..=hi_num {
                out.insert(p as u16);
            }
        }
    }
}

fn parse_port_token(tok: &str) -> Option<u32> {
    if let Ok(n) = tok.parse::<u32>() {
        return Some(n);
    }
    // Named service ports, e.g. http, ssh, https.
    let name = tok.to_lowercase();
    let p = match name.as_str() {
        "ssh" => Some(22),
        "http" => Some(80),
        "https" => Some(443),
        "ftp" => Some(21),
        "telnet" => Some(23),
        "smtp" => Some(25),
        "dns" | "domain" => Some(53),
        "dhcp" => Some(67),
        "pop3" => Some(110),
        "imap" => Some(143),
        "ntp" => Some(123),
        "snmp" => Some(161),
        "smtps" | "submission" => Some(587),
        "ldap" => Some(389),
        "rdp" => Some(3389),
        "mysql" => Some(3306),
        "postgres" | "pgsql" => Some(5432),
        "redis" => Some(6379),
        "mongo" | "mongod" => Some(27017),
        "smb" => Some(445),
        "netbios" => Some(139),
        "socks" => Some(1080),
        "proxy" => Some(8080),
        "sip" => Some(5060),
        _ => None,
    };
    p.map(|x| x as u32)
}

fn has_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        false
    }
}

/// Timing template parameters: (recv timeout, max concurrent connections).
pub fn timing_params(t: i32) -> (u64, usize) {
    match t {
        0 => (3000, 8),
        1 => (2000, 8),
        2 => (1500, 8),
        3 => (1000, 16),
        4 => (700, 64),
        5 => (500, 128),
        _ => (1000, 16),
    }
}