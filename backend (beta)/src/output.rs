use crate::cli::{OutFormat, ScanConfig, ScanType};
use crate::scan::{PortResult, PortState, Proto, ScanReport};

pub fn emit(cfg: &ScanConfig, rep: &ScanReport) {
    print_report(cfg, rep);
    for (fmt, path) in &cfg.outputs {
        let content = match fmt {
            OutFormat::Normal => render_text(cfg, rep),
            OutFormat::Grepable => render_grepable(cfg, rep),
            OutFormat::Json => render_json(cfg, rep),
            OutFormat::Xml => render_xml(cfg, rep),
        };
        match std::fs::write(path, content) {
            Ok(()) => println!("\nWrote {fmt:?} output to {path}."),
            Err(e) => eprintln!("ERROR: writing {path}: {e}"),
        }
    }
}

pub fn render_text(cfg: &ScanConfig, rep: &ScanReport) -> String {
    let mut s = String::new();
    push_report(cfg, rep, &mut s);
    s
}

fn scan_desc(cfg: &ScanConfig) -> String {
    let mut descs: Vec<&str> = Vec::new();
    for st in &cfg.scan_types {
        let d = match st {
            ScanType::TcpSyn => "SYN Stealth Scan",
            ScanType::TcpConnect => "Connect Scan",
            ScanType::Udp => "UDP Scan",
            ScanType::Ping => "Ping Scan",
            ScanType::Null => "NULL Scan",
            ScanType::Fin => "FIN Scan",
            ScanType::Xmas => "Xmas Scan",
            ScanType::Ack => "ACK Scan",
        };
        if !descs.contains(&d) {
            descs.push(d);
        }
    }
    descs.join("; ")
}

fn push_report(cfg: &ScanConfig, rep: &ScanReport, s: &mut String) {
    let up = rep.hosts.iter().filter(|h| h.up).count();

    s.push_str(&format!(
        "Starting Fake Nmap 1.0.0 ( https://fakenmap.local ) at {}\n",
        rep.started_at_str
    ));
    if cfg.verbose {
        s.push_str(&format!(
            "Initiating {} against {} host{} [ 65535 ports at {:?} ]\n",
            scan_desc(cfg),
            rep.hosts.len(),
            if rep.hosts.len() == 1 { "" } else { "s" },
            rep.start.elapsed(),
        ));
    }

    for host in &rep.hosts {
        push_host(cfg, host, s);
    }

    s.push_str(&format!(
        "\nNmap done: {} IP addres{} ({} host{} up) scanned in {:.2} seconds\n",
        rep.hosts.len(),
        if rep.hosts.len() == 1 { "s" } else { "ses" },
        up,
        if up == 1 { "" } else { "s" },
        rep.elapsed.as_secs_f64(),
    ));
}

fn push_host(cfg: &ScanConfig, host: &crate::scan::HostResult, s: &mut String) {
    s.push('\n');
    let label = if !host.hostname.is_empty() {
        format!("{} ({})", host.hostname, host.ip)
    } else {
        host.ip.to_string()
    };
    s.push_str(&format!("Nmap scan report for {label}\n"));

    if !host.up {
        s.push_str("Host is down.\n");
        return;
    }

    match host.latency_ms {
        Some(ms) => s.push_str(&format!("Host is up ({:.4}s latency).\n", ms / 1000.0)),
        None => s.push_str("Host is up.\n"),
    }

    let mut shown = Vec::new();
    let mut closed_tcp = 0usize;
    let mut closed_reason: Option<String> = None;
    let mut filtered = 0usize;
    for p in &host.ports {
        if cfg.open_only && !is_showable(state_only(p)) {
            continue;
        }
        match state_only(p) {
            PortState::Closed => {
                closed_tcp += 1;
                if closed_reason.is_none() {
                    closed_reason = Some(p.reason.clone());
                }
            }
            PortState::Filtered => filtered += 1,
            _ => shown.push(p),
        }
    }

    if shown.is_empty() && closed_tcp == 0 && filtered == 0 {
        // Nothing scanned (pure ping scan) or nothing found worth showing.
        if host.ports.is_empty() && !cfg.ping_scan {
            s.push_str("All 1000 scanned ports on  are in ignored states.\n");
        }
    } else {
        let mut parts = Vec::new();
        if closed_tcp > 0 {
            let proto = if closed_reason.as_deref() == Some("port-unreach") { "udp" } else { "tcp" };
            let reason = closed_reason.clone().unwrap_or_default();
            parts.push(format!("{closed_tcp} closed {proto} ports ({reason})"));
        }
        if filtered > 0 {
            parts.push(format!("{filtered} filtered ports (no-response)"));
        }
        if !parts.is_empty() {
            s.push_str(&format!("Not shown: {}\n", parts.join("; ")));
        }
    }

    if shown.is_empty() && !cfg.ping_scan {
        // Still show header if there is at least one open result row below.
        if shown.is_empty() && host.ports.iter().any(|p| shows_open(p)) {
            push_table(cfg, &shown, s);
        }
    } else if !shown.is_empty() {
        push_table(cfg, &shown, s);
    }

    if cfg.os_detect {
        if let Some(osm) = &host.os_match {
            s.push_str(&format!("OS details: {} ({}%)\n", osm.name, osm.accuracy));
            if !osm.details.is_empty() {
                s.push_str(&format!("                                     {}\n", osm.details.join("; ")));
            }
            s.push_str(&format!(
                "No exact OS matches for host (testing conditions non-ideal).\n"
            ));
            s.push_str(&format!("Network Distance: 1 hop\n"));
        }
    }

    // MAC address section is omitted since we do not touch layer 2.
}

fn shows_open(p: &PortResult) -> bool {
    matches!(state_only(p), PortState::Open | PortState::OpenFiltered)
}

fn is_showable(_st: PortState) -> bool {
    true
}

fn state_only(p: &PortResult) -> PortState {
    p.state
}

fn push_table(cfg: &ScanConfig, ports: &[&PortResult], s: &mut String) {
    if ports.is_empty() {
        // Nothing matched by --open.
        return;
    }
    let with_version = cfg.version_detect && ports.iter().any(|p| p.version.is_some());

        s.push_str("PORT     STATE     SERVICE       VERSION\n");
    for p in ports {
        let st = state_only(p);
        let state_str = st.label();
        let port_str = format!("{}/{}", p.port, p.proto.label());
        let service_clean = if p.service.is_empty() {
            "unknown"
        } else {
            p.service.as_str()
        };
        let mut row = format!(
            "{:8} {:9} {:<14}",
            port_str,
            state_str,
            service_clean,
        );
        if with_version {
            if let Some(v) = &p.version {
                let mut ver = String::new();
                if !v.product.is_empty() {
                    ver.push_str(&v.product);
                }
                if !v.version.is_empty() {
                    ver.push_str(&format!(" {}", v.version));
                }
                if !v.info.is_empty() {
                    ver.push_str(&format!(" ({})", v.info));
                }
                row.push(' ');
                row.push_str(&ver);
            }
        }
        row.push('\n');
        s.push_str(&row);
    }
    // Version/host line is omitted here.
    let _ = cfg;
}

pub fn render_grepable(_cfg: &ScanConfig, rep: &ScanReport) -> String {
    let mut s = String::new();
    s.push_str("# Fake Nmap 1.0.0 scan initiated \n");
    for h in &rep.hosts {
        if !h.up {
            s.push_str(&format!(
                "Host: {} ({})  Status: Down  Ignored State: 'down'\n",
                h.ip,
                h.hostname
            ));
            continue;
        }
        let mut ports: Vec<String> = Vec::new();
        let mut ignored_tcp = 0;
        let mut ignored_udp = 0;
        for p in &h.ports {
            if state_only(p) == PortState::Closed {
                if p.proto == Proto::Tcp {
                    ignored_tcp += 1;
                } else {
                    ignored_udp += 1;
                }
            } else {
                let state = state_only(p).label();
                let ver = p
                    .version
                    .as_ref()
                    .map(|v| format!("{}/{}", v.product, v.version))
                    .unwrap_or_default();
                ports.push(format!(
                    "{}/{}/{}/{}/{}/{}/{}",
                    p.port,
                    state,
                    p.proto.label(),
                    p.service,
                    ver,
                    p.reason,
                    "-"
                ));
            }
        }
        let mut ig = Vec::new();
        if ignored_tcp > 0 {
            ig.push(format!("tcp ({ignored_tcp})"));
        }
        if ignored_udp > 0 {
            ig.push(format!("udp ({ignored_udp})"));
        }
        let ports_str = if ports.is_empty() {
            "-".to_string()
        } else {
            ports.join(",")
        };
        let ig_str = if ig.is_empty() { "-".to_string() } else { ig.join(",") };
        let os = h
            .os_match
            .as_ref()
            .map(|o| o.name.as_str())
            .unwrap_or("");
        s.push_str(&format!(
            "Host: {} ({})\tPorts: {}\tIgnored State: {}\tOS: {}\n",
            h.ip, h.hostname, ports_str, ig_str, os
        ));
    }
    s.push_str(&format!(
        "# Nmap done at {}: 1 IP address\n",
        rep.start.elapsed().as_secs_f64()
    ));
    s
}

pub fn render_json(cfg: &ScanConfig, rep: &ScanReport) -> String {
    use serde_json::json;
    let mut hosts = Vec::new();
    for h in &rep.hosts {
        let mut ports = Vec::new();
        for p in &h.ports {
            let mut po = json!({
                "port": p.port.to_string(),
                "proto": p.proto.label(),
                "state": state_only(p).label(),
                "reason": p.reason,
                "service": p.service,
            });
            if let Some(v) = &p.version {
                po["product"] = json!(v.product);
                po["version"] = json!(v.version);
                po["extrainfo"] = json!(v.info);
            }
            if !p.extra.is_empty() {
                po["extra"] = json!(p.extra);
            }
            ports.push(po);
        }
        let mut ho = json!({
            "ip": h.ip.to_string(),
            "hostname": h.hostname,
            "status": if h.up { "up" } else { "down" },
            "latency": h.latency_ms.map(|l| format!("{:.4}s", l / 1000.0)).unwrap_or_default(),
            "ports": ports,
        });
        if let Some(osm) = &h.os_match {
            ho["osnames"] = json!([format!("{} ({}%)", osm.name, osm.accuracy)]);
            ho["osdetails"] = json!(osm.details);
        }
        hosts.push(ho);
    }

    let nup = rep.hosts.iter().filter(|h| h.up).count();
    let doc = json!({
        "scanner": "fakenmap",
        "version": "1.0.0",
        "args": cfg.raw_args,
        "startstr": rep.started_at_str,
        "elapsed": rep.elapsed.as_secs_f64(),
        "numhosts": rep.hosts.len(),
        "hostsup": nup,
        "hosts": hosts,
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

pub fn render_xml(cfg: &ScanConfig, rep: &ScanReport) -> String {
    let mut s = String::new();
    s.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    s.push_str("<!DOCTYPE nmaprun>\n<nmaprun scanner=\"fakenmap\" version=\"1.0.0\" start=\"\">\n");
    s.push_str(&format!(
        "\t<scaninfo type=\"\" protocol=\"\" numservices=\"{}\" services=\"\"/>\n",
        rep.hosts.len()
    ));
    for h in &rep.hosts {
        s.push_str("\t<host>\n");
        s.push_str(&format!(
            "\t\t<status state=\"{}\" reason=\"host-response\"/>\n",
            if h.up { "up" } else { "down" },
        ));
        s.push_str(&format!(
            "\t\t<address addr=\"{}\" addrtype=\"ipv4\"/>\n",
            h.ip
        ));
        if !h.hostname.is_empty() {
            s.push_str(&format!(
                "\t\t<hostnames><hostname name=\"{}\" type=\"PTR\"/></hostnames>\n",
                h.hostname
            ));
        }
        s.push_str("\t\t<ports>\n");
        for p in &h.ports {
            s.push_str(&format!(
                "\t\t\t<port protocol=\"{}\" portid=\"{}\"><state state=\"{}\" reason=\"{}\"/><service name=\"{}\"",
                p.proto.label(),
                p.port,
                state_only(p).label(),
                p.reason,
                p.service
            ));
            if let Some(v) = &p.version {
                if !v.product.is_empty() {
                    s.push_str(&format!(" product=\"{}\"", v.product));
                }
                if !v.version.is_empty() {
                    s.push_str(&format!(" version=\"{}\"", v.version));
                }
            }
            s.push_str("/></port>\n");
        }
        s.push_str("\t\t</ports>\n");
        if let Some(osm) = &h.os_match {
            s.push_str("\t\t<os><osmatch name=\"");
            s.push_str(&osm.name);
            s.push_str(&format!("\" accuracy=\"{}\"/></os>\n", osm.accuracy));
        }
        s.push_str("\t</host>\n");
    }
    s.push_str(&format!(
        "\t<runstats><runstat><elapsed seconds=\"{:.2}\"/><finished time=\"\"/></runstat></runstats>\n",
        rep.elapsed.as_secs_f64()
    ));
    s.push_str("</nmaprun>\n");
    let _ = cfg;
    s
}

fn print_report(cfg: &ScanConfig, rep: &ScanReport) {
    let mut s = String::new();
    push_report(cfg, rep, &mut s);
    print!("{s}");
    let _ = std::io::stdout().flush();
}

use std::io::Write;