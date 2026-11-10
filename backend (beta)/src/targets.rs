use std::net::{IpAddr, Ipv4Addr, ToSocketAddrs};
use std::str::FromStr;

/// Maximum number of individual IP addresses we will ever expand a target list
/// into, to avoid accidental memory bombs (e.g. a badly written /0 spec).
pub const MAX_TARGETS: usize = 16_384;

/// Expand one target specification (IP, CIDR, octet range, wildcard or
/// hostname) into a list of IP addresses.
pub fn expand_target(tok: &str, out: &mut Vec<IpAddr>) {
    if let Ok(ip) = IpAddr::from_str(tok) {
        out.push(ip);
        return;
    }

    // CIDR notation: 192.168.1.0/24
    if let Some((net, bits)) = tok.split_once('/') {
        if let Ok(prefix) = bits.parse::<u8>() {
            if let Some(ips) = cidr_hosts(net, prefix) {
                for ip in ips {
                    if out.len() >= MAX_TARGETS {
                        return;
                    }
                    out.push(ip);
                }
                return;
            }
        }
    }

    // Wildcards and per-octet ranges: 10.0.0.*, 192.168.1-5.1, 192.168.1.1-20
    if tok.contains('*') || tok.contains('-') {
        let parts: Vec<&str> = tok.split('.').collect();
        if parts.len() == 4 && parts.iter().all(|p| p.is_empty() || is_octet_spec(p)) {
            let mut ranges = Vec::new();
            let mut ok = true;
            for p in &parts {
                if let Some(r) = parse_octet(p) {
                    ranges.push(r);
                } else {
                    ok = false;
                    break;
                }
            }
            if ok {
                let mut octets = [0u32; 4];
                for a in ranges[0].clone() {
                    octets[0] = a;
                    for b in ranges[1].clone() {
                        octets[1] = b;
                        for c in ranges[2].clone() {
                            octets[2] = c;
                            for d in ranges[3].clone() {
                                if out.len() >= MAX_TARGETS {
                                    return;
                                }
                                octets[3] = d;
                                out.push(Ipv4Addr::new(
                                    octets[0] as u8,
                                    octets[1] as u8,
                                    octets[2] as u8,
                                    octets[3] as u8,
                                )
                                .into());
                            }
                        }
                    }
                }
                return;
            }
        }
    }

    // Hostname / DNS resolution.
    let name = tok.to_string();
    match (name.as_str(), 0u16).to_socket_addrs() {
        Ok(iter) => {
            for addr in iter.into_iter() {
                if out.len() >= MAX_TARGETS {
                    return;
                }
                let ip = addr.ip();
                if !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
        Err(_) => {
            eprintln!("Failed to resolve \x1b[31m\"{tok}\"\x1b[0m (unlikely to be a hostname)");
        }
    }
}

fn parse_octet(spec: &str) -> Option<Vec<u32>> {
    if spec == "*" {
        return Some((0..=255).collect());
    }
    if let Some((a, b)) = spec.split_once('-') {
        let lo = a.parse::<u32>().ok()?;
        let hi = b.parse::<u32>().ok()?;
        if lo <= hi && hi <= 255 {
            return Some((lo..=hi).collect());
        }
        return None;
    }
    let v = spec.parse::<u32>().ok()?;
    if v <= 255 {
        Some(vec![v])
    } else {
        None
    }
}

fn is_octet_spec(spec: &str) -> bool {
    parse_octet(spec).is_some()
}

fn cidr_hosts(net: &str, prefix: u8) -> Option<Vec<IpAddr>> {
    let ip = Ipv4Addr::from_str(net).ok()?.octets();
    if prefix > 32 {
        return None;
    }
    let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let base = u32::from_be_bytes(ip) & mask;
    let host_bits = 32 - prefix;
    let count: u64 = 1u64 << host_bits;
    let take = count.min(MAX_TARGETS as u64);
    let mut out = Vec::new();
    for i in 0..take {
        out.push(
            Ipv4Addr::from(u32::from_be_bytes(base.to_be_bytes()).wrapping_add(i as u32)).into(),
        );
    }
    Some(out)
}