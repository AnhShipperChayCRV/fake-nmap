use crate::services::VersionInfo;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct OsMatch {
    pub name: String,
    pub accuracy: u8,
    pub details: Vec<String>,
}

pub struct OsHints {
    pub ttl: Option<u8>,
    pub open_tcp: Vec<(u16, Option<VersionInfo>)>,
}

/// A heuristic "OS fingerprint". This is a light-weight version of Nmap's -O;
/// it combines TTL hints with observed services and banners to produce a
/// ranked guess.
pub fn detect_os(_ip: IpAddr, hints: &OsHints) -> Option<OsMatch> {
    let mut evidence: Vec<(String, u8, String)> = Vec::new();
    if let Some(ttl) = hints.ttl {
        if ttl <= 64 {
            evidence.push((
                "Linux/Unix/*BSD".into(),
                55,
                format!("ICMP TTL={ttl}"),
            ));
        } else if ttl <= 128 {
            evidence.push((
                "Microsoft Windows".into(),
                60,
                format!("ICMP TTL={ttl}"),
            ));
        } else {
            evidence.push((
                "Some Unix".into(),
                40,
                format!("ICMP TTL={ttl}"),
            ));
        }
    }

    let mut has_rdp = false;
    let mut has_smb = false;
    let mut has_samba = false;
    let mut is_cisco = false;
    let mut is_jetdirect = false;
    let mut has_openbsd = false;

    for (port, ver) in &hints.open_tcp {
        match port {
            3389 => has_rdp = true,
            445 | 139 => {
                if let Some(v) = ver {
                    let l = v.product.to_lowercase() + &v.info.to_lowercase();
                    if l.contains("samba") {
                        has_samba = true;
                    } else {
                        has_smb = true;
                    }
                } else {
                    has_smb = true;
                }
            }
            22 => {
                if let Some(v) = ver {
                    let l = (v.os.clone() + &v.product).to_lowercase();
                    if l.contains("ubuntu") {
                        evidence.push(("Linux (Ubuntu)".into(), 75, "OpenSSH Ubuntu banner".into()));
                    } else if v.product.contains("Dropbear") {
                        evidence.push(("Linux".into(), 55, "Dropbear sshd".into()));
                    }
                    if v.product.contains("Cisco") {
                        is_cisco = true;
                    }
                    if l.contains("openbsd") {
                        has_openbsd = true;
                    }
                }
            }
            23 => {
                if let Some(v) = ver {
                    if v.info.to_lowercase().contains("cisco") {
                        is_cisco = true;
                    }
                }
            }
            9100 => is_jetdirect = true,
            80 | 443 | 8080 => {
                if let Some(v) = ver {
                    let l = v.product.to_lowercase();
                    if l.contains("iis") || l.contains("microsoft") {
                        evidence.push(("Microsoft Windows".into(), 70, "IIS/Windows HTTP server".into()));
                    } else if l.contains("nginx") || l.contains("apache") {
                        evidence.push(("Linux".into(), 50, format!("{} server", v.product)));
                    }
                }
            }
            25 | 110 | 143 => {
                if let Some(v) = ver {
                    if v.os.contains("Linux") {
                        evidence.push(("Linux".into(), 45, format!("{}", v.product)));
                    }
                }
            }
            _ => {}
        }
    }

    if has_rdp {
        evidence.push(("Microsoft Windows".into(), 80, "RDP (port 3389) open".into()));
    }
    if has_samba {
        evidence.push(("Linux".into(), 80, "Samba SMB detected".into()));
    }
    if has_smb && !has_samba {
        // 139/445 with no Samba banner is usually Windows.
        evidence.push(("Microsoft Windows".into(), 55, "SMB ports open".into()));
    }
    if is_cisco {
        evidence.push(("Cisco IOS".into(), 80, "Cisco service banner".into()));
    }
    if is_jetdirect {
        evidence.push(("HP (JetDirect)".into(), 70, "JetDirect printing service".into()));
    }
    if has_openbsd {
        evidence.push(("OpenBSD".into(), 70, "OpenSSH from OpenBSD".into()));
    }

    if evidence.is_empty() {
        return None;
    }

    // Score and pick the top candidate. Later evidence should trump TTL-only
    // guesses, so we weight by accuracy but also prefer strong service hints.
    let mut best: Option<(String, u8)> = None;
    let mut best_certainty = 0u32;
    for (name, acc, _why) in &evidence {
        let service_weight = (*acc as u32) * 2 + (name.len() as u32 % 3);
        if service_weight > best_certainty {
            best_certainty = service_weight;
            best = Some((name.clone(), *acc));
        }
    }

    let (name, acc) = best?;
    let details: Vec<String> = evidence.iter().map(|(_, _, why)| why.clone()).collect();
    Some(OsMatch {
        name,
        accuracy: acc,
        details,
    })
}