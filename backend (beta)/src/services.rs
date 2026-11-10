use std::collections::HashMap;

/// Common TCP/UDP ports mapped to service names (mimics nmap-services).
pub fn known_service(port: u16, tcp: bool) -> &'static str {
    let name = match port {
        7 => "echo",
        9 => "discard",
        11 => "systat",
        13 => "daytime",
        17 => "qotd",
        19 => "chargen",
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        37 => "time",
        42 => "nameserver",
        43 => "whois",
        49 => "tacacs",
        50 => "re-mail-ck",
        53 => "domain",
        67 => "dhcp",
        68 => "dhcp",
        69 => "tftp",
        70 => "gopher",
        79 => "finger",
        80 => "http",
        81 => "http-alt",
        88 => "kerberos-sec",
        102 => "iso-tsap",
        110 => "pop3",
        111 => "rpcbind",
        113 => "ident",
        119 => "nntp",
        123 => "ntp",
        135 => "msrpc",
        137 => "netbios-ns",
        138 => "netbios-dgm",
        139 => "netbios-ssn",
        143 => "imap",
        161 => "snmp",
        162 => "snmptrap",
        177 => "xdmcp",
        179 => "bgp",
        194 => "irc",
        201 => "at-rtmp",
        209 => "z3950",
        220 => "imap3",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        464 => "kpasswd5",
        465 => "smtps",
        500 => "isakmp",
        513 => "login",
        514 => "shell",
        515 => "printer",
        520 => "route",
        523 => "ibm-db2",
        548 => "afp",
        554 => "rtsp",
        587 => "submission",
        591 => "http-alt",
        631 => "ipp",
        636 => "ldaps",
        873 => "rsync",
        901 => "swat",
        902 => "vmware-auth",
        953 => "rndc",
        990 => "ftps",
        992 => "telnets",
        993 => "imaps",
        995 => "pop3s",
        1053 => "domain",
        1080 => "socks",
        1099 => "rmiregistry",
        1110 => "webmin",
        1433 => "ms-sql-s",
        1434 => "ms-sql-m",
        1521 => "oracle",
        1723 => "pptp",
        1812 => "radius",
        2000 => "cisco-sccp",
        2008 => "net-tsqp",
        2049 => "nfs",
        2100 => "amanda",
        2181 => "zookeeper",
        2222 => "ssh",
        2375 => "docker",
        2376 => "docker",
        3000 => "http-proxy",
        3128 => "squid-http",
        3268 => "globalcatLDAP",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        3478 => "stun",
        3545 => "nat-stun-port",
        3690 => "svn",
        4369 => "epmd",
        4500 => "ipsec-nat-t",
        4621 => "ipsecrita",
        5000 => "upnp",
        5001 => "assyst-data",
        5003 => "filemaker",
        5009 => "winfs",
        5054 => "iod",
        5060 => "sip",
        5101 => "sip",
        5222 => "xmpp-client",
        5269 => "xmpp-server",
        5353 => "zeroconf",
        5355 => "llmnr",
        5432 => "postgresql",
        5481 => "snmptrap",
        5666 => "nrpe",
        5900 => "vnc",
        5938 => "teamviewer",
        6000 => "X11",
        6001 => "X11",
        6379 => "redis",
        6667 => "irc",
        7001 => "afs3-callback",
        7002 => "afs3-prserver",
        7100 => "font-service",
        8000 => "http-alt",
        8008 => "http-alt",
        8009 => "ajp13",
        8010 => "http-wbem",
        8080 => "http-proxy",
        8081 => "http-proxy",
        8086 => "influxdb",
        8088 => "http-proxy",
        8090 => "http-alt",
        8123 => "polipo",
        8161 => "activemq",
        8181 => "http-alt",
        8443 => "https-alt",
        8888 => "sun-answerbook",
        9000 => "cslistener",
        9001 => "etlbroker",
        9042 => "cassandra",
        9090 => "websm",
        9092 => "kafka",
        9100 => "jetdirect",
        9200 => "wap-wsp",
        9201 => "wap-push",
        9300 => "vrml-multi-use",
        9443 => "https-alt",
        9999 => "abyss",
        10000 => "webmin",
        11211 => "memcache",
        11234 => "ssh",
        12345 => "netbus",
        15672 => "amqp",
        16379 => "redis",
        18017 => "lsi-bos-svc",
        20000 => "dnp",
        27017 => "mongod",
        28017 => "mongod-http",
        30000 => "dnp",
        32400 => "plex",
        37951 => "http-proxy",
        49152 => "unknown",
        50000 => "db2c",
        50001 => "agentx",
        _ => {
            if tcp {
                return "unknown";
            }
            return "unknown";
        }
    };
    name
}

#[derive(Debug, Clone, Default)]
pub struct VersionInfo {
    pub product: String,
    pub version: String,
    pub info: String,
    pub os: String,
}

/// A protocol probe: what we send and how long we wait for a banner.
#[allow(dead_code)]
struct Probe {
    name: &'static str,
    payload: &'static [u8],
    wait_ms: u64,
}

fn probes_for(port: u16, tcp: bool) -> Vec<Probe> {
    let mut base: Vec<Probe> = vec![Probe {
        name: "GenericLines",
        payload: b"\r\n\r\n",
        wait_ms: 600,
    }];
    if !tcp {
        return base;
    }
    match port {
        80 | 443 | 8080 | 8000 | 8888 | 8443 | 3000 | 8081 | 8090 => {
            base.insert(
                0,
                Probe {
                    name: "GetRequest",
                    payload: b"GET / HTTP/1.0\r\n\r\n",
                    wait_ms: 900,
                },
            );
        }
        21 | 990 => {
            base.insert(
                0,
                Probe {
                    name: "None",
                    payload: b"",
                    wait_ms: 600,
                },
            );
        }
        25 | 465 | 587 | 2525 => {
            base.insert(
                0,
                Probe {
                    name: "None",
                    payload: b"",
                    wait_ms: 600,
                },
            );
        }
        22 | 2222 => {
            base.insert(
                0,
                Probe {
                    name: "SSH-1.0",
                    payload: b"SSH-1.0-OpenSSH_ove",
                    wait_ms: 700,
                },
            );
        }
        110 | 995 => {
            base.insert(
                0,
                Probe {
                    name: "None",
                    payload: b"",
                    wait_ms: 600,
                },
            );
        }
        143 | 993 => {
            base.insert(
                0,
                Probe {
                    name: "None",
                    payload: b"",
                    wait_ms: 600,
                },
            );
        }
        53 => {
            base.insert(
                0,
                Probe {
                    name: "DNSVersionBindReq",
                    payload: &[0x00, 0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
                        0x6e, 0x06, 0x62, 0x69, 0x6e, 0x64, 0x00, 0x00, 0x10, 0x00,
                        0x03, 0x00, 0x00, 0x29],
                    wait_ms: 800,
                },
            );
        }
        3306 | 5432 | 6379 | 9092 | 27017 | 11211 | 8086 => {
            base.insert(0, Probe { name: "None", payload: b"", wait_ms: 900 });
        }
        _ => {}
    }
    base
}

/// Grab a banner and fingerprint the service running on this port.
pub fn detect_version(
    port: u16,
    tcp: bool,
    mut send_fn: Box<dyn FnMut(&[u8]) -> Result<Vec<u8>, String> + Send>,
) -> Option<VersionInfo> {
    for probe in probes_for(port, tcp) {
        match send_fn(probe.payload) {
            Ok(bytes) => {
                let info = fingerprint(port, &probe.name, &bytes);
                if info.is_some() {
                    return info;
                }
            }
            Err(_) => return None,
        }
    }
    None
}

/// Simple regex-like fingerprinting against received banner bytes.
pub fn fingerprint(port: u16, probe_name: &str, data: &[u8]) -> Option<VersionInfo> {
    let text = String::from_utf8_lossy(&data[..data.len().min(4096)]);
    let text_l = text.to_lowercase();
    let mut v = VersionInfo::default();

    // SSH banners: SSH-<protocol>-<software>[_<version>] [distro-...]
    if text_l.starts_with("ssh-") {
        let end = text.find("\r").or_else(|| text.find("\n")).unwrap_or(text.len().min(80));
        let banner = &text[..end];
        let segments: Vec<&str> = banner.split('-').collect();
        let protocol = segments.get(1).copied().unwrap_or("");
        let software = segments.get(2).copied().unwrap_or("");
        if let Some(und) = software.find('_') {
            v.product = software[..und].to_string();
            v.version = software[und + 1..].to_string();
        } else {
            v.product = software.to_string();
        }
        v.info = format!("protocol {protocol}");
        if text_l.contains("ubuntu") {
            v.os = if text_l.contains("freebsd") { "FreeBSD".into() } else { "Linux (Ubuntu)".into() };
        } else if text_l.contains("debian") {
            v.os = "Linux (Debian)".into();
        } else if text_l.contains("cisco") {
            v.os = "Cisco IOS".into();
        } else if text_l.contains("dropbear") {
            v.product = "Dropbear".into();
            v.os = "Linux".into();
        }
        return Some(v);
    }

    // FTP banners ("220 ... FTP server ready").
    if text_l.len() >= 3 && text_l.starts_with("220") {
        if text_l.contains("vsftpd") {
            v.product = "vsftpd".into();
        } else if text_l.contains("proftpd") {
            v.product = "ProFTPD".into();
        } else if text_l.contains("filezilla") {
            v.product = "FileZilla".into();
        } else if text_l.contains("microsoft") {
            v.product = "Microsoft ftpd".into();
        } else if text_l.contains("pure-ftpd") {
            v.product = "Pure-FTPd".into();
        } else {
            v.product = "FTP server".into();
        }
        grab_word(&text, &mut v.version, 1);
        v.info = "FTP server banner".into();
        return Some(v);
    }

    // SMTP banners ("220 ... ESMTP").
    if text_l.starts_with("220") {
        if text_l.contains("esmtp") || text_l.contains("smtp") {
            if text_l.contains("postfix") {
                v.product = "Postfix smtpd".into();
            } else if text_l.contains("exim") {
                v.product = "Exim smtpd".into();
            } else if text_l.contains("sendmail") {
                v.product = "Sendmail".into();
            } else if text_l.contains("microsoft") || text_l.contains("smtp server") {
                v.product = "Microsoft ESMTP".into();
            } else if text_l.contains("hMailServer") {
                v.product = "hMailServer".into();
            } else {
                v.product = "SMTP server".into();
            }
            v.info = "SMTP banner".into();
            return Some(v);
        }
    }

    // HTTP responses.
    if text_l.starts_with("http/") {
        if let Some(server) = extract_header(&text, "server") {
            v.product = server.to_string();
        } else {
            v.product = "HTTP server".into();
        }
        if let Some(ver) = extract_header_other(&text, "x-powered-by") {
            v.info = ver.to_string();
        }
        let s = v.product.to_lowercase();
        if s.contains("iis") || s.contains("microsoft") {
            v.os = "Microsoft Windows".into();
        } else if s.contains("nginx") {
            v.os = "Linux".into();
        } else if s.contains("apache") {
            v.os = if s.contains("ubuntu") { "Linux (Ubuntu)".into() } else { "Linux".into() };
        } else if s.contains("windows") {
            v.os = "Microsoft Windows".into();
        }
        if let Some(w) = v.product.find('/') {
            let prod = v.product[..w].to_string();
            let ver = v.product[w + 1..].to_string();
            v.product = prod;
            v.version = ver.split_whitespace().next().unwrap_or("").to_string();
        }
        return Some(v);
    }

    // POP3 ("+OK").
    if text_l.starts_with("+ok") {
        if text_l.contains("dovecot") {
            v.product = "Dovecot POP3".into();
            v.os = "Linux".into();
        } else {
            v.product = "POP3 server".into();
        }
        return Some(v);
    }

    // IMAP ("* OK").
    if text_l.starts_with("* ok") || text_l.starts_with("* ok ") {
        if text_l.contains("dovecot") {
            v.product = "Dovecot IMAP".into();
            v.os = "Linux".into();
        } else if text_l.contains("courier") {
            v.product = "Courier IMAP".into();
        } else {
            v.product = "IMAP server".into();
        }
        return Some(v);
    }

    // MySQL (narrow handshake).
    if port == 3306 && !data.is_empty() {
        v.product = "MySQL".into();
        if data.len() >= 7 {
            let major = data[3] as u8;
            let minor = data[4] as u8;
            let patch = data[5] as u8;
            v.version = format!("{major}.{minor}.{patch}");
        }
        return Some(v);
    }

    // Redis.
    if port == 6379 {
        v.product = "Redis key-value store".into();
        v.info = "Followup with INFO command".into();
        return Some(v);
    }

    // RDP (Windows).
    if port == 3389 {
        v.product = "Microsoft Terminal Services".into();
        v.os = "Microsoft Windows".into();
        return Some(v);
    }

    // DNS version.bind reply (port 53).
    if port == 53 && data.len() > 14 && probe_name == "DNSVersionBindReq" {
        if let Some(escaped) = String::from_utf8(data[..].to_vec()).ok() {
            let lower = escaped.to_lowercase();
            if lower.contains("bind") || lower.contains("unbound") || lower.contains("dnsmasq")
                || lower.contains("microsoft") {
                v.product = "DNS (BIND)".into();
                v.info = "version.bind reply".into();
                if lower.contains("bind") {
                    if let Some(p) = lower.find("bind ") {
                        v.version = escaped[p + 5..p + 12].trim_matches(|c: char| !c.is_ascii_digit() && c != '.').to_string();
                    }
                }
                return Some(v);
            }
        }
    }

    // SQL Server (TDS prelogin).
    if port == 1433 && data.len() >= 6 {
        v.product = "Microsoft SQL Server".into();
        v.os = "Microsoft Windows".into();
        return Some(v);
    }

    // Telnet.
    if port == 23 && !data.is_empty() {
        v.product = "Telnet".into();
        return Some(v);
    }

    // SMB (445).
    if port == 445 {
        v.product = "SMB".into();
        if !data.is_empty() {
            v.os = "Microsoft Windows".into();
        }
        return Some(v);
    }

    // Default: any recognizable text banner.
    if !text.is_empty() {
        let first = text.split_whitespace().next().unwrap_or("");
        if probe_name == "GenericLines" && first.len() >= 3 {
            v.product = first.into();
            return Some(v);
        }
    }

    None
}

fn extract_header(text: &str, name: &str) -> Option<String> {
    let hdr = format!("\r\n{name}:", name = name.to_lowercase());
    let lower = text.to_lowercase();
    if let Some(pos) = lower.find(&hdr.to_lowercase()) {
        let start = pos + hdr.len();
        if let Some(end_rel) = text[start..].find("\r\n") {
            let val = text[start..start + end_rel].trim();
            if !val.is_empty() {
                return Some(val.to_string());
            }
        }
    }
    None
}

fn extract_header_other(text: &str, name: &str) -> Option<String> {
    extract_header(text, name)
}

fn grab_word(text: &str, out: &mut String, idx: usize) {
    for (i, w) in text.split_whitespace().enumerate() {
        if i == idx {
            out.push_str(w);
            break;
        }
    }
}

/// Build a static lookup of interesting well-known ports for the GUI.
#[allow(dead_code)]
pub fn common_ports_tcp() -> Vec<u16> {
    vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433,
        1521, 1723, 2049, 3306, 3389, 5432, 5900, 6000, 6379, 8080, 8443, 8081, 33060, 27017,
    ]
}

pub fn top_ports(n: usize) -> Vec<u16> {
    // Canonical "most common" port list (roughly Nmap's top-100).
    const CANON: [u16; 124] = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 105, 110, 111, 113, 119, 123,
        135, 139, 143, 161, 179, 194, 199, 389, 443, 445, 464, 465, 500, 513, 514, 515, 548,
        554, 587, 601, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1030,
        1080, 1099, 1110, 1433, 1434, 1521, 1720, 1723, 1755, 1812, 2000, 2001, 2049, 2121,
        2222, 2375, 3000, 3128, 3268, 3306, 3389, 3545, 4000, 4444, 5000, 5001, 5060, 5222,
        5353, 5432, 5555, 5631, 5666, 5800, 5900, 5901, 6000, 6001, 6379, 6667, 7000, 7001,
        7002, 7070, 7100, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9001, 9090, 9100,
        9200, 9443, 10000, 10001, 11211, 12345, 32768, 49152, 49153, 49154, 49155, 49156,
        49157, 49158, 49159,
    ];
    let mut unique: Vec<u16> = Vec::new();
    for p in CANON {
        if !unique.contains(&p) {
            unique.push(p);
        }
    }
    unique.truncate(n);
    unique
}

#[allow(dead_code)]
pub fn build_service_map(ports: &[u16]) -> HashMap<u16, String> {
    ports.iter().map(|p| (*p, known_service(*p, true).to_string())).collect()
}