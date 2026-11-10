//! Raw socket primitives used for half-open SYN scanning, UDP ICMP error
//! tracking and reverse DNS.
//!
//! On Windows raw TCP packet injection is blocked by the OS since XP SP2, so
//! the SYN scan transparently falls back to a connect()-based scan there and
//! UDP "closed" detection is not available. Everything still compiles and the
//! rest of the scanner behaves exactly like Nmap.

use std::net::IpAddr;
use std::time::Duration;

#[cfg(unix)]
mod imp {
    use super::*;
    use std::net::Ipv4Addr;

    pub fn syn_supported() -> bool {
        true
    }

    fn open_raw_socket(proto: i32) -> Option<i32> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return None;
        }
        Some(fd)
    }

    pub fn local_ip_for(target: Ipv4Addr) -> Option<Ipv4Addr> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return None;
        }
        let sa = sockaddr_in_v4(target, 9);
        let res = unsafe {
            libc::connect(
                fd,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        let mut out = None;
        if res == 0 {
            let mut name: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as u32;
            let r = unsafe {
                libc::getsockname(
                    fd,
                    &mut name as *mut _ as *mut libc::sockaddr,
                    &mut len,
                )
            };
            if r == 0 {
                let [a, b, c, d] = name.sin_addr.s_addr.to_ne_bytes();
                out = Some(Ipv4Addr::new(a, b, c, d));
            }
        }
        unsafe { libc::close(fd) };
        out
    }

    fn sockaddr_in_v4(ip: Ipv4Addr, port: u16) -> libc::sockaddr_in {
        libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            },
            sin_zero: [0; 8],
        }
    }

    fn set_rto(fd: i32, timeout: Duration) {
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: timeout.subsec_micros() as libc::suseconds_t,
        };
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as u32,
            );
        }
    }

    fn rand16() -> u16 {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let mix = (t ^ (t >> 17)) ^ (std::process::id() as u64);
        (mix as u16) | 0x4000
    }

    fn rand32() -> u32 {
        ((rand16() as u32) << 16) | rand16() as u32
    }

    fn ip_checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;
        while i + 1 < data.len() {
            sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
            i += 2;
        }
        if i < data.len() {
            sum += (data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn build_ip(src: Ipv4Addr, dst: Ipv4Addr, tcp_len: usize) -> [u8; 20] {
        let mut h = [0u8; 20];
        h[0] = 0x45;
        h[1] = 0x00;
        h[2..4].copy_from_slice(&((20 + tcp_len) as u16).to_be_bytes());
        h[4..6].copy_from_slice(&rand16().to_be_bytes());
        h[8] = 64;
        h[9] = 6;
        h[12..16].copy_from_slice(&src.octets());
        h[16..20].copy_from_slice(&dst.octets());
        let c = ip_checksum(&h);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h
    }

    fn build_tcp(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
    ) -> [u8; 20] {
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&window.to_be_bytes());
        tcp[18..20] = [0, 0];

        let mut pseudo = Vec::with_capacity(40);
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(20u16).to_be_bytes());
        pseudo.extend_from_slice(&tcp);
        let c = ip_checksum(&pseudo);
        tcp[16..18].copy_from_slice(&c.to_be_bytes());
        tcp
    }

    fn send_raw(fd: i32, dst: Ipv4Addr, header: &[u8]) -> bool {
        let sa = sockaddr_in_v4(dst, 9);
        let r = unsafe {
            libc::sendto(
                fd,
                header.as_ptr() as *const libc::c_void,
                header.len(),
                0,
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        r >= 0
    }

    /// Returns Some(true) when open, Some(false) when closed, None when
    /// filtered (no response), the socket could not be created, or non-IPv4.
    pub fn syn_probe(ip: IpAddr, dport: u16, timeout: Duration) -> Option<bool> {
        let IpAddr::V4(dst) = ip else {
            return None;
        };
        let fd = open_raw_socket(libc::IPPROTO_TCP)?;
        set_rto(fd, timeout);
        let enabled: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            );
        }
        let src = match local_ip_for(dst) {
            Some(s) => s,
            None => {
                unsafe { libc::close(fd) };
                return None;
            }
        };

        let sport = rand16();
        let seq = rand32();
        let ip_hdr = build_ip(src, dst, 20);
        let tcp_hdr = build_tcp(src, dst, sport, dport, seq, 0, 0x02, 14600);
        let mut pkt = Vec::with_capacity(40);
        pkt.extend_from_slice(&ip_hdr);
        pkt.extend_from_slice(&tcp_hdr);
        if !send_raw(fd, dst, &pkt) {
            unsafe { libc::close(fd) };
            return None;
        }

        let mut buf = [0u8; 65536];
        loop {
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            if n <= 0 {
                break; // timeout (or error) => filtered
            }
            if let Some(verdict) = parse_response(&buf[..n as usize], dst, dport, sport) {
                if verdict == Response::Open {
                    // Politely RST the newly opened connection, like Nmap.
                    let rst = build_tcp(src, dst, sport, dport, seq + 1, seq + 1, 0x14, 0);
                    let mut p = Vec::with_capacity(40);
                    p.extend_from_slice(&build_ip(src, dst, 20));
                    p.extend_from_slice(&rst);
                    let _ = send_raw(fd, dst, &p);
                    unsafe { libc::close(fd) };
                    return Some(true);
                }
                unsafe { libc::close(fd) };
                return Some(false);
            }
        }
        unsafe { libc::close(fd) };
        None
    }

    #[derive(PartialEq, Eq)]
    enum Response {
        Open,
        Closed,
    }

    fn parse_response(buf: &[u8], expect_ip: Ipv4Addr, dport: u16, sport: u16) -> Option<Response> {
        if buf.len() < 20 {
            return None;
        }
        let ihl = ((buf[0] & 0x0f) as usize) * 4;
        if buf[9] != 6 || buf.len() < ihl + 20 {
            return None;
        }
        let src_oct = [buf[12], buf[13], buf[14], buf[15]];
        if Ipv4Addr::from(src_oct) != expect_ip {
            return None;
        }
        let tcp = &buf[ihl..];
        let tcp_sport = u16::from_be_bytes([tcp[0], tcp[1]]);
        let tcp_dport = u16::from_be_bytes([tcp[2], tcp[3]]);
        if tcp_sport != dport || tcp_dport != sport {
            return None;
        }
        let flags = tcp[13];
        if flags & 0x04 != 0 {
            return Some(Response::Closed);
        }
        if flags & 0x12 == 0x12 {
            return Some(Response::Open);
        }
        None
    }

    pub fn udp_supported() -> bool {
        true
    }

    /// Wait for an ICMP "port unreachable" for our (src, dport, sport) probe.
    /// Some(true) => closed, Some(false) => not closed so far, None => no raw ICMP.
    pub fn udp_icmp_check(ip: IpAddr, dport: u16, sport: u16, timeout_ms: u64) -> Option<bool> {
        let IpAddr::V4(dst) = ip else {
            return None;
        };
        let fd = open_raw_socket(libc::IPPROTO_ICMP)?;
        set_rto(fd, Duration::from_millis(timeout_ms));
        let mut buf = [0u8; 65536];
        let result = loop {
            let n = unsafe {
                libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
            };
            if n <= 0 {
                break Some(false);
            }
            if let Some(closed) = parse_icmp_unreach(&buf[..n as usize], dst, dport, sport) {
                break Some(closed);
            }
        };
        unsafe { libc::close(fd) };
        result
    }

    fn parse_icmp_unreach(buf: &[u8], expect_ip: Ipv4Addr, dport: u16, sport: u16) -> Option<bool> {
        if buf.len() < 8 {
            return None;
        }
        let icmp_type = buf[0];
        let icmp_code = buf[1];
        if icmp_type == 3 && icmp_code == 3 {
            // Original IP header starts at byte 8 (ICMP header is 8 bytes).
            let ip_start = 8usize;
            if buf.len() < ip_start + 20 {
                return None;
            }
            let emb_ihl = ((buf[ip_start] & 0x0f) as usize) * 4;
            let emb_proto = buf[ip_start + 9];
            let emb_src = [
                buf[ip_start + 12],
                buf[ip_start + 13],
                buf[ip_start + 14],
                buf[ip_start + 15],
            ];
            if Ipv4Addr::from(emb_src) != expect_ip {
                return None;
            }
            if emb_proto == 17 {
                // UDP: the original UDP header (8 bytes) follows the IP header.
                let udp_start = ip_start + emb_ihl;
                if buf.len() < udp_start + 8 {
                    return None;
                }
                let u_sport = u16::from_be_bytes([buf[udp_start], buf[udp_start + 1]]);
                let u_dport = u16::from_be_bytes([buf[udp_start + 2], buf[udp_start + 3]]);
                if u_sport == sport && u_dport == dport {
                    return Some(true);
                }
            }
            return Some(false);
        }
        None
    }

    pub fn reverse_dns(ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else {
            return None;
        };
        let sa = sockaddr_in_v4(v4, 0);
        let mut host = [0i8; 1024];
        let rc = unsafe {
            libc::getnameinfo(
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
                host.as_mut_ptr(),
                host.len() as u32,
                std::ptr::null_mut(),
                0,
                0,
            )
        };
        if rc != 0 {
            return None;
        }
        let len = host.iter().position(|&c| c == 0).unwrap_or(host.len());
        let bytes: Vec<u8> = host[..len].iter().map(|&c| c as u8).collect();
        let s = String::from_utf8(bytes).ok()?;
        let is_numeric = s.split('.').all(|p| p.parse::<u8>().is_ok());
        if is_numeric {
            return None;
        }
        Some(s)
    }
}

#[cfg(windows)]
mod imp {
    use super::*;

    pub fn syn_supported() -> bool {
        false
    }

    pub fn syn_probe(_ip: IpAddr, _dport: u16, _timeout: Duration) -> Option<bool> {
        None
    }

    pub fn udp_supported() -> bool {
        false
    }

    pub fn udp_icmp_check(_ip: IpAddr, _dport: u16, _sport: u16, _timeout_ms: u64) -> Option<bool> {
        None
    }

    pub fn reverse_dns(_ip: IpAddr) -> Option<String> {
        None
    }
}

pub use imp::*;