//! Bounded, passive fingerprint signal parsers. These functions deliberately
//! return normalized metadata only; raw HTTP headers and packet payloads are
//! never part of the registry.

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderFingerprint {
    pub user_agent: String,
    pub language: String,
    pub encoding: String,
    pub client_hints: String,
}

pub fn parse_cookie(header: &str, name: &str) -> Option<String> {
    header
        .split(';')
        .filter_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name && valid_token(value)).then(|| value.to_string())
        })
        .next()
}

pub fn generate_cookie_token() -> Option<String> {
    let mut bytes = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom").ok()?;
    std::io::Read::read_exact(&mut file, &mut bytes).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn valid_token(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn normalize_headers(headers: &[(&str, &str)]) -> HeaderFingerprint {
    let mut out = HeaderFingerprint::default();
    for &(name, value) in headers {
        let value = normalize_value(value);
        match name.to_ascii_lowercase().as_str() {
            "user-agent" => out.user_agent = value,
            "accept-language" => out.language = normalize_list(&value),
            "accept-encoding" => out.encoding = normalize_list(&value),
            n if (n.starts_with("sec-ch-ua")
                || n == "sec-ch-ua-mobile"
                || n == "sec-ch-ua-platform")
                && !value.is_empty() =>
            {
                if !value.is_empty() {
                    out.client_hints.push_str(n);
                    out.client_hints.push('=');
                    out.client_hints.push_str(&value);
                    out.client_hints.push(';');
                }
            }
            _ => {}
        }
    }
    out
}

pub fn header_fingerprint_string(h: &HeaderFingerprint) -> String {
    [
        h.user_agent.as_str(),
        h.language.as_str(),
        h.encoding.as_str(),
        h.client_hints.as_str(),
    ]
    .join("|")
}

fn normalize_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(512)
        .collect()
}

fn normalize_list(value: &str) -> String {
    let mut values: Vec<String> = value
        .split(',')
        .map(|s| {
            s.trim()
                .split(';')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
        })
        .filter(|s| !s.is_empty())
        .collect();
    values.sort();
    values.dedup();
    values.join(",")
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpSynFingerprint {
    pub version: String,
    pub ttl: String,
    pub window: u16,
    pub options: String,
}

pub fn parse_tcp_syn(packet: &[u8]) -> Option<TcpSynFingerprint> {
    let (ip, ihl) = ipv4(packet)?;
    if ip[9] != 6 {
        return None;
    }
    let tcp = ip.get(ihl..)?;
    if tcp.len() < 20 || tcp[13] & 2 == 0 {
        return None;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return None;
    }
    let mut opts = Vec::new();
    let mut p = 20;
    while p < data_offset {
        let kind = *tcp.get(p)?;
        if kind == 0 {
            break;
        } else if kind == 1 {
            opts.push("nop");
            p += 1;
            continue;
        }
        let len = *tcp.get(p + 1)? as usize;
        if len < 2 || p + len > data_offset {
            return None;
        }
        opts.push(match kind {
            2 => "mss",
            3 => "ws",
            4 => "sack",
            8 => "ts",
            _ => "other",
        });
        p += len;
    }
    Some(TcpSynFingerprint {
        version: "ipv4".into(),
        ttl: ip[8].to_string(),
        window: u16::from_be_bytes([tcp[14], tcp[15]]),
        options: opts.join(","),
    })
}

fn ipv4(packet: &[u8]) -> Option<(&[u8], usize)> {
    let ip = if packet.len() >= 14 && packet[12..14] == [0x08, 0x00] {
        packet.get(14..)?
    } else {
        packet
    };
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = (ip[0] & 0xf) as usize * 4;
    (ihl >= 20 && ip.len() >= ihl).then_some((ip, ihl))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsFingerprint {
    pub version: String,
    pub ciphers: String,
    pub extensions: String,
    pub alpn: String,
}

pub fn parse_tls_client_hello(mut p: &[u8]) -> Option<TlsFingerprint> {
    if p.len() >= 14 && p[12..14] == [0x08, 0x00] {
        p = p.get(14..)?;
    }
    if p.len() >= 20 && p[9] == 6 {
        let ihl = (p[0] & 15) as usize * 4;
        let off = ihl + 20;
        p = p.get(off..)?;
    }
    if p.len() < 9 || p[0] != 22 || p[5] != 1 {
        return None;
    }
    let len = u16::from_be_bytes([p[6], p[7]]) as usize;
    let body = p.get(9..9 + len)?;
    if body.len() < 38 {
        return None;
    }
    let legacy = u16::from_be_bytes([body[0], body[1]]);
    let mut q = 34;
    let sid = *body.get(q)? as usize;
    q += 1 + sid;
    let clen = u16::from_be_bytes([*body.get(q)?, *body.get(q + 1)?]) as usize;
    q += 2;
    let ciphers = body
        .get(q..q + clen)?
        .chunks(2)
        .filter(|x| x.len() == 2)
        .map(|x| format!("{:02x}{:02x}", x[0], x[1]))
        .collect::<Vec<_>>()
        .join("-");
    q += clen;
    let comp = *body.get(q)? as usize;
    q += 1 + comp;
    let extlen = u16::from_be_bytes([*body.get(q)?, *body.get(q + 1)?]) as usize;
    q += 2;
    let exts = body.get(q..q + extlen)?;
    let mut names = Vec::new();
    let mut alpn = String::new();
    let mut e = 0;
    while e + 4 <= exts.len() {
        let typ = u16::from_be_bytes([exts[e], exts[e + 1]]);
        let n = u16::from_be_bytes([exts[e + 2], exts[e + 3]]) as usize;
        e += 4;
        let d = exts.get(e..e + n)?;
        if typ == 16 && d.len() > 2 {
            let l = d[2] as usize;
            if let Some(a) = d.get(3..3 + l) {
                alpn = String::from_utf8_lossy(a)
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
                    .collect();
            }
        }
        names.push(format!("{typ:04x}"));
        e += n;
    }
    Some(TlsFingerprint {
        version: format!("{legacy:04x}"),
        ciphers,
        extensions: names.join("-"),
        alpn,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuicFingerprint {
    pub version: String,
    pub connection_id: String,
    pub transport: String,
}

pub fn parse_quic_initial(p: &[u8]) -> Option<QuicFingerprint> {
    if p.len() < 7 || p[0] & 0x80 == 0 || p[0] & 0x40 == 0 {
        return None;
    }
    let version = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let dcil = p[5] as usize;
    if dcil > 20 || p.len() < 6 + dcil + 1 {
        return None;
    }
    let dcid = &p[6..6 + dcil];
    let scil = p[6 + dcil] as usize;
    if scil > 20 || p.len() < 7 + dcil + scil {
        return None;
    }
    Some(QuicFingerprint {
        version: format!("{version:08x}"),
        connection_id: dcid.iter().map(|b| format!("{b:02x}")).collect(),
        transport: format!("dcid={dcil};scid={scil};type={}", p[0] & 3),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cookie_is_strict_and_random() {
        let t = generate_cookie_token().unwrap();
        assert_eq!(t.len(), 64);
        assert_eq!(
            parse_cookie(
                &format!("x=1; kestrel_identity={t}; y=2"),
                "kestrel_identity"
            ),
            Some(t)
        );
        assert!(parse_cookie("kestrel_identity=bad", "kestrel_identity").is_none());
    }
    #[test]
    fn headers_are_normalized_without_unknowns() {
        let h = normalize_headers(&[
            ("User-Agent", " A  B\n"),
            ("Accept-Language", "en-US, en;q=0.9"),
            ("X-Secret", "raw"),
        ]);
        assert_eq!(h.user_agent, "A B");
        assert_eq!(h.language, "en,en-us");
        assert!(!format!("{:?}", h).contains("raw"));
    }
    #[test]
    fn malformed_packets_are_ignored() {
        assert!(parse_tcp_syn(&[0; 5]).is_none());
        assert!(parse_tls_client_hello(&[0; 9]).is_none());
        assert!(parse_quic_initial(&[0; 7]).is_none());
    }
    #[test]
    fn quic_header_is_bounded() {
        let p = [0xc0, 0, 0, 0, 1, 2, 1, 2, 3, 4, 0, 0];
        let q = parse_quic_initial(&p).unwrap();
        assert_eq!(q.connection_id, "0102");
    }
}
