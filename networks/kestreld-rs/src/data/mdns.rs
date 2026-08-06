//! Raw mDNS (multicast DNS, RFC 6762/6763) client — used instead of
//! `avahi-browse`/`avahi-resolve` because this project's router runs
//! `avahi-nodbus-daemon` (see `install.sh` and its commit message):
//! `avahi-dbus-daemon` fails to start under OpenWrt's ujail, so D-Bus
//! support was deliberately compiled out. The standard avahi client tools
//! only talk to the daemon over D-Bus, so with it gone they have nothing
//! to connect to — this module bypasses the local daemon entirely and
//! queries the network directly, the same way avahi itself does.
//!
//! Sends one PTR query for `_device-info._tcp.local` with the "unicast
//! response requested" (QU) bit set, so replies come back directly to our
//! own ephemeral port rather than requiring us to join the multicast
//! group (which would fight the already-running `avahi-daemon` for
//! `224.0.0.251:5353`). Not every responder honors QU, but most
//! mainstream mDNS stacks (Apple's, Android's) do.
//!
//! The query is bound to (and its multicast egress interface pinned to)
//! the caller-supplied bridge address — mDNS is link-local multicast and
//! never crosses a bridge/VLAN boundary, so binding to whatever the OS's
//! default route happens to be would silently reach nothing on an
//! isolated network like `guest`/`untrusted`.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;

const MDNS_GROUP: &str = "224.0.0.251:5353";
const QUERY_WINDOW: Duration = Duration::from_millis(1200);
const SERVICE: &str = "_device-info._tcp.local";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MdnsInfo {
    /// The service instance name (e.g. "Kirils-iPhone"), with the
    /// `._device-info._tcp.local` suffix stripped.
    pub name: String,
    /// The `model=` TXT record value, if present (Apple devices: e.g.
    /// "iPhone16,2").
    pub model: String,
}

/// Queries the LAN for `_device-info._tcp.local` and returns whichever
/// responding device's advertised IP matches `target_ip`, if any. This is
/// a real network round-trip (up to ~1.2s) — call it only where that cost
/// is acceptable (a device join, not a per-request dashboard refresh).
///
/// `bind_ip` must be an address on the bridge the target device is
/// actually on (e.g. the network's own gateway address, `192.168.3.1` for
/// `guest`) — mDNS is link-local multicast (RFC 6762) and does not cross
/// a bridge/VLAN boundary, so a query sent out the wrong interface (e.g.
/// whatever the OS's default route happens to be) will reach nothing on
/// an isolated network like `guest`/`untrusted`, regardless of what's
/// actually on it.
pub async fn lookup_device_info(bind_ip: &str, target_ip: &str) -> Option<MdnsInfo> {
    let target: Ipv4Addr = target_ip.parse().ok()?;
    let responses = query_and_collect(bind_ip).await;
    let records = parse_all_records(&responses);
    correlate(&records, target)
}

async fn query_and_collect(bind_ip: &str) -> Vec<Vec<u8>> {
    let socket = match bind_socket(bind_ip) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let query = encode_query(SERVICE);
    if socket.send_to(&query, MDNS_GROUP).await.is_err() {
        return Vec::new();
    }

    let mut responses = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + QUERY_WINDOW;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => responses.push(buf[..n].to_vec()),
            _ => break,
        }
    }
    responses
}

/// Builds a UDP socket bound to `bind_ip` with its multicast egress
/// interface (`IP_MULTICAST_IF`) explicitly pinned to the same address —
/// without this, the send would go out whatever interface the OS's
/// default route selects, which on a multi-bridge router is generally
/// not the bridge the query actually needs to reach.
fn bind_socket(bind_ip: &str) -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let addr: Ipv4Addr = bind_ip
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&std::net::SocketAddrV4::new(addr, 0).into())?;
    socket.set_multicast_if_v4(&addr)?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

fn encode_query(name: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(&0u16.to_be_bytes()); // ID (irrelevant for mDNS)
    buf.extend_from_slice(&0u16.to_be_bytes()); // flags: standard query
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    buf.extend_from_slice(&encode_name(name));
    buf.extend_from_slice(&12u16.to_be_bytes()); // QTYPE: PTR
    buf.extend_from_slice(&0x8001u16.to_be_bytes()); // QCLASS: IN, QU bit set
    buf
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    buf
}

/// Decodes a (possibly compressed) DNS name starting at `pos` in `buf`.
/// Returns the name and the offset of the byte immediately following the
/// name *as it appeared at the call site* (i.e. after a compression
/// pointer, not after whatever it points to).
fn decode_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut resume_at: Option<usize> = None;
    let mut hops = 0;

    loop {
        if hops > 20 {
            return None; // guard against a pointer loop
        }
        let len = *buf.get(pos)?;
        if len == 0 {
            let end = resume_at.unwrap_or(pos + 1);
            return Some((labels.join("."), end));
        }
        if len & 0xC0 == 0xC0 {
            let lo = *buf.get(pos + 1)?;
            let ptr = (((len & 0x3F) as usize) << 8) | lo as usize;
            if resume_at.is_none() {
                resume_at = Some(pos + 2);
            }
            hops += 1;
            pos = ptr;
            continue;
        }
        let start = pos + 1;
        let end = start + len as usize;
        labels.push(String::from_utf8_lossy(buf.get(start..end)?).to_string());
        pos = end;
    }
}

#[derive(Debug, Default)]
struct Records {
    /// PTR-discovered instance names under `_device-info._tcp.local`.
    ptr: Vec<String>,
    /// instance name -> SRV target hostname
    srv: HashMap<String, String>,
    /// instance name -> TXT key/value pairs
    txt: HashMap<String, HashMap<String, String>>,
    /// hostname -> IPv4 address
    a: HashMap<String, Ipv4Addr>,
}

fn parse_all_records(packets: &[Vec<u8>]) -> Records {
    let mut records = Records::default();
    for buf in packets {
        parse_one_packet(buf, &mut records);
    }
    records
}

fn parse_one_packet(buf: &[u8], out: &mut Records) {
    if buf.len() < 12 {
        return;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12;
    for _ in 0..qdcount {
        let Some((_, next)) = decode_name(buf, pos) else {
            return;
        };
        pos = next + 4; // QTYPE + QCLASS
    }
    for _ in 0..(ancount + nscount + arcount) {
        let Some(next) = parse_one_record(buf, pos, out) else {
            return;
        };
        pos = next;
    }
}

/// Parses one resource record at `pos`, folding it into `out`. Returns the
/// offset immediately after the record, or `None` if the buffer is
/// malformed (in which case the caller stops parsing this packet — a
/// best-effort feature, not something to panic over on a stray byte).
fn parse_one_record(buf: &[u8], pos: usize, out: &mut Records) -> Option<usize> {
    let (name, pos) = decode_name(buf, pos)?;
    let rtype = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
    // CLASS (2 bytes) carries the mDNS cache-flush bit in its top bit —
    // irrelevant here, skip over it uninspected.
    let rdlength = u16::from_be_bytes([*buf.get(pos + 8)?, *buf.get(pos + 9)?]) as usize;
    let rdata_start = pos + 10;
    let rdata_end = rdata_start.checked_add(rdlength)?;
    if rdata_end > buf.len() {
        return None;
    }

    match rtype {
        12 => {
            // PTR: rdata is a name, relative to the full packet (may be compressed).
            if let Some((target, _)) = decode_name(buf, rdata_start) {
                if name.eq_ignore_ascii_case(SERVICE) {
                    out.ptr.push(target);
                }
            }
        }
        16 => {
            // TXT: sequence of length-prefixed "key=value" strings.
            let mut kv = HashMap::new();
            let mut p = rdata_start;
            while p < rdata_end {
                let len = *buf.get(p)? as usize;
                p += 1;
                let end = p + len;
                if end > rdata_end {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&buf[p..end]) {
                    if let Some((k, v)) = s.split_once('=') {
                        kv.insert(k.to_lowercase(), v.to_string());
                    }
                }
                p = end;
            }
            if !kv.is_empty() {
                out.txt.insert(name, kv);
            }
        }
        33 => {
            // SRV: priority(2) + weight(2) + port(2) + target name.
            if rdata_start + 6 <= rdata_end {
                if let Some((target, _)) = decode_name(buf, rdata_start + 6) {
                    out.srv.insert(name, target);
                }
            }
        }
        1 => {
            // A: 4-byte IPv4 address.
            if rdlength == 4 {
                let ip = Ipv4Addr::new(
                    buf[rdata_start],
                    buf[rdata_start + 1],
                    buf[rdata_start + 2],
                    buf[rdata_start + 3],
                );
                out.a.insert(name, ip);
            }
        }
        _ => {}
    }

    Some(rdata_end)
}

fn correlate(records: &Records, target: Ipv4Addr) -> Option<MdnsInfo> {
    records.ptr.iter().find_map(|instance| {
        let host = records.srv.get(instance)?;
        let ip = records.a.get(host)?;
        if *ip != target {
            return None;
        }
        let model = records
            .txt
            .get(instance)
            .and_then(|kv| kv.get("model"))
            .cloned()
            .unwrap_or_default();
        let name = instance
            .strip_suffix(&format!(".{SERVICE}"))
            .unwrap_or(instance)
            .to_string();
        Some(MdnsInfo { name, model })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(s: &str) -> Vec<u8> {
        let mut v = vec![s.len() as u8];
        v.extend_from_slice(s.as_bytes());
        v
    }

    #[test]
    fn encode_name_produces_length_prefixed_labels() {
        assert_eq!(encode_name("_tcp.local"), {
            let mut v = label("_tcp");
            v.extend(label("local"));
            v.push(0);
            v
        });
    }

    #[test]
    fn decode_name_reads_uncompressed_labels() {
        let mut buf = label("foo");
        buf.extend(label("local"));
        buf.push(0);
        let (name, end) = decode_name(&buf, 0).unwrap();
        assert_eq!(name, "foo.local");
        assert_eq!(end, buf.len());
    }

    #[test]
    fn decode_name_follows_a_compression_pointer() {
        // buf: [0]="local\0" (6 bytes), then a name that's "foo" + pointer to offset 0.
        let mut buf = label("local");
        buf.push(0);
        let pointer_target = buf.len();
        buf.extend(label("foo"));
        buf.extend_from_slice(&[0xC0, 0x00]); // pointer to offset 0 ("local")
        let (name, end) = decode_name(&buf, pointer_target).unwrap();
        assert_eq!(name, "foo.local");
        // end is the offset right after the 2-byte pointer at the call site,
        // not after whatever it points to.
        assert_eq!(end, buf.len());
    }

    #[test]
    fn decode_name_rejects_pointer_loop_instead_of_hanging() {
        let buf = [0xC0, 0x00]; // points at itself
        assert!(decode_name(&buf, 0).is_none());
    }

    /// Builds a minimal, realistic mDNS response packet: PTR for
    /// `_device-info._tcp.local` -> an instance, with SRV/TXT/A records
    /// for that instance, all as answer records (ANCOUNT=4, no question
    /// section — exactly how real mDNS responses are typically sent).
    fn sample_response(instance_label: &str, model: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_be_bytes()); // ID
        buf.extend_from_slice(&0x8400u16.to_be_bytes()); // flags: response, authoritative
        buf.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT
        buf.extend_from_slice(&4u16.to_be_bytes()); // ANCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        let service_name = encode_name(SERVICE);
        let instance_fqdn = format!("{instance_label}.{SERVICE}");
        let instance_name = encode_name(&instance_fqdn);
        let host_fqdn = format!("{instance_label}.local");
        let host_name = encode_name(&host_fqdn);

        // PTR record: _device-info._tcp.local -> instance
        buf.extend_from_slice(&service_name);
        buf.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
        buf.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        buf.extend_from_slice(&0u32.to_be_bytes()); // TTL
        buf.extend_from_slice(&(instance_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(&instance_name);

        // TXT record on the instance name
        buf.extend_from_slice(&instance_name);
        buf.extend_from_slice(&16u16.to_be_bytes()); // TYPE TXT
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        let txt_kv = format!("model={model}");
        let mut txt_rdata = vec![txt_kv.len() as u8];
        txt_rdata.extend_from_slice(txt_kv.as_bytes());
        buf.extend_from_slice(&(txt_rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&txt_rdata);

        // SRV record on the instance name -> host
        buf.extend_from_slice(&instance_name);
        buf.extend_from_slice(&33u16.to_be_bytes()); // TYPE SRV
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        let mut srv_rdata = vec![0u8, 0, 0, 0, 0, 0]; // priority, weight, port
        srv_rdata.extend_from_slice(&host_name);
        buf.extend_from_slice(&(srv_rdata.len() as u16).to_be_bytes());
        buf.extend_from_slice(&srv_rdata);

        // A record for the host
        buf.extend_from_slice(&host_name);
        buf.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&ip);

        buf
    }

    #[test]
    fn parses_and_correlates_a_full_response_by_ip() {
        let packet = sample_response("Kirils-iPhone", "iPhone16,2", [192, 168, 3, 105]);
        let records = parse_all_records(&[packet]);
        assert_eq!(records.ptr, vec!["Kirils-iPhone._device-info._tcp.local"]);

        let info = correlate(&records, Ipv4Addr::new(192, 168, 3, 105)).expect("match found");
        assert_eq!(info.name, "Kirils-iPhone");
        assert_eq!(info.model, "iPhone16,2");
    }

    #[test]
    fn correlate_returns_none_when_ip_does_not_match_any_advertised_device() {
        let packet = sample_response("Kirils-iPhone", "iPhone16,2", [192, 168, 3, 105]);
        let records = parse_all_records(&[packet]);
        assert!(correlate(&records, Ipv4Addr::new(192, 168, 3, 200)).is_none());
    }

    #[test]
    fn parse_all_records_merges_multiple_responder_packets() {
        let p1 = sample_response("Phone-A", "modelA", [192, 168, 3, 101]);
        let p2 = sample_response("Phone-B", "modelB", [192, 168, 3, 102]);
        let records = parse_all_records(&[p1, p2]);
        assert_eq!(records.ptr.len(), 2);
        assert!(correlate(&records, Ipv4Addr::new(192, 168, 3, 102))
            .is_some_and(|i| i.name == "Phone-B" && i.model == "modelB"));
    }

    #[test]
    fn malformed_short_packet_is_ignored_without_panicking() {
        let records = parse_all_records(&[vec![1, 2, 3]]);
        assert!(records.ptr.is_empty());
    }

    #[test]
    fn bind_socket_rejects_a_non_ip_bind_address() {
        assert!(bind_socket("not-an-ip").is_err());
    }

    #[tokio::test]
    async fn bind_socket_succeeds_on_loopback() {
        // Full multicast-egress-selection behavior needs a real
        // multi-bridge box to verify end to end (see the module docs and
        // this session's plan notes) — this just confirms the socket2
        // setup (bind + IP_MULTICAST_IF + nonblocking + tokio handoff)
        // doesn't error out for a valid local address.
        assert!(bind_socket("127.0.0.1").is_ok());
    }
}
