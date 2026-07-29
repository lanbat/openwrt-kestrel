//! Inbound IPsec (strongSwan) peer visibility — the IPsec counterpart to
//! `data::wg`'s WireGuard peer panel. There's no structured-status
//! equivalent to OpenVPN's status file or WireGuard's `wg show dump` for
//! strongSwan, so this parses `ipsec statusall`'s free-text output for
//! established SAs — heuristic, tolerant of the exact wording varying
//! slightly across strongSwan versions, but stable across the fields this
//! project actually displays (connection name, remote identity, uptime,
//! byte counters).

use tokio::process::Command;

#[derive(Clone)]
pub struct IpsecPeer {
    pub name: String,
    pub remote: String,
    pub established: String,
    /// "rx / tx" human-readable bytes, reusing `wg::human_bytes`; "—" if
    /// no byte-counter line was found for this connection.
    pub traffic: String,
}

pub async fn fetch_peers() -> Vec<IpsecPeer> {
    let out = Command::new("ipsec")
        .arg("statusall")
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    parse_statusall(&out)
}

/// Extracts the trailing number immediately before `marker` in a
/// comma-separated fragment, e.g. `"..., 1234 " ` before `"bytes_i"`.
fn number_before(line: &str, marker: &str) -> Option<u64> {
    let idx = line.find(marker)?;
    line[..idx].rsplit(',').next()?.trim().split_whitespace().next()?.parse().ok()
}

fn parse_statusall(output: &str) -> Vec<IpsecPeer> {
    let mut peers: Vec<IpsecPeer> = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        if let Some((head, tail)) = line.split_once("]: ESTABLISHED ") {
            let name = head.split('[').next().unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let (established, remote) = match tail.split_once(", ") {
                Some((e, r)) => (e.to_string(), r.split("...").nth(1).unwrap_or(r).to_string()),
                None => (tail.to_string(), String::new()),
            };
            peers.push(IpsecPeer { name, remote, established, traffic: "—".to_string() });
        } else if line.contains("bytes_i") && line.contains("bytes_o") {
            let Some(name) = line.split('{').next().map(|s| s.trim().to_string()) else { continue };
            let Some(peer) = peers.iter_mut().rev().find(|p| p.name == name) else { continue };
            let rx = number_before(line, "bytes_i").unwrap_or(0);
            let tx = number_before(line, "bytes_o").unwrap_or(0);
            peer.traffic = format!("{} / {}", super::wg::human_bytes(rx), super::wg::human_bytes(tx));
        }
    }

    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUSALL_SAMPLE: &str = "\
Status of IKE charon daemon (strongSwan 5.9.8, Linux 5.15.0, mips):
  uptime: 4 days, since Jan 01 00:00:00 2024
Listening IP addresses:
  192.0.2.1
Connections:
     con1:  %any...192.0.2.50  IKEv2, dpddelay=30s
     con1:   local:  [192.0.2.1] uses pre-shared key authentication
     con1:   remote: [192.0.2.50] uses pre-shared key authentication
Security Associations (1 up, 0 connecting):
     con1[1]: ESTABLISHED 3 minutes ago, 192.0.2.1[192.0.2.1]...192.0.2.50[192.0.2.50]
     con1[1]: IKEv2 SPIs: aaaa_i bbbb_r*, pre-shared key reauthentication in 2 hours
     con1[1]: IKE proposal: AES_CBC_256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048
     con1{1}:  INSTALLED, TUNNEL, reqid 1, ESP in UDP SPIs: cccc_i dddd_o
     con1{1}:  AES_CBC_256/HMAC_SHA2_256_128, 1234 bytes_i (10 pkts, 5s ago), 5678 bytes_o (12 pkts, 5s ago), rekeying in 40 minutes
     con1{1}:   192.0.2.1/32 === 192.0.2.50/32
";

    #[test]
    fn parses_established_connection_name_and_remote() {
        let peers = parse_statusall(STATUSALL_SAMPLE);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name, "con1");
        assert_eq!(peers[0].established, "3 minutes ago");
        assert_eq!(peers[0].remote, "192.0.2.50[192.0.2.50]");
    }

    #[test]
    fn attributes_byte_counters_to_matching_connection() {
        let peers = parse_statusall(STATUSALL_SAMPLE);
        assert_eq!(peers[0].traffic, "1.2 KB / 5.5 KB");
    }

    #[test]
    fn no_established_sas_returns_empty() {
        let output = "Security Associations (0 up, 0 connecting):\n";
        assert!(parse_statusall(output).is_empty());
    }

    #[test]
    fn traffic_defaults_to_dash_when_no_byte_counter_line() {
        let output = "     con1[1]: ESTABLISHED 1 second ago, 192.0.2.1[192.0.2.1]...192.0.2.50[192.0.2.50]\n";
        let peers = parse_statusall(output);
        assert_eq!(peers[0].traffic, "—");
    }
}
