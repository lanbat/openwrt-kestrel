#[derive(Default, Clone)]
pub struct Lease {
    pub expiry: u64,
    pub mac: String,
    pub ip: String,
    pub hostname: String,
}

pub async fn fetch() -> Vec<Lease> {
    let content = tokio::fs::read_to_string("/tmp/dhcp.leases")
        .await
        .unwrap_or_default();
    parse(&content)
}

fn parse(content: &str) -> Vec<Lease> {
    content
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                return None;
            }
            Some(Lease {
                expiry: parts[0].parse().unwrap_or(0),
                mac: parts[1].to_lowercase(),
                ip: parts[2].to_string(),
                hostname: parts[3].to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_lease() {
        let leases = parse("1700000000 aa:bb:cc:dd:ee:ff 192.168.1.100 myhost\n");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].expiry, 1700000000);
        assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(leases[0].ip, "192.168.1.100");
        assert_eq!(leases[0].hostname, "myhost");
    }

    #[test]
    fn parse_lowercases_mac() {
        let leases = parse("0 AA:BB:CC:DD:EE:FF 10.0.0.1 host\n");
        assert_eq!(leases[0].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn parse_invalid_expiry_defaults_to_zero() {
        let leases = parse("notanumber aa:bb:cc:dd:ee:ff 10.0.0.1 host\n");
        assert_eq!(leases[0].expiry, 0);
    }

    #[test]
    fn parse_skips_lines_with_fewer_than_4_fields() {
        let leases = parse("1700000000 aa:bb:cc:dd:ee:ff 10.0.0.1\n");
        assert!(leases.is_empty());
    }

    #[test]
    fn parse_skips_empty_lines() {
        let leases = parse("\n1700000000 aa:bb:cc:dd:ee:ff 10.0.0.2 host\n\n");
        assert_eq!(leases.len(), 1);
    }

    #[test]
    fn parse_multiple_leases() {
        let input = "\
1700000001 aa:bb:cc:00:00:01 192.168.1.1 host1
1700000002 aa:bb:cc:00:00:02 192.168.1.2 host2
1700000003 aa:bb:cc:00:00:03 192.168.1.3 host3
";
        let leases = parse(input);
        assert_eq!(leases.len(), 3);
        assert_eq!(leases[2].ip, "192.168.1.3");
    }

    #[test]
    fn parse_real_dnsmasq_lease_format() {
        // Real dnsmasq format includes a 5th field (client id / *)
        let leases = parse("1700000000 de:ad:be:ef:00:01 192.168.10.5 android-phone *\n");
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].hostname, "android-phone");
    }
}
