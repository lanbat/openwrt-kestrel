use std::collections::HashMap;
use tokio::process::Command;

#[derive(Default, Clone)]
pub struct IwState {
    pub phys: Vec<WifiPhy>,
    /// vap interface name → (channel, band)
    pub vap_info: HashMap<String, (String, String)>,
}

#[derive(Clone)]
pub struct WifiPhy {
    pub name: String,
    pub band: String,
    pub channel: String,
    pub vap_count: usize,
    pub expected_vaps: usize,
    pub status_ok: bool,
    pub status_label: String,
}

pub async fn fetch() -> IwState {
    let iw_raw = Command::new("iw")
        .arg("dev")
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    let uci_raw = Command::new("uci")
        .args(["show", "wireless"])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    parse(&iw_raw, &uci_raw)
}

struct VapRecord {
    phy: String,
    iface: String,
    channel: String,
    band: String,
}

fn parse(iw_raw: &str, uci_raw: &str) -> IwState {
    let mut vaps: Vec<VapRecord> = Vec::new();
    let mut cur_phy = String::new();
    let mut cur_iface = String::new();
    let mut cur_ch = String::new();
    let mut cur_band = String::new();

    for line in iw_raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = line.strip_prefix("phy#") {
            commit(&mut vaps, &cur_phy, &cur_iface, &cur_ch, &cur_band);
            cur_phy = format!("phy{}", rest.split_whitespace().next().unwrap_or("?"));
            cur_iface.clear();
            cur_ch.clear();
            cur_band.clear();
        } else if let Some(rest) = trimmed.strip_prefix("Interface ") {
            commit(&mut vaps, &cur_phy, &cur_iface, &cur_ch, &cur_band);
            cur_iface = rest.split_whitespace().next().unwrap_or("").to_string();
            cur_ch.clear();
            cur_band.clear();
        } else if let Some(rest) = trimmed.strip_prefix("channel ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            cur_ch = parts.first().copied().unwrap_or("").to_string();
            let freq: u32 = parts
                .get(1)
                .and_then(|s| s.trim_start_matches('(').parse().ok())
                .unwrap_or(0);
            cur_band = freq_to_band(freq).to_string();
        }
    }
    commit(&mut vaps, &cur_phy, &cur_iface, &cur_ch, &cur_band);

    // Count expected VAPs per radio from `uci show wireless`
    // Lines like: wireless.<section>.device='radio0'
    let mut expected: HashMap<String, usize> = HashMap::new();
    for line in uci_raw.lines() {
        if line.contains(".device=") {
            if let Some(val) = line.splitn(2, '=').nth(1) {
                let radio = val.trim().trim_matches('\'');
                if radio.starts_with("radio") {
                    *expected.entry(radio.to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    // Group vaps by phy
    let mut phy_groups: HashMap<&str, Vec<&VapRecord>> = HashMap::new();
    for vap in &vaps {
        phy_groups.entry(&vap.phy).or_default().push(vap);
    }

    let mut phy_names: Vec<&str> = phy_groups.keys().copied().collect();
    phy_names.sort_unstable();

    let mut phys = Vec::new();
    let mut vap_info: HashMap<String, (String, String)> = HashMap::new();

    for phy_name in phy_names {
        let group = &phy_groups[phy_name];
        let vap_count = group.len();
        let band = group.iter().find_map(|v| {
            (!v.band.is_empty()).then(|| v.band.clone())
        }).unwrap_or_default();
        let channel = group.iter().find_map(|v| {
            (!v.channel.is_empty()).then(|| v.channel.clone())
        }).unwrap_or_default();

        let radio_name = format!("radio{}", phy_name.trim_start_matches("phy"));
        let exp = expected.get(&radio_name).copied().unwrap_or(0);

        let status_ok = vap_count > 0 && (exp == 0 || vap_count >= exp);
        let status_label = if vap_count == 0 {
            "down — no VAPs".to_string()
        } else if exp > 0 && vap_count < exp {
            format!("{vap_count} of {exp} VAPs up")
        } else {
            format!("{vap_count} VAP{}", if vap_count != 1 { "s" } else { "" })
        };

        for vap in group {
            vap_info.insert(vap.iface.clone(), (vap.channel.clone(), vap.band.clone()));
        }

        phys.push(WifiPhy {
            name: phy_name.to_string(),
            band,
            channel,
            vap_count,
            expected_vaps: exp,
            status_ok,
            status_label,
        });
    }

    IwState { phys, vap_info }
}

fn commit(vaps: &mut Vec<VapRecord>, phy: &str, iface: &str, ch: &str, band: &str) {
    if !iface.is_empty() {
        vaps.push(VapRecord {
            phy: phy.to_string(),
            iface: iface.to_string(),
            channel: ch.to_string(),
            band: band.to_string(),
        });
    }
}

fn freq_to_band(freq: u32) -> &'static str {
    if freq > 0 && freq < 3000 {
        "2.4 GHz"
    } else if freq >= 5000 && freq < 6000 {
        "5 GHz"
    } else if freq >= 6000 {
        "6 GHz"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── freq_to_band ──────────────────────────────────────────────────────────

    #[test]
    fn band_2ghz() {
        assert_eq!(freq_to_band(2412), "2.4 GHz");
        assert_eq!(freq_to_band(2472), "2.4 GHz");
    }

    #[test]
    fn band_5ghz() {
        assert_eq!(freq_to_band(5180), "5 GHz");
        assert_eq!(freq_to_band(5825), "5 GHz");
    }

    #[test]
    fn band_6ghz() {
        assert_eq!(freq_to_band(6135), "6 GHz");
    }

    #[test]
    fn band_unknown() {
        assert_eq!(freq_to_band(0), "");
        assert_eq!(freq_to_band(3500), "");
    }

    // ── parse ─────────────────────────────────────────────────────────────────

    const IW_SAMPLE: &str = "\
phy#0
\tInterface wlan0
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
\tInterface wlan0-1
\t\tchannel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
phy#1
\tInterface wlan1
\t\tchannel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz
";

    const UCI_SAMPLE: &str = "\
wireless.@wifi-iface[0].device='radio0'
wireless.@wifi-iface[1].device='radio0'
wireless.@wifi-iface[2].device='radio1'
";

    #[test]
    fn parse_two_radios() {
        let state = parse(IW_SAMPLE, UCI_SAMPLE);
        assert_eq!(state.phys.len(), 2);
    }

    #[test]
    fn parse_phy0_has_2_vaps() {
        let state = parse(IW_SAMPLE, UCI_SAMPLE);
        let phy0 = state.phys.iter().find(|p| p.name == "phy0").unwrap();
        assert_eq!(phy0.vap_count, 2);
        assert_eq!(phy0.band, "2.4 GHz");
        assert_eq!(phy0.channel, "6");
    }

    #[test]
    fn parse_phy1_has_1_vap() {
        let state = parse(IW_SAMPLE, UCI_SAMPLE);
        let phy1 = state.phys.iter().find(|p| p.name == "phy1").unwrap();
        assert_eq!(phy1.vap_count, 1);
        assert_eq!(phy1.band, "5 GHz");
        assert_eq!(phy1.channel, "36");
    }

    #[test]
    fn parse_vap_info_populated() {
        let state = parse(IW_SAMPLE, UCI_SAMPLE);
        let (ch, band) = state.vap_info.get("wlan0").unwrap();
        assert_eq!(ch, "6");
        assert_eq!(band, "2.4 GHz");
        assert!(state.vap_info.contains_key("wlan0-1"));
        assert!(state.vap_info.contains_key("wlan1"));
    }

    #[test]
    fn parse_status_ok_when_vap_count_matches_expected() {
        let state = parse(IW_SAMPLE, UCI_SAMPLE);
        let phy0 = state.phys.iter().find(|p| p.name == "phy0").unwrap();
        // radio0 has 2 expected VAPs from UCI, and 2 are up
        assert_eq!(phy0.expected_vaps, 2);
        assert!(phy0.status_ok);
    }

    #[test]
    fn parse_status_label_down_when_no_vaps() {
        let iw = "phy#0\n";
        let state = parse(iw, "");
        // phy0 has no VAPs — no Interface lines → not parsed at all
        assert!(state.phys.is_empty(), "empty phy with no interfaces should produce no phys");
    }

    #[test]
    fn parse_empty_input() {
        let state = parse("", "");
        assert!(state.phys.is_empty());
        assert!(state.vap_info.is_empty());
    }
}
