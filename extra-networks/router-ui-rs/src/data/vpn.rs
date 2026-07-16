use std::path::Path;
use tokio::process::Command;

#[derive(Clone)]
pub struct VpnTier {
    pub name: String,   // "bg"
    pub iface: String,  // "mv_bg"
    pub state: VpnState,
}

#[derive(Clone, PartialEq)]
pub enum VpnState {
    Up,
    RoutingFault,
    Down,
}

impl VpnState {
    pub fn css_class(&self) -> &'static str {
        match self {
            VpnState::Up => "ok",
            _ => "warn",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            VpnState::Up => "Up",
            VpnState::RoutingFault => "Up — routing fault",
            VpnState::Down => "Down",
        }
    }
}

pub async fn fetch_tiers() -> Vec<VpnTier> {
    let dir = Path::new("/etc/split-routing");
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    let mut confs: Vec<(String, String, u32)> = Vec::new(); // (name, iface, table)
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(tier) = name.strip_prefix("vpn-").and_then(|s| s.strip_suffix(".conf")) else {
            continue;
        };
        let content = tokio::fs::read_to_string(entry.path()).await.unwrap_or_default();
        let vars = crate::data::files::parse_sh_vars(&content);
        let Some(iface) = vars.get("VPN_IFACE").cloned() else { continue };
        let table: u32 = vars.get("ROUTE_TABLE").and_then(|v| v.parse().ok()).unwrap_or(0);
        confs.push((tier.to_string(), iface, table));
    }
    confs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut tiers = Vec::new();
    for (name, iface, table) in confs {
        let state = check_state(&iface, table).await;
        tiers.push(VpnTier { name, iface, state });
    }
    tiers
}

async fn check_state(iface: &str, table: u32) -> VpnState {
    let link = Command::new("ip")
        .args(["link", "show", iface])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let if_up = link.contains("LOWER_UP");

    if !if_up {
        return VpnState::Down;
    }

    let rules = Command::new("ip")
        .args(["rule", "show"])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let rule_ok = rules.contains(&format!("lookup {table}"));

    let routes = Command::new("ip")
        .args(["route", "show", "table", &table.to_string()])
        .output()
        .await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let route_ok = routes.lines().any(|l| l.starts_with("default"));

    if rule_ok && route_ok {
        VpnState::Up
    } else {
        VpnState::RoutingFault
    }
}
