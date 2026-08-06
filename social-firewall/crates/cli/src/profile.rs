use anyhow::{bail, Result};
use domain_types::{LocalProfile, LocalRouteProfile};
use domain_types::{PolicyAction, TargetSelector};
use state_store::StateStore;

use crate::parse_hash32;

pub fn create(store: &StateStore, name: &str, description: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 80 {
        bail!("profile name must be 1-80 bytes");
    }
    let profile_id = crypto::hash(name.as_bytes());
    store.create_local_profile(&LocalProfile {
        profile_id,
        name: name.into(),
        description: description.into(),
        active: false,
        policy_ids: vec![],
    })?;
    println!("created profile {} ({})", name, profile_id);
    Ok(())
}

pub fn add_policy(store: &StateStore, profile_id: &str, policy_id: &str) -> Result<()> {
    store.add_policy_to_profile(parse_hash32(profile_id)?, parse_hash32(policy_id)?)?;
    println!("added policy to profile");
    Ok(())
}

pub fn select(store: &StateStore, profile_id: &str) -> Result<()> {
    store.set_active_profile(parse_hash32(profile_id)?)?;
    println!("selected profile {}", profile_id);
    Ok(())
}

pub fn list(store: &StateStore) -> Result<()> {
    for profile in store.list_local_profiles()? {
        println!(
            "{} {}{} ({} policies)",
            profile.profile_id,
            profile.name,
            if profile.active { " [active]" } else { "" },
            profile.policy_ids.len()
        );
    }
    Ok(())
}

pub fn list_active_policies(store: &StateStore) -> Result<()> {
    match store.active_local_profile()? {
        Some(profile) => {
            println!("active profile: {} ({})", profile.name, profile.profile_id);
            for policy in store.list_active_shared_policies()? {
                println!(
                    "policy {} #{} {} ({} entries)",
                    policy.policy_id,
                    policy.sequence,
                    policy.name,
                    policy.entries.len()
                );
            }
        }
        None => println!("no active profile"),
    }
    Ok(())
}

pub fn effects(store: &StateStore) -> Result<()> {
    for policy in store.list_active_shared_policies()? {
        for entry in policy.entries {
            let status = match &entry.action {
                domain_types::PolicyAction::Block
                    if matches!(
                        entry.target,
                        domain_types::TargetSelector::Ip(_) | domain_types::TargetSelector::Cidr(_)
                    ) =>
                {
                    "ready for nft firewall"
                }
                domain_types::PolicyAction::Block => "pending DNS materializer",
                domain_types::PolicyAction::Route { profile } => match store.local_route_profile(profile)? {
                    Some(route) if route.enabled && !route.vpn => "ready for route preview",
                    Some(route) if route.enabled => "pending VPN materializer",
                    Some(_) => "route profile disabled",
                    None => "missing local route profile",
                },
                domain_types::PolicyAction::DnsBlock
                | domain_types::PolicyAction::DnsRedirect { .. } => {
                    "ready for dnsmasq materializer"
                }
                domain_types::PolicyAction::DnsRecord {
                    ref record_type, ..
                } if matches!(record_type.to_ascii_uppercase().as_str(), "A" | "AAAA") => {
                    "ready for dnsmasq materializer"
                }
                domain_types::PolicyAction::DnsRecord { .. } => "pending resolver backend",
                domain_types::PolicyAction::Allow => "policy input only",
            };
            println!("{} {}: {}", policy.policy_id, entry.entry_id, status);
        }
    }
    Ok(())
}

pub fn add_route_profile(
    store: &StateStore,
    name: &str,
    table: u32,
    interface: &str,
    enabled: bool,
    vpn: bool,
) -> Result<()> {
    if name.trim().is_empty() || name.len() > 80 {
        bail!("route profile name must be 1-80 bytes");
    }
    if interface.trim().is_empty() || interface.len() >  IFACE_MAX {
        bail!("route profile interface must be 1-32 bytes");
    }
    if table == 0 {
        bail!("route table must be non-zero");
    }
    store.upsert_local_route_profile(&LocalRouteProfile {
        name: name.into(), table, interface: interface.into(), enabled, vpn,
    })?;
    println!("saved route profile {name}");
    Ok(())
}

pub fn list_route_profiles(store: &StateStore) -> Result<()> {
    for profile in store.list_local_route_profiles()? {
        println!("{} table={} interface={}{}{}", profile.name, profile.table, profile.interface,
            if profile.enabled { " [enabled]" } else { " [disabled]" },
            if profile.vpn { " [vpn]" } else { "" });
    }
    Ok(())
}

pub fn route_preview(store: &StateStore) -> Result<()> {
    let mut previewed = 0;
    let mut pending = 0;
    for policy in store.list_active_shared_policies()? {
        for entry in policy.entries {
            let PolicyAction::Route { profile } = entry.action else {
                continue;
            };
            let Some(route) = store.local_route_profile(&profile)? else {
                println!("{} {}: missing local route profile {profile}", policy.policy_id, entry.entry_id);
                pending += 1;
                continue;
            };
            if !route.enabled {
                println!("{} {}: route profile {profile} is disabled", policy.policy_id, entry.entry_id);
                pending += 1;
                continue;
            }
            if route.vpn {
                println!("{} {}: VPN route profile {profile} awaits VPN materializer", policy.policy_id, entry.entry_id);
                pending += 1;
                continue;
            }
            let Some(target) = route_target(&entry.target) else {
                println!("{} {}: target requires DNS resolution before route preview", policy.policy_id, entry.entry_id);
                pending += 1;
                continue;
            };
            println!("{} {}: ip route replace {target} dev {} table {}", policy.policy_id, entry.entry_id, route.interface, route.table);
            previewed += 1;
        }
    }
    println!("route preview: {previewed} ready, {pending} pending; no route commands executed");
    Ok(())
}

const IFACE_MAX: usize = 32;

fn route_target(target: &TargetSelector) -> Option<&str> {
    match target {
        TargetSelector::Ip(value) | TargetSelector::Cidr(value) => Some(value),
        TargetSelector::ProtoPort { inner, .. } => route_target(inner),
        TargetSelector::Domain(_) | TargetSelector::DomainSuffix(_) | TargetSelector::Service(_) => None,
    }
}

fn dns_name(target: &TargetSelector) -> Option<&str> {
    match target {
        TargetSelector::Domain(name) | TargetSelector::DomainSuffix(name) => Some(name),
        _ => None,
    }
}

fn valid_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

pub(crate) fn render_dnsmasq(store: &StateStore) -> Result<(String, usize)> {
    let mut lines = vec!["# Managed by social-firewall; do not edit.".to_string()];
    let mut applied = 0;
    for policy in store.list_active_shared_policies()? {
        for entry in policy.entries {
            let Some(name) = dns_name(&entry.target) else {
                continue;
            };
            if !valid_dns_name(name) {
                continue;
            }
            match entry.action {
                PolicyAction::DnsBlock => {
                    lines.push(format!("address=/{name}/0.0.0.0"));
                    lines.push(format!("address=/{name}/::"));
                    applied += 1;
                }
                PolicyAction::DnsRedirect { address } => {
                    if address.parse::<std::net::IpAddr>().is_ok() {
                        lines.push(format!("address=/{name}/{address}"));
                        applied += 1;
                    }
                }
                PolicyAction::DnsRecord {
                    record_type, value, ..
                } if matches!(record_type.to_ascii_uppercase().as_str(), "A" | "AAAA")
                    && value.parse::<std::net::IpAddr>().is_ok() =>
                {
                    lines.push(format!("address=/{name}/{value}"));
                    applied += 1;
                }
                _ => {}
            }
        }
    }
    lines.sort();
    lines.dedup();
    Ok((format!("{}\n", lines.join("\n")), applied))
}

pub fn apply_dns(store: &StateStore, dry_run: bool) -> Result<()> {
    let (content, applied) = render_dnsmasq(store)?;
    if dry_run {
        println!("dns entries ready: {applied}");
        println!("{content}");
        return Ok(());
    }
    let path = std::env::var_os("SF_DNSMASQ_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/etc/dnsmasq.d/99-social-firewall.conf".into());
    let previous = std::fs::read_to_string(&path).unwrap_or_default();
    if previous == content {
        println!("dns materializer: no change ({applied} entries)");
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, content)?;
    if !openwrt_runtime() {
        println!("dnsmasq materializer: wrote {applied} entries; reload skipped outside OpenWrt");
        return Ok(());
    }
    let status = std::process::Command::new("/etc/init.d/dnsmasq")
        .arg("reload")
        .status();
    match status {
        Ok(status) if status.success() => println!("dns materializer: applied {applied} entries"),
        Ok(status) => anyhow::bail!("dnsmasq reload failed with {status}"),
        Err(error) => anyhow::bail!("could not reload dnsmasq: {error}"),
    }
    Ok(())
}

fn openwrt_runtime() -> bool {
    should_reload_dnsmasq(
        std::path::Path::new("/etc/openwrt_release").is_file(),
        std::path::Path::new("/sbin/procd").exists(),
        std::env::var("SF_ALLOW_SYSTEM_RELOAD").as_deref() == Ok("1"),
    )
}

fn should_reload_dnsmasq(openwrt_release: bool, procd: bool, override_enabled: bool) -> bool {
    override_enabled || (openwrt_release && procd)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names_are_bounded_and_reject_config_injection() {
        assert!(valid_dns_name("example.com"));
        assert!(valid_dns_name("_service.example.com"));
        assert!(!valid_dns_name("example.com\naddress=/evil/1.2.3.4"));
        assert!(!valid_dns_name(""));
    }

    #[test]
    fn route_preview_only_accepts_ip_targets_without_resolving_or_executing() {
        assert_eq!(route_target(&TargetSelector::Ip("192.0.2.1".into())), Some("192.0.2.1"));
        assert_eq!(route_target(&TargetSelector::Cidr("192.0.2.0/24".into())), Some("192.0.2.0/24"));
        assert_eq!(route_target(&TargetSelector::Domain("example.com".into())), None);
    }

    #[test]
    fn route_profiles_reject_empty_or_unsafe_local_configuration() {
        let store = StateStore::open_in_memory().unwrap();
        assert!(add_route_profile(&store, "", 100, "wan", true, false).is_err());
        assert!(add_route_profile(&store, "wan", 0, "wan", true, false).is_err());
        assert!(add_route_profile(&store, "wan", 100, &"x".repeat(IFACE_MAX + 1), true, false).is_err());
    }

    #[test]
    fn route_profiles_round_trip_without_enabling_mutation() {
        let store = StateStore::open_in_memory().unwrap();
        add_route_profile(&store, "wan", 100, "eth0", true, false).unwrap();
        add_route_profile(&store, "vpn", 200, "wg0", true, true).unwrap();

        let profiles = store.list_local_route_profiles().unwrap();
        assert_eq!(profiles.len(), 2);
        assert_eq!(store.local_route_profile("wan").unwrap().unwrap().table, 100);
        assert!(store.local_route_profile("missing").unwrap().is_none());
        assert!(profiles.iter().any(|profile| profile.vpn));
    }

    #[test]
    fn dnsmasq_reload_requires_openwrt_markers_or_explicit_override() {
        assert!(!should_reload_dnsmasq(false, false, false));
        assert!(!should_reload_dnsmasq(true, false, false));
        assert!(should_reload_dnsmasq(true, true, false));
        assert!(should_reload_dnsmasq(false, false, true));
    }
}
