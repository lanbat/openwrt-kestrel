//! fwmark + nft interval sets + policy routing for a *consuming*
//! tunnel's selected targets — the traffic-marking half of "route this
//! domain through this tunnel," mirroring `split-routing`'s own proven
//! DNS-response-triggered mechanism (a domain resolves, dnsmasq's
//! `nftset=` directive drops the answer straight into an nft set, a mark
//! chain matches that set) rather than inventing a new DNS-to-IP
//! resolution path. The mark chain lives in its own dedicated table —
//! see this crate's own module doc for why that must be a *third* table,
//! distinct from both `split-routing`'s and `nft-enforcer`'s.

use crate::command::CommandRunner;
use crate::NFT_TABLE;
use std::time::Duration;

/// One dnsmasq conf-dir snippet, ready to write to
/// `/etc/dnsmasq.d/social-firewall-tunnel-<short-id>.conf` — same
/// `nftset=/domain/family#table#set` directive shape
/// `split-routing/install.sh`'s own `dns()` function already generates,
/// just pointed at this crate's own table/set names instead of `fw4`'s.
pub fn dnsmasq_conf_snippet(domains: &[String], fwmark_set_v4: &str, fwmark_set_v6: &str) -> String {
    let mut out = String::new();
    for d in domains {
        out.push_str(&format!("nftset=/{d}/4#inet#{NFT_TABLE}#{fwmark_set_v4},6#inet#{NFT_TABLE}#{fwmark_set_v6}\n"));
    }
    out
}

/// Deterministic nft script creating (idempotently — `add`, not
/// `create`) this peer's dedicated sets and (re-)populating its own
/// dedicated mark chain. Mirrors `nft-enforcer::compile`'s "pure, no I/O,
/// byte-identical for identical input" shape, adapted for marking
/// traffic instead of dropping it.
///
/// Two independent kinds of selected target, two independent
/// populating mechanisms, sharing one fwmark:
/// - **Domains** (`Domain`/`DomainSuffix`) reach the dynamic
///   `..._v4`/`..._v6` sets via dnsmasq's own `nftset=` directive as they
///   resolve (see `dnsmasq_conf_snippet`) — this function only declares
///   those sets, it never populates them itself.
/// - **Static addresses** (`Cidr`/`Ip`) are known up front, so they're
///   populated directly, here, into a separate `..._static_v4`/`_v6`
///   interval set — no DNS trigger needed or possible for a bare address.
///
/// **Idempotency, the part a `FakeCommandRunner` test can't catch**: a
/// real `nft add rule` is *not* idempotent the way `add table`/`add set`/
/// `add chain` are — naming and re-adding an identical rule still appends
/// a second, duplicate copy rather than silently no-op'ing. Since this
/// function (via `WgTunnelController::reconcile`) runs on every cron
/// tick for every active tunnel, a shared, never-flushed chain would
/// accumulate a duplicate pair of mark rules *every single reconcile
/// pass*, unboundedly. Fixed by giving every peer its own dedicated
/// chain (never a chain shared across peers) and unconditionally
/// `flush`ing it before re-adding exactly the rules this call wants —
/// the same "flush before repopulate" idempotency fix already needed for
/// nftables *sets* in `nft-enforcer::compile` (see that crate's own
/// history), just applied here to a *chain* instead. Flushing only this
/// peer's own chain, never a shared one, is what keeps that safe to do
/// on every call without disturbing any other peer's already-live rules.
pub fn compile_mark_script(peer_short_id: &str, fwmark: i64, static_addrs: &[String], max_connections: Option<u32>, max_bandwidth_kbps: Option<u64>) -> CompiledMarkScript {
    let set_v4 = format!("tunnel_{peer_short_id}_v4");
    let set_v6 = format!("tunnel_{peer_short_id}_v6");
    let static_set_v4 = format!("tunnel_{peer_short_id}_static_v4");
    let static_set_v6 = format!("tunnel_{peer_short_id}_static_v6");
    let chain = format!("mark_chain_{peer_short_id}");

    let mut script = String::new();
    script.push_str(&format!("add table inet {NFT_TABLE}\n"));
    script.push_str(&format!("add set inet {NFT_TABLE} {set_v4} {{ type ipv4_addr; flags dynamic,timeout; timeout 24h; }}\n"));
    script.push_str(&format!("add set inet {NFT_TABLE} {set_v6} {{ type ipv6_addr; flags dynamic,timeout; timeout 24h; }}\n"));
    script.push_str(&format!("add set inet {NFT_TABLE} {static_set_v4} {{ type ipv4_addr; flags interval; }}\n"));
    script.push_str(&format!("add set inet {NFT_TABLE} {static_set_v6} {{ type ipv6_addr; flags interval; }}\n"));

    // IPv6 addresses/CIDRs always contain a `:`; IPv4 never do — cheap,
    // reliable enough discriminator without a full address parser.
    let (v6_static, v4_static): (Vec<&str>, Vec<&str>) = static_addrs.iter().map(String::as_str).partition(|a| a.contains(':'));
    script.push_str(&format!("flush set inet {NFT_TABLE} {static_set_v4}\n"));
    if !v4_static.is_empty() {
        script.push_str(&format!("add element inet {NFT_TABLE} {static_set_v4} {{ {} }}\n", v4_static.join(", ")));
    }
    script.push_str(&format!("flush set inet {NFT_TABLE} {static_set_v6}\n"));
    if !v6_static.is_empty() {
        script.push_str(&format!("add element inet {NFT_TABLE} {static_set_v6} {{ {} }}\n", v6_static.join(", ")));
    }

    script.push_str(&format!("add chain inet {NFT_TABLE} {chain} {{ type filter hook prerouting priority mangle; policy accept; }}\n"));
    script.push_str(&format!("flush chain inet {NFT_TABLE} {chain}\n"));
    script.push_str(&format!("add rule inet {NFT_TABLE} {chain} ip daddr @{set_v4} meta mark set {fwmark}\n"));
    script.push_str(&format!("add rule inet {NFT_TABLE} {chain} ip6 daddr @{set_v6} meta mark set {fwmark}\n"));
    script.push_str(&format!("add rule inet {NFT_TABLE} {chain} ip daddr @{static_set_v4} meta mark set {fwmark}\n"));
    script.push_str(&format!("add rule inet {NFT_TABLE} {chain} ip6 daddr @{static_set_v6} meta mark set {fwmark}\n"));

    // Gates on the fwmark just set above, not on the destination sets
    // directly — one rule each regardless of how many sets/domains feed
    // this peer's mark, evaluated after the packet already carries the
    // mark from this same chain pass. Advertised by the provider, but
    // only ever enforced here, by the consumer's own router, against its
    // own traffic — the provider has no local enforcement point for
    // someone else's outbound rate/connection count.
    if let Some(max_conn) = max_connections {
        script.push_str(&format!("add rule inet {NFT_TABLE} {chain} meta mark {fwmark} ct count over {max_conn} drop\n"));
    }
    if let Some(max_kbps) = max_bandwidth_kbps {
        // nft's `limit rate` speaks bytes/second, not bits — this
        // advertised value is kbit/s (the conventional network-bandwidth
        // unit), so convert: kbit/s * 1000 / 8 = bytes/second. Real
        // fair-queuing bandwidth shaping under contention wants a `tc`
        // qdisc instead — this is deliberately just a coarse cap.
        let bytes_per_second = max_kbps * 1000 / 8;
        script.push_str(&format!("add rule inet {NFT_TABLE} {chain} meta mark {fwmark} limit rate over {bytes_per_second} bytes/second drop\n"));
    }

    CompiledMarkScript { script, set_v4, set_v6, static_set_v4, static_set_v6 }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMarkScript {
    pub script: String,
    pub set_v4: String,
    pub set_v6: String,
    pub static_set_v4: String,
    pub static_set_v6: String,
}

/// Real `ip rule`/`ip route` policy-routing setup for a fwmark — same
/// commands `split-routing`'s own hotplug script issues for its VPN
/// tiers, just against this crate's own reserved fwmark/table range.
/// Idempotent: deletes any existing rule for this fwmark first (a
/// `while ip rule del ...` loop, matching the hotplug script's own
/// idempotency idiom) before adding the current one.
pub fn apply_policy_route(runner: &dyn CommandRunner, fwmark: i64, route_table: i64, interface_name: &str, timeout: Duration) -> Result<(), String> {
    let fwmark_str = format!("{fwmark:#x}");
    let table_str = route_table.to_string();

    loop {
        let out = runner.run("ip", &["rule", "del", "fwmark", &fwmark_str, "lookup", &table_str], timeout);
        if !out.success {
            break;
        }
    }
    let add_rule = runner.run("ip", &["rule", "add", "fwmark", &fwmark_str, "lookup", &table_str], timeout);
    if !add_rule.success {
        return Err(format!("failed to add ip rule: {}", add_rule.stderr));
    }
    let add_route = runner.run("ip", &["route", "replace", "default", "dev", interface_name, "table", &table_str], timeout);
    if !add_route.success {
        return Err(format!("failed to add ip route: {}", add_route.stderr));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::FakeCommandRunner;

    #[test]
    fn dnsmasq_snippet_targets_this_crates_own_table_not_fw4() {
        let snippet = dnsmasq_conf_snippet(&["example.com".to_string()], "tunnel_ab12_v4", "tunnel_ab12_v6");
        assert!(snippet.contains(&format!("#inet#{NFT_TABLE}#tunnel_ab12_v4")));
        assert!(!snippet.contains("#fw4#"));
    }

    #[test]
    fn dnsmasq_snippet_has_one_line_per_domain() {
        let snippet = dnsmasq_conf_snippet(&["a.example".to_string(), "b.example".to_string()], "v4set", "v6set");
        assert_eq!(snippet.lines().count(), 2);
    }

    #[test]
    fn compile_mark_script_never_references_fw4_or_split_routings_own_table() {
        let compiled = compile_mark_script("ab12", 0x1000, &[], None, None);
        assert!(!compiled.script.contains("fw4"));
        assert!(!compiled.script.contains("split_routing"));
        assert!(compiled.script.contains(&format!("table inet {NFT_TABLE}")));
    }

    #[test]
    fn compile_mark_script_uses_add_not_create_for_idempotency() {
        let compiled = compile_mark_script("ab12", 0x1000, &[], None, None);
        assert!(!compiled.script.contains("create "), "must use idempotent `add`, not strict `create`, so a second apply doesn't error");
    }

    #[test]
    fn compile_mark_script_is_deterministic() {
        let a = compile_mark_script("ab12", 0x1000, &["10.0.0.0/8".to_string()], None, None);
        let b = compile_mark_script("ab12", 0x1000, &["10.0.0.0/8".to_string()], None, None);
        assert_eq!(a, b);
    }

    #[test]
    fn compile_mark_script_always_flushes_its_own_chain_before_repopulating() {
        // The real bug this guards against: `add rule` is not idempotent
        // the way `add table`/`add set`/`add chain` are, so a shared,
        // never-flushed chain would accumulate a duplicate pair of mark
        // rules on every reconcile pass. Every call must flush first.
        let compiled = compile_mark_script("ab12", 0x1000, &[], None, None);
        assert!(compiled.script.contains("flush chain inet"), "must flush this peer's own chain before re-adding its rules");
    }

    #[test]
    fn compile_mark_script_uses_a_dedicated_chain_per_peer_not_a_shared_one() {
        let a = compile_mark_script("ab12", 0x1000, &[], None, None);
        let b = compile_mark_script("cd34", 0x2000, &[], None, None);
        assert!(a.script.contains("mark_chain_ab12"));
        assert!(b.script.contains("mark_chain_cd34"));
        assert!(!a.script.contains("mark_chain_cd34"), "one peer's script must never reference another peer's chain");
    }

    #[test]
    fn compile_mark_script_populates_the_static_set_from_ipv4_and_ipv6_addresses() {
        let compiled = compile_mark_script("ab12", 0x1000, &["10.0.0.0/8".to_string(), "203.0.113.5".to_string(), "2001:db8::/32".to_string()], None, None);
        assert!(compiled.script.contains("10.0.0.0/8"));
        assert!(compiled.script.contains("203.0.113.5"));
        assert!(compiled.script.contains("2001:db8::/32"));
        // The IPv6 address must land in the v6 static set's `add
        // element`, not get miscategorized into the v4 one.
        let static_v6_line = compiled.script.lines().find(|l| l.contains(&compiled.static_set_v6) && l.starts_with("add element")).unwrap();
        assert!(static_v6_line.contains("2001:db8::/32"));
    }

    #[test]
    fn compile_mark_script_with_no_static_addrs_still_flushes_both_static_sets() {
        // Selecting fewer static addresses on a later reconcile pass must
        // actually remove the stale ones, not just stop adding new ones —
        // the flush must run unconditionally, whether or not there's
        // anything to add afterward.
        let compiled = compile_mark_script("ab12", 0x1000, &[], None, None);
        assert!(compiled.script.contains(&format!("flush set inet {NFT_TABLE} {}", compiled.static_set_v4)));
        assert!(compiled.script.contains(&format!("flush set inet {NFT_TABLE} {}", compiled.static_set_v6)));
    }

    #[test]
    fn compile_mark_script_with_no_limits_emits_no_ct_count_or_limit_rate_rules() {
        let compiled = compile_mark_script("ab12", 0x1000, &[], None, None);
        assert!(!compiled.script.contains("ct count"));
        assert!(!compiled.script.contains("limit rate"));
    }

    #[test]
    fn compile_mark_script_emits_a_connection_cap_gated_on_this_peers_own_fwmark() {
        let compiled = compile_mark_script("ab12", 0x1000, &[], Some(50), None);
        assert!(compiled.script.contains("meta mark 4096 ct count over 50 drop"), "script was:\n{}", compiled.script);
    }

    #[test]
    fn compile_mark_script_converts_kbit_per_second_to_bytes_per_second_for_nft() {
        // 8000 kbit/s = 1_000_000 bytes/second.
        let compiled = compile_mark_script("ab12", 0x1000, &[], None, Some(8000));
        assert!(compiled.script.contains("meta mark 4096 limit rate over 1000000 bytes/second drop"), "script was:\n{}", compiled.script);
    }

    #[test]
    fn compile_mark_script_can_apply_both_limits_at_once() {
        let compiled = compile_mark_script("ab12", 0x1000, &[], Some(50), Some(8000));
        assert!(compiled.script.contains("ct count over 50 drop"));
        assert!(compiled.script.contains("limit rate over 1000000 bytes/second drop"));
    }

    #[test]
    fn apply_policy_route_issues_rule_and_route_commands() {
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| p == "ip" && a.first().map(String::as_str) == Some("rule") && a.get(1).map(String::as_str) == Some("del"));
        apply_policy_route(&runner, 0x1000, 200, "sf_tun0", Duration::from_secs(1)).unwrap();

        let calls = runner.calls();
        assert!(calls.iter().any(|(p, a)| p == "ip" && a.contains(&"rule".to_string()) && a.contains(&"add".to_string())));
        assert!(calls.iter().any(|(p, a)| p == "ip" && a.contains(&"route".to_string()) && a.contains(&"replace".to_string())));
    }

    #[test]
    fn apply_policy_route_fails_when_ip_rule_add_fails() {
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| p == "ip" && a.first().map(String::as_str) == Some("rule") && a.get(1).map(String::as_str) == Some("del"));
        runner.fail_next_matching(|p, a| p == "ip" && a.first().map(String::as_str) == Some("rule") && a.get(1).map(String::as_str) == Some("add"));
        assert!(apply_policy_route(&runner, 0x1000, 200, "sf_tun0", Duration::from_secs(1)).is_err());
    }
}
