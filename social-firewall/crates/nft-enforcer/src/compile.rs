//! Deterministic compilation from decisions to an nft script — pure, no
//! I/O, so it's directly unit-testable and so the same input always
//! produces byte-identical output (the idempotency comparison in
//! `NftablesController::apply` depends on that).

use crate::{EnforcementAction, ProtectedDestinations, NFT_TABLE};
use domain_types::{Decision, TargetSelector};
use ipnet::{Ipv4Net, Ipv6Net};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    pub target: TargetSelector,
    pub decision: Decision,
}

/// What a target classifies as for enforcement purposes. `Hostname`
/// exists so this type doesn't need to change shape when DNS-derived
/// enforcement is built later — it is never compiled into an nft rule
/// today, only recorded in [`CompiledFirewallPolicy::skipped_hostnames`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Destination {
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
    Ipv4Cidr(Ipv4Net),
    Ipv6Cidr(Ipv6Net),
    Hostname(String),
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CompileError {
    #[error("`{0}` is not a valid IPv4 or IPv6 address")]
    InvalidAddress(String),
    #[error("`{0}` is not a valid IPv4 or IPv6 CIDR range")]
    InvalidCidr(String),
    #[error("target kind not supported by nft-enforcer yet: {0}")]
    UnsupportedTarget(String),
    #[error("`{0}` has conflicting decisions in the same policy input (deny vs. quarantine)")]
    Conflict(String),
}

fn classify(target: &TargetSelector) -> Result<Destination, CompileError> {
    match target {
        TargetSelector::Ip(s) => {
            if let Ok(v4) = s.parse::<Ipv4Addr>() {
                Ok(Destination::Ipv4Addr(v4))
            } else if let Ok(v6) = s.parse::<Ipv6Addr>() {
                Ok(Destination::Ipv6Addr(v6))
            } else {
                Err(CompileError::InvalidAddress(s.clone()))
            }
        }
        TargetSelector::Cidr(s) => {
            if let Ok(v4) = s.parse::<Ipv4Net>() {
                Ok(Destination::Ipv4Cidr(v4))
            } else if let Ok(v6) = s.parse::<Ipv6Net>() {
                Ok(Destination::Ipv6Cidr(v6))
            } else {
                Err(CompileError::InvalidCidr(s.clone()))
            }
        }
        TargetSelector::Domain(s) | TargetSelector::DomainSuffix(s) => {
            Ok(Destination::Hostname(s.clone()))
        }
        TargetSelector::Service(s) => Err(CompileError::UnsupportedTarget(format!("service:{s}"))),
        TargetSelector::ProtoPort { .. } => {
            Err(CompileError::UnsupportedTarget("proto_port".into()))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledFirewallPolicy {
    pub deny_v4: Vec<String>,
    pub deny_v6: Vec<String>,
    pub quarantine_v4: Vec<String>,
    pub quarantine_v6: Vec<String>,
    pub skipped_hostnames: Vec<String>,
    /// Destinations excluded from enforcement because they matched
    /// [`ProtectedDestinations`] — recorded so this is visible/auditable,
    /// never silent.
    pub skipped_protected: Vec<String>,
    pub script: String,
    pub digest: String,
}

impl CompiledFirewallPolicy {
    /// One-line-per-bucket human summary for the apply log — not meant to
    /// be parsed back, just readable in an audit trail.
    pub fn summarize(&self) -> String {
        format!(
            "deny_v4={} deny_v6={} quarantine_v4={} quarantine_v6={} skipped_hostnames={} skipped_protected={}",
            self.deny_v4.len(), self.deny_v6.len(), self.quarantine_v4.len(), self.quarantine_v6.len(),
            self.skipped_hostnames.len(), self.skipped_protected.len(),
        )
    }
}

pub fn compile(
    entries: &[PolicyEntry],
    protected: &ProtectedDestinations,
) -> Result<CompiledFirewallPolicy, CompileError> {
    let mut deny_v4 = Vec::new();
    let mut deny_v6 = Vec::new();
    let mut quarantine_v4 = Vec::new();
    let mut quarantine_v6 = Vec::new();
    let mut skipped_hostnames = Vec::new();
    let mut skipped_protected = Vec::new();
    let mut seen: HashMap<String, EnforcementAction> = HashMap::new();

    for entry in entries {
        let action = EnforcementAction::from(entry.decision);
        if matches!(
            action,
            EnforcementAction::Allow | EnforcementAction::NoOpinion
        ) {
            continue;
        }

        let dest = classify(&entry.target)?;
        match dest {
            Destination::Hostname(h) => {
                skipped_hostnames.push(h);
                continue;
            }
            Destination::Ipv4Addr(addr) => {
                if protected.protects_v4(addr) {
                    skipped_protected.push(addr.to_string());
                    continue;
                }
                record(&mut seen, addr.to_string(), action.clone())?;
                match action {
                    EnforcementAction::Deny => deny_v4.push(addr.to_string()),
                    EnforcementAction::Quarantine => quarantine_v4.push(addr.to_string()),
                    _ => unreachable!(),
                }
            }
            Destination::Ipv6Addr(addr) => {
                if protected.protects_v6(addr) {
                    skipped_protected.push(addr.to_string());
                    continue;
                }
                record(&mut seen, addr.to_string(), action.clone())?;
                match action {
                    EnforcementAction::Deny => deny_v6.push(addr.to_string()),
                    EnforcementAction::Quarantine => quarantine_v6.push(addr.to_string()),
                    _ => unreachable!(),
                }
            }
            Destination::Ipv4Cidr(net) => {
                if protected.protects_v4_net(net) {
                    skipped_protected.push(net.to_string());
                    continue;
                }
                record(&mut seen, net.to_string(), action.clone())?;
                match action {
                    EnforcementAction::Deny => deny_v4.push(net.to_string()),
                    EnforcementAction::Quarantine => quarantine_v4.push(net.to_string()),
                    _ => unreachable!(),
                }
            }
            Destination::Ipv6Cidr(net) => {
                if protected.protects_v6_net(net) {
                    skipped_protected.push(net.to_string());
                    continue;
                }
                record(&mut seen, net.to_string(), action.clone())?;
                match action {
                    EnforcementAction::Deny => deny_v6.push(net.to_string()),
                    EnforcementAction::Quarantine => quarantine_v6.push(net.to_string()),
                    _ => unreachable!(),
                }
            }
        }
    }

    for bucket in [
        &mut deny_v4,
        &mut deny_v6,
        &mut quarantine_v4,
        &mut quarantine_v6,
        &mut skipped_hostnames,
        &mut skipped_protected,
    ] {
        bucket.sort();
        bucket.dedup();
    }

    let script = render_script(
        &deny_v4,
        &deny_v6,
        &quarantine_v4,
        &quarantine_v6,
        protected,
    );
    let digest = blake3::hash(script.as_bytes()).to_hex().to_string();

    Ok(CompiledFirewallPolicy {
        deny_v4,
        deny_v6,
        quarantine_v4,
        quarantine_v6,
        skipped_hostnames,
        skipped_protected,
        script,
        digest,
    })
}

fn record(
    seen: &mut HashMap<String, EnforcementAction>,
    key: String,
    action: EnforcementAction,
) -> Result<(), CompileError> {
    match seen.get(&key) {
        Some(existing) if *existing != action => Err(CompileError::Conflict(key)),
        _ => {
            seen.insert(key, action);
            Ok(())
        }
    }
}

fn set_block(name: &str, family: &str, elements: &[String]) -> String {
    if elements.is_empty() {
        format!("    set {name} {{\n        type {family}\n        flags interval\n    }}\n")
    } else {
        format!(
            "    set {name} {{\n        type {family}\n        flags interval\n        elements = {{ {} }}\n    }}\n",
            elements.join(", ")
        )
    }
}

fn render_script(
    deny_v4: &[String],
    deny_v6: &[String],
    quarantine_v4: &[String],
    quarantine_v6: &[String],
    protected: &ProtectedDestinations,
) -> String {
    let mut protected_accept_lines = Vec::new();
    let mut v4_addrs = protected.v4_addrs.clone();
    v4_addrs.sort();
    for a in v4_addrs {
        protected_accept_lines.push(format!(
            "        ip daddr {a} accept comment \"social-firewall:protected\""
        ));
    }
    let mut v4_nets = protected.v4_nets.clone();
    v4_nets.sort_by_key(|n| (n.addr(), n.prefix_len()));
    for n in v4_nets {
        protected_accept_lines.push(format!(
            "        ip daddr {n} accept comment \"social-firewall:protected\""
        ));
    }
    let mut v6_addrs = protected.v6_addrs.clone();
    v6_addrs.sort();
    for a in v6_addrs {
        protected_accept_lines.push(format!(
            "        ip6 daddr {a} accept comment \"social-firewall:protected\""
        ));
    }
    let mut v6_nets = protected.v6_nets.clone();
    v6_nets.sort_by_key(|n| (n.addr(), n.prefix_len()));
    for n in v6_nets {
        protected_accept_lines.push(format!(
            "        ip6 daddr {n} accept comment \"social-firewall:protected\""
        ));
    }

    let deny_v4_set = set_block("deny_v4", "ipv4_addr", deny_v4);
    let deny_v6_set = set_block("deny_v6", "ipv6_addr", deny_v6);
    let quarantine_v4_set = set_block("quarantine_v4", "ipv4_addr", quarantine_v4);
    let quarantine_v6_set = set_block("quarantine_v6", "ipv6_addr", quarantine_v6);
    let protected_lines = if protected_accept_lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", protected_accept_lines.join("\n"))
    };

    let mut out = String::new();
    out.push_str(&format!("add table inet {NFT_TABLE}\n"));
    // `flush table` only clears chain *rules* — it does NOT clear named
    // sets' elements (confirmed against a real `nft` on a QEMU VM: a
    // previously-added set element survived `add table` + `flush table`
    // + a redeclared `set X { elements = {...} }` block indefinitely,
    // because re-declaring an *existing* set's `elements = {...}` merges
    // into its current contents rather than replacing them). `add set`
    // is idempotent (a no-op if the set already exists with a matching
    // type/flags — same idempotent semantics as `add table` above), so
    // it safely guarantees each set exists before the `flush set` calls
    // that immediately follow — that ordering is what makes those
    // flushes safe on both the very first apply (nothing exists yet) and
    // every subsequent one (something does). Only after that genuine
    // flush does the `table { ... }` block below add back exactly the
    // current elements, so removals actually take effect instead of
    // accumulating forever.
    for name in ["deny_v4", "quarantine_v4"] {
        out.push_str(&format!(
            "add set inet {NFT_TABLE} {name} {{ type ipv4_addr; flags interval; }}\n"
        ));
    }
    for name in ["deny_v6", "quarantine_v6"] {
        out.push_str(&format!(
            "add set inet {NFT_TABLE} {name} {{ type ipv6_addr; flags interval; }}\n"
        ));
    }
    for name in ["deny_v4", "deny_v6", "quarantine_v4", "quarantine_v6"] {
        out.push_str(&format!("flush set inet {NFT_TABLE} {name}\n"));
    }
    out.push_str(&format!("flush table inet {NFT_TABLE}\n"));
    out.push_str(&format!("table inet {NFT_TABLE} {{\n"));
    out.push_str(&deny_v4_set);
    out.push_str(&deny_v6_set);
    out.push_str(&quarantine_v4_set);
    out.push_str(&quarantine_v6_set);
    out.push_str("\n    chain forward {\n");
    out.push_str("        type filter hook forward priority filter - 5; policy accept;\n");
    out.push_str(&protected_lines);
    out.push_str("        ip daddr @deny_v4 counter drop comment \"social-firewall:deny\"\n");
    out.push_str("        ip6 daddr @deny_v6 counter drop comment \"social-firewall:deny\"\n");
    out.push_str(
        "        ip daddr @quarantine_v4 counter drop comment \"social-firewall:quarantine\"\n",
    );
    out.push_str(
        "        ip6 daddr @quarantine_v6 counter drop comment \"social-firewall:quarantine\"\n",
    );
    out.push_str("    }\n");
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(target: TargetSelector, decision: Decision) -> PolicyEntry {
        PolicyEntry { target, decision }
    }

    fn no_protection() -> ProtectedDestinations {
        ProtectedDestinations::default()
    }

    #[test]
    fn script_explicitly_flushes_every_set_before_redeclaring_elements() {
        // Regression test for a real bug found via QEMU VM testing against
        // actual `nft`: `flush table` only clears chain rules, never named
        // set elements, so a previously-denied entry survived every
        // subsequent apply forever once `flush table` was the only
        // clearing mechanism. `add set` (idempotent, safe whether or not
        // the set already exists) followed by an explicit `flush set` for
        // each of the four sets is what actually makes removal work.
        let entries = vec![entry(
            TargetSelector::Ip("203.0.113.9".into()),
            Decision::Deny,
        )];
        let compiled = compile(&entries, &no_protection()).unwrap();
        for name in ["deny_v4", "deny_v6", "quarantine_v4", "quarantine_v6"] {
            assert!(
                compiled
                    .script
                    .contains(&format!("add set inet {NFT_TABLE} {name} ")),
                "missing `add set` for {name}"
            );
            assert!(
                compiled
                    .script
                    .contains(&format!("flush set inet {NFT_TABLE} {name}\n")),
                "missing `flush set` for {name}"
            );
        }
        // The `flush set` calls must precede the `table { ... }` block that
        // redeclares elements, or the ordering guarantee is meaningless.
        let flush_set_pos = compiled.script.find("flush set").unwrap();
        let table_block_pos = compiled
            .script
            .find(&format!("table inet {NFT_TABLE} {{"))
            .unwrap();
        assert!(
            flush_set_pos < table_block_pos,
            "flush set must run before the table block redeclares elements"
        );
    }

    #[test]
    fn compile_is_deterministic_regardless_of_input_order() {
        let a = vec![
            entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Deny),
            entry(TargetSelector::Ip("2.2.2.2".into()), Decision::Deny),
        ];
        let b = vec![
            entry(TargetSelector::Ip("2.2.2.2".into()), Decision::Deny),
            entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Deny),
        ];
        let compiled_a = compile(&a, &no_protection()).unwrap();
        let compiled_b = compile(&b, &no_protection()).unwrap();
        assert_eq!(compiled_a.script, compiled_b.script);
        assert_eq!(compiled_a.digest, compiled_b.digest);
    }

    #[test]
    fn ask_decisions_go_to_quarantine_not_deny() {
        let entries = vec![entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Ask)];
        let compiled = compile(&entries, &no_protection()).unwrap();
        assert!(compiled.deny_v4.is_empty());
        assert_eq!(compiled.quarantine_v4, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn allow_and_no_decision_produce_no_rules_at_all() {
        let entries = vec![
            entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Allow),
            entry(TargetSelector::Ip("2.2.2.2".into()), Decision::NoDecision),
        ];
        let compiled = compile(&entries, &no_protection()).unwrap();
        assert!(compiled.deny_v4.is_empty() && compiled.quarantine_v4.is_empty());
    }

    #[test]
    fn hostname_targets_are_recorded_but_never_enforced() {
        let entries = vec![entry(
            TargetSelector::Domain("ads.example".into()),
            Decision::Deny,
        )];
        let compiled = compile(&entries, &no_protection()).unwrap();
        assert!(compiled.deny_v4.is_empty() && compiled.deny_v6.is_empty());
        assert_eq!(compiled.skipped_hostnames, vec!["ads.example".to_string()]);
    }

    #[test]
    fn conflicting_deny_and_quarantine_for_the_same_destination_is_rejected() {
        let entries = vec![
            entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Deny),
            entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Ask),
        ];
        let result = compile(&entries, &no_protection());
        assert_eq!(result, Err(CompileError::Conflict("1.1.1.1".to_string())));
    }

    #[test]
    fn duplicate_identical_decisions_for_the_same_destination_are_not_a_conflict() {
        let entries = vec![
            entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Deny),
            entry(TargetSelector::Ip("1.1.1.1".into()), Decision::Deny),
        ];
        let compiled = compile(&entries, &no_protection()).unwrap();
        assert_eq!(compiled.deny_v4, vec!["1.1.1.1".to_string()]);
    }

    #[test]
    fn invalid_cidr_is_rejected() {
        let entries = vec![entry(
            TargetSelector::Cidr("not-a-cidr".into()),
            Decision::Deny,
        )];
        assert!(matches!(
            compile(&entries, &no_protection()),
            Err(CompileError::InvalidCidr(_))
        ));
    }

    #[test]
    fn service_and_proto_port_targets_are_rejected_as_unsupported() {
        let entries = vec![entry(TargetSelector::Service("ssh".into()), Decision::Deny)];
        assert!(matches!(
            compile(&entries, &no_protection()),
            Err(CompileError::UnsupportedTarget(_))
        ));
    }

    #[test]
    fn empty_set_omits_the_elements_line() {
        let compiled = compile(&[], &no_protection()).unwrap();
        assert!(!compiled.script.contains("elements ="));
        assert!(compiled.script.contains("set deny_v4"));
    }
}
