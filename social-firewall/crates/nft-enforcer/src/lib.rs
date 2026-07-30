//! The smallest safe path from an `EffectivePolicyDecision` to real
//! OpenWrt firewall enforcement: a dedicated `inet social_firewall`
//! nftables table (never `inet fw4`, never touched by `fw4 reload`),
//! populated from IP/CIDR-shaped decisions via `nft` sets, applied
//! atomically with `nft --check` validation, a pre-apply snapshot, and
//! automatic rollback if validation, application, or a post-apply health
//! check fails.
//!
//! **Deliberately out of scope for this pass** (per the request that
//! introduced this crate): hostname/DNS-derived rules (see
//! [`Destination::Hostname`] — the type exists so the interface doesn't
//! need to change shape later, but it is never compiled into an nft rule
//! today), Iroh, CometBFT, ntfy, peer presence. This crate only ever
//! consumes an already-computed decision list; it has no opinion about
//! where that list came from.
//!
//! # Why a dedicated table, not editing `inet fw4`
//!
//! nftables evaluates every table's base chains at the same network hook
//! independently, in priority order — a second table at a hook is not a
//! merge into fw4's table, it's an entirely separate set of rules that
//! fw4 never sees, never flushes, and never regenerates. That's what
//! makes "use sets instead of rewriting the whole ruleset" and "never
//! touch unrelated fw4 rules" both true *by construction* here: every nft
//! command this crate runs is scoped to `table inet social_firewall`
//! specifically (`flush table ...`, `delete table ...`, `-f` script
//! defining only that table) — there is no code path that can reach
//! `inet fw4` at all. This mirrors how `banip` already coexists with fw4
//! in this same project (see `kestreld`'s `data::banip`, which reads
//! banIP's independently-managed sets out of the same `nft list ruleset`
//! dump rather than assuming a merged model).
//!
//! # Enforcement semantics
//!
//! - `Deny` → the destination is added to a `deny_v4`/`deny_v6` set;
//!   the chain drops on membership.
//! - `Ask` (mapped to [`EnforcementAction::Quarantine`]) → same
//!   drop-on-membership treatment today, in a *separate* set/counter so
//!   it's independently observable and can grow a different treatment
//!   later (e.g. a walled-garden redirect) without a schema change.
//! - `Allow` / `NoDecision` → no rule at all. This table only ever
//!   expresses restrictions; "allow" is the *absence* of a restriction,
//!   not a positive rule — this crate never needs to know what the
//!   router's own default policy is elsewhere.
//!
//! # Management-lockout protection
//!
//! Two independent layers, either one alone would be enough:
//! 1. [`ProtectedDestinations`] is consulted at compile time — any
//!    decision targeting a protected address/CIDR is *excluded* from the
//!    deny/quarantine sets regardless of what the decision says, and
//!    recorded in [`CompiledFirewallPolicy::skipped_protected`].
//! 2. The generated chain also emits an explicit `accept` rule for every
//!    protected destination, positioned *before* the deny/quarantine
//!    drops — so even a future bug in (1) can't silently deny management
//!    access.

use domain_types::Decision;
use ipnet::{Ipv4Net, Ipv6Net};
use state_store::{AppliedRulesetState, StateStore, StoreError};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

mod command;
mod compile;
mod health;

pub use command::{CommandOutput, CommandRunner, FakeCommandRunner, SystemCommandRunner};
pub use compile::{compile, CompileError, CompiledFirewallPolicy, Destination, PolicyEntry};
pub use health::{HealthCheck, HealthCheckResult, RulesetHealthCheck};

pub const NFT_TABLE: &str = "social_firewall";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementAction {
    Allow,
    Deny,
    Quarantine,
    NoOpinion,
}

impl From<Decision> for EnforcementAction {
    fn from(d: Decision) -> Self {
        match d {
            Decision::Allow => EnforcementAction::Allow,
            Decision::Deny => EnforcementAction::Deny,
            // Ask means "conflicting/uncertain signal, a human should
            // look" — neither a confident allow nor deny, so it gets its
            // own middle enforcement rather than being folded into
            // either. See the module doc's "Enforcement semantics".
            Decision::Ask => EnforcementAction::Quarantine,
            Decision::NoDecision => EnforcementAction::NoOpinion,
        }
    }
}

/// Addresses/ranges that can never be compiled into a deny/quarantine
/// set, regardless of what any decision says — see the module doc's
/// "Management-lockout protection" section. Always includes loopback and
/// link-local; callers add the router's own real LAN/management
/// addresses on top.
#[derive(Debug, Clone, Default)]
pub struct ProtectedDestinations {
    pub v4_addrs: Vec<Ipv4Addr>,
    pub v4_nets: Vec<Ipv4Net>,
    pub v6_addrs: Vec<Ipv6Addr>,
    pub v6_nets: Vec<Ipv6Net>,
}

impl ProtectedDestinations {
    /// Loopback + link-local, always protected regardless of
    /// configuration — a sane floor, not the whole story; callers must
    /// still add the router's actual management address(es).
    pub fn with_defaults(mut self) -> Self {
        self.v4_nets.push("127.0.0.0/8".parse().unwrap());
        self.v4_nets.push("169.254.0.0/16".parse().unwrap());
        self.v6_nets.push("::1/128".parse().unwrap());
        self.v6_nets.push("fe80::/10".parse().unwrap());
        self
    }

    /// Parses `s` as an IPv4/IPv6 address or CIDR range and adds it to
    /// whichever field matches. Shared by every caller that takes
    /// protected addresses as plain strings (CLI flags, env vars, config
    /// files) so the address-vs-CIDR sniffing logic exists in exactly one
    /// place rather than being copy-pasted at each call site.
    pub fn add(&mut self, s: &str) -> Result<(), String> {
        if let Ok(v4) = s.parse::<Ipv4Addr>() {
            self.v4_addrs.push(v4);
        } else if let Ok(v6) = s.parse::<Ipv6Addr>() {
            self.v6_addrs.push(v6);
        } else if let Ok(v4n) = s.parse::<Ipv4Net>() {
            self.v4_nets.push(v4n);
        } else if let Ok(v6n) = s.parse::<Ipv6Net>() {
            self.v6_nets.push(v6n);
        } else {
            return Err(format!("`{s}` is not a valid IPv4/IPv6 address or CIDR range"));
        }
        Ok(())
    }

    pub fn protects_v4(&self, addr: Ipv4Addr) -> bool {
        self.v4_addrs.contains(&addr) || self.v4_nets.iter().any(|n| n.contains(&addr))
    }
    pub fn protects_v4_net(&self, net: Ipv4Net) -> bool {
        self.v4_addrs.iter().any(|a| net.contains(a)) || self.v4_nets.iter().any(|n| n.contains(&net) || net.contains(n))
    }
    pub fn protects_v6(&self, addr: Ipv6Addr) -> bool {
        self.v6_addrs.contains(&addr) || self.v6_nets.iter().any(|n| n.contains(&addr))
    }
    pub fn protects_v6_net(&self, net: Ipv6Net) -> bool {
        self.v6_addrs.iter().any(|a| net.contains(a)) || self.v6_nets.iter().any(|n| n.contains(&net) || net.contains(n))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallSnapshot {
    /// `false` on the very first-ever apply, when `table inet
    /// social_firewall` doesn't exist yet — rollback then means deleting
    /// the table outright rather than restoring text.
    pub existed: bool,
    pub ruleset_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    /// The compiled policy's digest matched what's already applied — no
    /// nft command was run at all.
    NoChange { digest: String },
    Applied { digest: String, revision: i64 },
    /// Rejected before touching live state (`nft --check` failed, or the
    /// policy failed to compile) — nothing to roll back.
    Rejected { reason: String },
    /// Something failed after we started changing live state; `rollback`
    /// records whether the rollback itself succeeded.
    Failed { reason: String, rollback: RollbackResult },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackResult {
    pub attempted: bool,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunReport {
    pub compiled: CompiledFirewallPolicy,
    pub would_apply: bool,
    pub previous_digest: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum EnforcementError {
    #[error("policy failed to compile: {0}")]
    Compile(#[from] CompileError),
    #[error("state store error: {0}")]
    Store(#[from] StoreError),
    #[error("io error writing scratch file: {0}")]
    Io(#[from] std::io::Error),
}

pub struct NftablesControllerConfig {
    pub protected: ProtectedDestinations,
    pub command_timeout: Duration,
    /// Where compiled `.nft` scripts are written before being handed to
    /// `nft -f`/`nft --check -f` — a real directory on the router (e.g.
    /// under `/etc/kestrel/social-firewall/nft/`), a tempdir in tests.
    pub scratch_dir: PathBuf,
}

impl Default for NftablesControllerConfig {
    fn default() -> Self {
        Self {
            protected: ProtectedDestinations::default().with_defaults(),
            command_timeout: Duration::from_secs(5),
            scratch_dir: std::env::temp_dir(),
        }
    }
}

pub struct NftablesController<'a> {
    runner: &'a dyn CommandRunner,
    store: &'a StateStore,
    config: NftablesControllerConfig,
    health_checks: Vec<Box<dyn HealthCheck>>,
}

impl<'a> NftablesController<'a> {
    pub fn new(runner: &'a dyn CommandRunner, store: &'a StateStore, config: NftablesControllerConfig) -> Self {
        Self { runner, store, config, health_checks: vec![Box::new(RulesetHealthCheck)] }
    }

    /// Overrides the default health-check set — mainly for tests that
    /// want to force a specific health-check outcome without going
    /// through `RulesetHealthCheck`'s real parsing.
    pub fn with_health_checks(mut self, checks: Vec<Box<dyn HealthCheck>>) -> Self {
        self.health_checks = checks;
        self
    }

    /// Pure — compiles decisions into an nft representation, no I/O.
    pub fn plan(&self, entries: &[PolicyEntry]) -> Result<CompiledFirewallPolicy, EnforcementError> {
        Ok(compile(entries, &self.config.protected)?)
    }

    /// Shows exactly what would change without applying anything.
    pub fn dry_run(&self, entries: &[PolicyEntry]) -> Result<DryRunReport, EnforcementError> {
        let compiled = self.plan(entries)?;
        let previous = self.store.get_applied_ruleset()?;
        let would_apply = previous.as_ref().map(|p| p.digest != compiled.digest).unwrap_or(true);
        Ok(DryRunReport { compiled, would_apply, previous_digest: previous.map(|p| p.digest) })
    }

    /// The full ten-step apply flow described in the module doc.
    /// Idempotent: reapplying an already-active policy makes no changes
    /// and runs no `nft` commands at all.
    pub fn apply(&self, entries: &[PolicyEntry], revision: i64) -> Result<ApplyResult, EnforcementError> {
        let previous = self.store.get_applied_ruleset()?;
        let compiled = match self.plan(entries) {
            Ok(c) => c,
            Err(e) => return Ok(ApplyResult::Rejected { reason: e.to_string() }),
        };

        if let Some(prev) = &previous {
            if prev.digest == compiled.digest {
                return Ok(ApplyResult::NoChange { digest: compiled.digest });
            }
        }

        let script_path = self.config.scratch_dir.join("social_firewall_compiled.nft");
        std::fs::write(&script_path, &compiled.script)?;
        let script_path_str = script_path.to_string_lossy().into_owned();

        let check = self.runner.run("nft", &["--check", "-f", &script_path_str], self.config.command_timeout);
        if !check.success {
            self.log(revision, &compiled, "rejected_check_failed")?;
            return Ok(ApplyResult::Rejected { reason: check.stderr });
        }

        let snapshot = self.snapshot_live();

        let apply_out = self.runner.run("nft", &["-f", &script_path_str], self.config.command_timeout);
        if !apply_out.success {
            let rollback = self.rollback(&snapshot);
            self.log(revision, &compiled, "apply_failed_rolled_back")?;
            return Ok(ApplyResult::Failed { reason: apply_out.stderr, rollback });
        }

        for hc in &self.health_checks {
            let result = hc.check(self.runner, &compiled, &self.config.protected, self.config.command_timeout);
            if !result.ok {
                let rollback = self.rollback(&snapshot);
                self.log(revision, &compiled, "health_check_failed_rolled_back")?;
                return Ok(ApplyResult::Failed { reason: result.reason.unwrap_or_default(), rollback });
            }
        }

        self.store.save_applied_ruleset(&AppliedRulesetState {
            digest: compiled.digest.clone(),
            ruleset_text: compiled.script.clone(),
            revision,
            updated_at: now(),
        })?;
        self.log(revision, &compiled, "applied")?;
        Ok(ApplyResult::Applied { digest: compiled.digest, revision })
    }

    fn snapshot_live(&self) -> FirewallSnapshot {
        let out = self.runner.run("nft", &["-a", "list", "table", "inet", NFT_TABLE], self.config.command_timeout);
        FirewallSnapshot { existed: out.success, ruleset_text: if out.success { out.stdout } else { String::new() } }
    }

    fn rollback(&self, snapshot: &FirewallSnapshot) -> RollbackResult {
        if snapshot.existed {
            let path = self.config.scratch_dir.join("social_firewall_rollback.nft");
            // `snapshot.ruleset_text` is the output of `nft -a list table
            // ...` — a listing, not a from-scratch script. Writing it back
            // via `-f` with no `delete`/`add` first re-declares the same
            // objects onto whatever's already live rather than replacing
            // it, and (confirmed against a real `nft` on a QEMU VM) that
            // duplicates every chain rule on each rollback, compounding
            // without bound across repeated failures. `delete table` +
            // `add table` first, in the same atomic `-f` transaction,
            // guarantees the restore starts from a genuinely clean slate.
            let script = format!("delete table inet {NFT_TABLE}\nadd table inet {NFT_TABLE}\n{}\n", snapshot.ruleset_text);
            if let Err(e) = std::fs::write(&path, &script) {
                return RollbackResult { attempted: true, ok: false, detail: format!("failed to write rollback script: {e}") };
            }
            let out = self.runner.run("nft", &["-f", &path.to_string_lossy()], self.config.command_timeout);
            RollbackResult { attempted: true, ok: out.success, detail: if out.success { "restored previous ruleset".into() } else { out.stderr } }
        } else {
            let out = self.runner.run("nft", &["delete", "table", "inet", NFT_TABLE], self.config.command_timeout);
            RollbackResult { attempted: true, ok: out.success, detail: if out.success { "deleted table (none existed before)".into() } else { out.stderr } }
        }
    }

    fn log(&self, revision: i64, compiled: &CompiledFirewallPolicy, outcome: &str) -> Result<(), EnforcementError> {
        let decision_count = compiled.deny_v4.len() + compiled.deny_v6.len() + compiled.quarantine_v4.len() + compiled.quarantine_v6.len();
        let summary = compiled.summarize();
        self.store.append_apply_log(revision, &compiled.digest, decision_count as i64, &summary, outcome, now())?;
        Ok(())
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Only used by `SystemCommandRunner`'s bounded wait loop — kept here so
/// `command.rs` doesn't need its own `Instant` import ceremony.
pub(crate) fn deadline_from(timeout: Duration) -> Instant {
    Instant::now() + timeout
}

// Re-exported so downstream crates (the CLI) can build `PolicyEntry`
// lists directly from `policy_engine`/`domain_types` output without an
// extra import.
pub use domain_types::TargetSelector as Target;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::FakeCommandRunner;
    use domain_types::TargetSelector;

    fn entry(target: TargetSelector, decision: Decision) -> PolicyEntry {
        PolicyEntry { target, decision }
    }

    fn controller<'a>(runner: &'a FakeCommandRunner, store: &'a StateStore, dir: &std::path::Path) -> NftablesController<'a> {
        let config = NftablesControllerConfig { scratch_dir: dir.to_path_buf(), ..NftablesControllerConfig::default() };
        NftablesController::new(runner, store, config)
    }

    #[test]
    fn reapplying_the_same_policy_makes_no_further_nft_calls() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let entries = vec![entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)];

        let ctrl = controller(&runner, &store, dir.path());
        let first = ctrl.apply(&entries, 1).unwrap();
        assert!(matches!(first, ApplyResult::Applied { .. }));
        let calls_after_first = runner.call_count();
        assert!(calls_after_first > 0);

        let second = ctrl.apply(&entries, 2).unwrap();
        assert!(matches!(second, ApplyResult::NoChange { .. }));
        assert_eq!(runner.call_count(), calls_after_first, "no additional nft commands should run on a true no-op reapply");
    }

    #[test]
    fn adding_and_removing_an_ip_changes_the_compiled_script() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store, dir.path());

        let with_ip = vec![entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)];
        let r1 = ctrl.apply(&with_ip, 1).unwrap();
        let ApplyResult::Applied { digest: d1, .. } = r1 else { panic!("expected Applied, got {r1:?}") };

        let without_ip: Vec<PolicyEntry> = vec![];
        let r2 = ctrl.apply(&without_ip, 2).unwrap();
        let ApplyResult::Applied { digest: d2, .. } = r2 else { panic!("expected Applied, got {r2:?}") };
        assert_ne!(d1, d2, "removing the only denied IP must change the applied digest");
    }

    #[test]
    fn cidr_targets_are_compiled_into_interval_sets() {
        let entries = vec![entry(TargetSelector::Cidr("198.51.100.0/24".into()), Decision::Deny)];
        let compiled = compile(&entries, &ProtectedDestinations::default().with_defaults()).unwrap();
        assert_eq!(compiled.deny_v4, vec!["198.51.100.0/24".to_string()]);
        assert!(compiled.script.contains("flags interval"));
    }

    #[test]
    fn ipv6_addr_and_cidr_are_supported() {
        let entries = vec![
            entry(TargetSelector::Ip("2001:db8::1".into()), Decision::Deny),
            entry(TargetSelector::Cidr("2001:db8:1::/48".into()), Decision::Ask),
        ];
        let compiled = compile(&entries, &ProtectedDestinations::default().with_defaults()).unwrap();
        assert_eq!(compiled.deny_v6, vec!["2001:db8::1".to_string()]);
        assert_eq!(compiled.quarantine_v6, vec!["2001:db8:1::/48".to_string()]);
    }

    #[test]
    fn invalid_ip_target_is_rejected_before_enforcement() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store, dir.path());
        let entries = vec![entry(TargetSelector::Ip("not-an-ip".into()), Decision::Deny)];

        let result = ctrl.apply(&entries, 1).unwrap();
        assert!(matches!(result, ApplyResult::Rejected { .. }));
        assert_eq!(runner.call_count(), 0, "an invalid policy must never reach nft at all");
    }

    #[test]
    fn a_failed_nft_check_is_rejected_without_touching_live_state() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|program, args| program == "nft" && args.contains(&"--check".to_string()));
        let ctrl = controller(&runner, &store, dir.path());
        let entries = vec![entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)];

        let result = ctrl.apply(&entries, 1).unwrap();
        assert!(matches!(result, ApplyResult::Rejected { .. }));
        assert!(store.get_applied_ruleset().unwrap().is_none(), "a rejected check must never be committed as applied state");
    }

    #[test]
    fn rollback_script_clears_the_table_before_restoring_the_snapshot() {
        // Regression test for a real bug found via QEMU VM testing: the
        // rollback script used to write `snapshot.ruleset_text` (an `nft
        // -a list table` *listing*, not a from-scratch script) straight
        // to `-f` with no `delete`/`add` first. Re-declaring an
        // already-existing table's objects from a listing doesn't
        // replace them — it merges on top, so every real rollback
        // duplicated all of the previous chain's rules. `delete table` +
        // `add table` before the captured text is what makes the restore
        // start from a genuinely clean slate.
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        runner.set_default_stdout("table inet social_firewall {\n\tset deny_v4 { type ipv4_addr; elements = { 203.0.113.9 } }\n}\n");
        let ctrl = controller(&runner, &store, dir.path());

        ctrl.apply(&[entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)], 1).unwrap();
        runner.fail_next_matching(|program, args| program == "nft" && args.first().map(String::as_str) == Some("-f"));
        let result = ctrl.apply(&[entry(TargetSelector::Ip("203.0.113.10".into()), Decision::Deny)], 2).unwrap();
        assert!(matches!(result, ApplyResult::Failed { .. }));

        let rollback_script = std::fs::read_to_string(dir.path().join("social_firewall_rollback.nft")).unwrap();
        let delete_pos = rollback_script.find(&format!("delete table inet {NFT_TABLE}")).expect("rollback script must delete the table first");
        let add_pos = rollback_script.find(&format!("add table inet {NFT_TABLE}")).expect("rollback script must recreate the table");
        let snapshot_pos = rollback_script.find("elements = { 203.0.113.9 }").expect("rollback script must contain the captured snapshot");
        assert!(delete_pos < add_pos && add_pos < snapshot_pos, "must delete, then add, then restore the snapshot content, in that order");
    }

    #[test]
    fn a_simulated_apply_failure_triggers_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        // First real apply succeeds and establishes a "previous" state...
        let ctrl = controller(&runner, &store, dir.path());
        ctrl.apply(&[entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)], 1).unwrap();

        // ...then the *next* apply's actual `nft -f <script>` call (not --check) fails.
        runner.fail_next_matching(|program, args| program == "nft" && args.first().map(String::as_str) == Some("-f"));
        let result = ctrl.apply(&[entry(TargetSelector::Ip("203.0.113.10".into()), Decision::Deny)], 2).unwrap();

        match result {
            ApplyResult::Failed { rollback, .. } => assert!(rollback.attempted),
            other => panic!("expected Failed with a rollback attempt, got {other:?}"),
        }
        // Applied-state metadata must still reflect the last *successful* apply, not the failed one.
        assert_eq!(store.get_applied_ruleset().unwrap().unwrap().revision, 1);
    }

    #[test]
    fn a_failed_health_check_triggers_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();

        struct AlwaysFails;
        impl HealthCheck for AlwaysFails {
            fn check(&self, _runner: &dyn CommandRunner, _compiled: &CompiledFirewallPolicy, _protected: &ProtectedDestinations, _timeout: Duration) -> HealthCheckResult {
                HealthCheckResult { ok: false, reason: Some("simulated health check failure".into()) }
            }
        }

        let config = NftablesControllerConfig { scratch_dir: dir.path().to_path_buf(), ..NftablesControllerConfig::default() };
        let ctrl = NftablesController::new(&runner, &store, config).with_health_checks(vec![Box::new(AlwaysFails)]);

        let result = ctrl.apply(&[entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)], 1).unwrap();
        match result {
            ApplyResult::Failed { rollback, reason } => {
                assert!(rollback.attempted);
                assert_eq!(reason, "simulated health check failure");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(store.get_applied_ruleset().unwrap().is_none());
    }

    #[test]
    fn compiled_script_never_references_the_fw4_table() {
        let entries = vec![entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)];
        let compiled = compile(&entries, &ProtectedDestinations::default().with_defaults()).unwrap();
        assert!(!compiled.script.contains("fw4"), "must never reference fw4's own table");
        assert!(compiled.script.contains(&format!("table inet {NFT_TABLE}")));
    }

    #[test]
    fn management_address_can_never_be_denied_even_if_a_decision_says_so() {
        let mgmt = Ipv4Addr::new(192, 168, 1, 1);
        let mut protected = ProtectedDestinations::default().with_defaults();
        protected.v4_addrs.push(mgmt);

        let entries = vec![entry(TargetSelector::Ip(mgmt.to_string()), Decision::Deny)];
        let compiled = compile(&entries, &protected).unwrap();

        assert!(compiled.deny_v4.is_empty(), "the management address must never end up in the deny set");
        assert_eq!(compiled.skipped_protected, vec![mgmt.to_string()]);
        assert!(compiled.script.contains(&format!("ip daddr {mgmt} accept")), "an explicit accept-first rule must exist as a second layer of protection");
    }

    #[test]
    fn management_cidr_containing_a_denied_address_is_also_protected() {
        let mut protected = ProtectedDestinations::default().with_defaults();
        protected.v4_nets.push("192.168.1.0/24".parse().unwrap());

        let entries = vec![entry(TargetSelector::Ip("192.168.1.50".into()), Decision::Deny)];
        let compiled = compile(&entries, &protected).unwrap();
        assert!(compiled.deny_v4.is_empty());
    }

    #[test]
    fn dry_run_reports_pending_change_without_applying() {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store, dir.path());

        let entries = vec![entry(TargetSelector::Ip("203.0.113.9".into()), Decision::Deny)];
        let report = ctrl.dry_run(&entries).unwrap();
        assert!(report.would_apply);
        assert_eq!(report.previous_digest, None);
        assert_eq!(runner.call_count(), 0, "dry-run must never touch nft");
        assert!(store.get_applied_ruleset().unwrap().is_none());
    }

    #[test]
    fn protected_destinations_add_sniffs_address_vs_cidr_and_v4_vs_v6() {
        let mut p = ProtectedDestinations::default();
        p.add("192.168.1.1").unwrap();
        p.add("10.0.0.0/24").unwrap();
        p.add("2001:db8::1").unwrap();
        p.add("2001:db8:1::/48").unwrap();
        assert_eq!(p.v4_addrs, vec![Ipv4Addr::new(192, 168, 1, 1)]);
        assert_eq!(p.v4_nets, vec!["10.0.0.0/24".parse::<Ipv4Net>().unwrap()]);
        assert_eq!(p.v6_addrs, vec!["2001:db8::1".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(p.v6_nets, vec!["2001:db8:1::/48".parse::<Ipv6Net>().unwrap()]);
    }

    #[test]
    fn protected_destinations_add_rejects_garbage() {
        let mut p = ProtectedDestinations::default();
        assert!(p.add("not-an-address").is_err());
    }

}
