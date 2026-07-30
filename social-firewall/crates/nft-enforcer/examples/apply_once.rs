//! Throwaway integration-test driver — the crate itself has no `main.rs`;
//! this is the "simplest option" `INTEGRATION_TESTING.md` calls for: a
//! real binary that links `nft-enforcer`, opens a real `StateStore`, and
//! calls `NftablesController` with the real `SystemCommandRunner` against
//! whatever `nft` is actually on `$PATH`. Not part of the crate's public
//! API or any production deployment — exists purely to be cross-compiled
//! and run by hand on the QEMU VM per that doc's checklist.
//!
//! Usage:
//!   apply_once <store.sqlite> <scratch-dir> <apply|dry-run> <revision> [entry...]
//!
//! Each entry is `<decision>:<kind>:<value>`, e.g.:
//!   deny:ip:203.0.113.9
//!   ask:cidr:198.51.100.0/28
//!   allow:ip:203.0.113.10
//!
//! Extra protected (never-denyable) addresses/CIDRs beyond the built-in
//! loopback/link-local defaults come from the `SF_PROTECT_IPS` env var —
//! comma-separated, each either a bare address or a CIDR, e.g.
//! `SF_PROTECT_IPS=192.168.1.1,10.0.0.0/24`. This is how the "management
//! access survives an adversarial policy" checklist item is exercised:
//! set it to the VM's own SSH-reachable address, then include that same
//! address as a `deny:ip:...` entry and confirm you can still SSH in.

use nft_enforcer::{ApplyResult, NftablesController, NftablesControllerConfig, PolicyEntry, ProtectedDestinations, SystemCommandRunner, Target};
use state_store::StateStore;
use std::path::PathBuf;

fn parse_entry(raw: &str) -> PolicyEntry {
    let mut parts = raw.splitn(3, ':');
    let (decision_s, kind_s, value) = match (parts.next(), parts.next(), parts.next()) {
        (Some(d), Some(k), Some(v)) => (d, k, v),
        _ => panic!("entry `{raw}` must be `<decision>:<kind>:<value>`, e.g. deny:ip:203.0.113.9"),
    };
    let decision = match decision_s {
        "allow" => domain_types::Decision::Allow,
        "deny" => domain_types::Decision::Deny,
        "ask" => domain_types::Decision::Ask,
        "none" => domain_types::Decision::NoDecision,
        other => panic!("unknown decision `{other}` — expected allow|deny|ask|none"),
    };
    let target = match kind_s {
        "ip" => Target::Ip(value.to_string()),
        "cidr" => Target::Cidr(value.to_string()),
        other => panic!("unknown kind `{other}` — expected ip|cidr"),
    };
    PolicyEntry { target, decision }
}

fn parse_protected(raw: &str) -> ProtectedDestinations {
    let mut p = ProtectedDestinations::default().with_defaults();
    for tok in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        p.add(tok).unwrap_or_else(|e| panic!("SF_PROTECT_IPS: {e}"));
    }
    p
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: {} <store.sqlite> <scratch-dir> <apply|dry-run> <revision> [entry...]", args[0]);
        std::process::exit(2);
    }
    let store_path = PathBuf::from(&args[1]);
    let scratch_dir = PathBuf::from(&args[2]);
    let mode = args[3].as_str();
    let revision: i64 = args[4].parse().expect("revision must be an integer");
    let entries: Vec<PolicyEntry> = args[5..].iter().map(|s| parse_entry(s)).collect();

    std::fs::create_dir_all(&scratch_dir).expect("failed to create scratch dir");
    let store = StateStore::open(&store_path).expect("failed to open state store");
    let protected = std::env::var("SF_PROTECT_IPS").map(|v| parse_protected(&v)).unwrap_or_else(|_| ProtectedDestinations::default().with_defaults());

    let runner = SystemCommandRunner;
    let config = NftablesControllerConfig { protected, scratch_dir, ..NftablesControllerConfig::default() };
    let ctrl = NftablesController::new(&runner, &store, config);

    match mode {
        "dry-run" => {
            let report = ctrl.dry_run(&entries).expect("dry_run failed");
            println!("would_apply: {}", report.would_apply);
            println!("previous_digest: {:?}", report.previous_digest);
            println!("new_digest: {}", report.compiled.digest);
            println!("deny_v4: {:?}", report.compiled.deny_v4);
            println!("deny_v6: {:?}", report.compiled.deny_v6);
            println!("quarantine_v4: {:?}", report.compiled.quarantine_v4);
            println!("quarantine_v6: {:?}", report.compiled.quarantine_v6);
            println!("skipped_protected: {:?}", report.compiled.skipped_protected);
            println!("--- script ---");
            println!("{}", report.compiled.script);
        }
        "apply" => {
            let result = ctrl.apply(&entries, revision).expect("apply failed");
            match result {
                ApplyResult::NoChange { digest } => {
                    println!("NoChange digest={digest}");
                }
                ApplyResult::Applied { digest, revision } => {
                    println!("Applied digest={digest} revision={revision}");
                }
                ApplyResult::Rejected { reason } => {
                    println!("Rejected reason={reason}");
                    std::process::exit(1);
                }
                ApplyResult::Failed { reason, rollback } => {
                    println!("Failed reason={reason} rollback={rollback:?}");
                    std::process::exit(2);
                }
            }
        }
        other => {
            eprintln!("unknown mode `{other}` — expected apply|dry-run");
            std::process::exit(2);
        }
    }
}
