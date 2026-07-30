//! CLI implementation for the shared-rule-list subcommands: `publish-
//! list`, `ingest-list`, `list-subscribed-lists`, and
//! `set-follow-category-filter`. Reuses `tunnel.rs`'s sealing-envelope
//! and identity helpers rather than duplicating them — both features
//! publish signed, optionally-sealed, peer-discoverable things, so the
//! export/ingest machinery is shared infrastructure, not a coincidence.

use crate::tunnel::{
    bytes32, bytes64, parse_user_ref, parse_visibility, read_maybe_sealed,
    recipient_messaging_pubkey, self_identity, user_id_str, write_maybe_sealed,
};
use crate::{now_unix, parse_hash32, parse_reason_code, parse_stance, parse_target, reason_code_str, stance_str, target_value_str};
use anyhow::{bail, Context, Result};
use domain_types::{Hash32, PublicKeyBytes, Reason, SharedRuleEntry, SharedRuleList, Visibility};
use state_store::StateStore;
use std::path::{Path, PathBuf};

// ── entries file (JSON array, one object per rule) ───────────────────────

fn entry_to_json(e: &SharedRuleEntry) -> serde_json::Value {
    serde_json::json!({
        "target_kind": e.target.kind_str(),
        "target_value": target_value_str(&e.target),
        "stance": stance_str(e.stance),
        "reason_code": reason_code_str(e.reason.code),
        "reason_note": e.reason.note,
        "reason_evidence": e.reason.evidence.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
    })
}

fn entry_from_json(json: &serde_json::Value) -> Result<SharedRuleEntry> {
    let get_str = |key: &str| -> Result<&str> { json.get(key).and_then(|v| v.as_str()).with_context(|| format!("missing `{key}`")) };
    let target = parse_target(get_str("target_kind")?, get_str("target_value")?)?;
    let stance = parse_stance(get_str("stance")?)?;
    let reason_code = parse_reason_code(get_str("reason_code")?)?;
    let reason_note = json.get("reason_note").and_then(|v| v.as_str()).map(String::from);
    let reason_evidence: Vec<Hash32> = json
        .get("reason_evidence")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).map(parse_hash32).collect::<Result<Vec<_>>>())
        .transpose()?
        .unwrap_or_default();
    Ok(SharedRuleEntry { target, stance, reason: Reason { code: reason_code, note: reason_note, evidence: reason_evidence } })
}

fn read_entries_file(path: &Path) -> Result<Vec<SharedRuleEntry>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_str(&text)?;
    json.as_array()
        .with_context(|| format!("{} must contain a JSON array of entries", path.display()))?
        .iter()
        .map(entry_from_json)
        .collect()
}

// ── SharedRuleList wire format ────────────────────────────────────────────

fn list_to_json(list: &SharedRuleList, identity_pubkey: &PublicKeyBytes) -> serde_json::Value {
    serde_json::json!({
        "author": user_id_str(&list.author),
        "sequence": list.sequence,
        "name": list.name,
        "description": list.description,
        "categories": list.categories,
        "visibility": if list.visibility == Visibility::Public { "public" } else { "restricted" },
        "identity_pubkey": hex::encode(identity_pubkey.0),
        "entries": list.entries.iter().map(entry_to_json).collect::<Vec<_>>(),
        "issued_at": list.issued_at,
        "expires_at": list.expires_at,
        "supersedes": list.supersedes,
        "signature": hex::encode(list.signature.0),
    })
}

fn list_from_json(json: &serde_json::Value) -> Result<(SharedRuleList, PublicKeyBytes)> {
    let get_str = |key: &str| -> Result<&str> { json.get(key).and_then(|v| v.as_str()).with_context(|| format!("missing `{key}`")) };
    let author = parse_user_ref(get_str("author")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let categories: Vec<String> = json
        .get("categories")
        .and_then(|v| v.as_array())
        .context("missing `categories`")?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let entries: Vec<SharedRuleEntry> = json
        .get("entries")
        .and_then(|v| v.as_array())
        .context("missing `entries`")?
        .iter()
        .map(entry_from_json)
        .collect::<Result<_>>()?;
    let list = SharedRuleList {
        author,
        sequence: json.get("sequence").and_then(|v| v.as_u64()).context("missing `sequence`")?,
        name: get_str("name")?.to_string(),
        description: get_str("description")?.to_string(),
        categories,
        visibility: parse_visibility(get_str("visibility")?)?,
        entries,
        issued_at: json.get("issued_at").and_then(|v| v.as_i64()).context("missing `issued_at`")?,
        expires_at: json.get("expires_at").and_then(|v| v.as_i64()),
        supersedes: json.get("supersedes").and_then(|v| v.as_u64()),
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    Ok((list, identity_pubkey))
}

// ── subcommands ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn publish_list(
    store: &StateStore,
    name: &str,
    description: &str,
    categories: &[String],
    entries_file: &Path,
    visibility: &str,
    recipients: &[String],
    out: Option<PathBuf>,
    out_dir: Option<PathBuf>,
) -> Result<()> {
    let visibility = parse_visibility(visibility)?;
    if visibility == Visibility::Restricted && recipients.is_empty() {
        bail!("--visibility restricted requires at least one --recipient");
    }
    if visibility == Visibility::Public && !recipients.is_empty() {
        bail!("--recipient has no effect with --visibility public — it would be silently ignored");
    }
    let entries = read_entries_file(entries_file)?;
    if entries.is_empty() {
        bail!("{} contains no entries — refusing to publish an empty list", entries_file.display());
    }

    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let sequence = store.next_shared_rule_list_sequence(&author)?;

    let mut list = SharedRuleList {
        author,
        sequence,
        name: name.to_string(),
        description: description.to_string(),
        categories: categories.to_vec(),
        visibility,
        entries,
        issued_at: now_unix(),
        expires_at: None,
        supersedes: None,
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let signing_bytes = list.signing_bytes();
    list.signature = kp.sign(crypto::contexts::SHARED_RULE_LIST, &signing_bytes);

    store.store_own_shared_rule_list(&list)?;
    println!("published list #{sequence} \"{name}\" ({} entries)", list.entries.len());

    let identity_pubkey = kp.public_key();
    let json = list_to_json(&list, &identity_pubkey);
    let plaintext = serde_json::to_vec(&json)?;

    match visibility {
        Visibility::Public => {
            if let Some(path) = out {
                write_maybe_sealed(&plaintext, None, &path)?;
                println!("exported to {}", path.display());
            }
        }
        Visibility::Restricted => {
            let dir = out_dir.context("--visibility restricted requires --out-dir")?;
            std::fs::create_dir_all(&dir)?;
            for r in recipients {
                let recipient_user = parse_user_ref(r)?;
                let recipient_pubkey = recipient_messaging_pubkey(store, &recipient_user)?;
                let path = dir.join(format!("{}.json", r.replace('/', "_")));
                write_maybe_sealed(&plaintext, Some(&recipient_pubkey), &path)?;
                println!("exported (sealed) to {}", path.display());
            }
        }
    }
    Ok(())
}

pub fn ingest_list(store: &StateStore, file: &Path) -> Result<()> {
    let json = read_maybe_sealed(store, file)?;
    let (list, identity_pubkey) = list_from_json(&json)?;
    crypto::verify(&identity_pubkey, crypto::contexts::SHARED_RULE_LIST, &list.signing_bytes(), &list.signature)
        .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.ingest_shared_rule_list(&list)?;
    println!(
        "ingested list #{} \"{}\" from {} ({} entries)",
        list.sequence, list.name, user_id_str(&list.author), list.entries.len()
    );
    Ok(())
}

pub fn list_subscribed_lists(store: &StateStore) -> Result<()> {
    let lists = store.list_shared_rule_lists()?;
    if lists.is_empty() {
        println!("no known shared rule lists");
        return Ok(());
    }
    for list in lists {
        println!("#{} \"{}\" from {}", list.sequence, list.name, user_id_str(&list.author));
        println!("  description : {}", list.description);
        println!("  categories  : {:?}", list.categories);
        println!("  entries     : {}", list.entries.len());
    }
    Ok(())
}

/// Extends `add-follow`'s trust surface: sets (or clears, with
/// `category=None`) `LocalTrustRule.category_filter` for an existing
/// follow — this is the field that finally gets read by `policy-engine`
/// (see `evaluate_trust_weighted`'s list-entries loop), not a new trust
/// dimension of its own. Requires an existing follow (`add-follow` first)
/// rather than silently creating one with default weights, since a
/// category filter without any weights configured would be a confusing
/// half-set-up trust relationship.
pub fn set_follow_category_filter(store: &StateStore, target_user: domain_types::UserId, category: Option<String>) -> Result<()> {
    let mut rule = store.get_follow(&target_user)?.context("not following this user yet — run `add-follow` first")?;
    rule.category_filter = category.clone();
    store.upsert_follow(&rule)?;
    match category {
        Some(c) => println!("category filter for {} set to \"{c}\"", user_id_str(&target_user)),
        None => println!("category filter for {} cleared — every subscribed list from them counts again", user_id_str(&target_user)),
    }
    Ok(())
}
