//! CLI implementation for owner-controlled groups: creation/membership
//! updates, request-and-approve joining, per-target votes whose majority
//! feeds `policy-engine`, group trust weighting, and the sealed
//! group-scoped "party line" broadcast. Reuses `tunnel.rs`'s identity/
//! sealing helpers rather than duplicating them.
//!
//! The outbox retries point-to-point delivery; a durable catch-up protocol
//! for messages missed while a node was offline is the next reliability
//! slice and is intentionally not implemented here.

use crate::tunnel::{
    bytes32, bytes64, maybe_sealed_bytes, needs_file_fallback, parse_user_ref, read_maybe_sealed,
    recipient_messaging_pubkey, self_identity, try_deliver, user_id_str, write_maybe_sealed,
};
use crate::{now_unix, parse_reason_code, parse_stance, parse_target, reason_code_str, stance_str};
use anyhow::{bail, Context, Result};
use domain_types::{
    Group, GroupBlockReport, GroupId, GroupJoinRequest, GroupTrustRule, GroupVote, Hash32,
    PartyLineMessage, PublicKeyBytes, Reason, UserId,
};
use p2p_transport::PeerTransport;
use state_store::StateStore;
use std::path::{Path, PathBuf};

// ── id parsing ───────────────────────────────────────────────────────────

pub(crate) fn parse_group_id(s: &str) -> Result<GroupId> {
    let bytes = hex::decode(s).with_context(|| format!("`{s}` is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("group id must decode to exactly 32 bytes"))?;
    Ok(GroupId(Hash32(arr)))
}

/// Accepts either a canonical group hash or an exact local group name. Names
/// are a convenience for humans only; ambiguous names are rejected so a
/// command can never silently target the wrong group.
pub(crate) fn resolve_group_id(store: &StateStore, value: &str) -> Result<GroupId> {
    if let Ok(group_id) = parse_group_id(value) {
        return Ok(group_id);
    }
    let matches = store
        .list_groups()?
        .into_iter()
        .filter(|group| group.name == value)
        .map(|group| group.group_id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [group_id] => Ok(*group_id),
        [] => bail!("unknown group `{value}` — use its group ID or exact name"),
        _ => bail!("group name `{value}` is ambiguous — use the group ID"),
    }
}

pub(crate) fn group_id_str(id: GroupId) -> String {
    id.0.to_string()
}

pub(crate) fn self_group_id(pubkey: &PublicKeyBytes) -> GroupId {
    GroupId(crypto::hash(
        &[b"sf-self-group-v1".as_slice(), &pubkey.0].concat(),
    ))
}

/// Human-readable age, for display only — never used in any decision.
fn format_age(now: i64, issued_at: i64) -> String {
    let secs = (now - issued_at).max(0);
    let days = secs / 86_400;
    if days == 0 {
        "issued today".to_string()
    } else if days == 1 {
        "issued 1 day ago".to_string()
    } else {
        format!("issued {days} days ago")
    }
}

// ── Group wire format ──────────────────────────────────────────────────────

fn users_to_json(users: &[UserId]) -> serde_json::Value {
    serde_json::Value::Array(
        users
            .iter()
            .map(|u| serde_json::Value::String(user_id_str(u)))
            .collect(),
    )
}

fn users_from_json(json: &serde_json::Value, key: &str) -> Result<Vec<UserId>> {
    json.get(key)
        .and_then(|v| v.as_array())
        .with_context(|| format!("missing `{key}`"))?
        .iter()
        .map(|v| parse_user_ref(v.as_str().context("expected a string user reference")?))
        .collect()
}

fn group_to_json(g: &Group, identity_pubkey: &PublicKeyBytes) -> serde_json::Value {
    serde_json::json!({
        "group_id": group_id_str(g.group_id),
        "published_by": user_id_str(&g.published_by),
        "identity_pubkey": hex::encode(identity_pubkey.0),
        "sequence": g.sequence,
        "name": g.name,
        "description": g.description,
        "join_prompt": g.join_prompt,
        "owners": users_to_json(&g.owners),
        "admins": users_to_json(&g.admins),
        "voting_members": users_to_json(&g.voting_members),
        "non_voting_members": users_to_json(&g.non_voting_members),
        "party_line_moderated": g.party_line_moderated,
        "voiced_members": users_to_json(&g.voiced_members),
        "issued_at": g.issued_at,
        "expires_at": g.expires_at,
        "supersedes": g.supersedes,
        "signature": hex::encode(g.signature.0),
    })
}

fn group_from_json(json: &serde_json::Value) -> Result<(Group, PublicKeyBytes)> {
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let group = Group {
        group_id: parse_group_id(get_str("group_id")?)?,
        published_by: parse_user_ref(get_str("published_by")?)?,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        name: get_str("name")?.to_string(),
        description: get_str("description")?.to_string(),
        join_prompt: json
            .get("join_prompt")
            .and_then(|v| v.as_str())
            .map(String::from),
        owners: users_from_json(json, "owners")?,
        admins: users_from_json(json, "admins")?,
        voting_members: users_from_json(json, "voting_members")?,
        non_voting_members: users_from_json(json, "non_voting_members")?,
        party_line_moderated: json
            .get("party_line_moderated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        voiced_members: json
            .get("voiced_members")
            .map(|_| users_from_json(json, "voiced_members"))
            .transpose()?
            .unwrap_or_default(),
        issued_at: json
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing `issued_at`")?,
        expires_at: json.get("expires_at").and_then(|v| v.as_i64()),
        supersedes: json.get("supersedes").and_then(|v| v.as_u64()),
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    group.validate().map_err(|e| anyhow::anyhow!(e))?;
    Ok((group, identity_pubkey))
}

/// Signs and stores a new group version, from a caller-built `Group`
/// template — shared by every mutation (`create-group`,
/// `approve-group-join`, `set-group-voting-right`,
/// `set-group-join-prompt`, `set-group-party-line-moderation`,
/// `set-group-voice`) so they all go through the exact same signing/auth
/// path (`StateStore::ingest_group` itself enforces "only a current
/// owner/admin may publish the next version, and only an owner may
/// change who the owners are"). Takes a full `Group` rather than one
/// parameter per field — a `Group { some_field: new_value, ..current }`
/// at the call site reads far better than an ever-growing positional
/// argument list every time this type gains a new field, which has
/// already happened three times this session.
fn build_and_store_group(store: &StateStore, mut group: Group) -> Result<(Group, PublicKeyBytes)> {
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    group.published_by = author;
    group.sequence = store.next_group_sequence(group.group_id)?;
    group.issued_at = now_unix();
    group.signature = domain_types::SignatureBytes([0; 64]);
    group.validate().map_err(|e| anyhow::anyhow!(e))?;
    let signing_bytes = group.signing_bytes();
    group.signature = kp.sign(crypto::contexts::GROUP, &signing_bytes);
    store.ingest_group(&group)?;
    Ok((group, kp.public_key()))
}

pub(crate) fn create_self_group(
    store: &StateStore,
    owner: UserId,
    pubkey: &PublicKeyBytes,
) -> Result<()> {
    let template = Group {
        group_id: self_group_id(pubkey),
        published_by: owner,
        sequence: 0,
        name: "self".to_string(),
        description: "your own notification feed - auto-created, for anything with no other group"
            .to_string(),
        join_prompt: None,
        owners: vec![owner],
        admins: vec![],
        voting_members: vec![owner],
        non_voting_members: vec![],
        party_line_moderated: false,
        voiced_members: vec![],
        issued_at: 0,
        expires_at: None,
        supersedes: None,
        signature: domain_types::SignatureBytes([0; 64]),
    };
    build_and_store_group(store, template)?;
    Ok(())
}

fn export_group(
    store: &StateStore,
    group: &Group,
    identity_pubkey: &PublicKeyBytes,
    out: Option<PathBuf>,
) -> Result<()> {
    let plaintext = serde_json::to_vec(&group_to_json(group, identity_pubkey))?;
    let recipients: Vec<UserId> = group
        .owners
        .iter()
        .chain(&group.admins)
        .chain(&group.voting_members)
        .chain(&group.non_voting_members)
        .copied()
        .filter(|u| *u != group.published_by)
        .collect();
    for recipient in &recipients {
        let node_id = store.get_follow(recipient)?.and_then(|f| f.iroh_node_id);
        if let Some(node_id) = node_id {
            store.enqueue_outbox(
                &node_id,
                i64::from(p2p_transport::StatementKind::Group.wire_tag()),
                &plaintext,
                now_unix(),
            )?;
            println!("queued group delivery to {}", user_id_str(recipient));
        } else if needs_file_fallback(
            try_deliver(
                store,
                recipient,
                p2p_transport::StatementKind::Group,
                &plaintext,
            ),
            recipient,
        ) {
            if let Some(path) = &out {
                write_maybe_sealed(&plaintext, None, path)?;
                println!("exported to {}", path.display());
            }
        }
    }
    if recipients.is_empty() {
        if let Some(path) = out {
            write_maybe_sealed(&plaintext, None, &path)?;
            println!("exported to {}", path.display());
        }
    }
    Ok(())
}

// ── subcommands ──────────────────────────────────────────────────────────

pub fn create_group(
    store: &StateStore,
    name: &str,
    description: &str,
    join_prompt: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let (author, _) = self_identity(store)?;
    // A fresh, unpredictable id — never reused, never derived from any
    // single owner's identity so ownership can change hands later
    // without the group changing identity. A throwaway keypair's public
    // key is a convenient source of OS randomness already available here
    // (via the same audited RNG path `init-identity` itself uses),
    // without pulling in a separate randomness dependency just for this.
    let nonce = crypto::Keypair::generate().public_key();
    let group_id = GroupId(crypto::hash(
        &[b"sf-group-v1".as_slice(), &nonce.0].concat(),
    ));

    let template = Group {
        group_id,
        published_by: author,
        sequence: 0,
        name: name.to_string(),
        description: description.to_string(),
        join_prompt,
        owners: vec![author],
        admins: vec![],
        voting_members: vec![author],
        non_voting_members: vec![],
        party_line_moderated: false,
        voiced_members: vec![],
        issued_at: 0,
        expires_at: None,
        supersedes: None,
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let (group, identity_pubkey) = build_and_store_group(store, template)?;
    println!(
        "created group {} (\"{name}\")",
        group_id_str(group.group_id)
    );
    println!("note: you are the sole owner — if you lose your identity, this group can never be updated again. consider adding a co-owner once you have someone you trust.");
    export_group(store, &group, &identity_pubkey, out)
}

pub fn ingest_group(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_group_bytes(store, &bytes)
}

pub(crate) fn ingest_group_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = crate::tunnel::parse_maybe_sealed_bytes(store, bytes)?;
    let (group, identity_pubkey) = group_from_json(&json)?;
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::GROUP,
        &group.signing_bytes(),
        &group.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.ingest_group(&group)?;
    println!(
        "ingested group {} (\"{}\", sequence #{})",
        group_id_str(group.group_id),
        group.name,
        group.sequence
    );
    Ok(())
}

pub fn list_groups(store: &StateStore) -> Result<()> {
    let groups = store.list_groups()?;
    if groups.is_empty() {
        println!("no known groups");
        return Ok(());
    }
    for g in groups {
        println!(
            "\"{}\" [{}] (sequence #{})",
            g.name,
            group_id_str(g.group_id),
            g.sequence
        );
        println!("  description    : {}", g.description);
        if let Some(prompt) = &g.join_prompt {
            println!("  join prompt    : {prompt}");
        }
        println!(
            "  owners         : {}",
            g.owners
                .iter()
                .map(user_id_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
        if g.owners.len() == 1 {
            println!("  ! single point of failure: only one owner, no succession plan — if their identity is lost or compromised, this group can never be updated again. add a co-owner to fix this.");
        }
        if !g.admins.is_empty() {
            println!(
                "  admins         : {}",
                g.admins
                    .iter()
                    .map(user_id_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!(
            "  voting members : {}",
            g.voting_members
                .iter()
                .map(user_id_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
        if !g.non_voting_members.is_empty() {
            println!(
                "  other members  : {}",
                g.non_voting_members
                    .iter()
                    .map(user_id_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!(
            "  party line     : {}",
            if g.party_line_moderated {
                "moderated"
            } else {
                "open"
            }
        );
        if g.party_line_moderated && !g.voiced_members.is_empty() {
            println!(
                "  voiced         : {}",
                g.voiced_members
                    .iter()
                    .map(user_id_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(())
}

/// Requires `--answer` when the group's currently-known `join_prompt` is
/// set (fetched from this router's own local copy of the group — it
/// must already be ingested to request joining it) so a requester can't
/// accidentally submit a request the owner will just leave pending for
/// lack of an answer. Not enforced at ingest/signature level (see
/// `GroupJoinRequest::answer`'s own doc) — this is a CLI-level nudge
/// only, since the group may have gained a prompt since this router last
/// ingested it.
pub fn request_group_join(
    store: &StateStore,
    group_id: &str,
    answer: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = resolve_group_id(store, group_id)?;
    if let Some(group) = store.get_group(group_id)? {
        if let Some(prompt) = &group.join_prompt {
            if answer.is_none() {
                bail!("this group asks: \"{prompt}\" — please provide `--answer`");
            }
        }
    }
    let (requester, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let sequence = store.next_group_join_request_sequence(&requester)?;
    let mut req = GroupJoinRequest {
        requester,
        group_id,
        sequence,
        answer,
        issued_at: now_unix(),
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let signing_bytes = req.signing_bytes();
    req.signature = kp.sign(crypto::contexts::GROUP_JOIN_REQUEST, &signing_bytes);
    store.store_group_join_request(&req)?;
    println!(
        "requested to join group {} (request #{sequence})",
        group_id_str(group_id)
    );

    let json = serde_json::json!({
            "requester": user_id_str(&req.requester),
            "group_id": group_id_str(req.group_id),
            "identity_pubkey": hex::encode(kp.public_key().0),
            "sequence": req.sequence,
            "answer": req.answer,
            "issued_at": req.issued_at,
            "signature": hex::encode(req.signature.0),
    });
    let plaintext = serde_json::to_vec(&json)?;
    let group = store
        .get_group(group_id)?
        .context("unknown group - ingest it first")?;
    let recipients: Vec<UserId> = group
        .owners
        .iter()
        .chain(&group.admins)
        .copied()
        .filter(|u| *u != requester)
        .collect();
    for recipient in recipients {
        if needs_file_fallback(
            try_deliver(
                store,
                &recipient,
                p2p_transport::StatementKind::GroupJoinRequest,
                &plaintext,
            ),
            &recipient,
        ) {
            if let Some(path) = &out {
                write_maybe_sealed(&plaintext, None, path)?;
                println!("exported to {}", path.display());
            }
        }
    }
    if group
        .owners
        .iter()
        .chain(&group.admins)
        .all(|u| *u == requester)
    {
        if let Some(path) = out {
            write_maybe_sealed(&plaintext, None, &path)?;
            println!("exported to {}", path.display());
        }
    }
    Ok(())
}

pub fn ingest_group_join_request(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_group_join_request_bytes(store, &bytes)
}

pub(crate) fn ingest_group_join_request_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = crate::tunnel::parse_maybe_sealed_bytes(store, bytes)?;
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let requester = parse_user_ref(get_str("requester")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let req = GroupJoinRequest {
        requester,
        group_id: parse_group_id(get_str("group_id")?)?,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        answer: json
            .get("answer")
            .and_then(|v| v.as_str())
            .map(String::from),
        issued_at: json
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing `issued_at`")?,
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::GROUP_JOIN_REQUEST,
        &req.signing_bytes(),
        &req.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.store_group_join_request(&req)?;
    println!(
        "ingested join request #{} from {} for group {} (pending review)",
        req.sequence,
        user_id_str(&req.requester),
        group_id_str(req.group_id)
    );
    Ok(())
}

pub fn list_pending_group_joins(store: &StateStore, group_id: &str) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let pending = store.list_pending_group_join_requests(group_id)?;
    if pending.is_empty() {
        println!("no pending join requests for {}", group_id_str(group_id));
        return Ok(());
    }
    for r in pending {
        println!(
            "#{} from {}{}",
            r.sequence,
            user_id_str(&r.requester),
            r.answer.map(|a| format!(": {a}")).unwrap_or_default()
        );
    }
    Ok(())
}

/// Tallies every join-request decision this router has recorded for a
/// group — see `StateStore::group_join_track_record`'s own doc on why
/// this is most meaningful run from the owner's own router (a self-audit
/// of admission quality) rather than as something a prospective member
/// on a different router can currently query remotely.
pub fn group_join_track_record(store: &StateStore, group_id: &str) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let record = store.group_join_track_record(group_id)?;
    println!("join-request track record for {}:", group_id_str(group_id));
    println!("  approved : {}", record.approved);
    println!("  rejected : {}", record.rejected);
    println!("  blocked  : {}", record.blocked);
    println!("  pending  : {}", record.pending);
    Ok(())
}

/// Approves a pending join request: republishes the group with the
/// requester added (to `voting_members` if `--voting`, otherwise
/// `non_voting_members` — the owner-controlled "voting is optional"
/// choice), then marks the request approved. Requires *this* router's
/// identity to already be an owner/admin of the current version —
/// enforced by `StateStore::ingest_group` itself, not re-checked here.
pub fn approve_group_join(
    store: &StateStore,
    group_id: &str,
    requester: &str,
    sequence: u64,
    voting: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let requester_user = parse_user_ref(requester)?;
    let current = store
        .get_group(group_id)?
        .context("unknown group — ingest it first")?;

    let mut voting_members = current.voting_members.clone();
    let mut non_voting_members = current.non_voting_members.clone();
    if voting {
        if !voting_members.contains(&requester_user) {
            voting_members.push(requester_user);
        }
        non_voting_members.retain(|u| *u != requester_user);
    } else {
        if !non_voting_members.contains(&requester_user) {
            non_voting_members.push(requester_user);
        }
        voting_members.retain(|u| *u != requester_user);
    }

    let template = Group {
        voting_members,
        non_voting_members,
        supersedes: Some(current.sequence),
        ..current
    };
    let (group, identity_pubkey) = build_and_store_group(store, template)?;
    store.set_group_join_request_status(&requester_user, sequence, "approved")?;
    println!(
        "approved {} to join {} ({})",
        user_id_str(&requester_user),
        group_id_str(group_id),
        if voting {
            "voting member"
        } else {
            "non-voting member"
        }
    );
    export_group(store, &group, &identity_pubkey, out)
}

/// Denies one specific pending request without any lasting consequence —
/// the requester is free to submit a new request later. See
/// `block_group_user` for the permanent alternative.
pub fn reject_group_join(store: &StateStore, requester: &str, sequence: u64) -> Result<()> {
    let requester_user = parse_user_ref(requester)?;
    store.set_group_join_request_status(&requester_user, sequence, "rejected")?;
    println!(
        "rejected join request #{sequence} from {}",
        user_id_str(&requester_user)
    );
    Ok(())
}

/// Permanently blocks a user from a group — requires a reason (a block
/// with no reason is just an opaque veto, not evidence). Does two
/// things: applies purely local enforcement (see
/// `StateStore::block_group_user`'s own doc — any currently pending
/// request from them is immediately marked blocked too, and any future
/// request auto-lands as blocked rather than pending), and builds+signs
/// a `GroupBlockReport` under this router's own identity, storing it
/// locally and optionally exporting it via `--out` so the group's
/// owner (or anyone else) can `ingest-group-block-report` it — the
/// "surfaced, not silent" half. Ingesting someone *else's* report never
/// has this local-enforcement effect; only a router's own
/// self-authored block does.
pub fn block_group_user(
    store: &StateStore,
    group_id: &str,
    user: &str,
    reason_code: &str,
    note: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let blocked_user = parse_user_ref(user)?;
    let reason = Reason {
        code: parse_reason_code(reason_code)?,
        note,
        evidence: vec![],
    };
    let (reporter, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let sequence = store.next_group_block_report_sequence(group_id, &reporter)?;

    let mut report = GroupBlockReport {
        group_id,
        reporter,
        sequence,
        blocked_user,
        reason: reason.clone(),
        issued_at: now_unix(),
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let signing_bytes = report.signing_bytes();
    report.signature = kp.sign(crypto::contexts::GROUP_BLOCK_REPORT, &signing_bytes);
    store.store_group_block_report(&report)?;
    store.block_group_user(group_id, &blocked_user, &reason, now_unix())?;
    println!(
        "blocked {} from group {} ({})",
        user_id_str(&blocked_user),
        group_id_str(group_id),
        reason_code_str(reason.code)
    );

    if let Some(path) = out {
        let json = serde_json::json!({
            "group_id": group_id_str(report.group_id),
            "reporter": user_id_str(&report.reporter),
            "identity_pubkey": hex::encode(kp.public_key().0),
            "sequence": report.sequence,
            "blocked_user": user_id_str(&report.blocked_user),
            "reason_code": reason_code_str(report.reason.code),
            "reason_note": report.reason.note,
            "issued_at": report.issued_at,
            "signature": hex::encode(report.signature.0),
        });
        write_maybe_sealed(&serde_json::to_vec(&json)?, None, &path)?;
        println!(
            "exported to {} — hand this to the group's owner",
            path.display()
        );
    }
    Ok(())
}

/// Ingests a block report exported by `block-group-user --out`. Always
/// purely informational — storing this never causes *this* router to
/// enforce anything locally (no automatic global ban); it only makes the
/// report visible via `list-group-block-reports` / rolled up into
/// `explain-group-vote`.
pub fn ingest_group_block_report(store: &StateStore, file: &Path) -> Result<()> {
    let json = read_maybe_sealed(store, file)?;
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let reporter = parse_user_ref(get_str("reporter")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let report = GroupBlockReport {
        group_id: parse_group_id(get_str("group_id")?)?,
        reporter,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        blocked_user: parse_user_ref(get_str("blocked_user")?)?,
        reason: Reason {
            code: parse_reason_code(get_str("reason_code")?)?,
            note: json
                .get("reason_note")
                .and_then(|v| v.as_str())
                .map(String::from),
            evidence: vec![],
        },
        issued_at: json
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing `issued_at`")?,
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::GROUP_BLOCK_REPORT,
        &report.signing_bytes(),
        &report.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.store_group_block_report(&report)?;
    println!(
        "ingested block report: {} reports {} blocked from group {} ({})",
        user_id_str(&report.reporter),
        user_id_str(&report.blocked_user),
        group_id_str(report.group_id),
        reason_code_str(report.reason.code)
    );
    Ok(())
}

/// Every known report against a user in a group — from any reporter,
/// including this router's own — the "surfaced to the owner" view: how
/// many independent routers have reported this user, and why.
pub fn list_group_block_reports(store: &StateStore, group_id: &str, user: &str) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let user = parse_user_ref(user)?;
    let reports = store.list_group_block_reports_for(group_id, &user)?;
    if reports.is_empty() {
        println!(
            "no block reports against {} in group {}",
            user_id_str(&user),
            group_id_str(group_id)
        );
        return Ok(());
    }
    for r in reports {
        println!(
            "reported by {}: {}{}",
            user_id_str(&r.reporter),
            reason_code_str(r.reason.code),
            r.reason.note.map(|n| format!(" — {n}")).unwrap_or_default()
        );
    }
    Ok(())
}

pub fn unblock_group_user(store: &StateStore, group_id: &str, user: &str) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let user = parse_user_ref(user)?;
    store.unblock_group_user(group_id, &user)?;
    println!(
        "unblocked {} from group {}",
        user_id_str(&user),
        group_id_str(group_id)
    );
    Ok(())
}

pub fn list_blocked_group_users(store: &StateStore, group_id: &str) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let blocked = store.list_blocked_group_users(group_id)?;
    if blocked.is_empty() {
        println!("no blocked users for group {}", group_id_str(group_id));
        return Ok(());
    }
    for (u, reason) in blocked {
        println!(
            "{}: {}{}",
            user_id_str(&u),
            reason_code_str(reason.code),
            reason.note.map(|n| format!(" — {n}")).unwrap_or_default()
        );
    }
    Ok(())
}

/// Republishes the group with a new (or cleared) join prompt, otherwise
/// unchanged — an owner/admin-only action, enforced by
/// `StateStore::ingest_group` the same way every other group update is.
pub fn set_group_join_prompt(
    store: &StateStore,
    group_id: &str,
    join_prompt: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let current = store
        .get_group(group_id)?
        .context("unknown group — ingest it first")?;
    let template = Group {
        join_prompt,
        supersedes: Some(current.sequence),
        ..current
    };
    let (group, identity_pubkey) = build_and_store_group(store, template)?;
    match &group.join_prompt {
        Some(prompt) => println!(
            "join prompt for {} set to: {prompt}",
            group_id_str(group_id)
        ),
        None => println!("join prompt for {} cleared", group_id_str(group_id)),
    }
    export_group(store, &group, &identity_pubkey, out)
}

/// Republishes the group's description, which is displayed as its party-line
/// topic. This keeps the existing signed group snapshot format while giving
/// the chat window an IRC-style topic that all members see consistently.
pub fn set_group_topic(
    store: &StateStore,
    group_id: &str,
    topic: String,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = resolve_group_id(store, group_id)?;
    let current = store
        .get_group(group_id)?
        .context("unknown group — ingest it first")?;
    let template = Group {
        description: topic,
        supersedes: Some(current.sequence),
        ..current
    };
    let (group, identity_pubkey) = build_and_store_group(store, template)?;
    println!("topic for \"{}\" set to: {}", group.name, group.description);
    export_group(store, &group, &identity_pubkey, out)
}

/// Toggles the party line between open (any current member may post,
/// the default) and moderated (only owners/admins and explicitly voiced
/// members may post) — the IRC `+m`/`-m` analogue. Owner/admin-only,
/// enforced by `StateStore::ingest_group` the same way every other group
/// update is.
pub fn set_group_party_line_moderation(
    store: &StateStore,
    group_id: &str,
    moderated: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let current = store
        .get_group(group_id)?
        .context("unknown group — ingest it first")?;
    let template = Group {
        party_line_moderated: moderated,
        supersedes: Some(current.sequence),
        ..current
    };
    let (group, identity_pubkey) = build_and_store_group(store, template)?;
    println!(
        "party line for {} is now {}",
        group_id_str(group_id),
        if moderated { "moderated" } else { "open" }
    );
    export_group(store, &group, &identity_pubkey, out)
}

/// Grants or revokes a member's voice (the IRC `+v`/`-v` analogue) —
/// only meaningful while the party line is moderated, but settable
/// either way so an owner/admin can prepare a voice list before flipping
/// moderation on. Owner/admin-only, same enforcement as every other
/// group update.
pub fn set_group_voice(
    store: &StateStore,
    group_id: &str,
    user: &str,
    voiced: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let target_user = parse_user_ref(user)?;
    let current = store
        .get_group(group_id)?
        .context("unknown group — ingest it first")?;
    let mut voiced_members = current.voiced_members.clone();
    if voiced {
        if !voiced_members.contains(&target_user) {
            voiced_members.push(target_user);
        }
    } else {
        voiced_members.retain(|u| *u != target_user);
    }
    let template = Group {
        voiced_members,
        supersedes: Some(current.sequence),
        ..current
    };
    let (group, identity_pubkey) = build_and_store_group(store, template)?;
    println!(
        "{} {} voice in {}",
        user_id_str(&target_user),
        if voiced { "now has" } else { "no longer has" },
        group_id_str(group_id)
    );
    export_group(store, &group, &identity_pubkey, out)
}

/// Moves an existing member between `voting_members`/`non_voting_members`
/// without touching owners/admins — the "owner can choose which members
/// can vote, optionally" dial, usable any time after a member's already
/// joined, not just at approval time.
pub fn set_group_voting_right(
    store: &StateStore,
    group_id: &str,
    user: &str,
    voting: bool,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let target_user = parse_user_ref(user)?;
    let current = store
        .get_group(group_id)?
        .context("unknown group — ingest it first")?;
    if !current.voting_members.contains(&target_user)
        && !current.non_voting_members.contains(&target_user)
    {
        bail!(
            "{} isn't a member of this group yet — approve a join request first",
            user_id_str(&target_user)
        );
    }

    let mut voting_members = current.voting_members.clone();
    let mut non_voting_members = current.non_voting_members.clone();
    if voting {
        if !voting_members.contains(&target_user) {
            voting_members.push(target_user);
        }
        non_voting_members.retain(|u| *u != target_user);
    } else {
        if !non_voting_members.contains(&target_user) {
            non_voting_members.push(target_user);
        }
        voting_members.retain(|u| *u != target_user);
    }

    let template = Group {
        voting_members,
        non_voting_members,
        supersedes: Some(current.sequence),
        ..current
    };
    let (group, identity_pubkey) = build_and_store_group(store, template)?;
    println!(
        "{} is now a {}",
        user_id_str(&target_user),
        if voting {
            "voting member"
        } else {
            "non-voting member"
        }
    );
    export_group(store, &group, &identity_pubkey, out)
}

/// `ttl_seconds` gives the vote a lifespan — an aging vote counts exactly
/// as much as a fresh one in `group_stance_for`'s tally (no automatic
/// decay; changing that would be an aggregation-algorithm change, not a
/// visibility fix), so an explicit TTL is the only way a voter can make
/// their own stance stop counting without the owner having to remove
/// them. `None` (the default, matching every previous release of this
/// command) means the vote never expires on its own.
#[allow(clippy::too_many_arguments)]
pub fn cast_group_vote(
    store: &StateStore,
    group_id: &str,
    target_kind: &str,
    target_value: &str,
    stance: &str,
    reason_code: &str,
    note: Option<String>,
    ttl_seconds: Option<i64>,
    out: Option<PathBuf>,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let (voter, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let target = parse_target(target_kind, target_value)?;
    let sequence = store.next_group_vote_sequence(group_id, &voter)?;
    let now = now_unix();

    let mut vote = GroupVote {
        group_id,
        voter,
        sequence,
        target,
        stance: parse_stance(stance)?,
        reason: Reason {
            code: parse_reason_code(reason_code)?,
            note,
            evidence: vec![],
        },
        issued_at: now,
        expires_at: ttl_seconds.map(|s| now + s),
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let signing_bytes = vote.signing_bytes();
    vote.signature = kp.sign(crypto::contexts::GROUP_VOTE, &signing_bytes);
    store.store_group_vote(&vote)?;
    println!(
        "cast vote #{sequence} for group {}: {target_kind} {target_value} -> {:?}",
        group_id_str(group_id),
        vote.stance
    );

    if let Some(path) = out {
        let json = serde_json::json!({
            "group_id": group_id_str(vote.group_id),
            "voter": user_id_str(&vote.voter),
            "identity_pubkey": hex::encode(kp.public_key().0),
            "sequence": vote.sequence,
            "target_kind": target_kind,
            "target_value": target_value,
            "stance": stance_str(vote.stance),
            "reason_code": reason_code_str(vote.reason.code),
            "reason_note": vote.reason.note,
            "issued_at": vote.issued_at,
            "expires_at": vote.expires_at,
            "signature": hex::encode(vote.signature.0),
        });
        write_maybe_sealed(&serde_json::to_vec(&json)?, None, &path)?;
        println!("exported to {}", path.display());
    }
    Ok(())
}

pub fn ingest_group_vote(store: &StateStore, file: &Path) -> Result<()> {
    let json = read_maybe_sealed(store, file)?;
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let voter = parse_user_ref(get_str("voter")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let vote = GroupVote {
        group_id: parse_group_id(get_str("group_id")?)?,
        voter,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        target: parse_target(get_str("target_kind")?, get_str("target_value")?)?,
        stance: parse_stance(get_str("stance")?)?,
        reason: Reason {
            code: parse_reason_code(get_str("reason_code")?)?,
            note: json
                .get("reason_note")
                .and_then(|v| v.as_str())
                .map(String::from),
            evidence: vec![],
        },
        issued_at: json
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing `issued_at`")?,
        expires_at: json.get("expires_at").and_then(|v| v.as_i64()),
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::GROUP_VOTE,
        &vote.signing_bytes(),
        &vote.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.store_group_vote(&vote)?;
    println!(
        "ingested vote #{} from {} for group {}",
        vote.sequence,
        user_id_str(&vote.voter),
        group_id_str(vote.group_id)
    );
    Ok(())
}

pub fn set_group_trust(
    store: &StateStore,
    group_id: &str,
    allow_weight: f64,
    deny_weight: f64,
    exclude: bool,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    store.upsert_group_trust_rule(&GroupTrustRule {
        group_id,
        allow_weight,
        deny_weight,
        excluded: exclude,
        expires_at: None,
        created_at: now_unix(),
    })?;
    println!("group trust set for {}", group_id_str(group_id));
    Ok(())
}

pub fn publish_party_line(
    store: &StateStore,
    group_id: &str,
    body: &str,
    in_reply_to: Option<(String, String)>,
    out_dir: &Path,
) -> Result<()> {
    let group_id = resolve_group_id(store, group_id)?;
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let in_reply_to = in_reply_to
        .map(|(kind, value)| parse_target(&kind, &value))
        .transpose()?;
    let msg = build_and_store_party_line_message(store, group_id, body, in_reply_to)?;
    let group = store
        .get_group(group_id)?
        .context("unknown group - ingest it first")?;
    println!(
        "published party-line message #{} to group \"{}\" [{}]",
        msg.sequence,
        group.name,
        group_id_str(group_id)
    );

    let (in_reply_to_target_kind, in_reply_to_target_value) = match &msg.in_reply_to {
        Some(t) => {
            let (k, v) = target_to_kind_value(t)?;
            (Some(k), Some(v))
        }
        None => (None, None),
    };
    let plaintext = serde_json::to_vec(&serde_json::json!({
        "group_id": group_id_str(msg.group_id),
        "author": user_id_str(&msg.author),
        "identity_pubkey": hex::encode(kp.public_key().0),
        "sequence": msg.sequence,
        "body": msg.body,
        "in_reply_to_target_kind": in_reply_to_target_kind,
        "in_reply_to_target_value": in_reply_to_target_value,
        "issued_at": msg.issued_at,
        "signature": hex::encode(msg.signature.0),
    }))?;

    std::fs::create_dir_all(out_dir)?;
    // Fan out to every *current* member (owners/admins/voting/non-voting
    // alike) — membership is a point-in-time snapshot, same as
    // `Restricted`'s explicit recipient list already is elsewhere.
    let all_members: Vec<UserId> = group
        .owners
        .iter()
        .chain(&group.admins)
        .chain(&group.voting_members)
        .chain(&group.non_voting_members)
        .copied()
        .filter(|u| *u != author)
        .collect();
    let mut skipped = 0;
    for member in all_members {
        match recipient_messaging_pubkey(store, &member) {
            Ok(pubkey) => {
                let path = out_dir.join(format!("{}.json", user_id_str(&member).replace('/', "_")));
                let payload = maybe_sealed_bytes(&plaintext, Some(&pubkey))?;
                let node_id = store.get_follow(&member)?.and_then(|f| f.iroh_node_id);
                if let Some(node_id) = node_id {
                    store.enqueue_outbox(
                        &node_id,
                        i64::from(p2p_transport::StatementKind::PartyLineMessage.wire_tag()),
                        &payload,
                        now_unix(),
                    )?;
                    println!("queued party-line delivery to {}", user_id_str(&member));
                } else if needs_file_fallback(
                    try_deliver(
                        store,
                        &member,
                        p2p_transport::StatementKind::PartyLineMessage,
                        &payload,
                    ),
                    &member,
                ) {
                    write_maybe_sealed(&plaintext, Some(&pubkey), &path)?;
                    println!("exported (sealed) to {}", path.display());
                }
            }
            Err(_) => {
                skipped += 1;
            }
        }
    }
    if skipped > 0 {
        println!("skipped {skipped} member(s) with no known messaging pubkey yet");
    }
    Ok(())
}

pub fn sync_outbox(store: &StateStore) -> Result<()> {
    let due = store.list_due_outbox(now_unix())?;
    let mut delivered = 0;
    for item in due {
        let kind = match item.statement_kind {
            4 => p2p_transport::StatementKind::Group,
            5 => p2p_transport::StatementKind::PartyLineMessage,
            _ => continue,
        };
        match crate::tunnel::deliver_to_node(store, &item.destination_node_id, kind, &item.payload)
        {
            Ok(()) => {
                store.mark_outbox_success(item.id)?;
                delivered += 1;
            }
            Err(e) => store.mark_outbox_failure(item.id, &e.to_string(), now_unix())?,
        }
    }
    println!("sync: {delivered} outbox message(s) delivered");
    Ok(())
}

const GROUP_SYNC_BATCH: usize = 64;

fn party_line_json(msg: &PartyLineMessage, pubkey: &PublicKeyBytes) -> serde_json::Value {
    let (kind, value) = match &msg.in_reply_to {
        Some(target) => target_to_kind_value(target)
            .map(|(k, v)| (Some(k), Some(v)))
            .unwrap_or((None, None)),
        None => (None, None),
    };
    serde_json::json!({
        "group_id": group_id_str(msg.group_id), "author": user_id_str(&msg.author),
        "identity_pubkey": hex::encode(pubkey.0), "sequence": msg.sequence,
        "body": msg.body, "in_reply_to_target_kind": kind,
        "in_reply_to_target_value": value, "issued_at": msg.issued_at,
        "signature": hex::encode(msg.signature.0)
    })
}

fn sync_group_response(
    store: &StateStore,
    group_id: GroupId,
    inventory: &std::collections::HashMap<UserId, u64>,
) -> Result<p2p_transport::Envelope> {
    let mut messages = Vec::new();
    for msg in store.list_party_line_messages(group_id)? {
        if msg.sequence < inventory.get(&msg.author).copied().unwrap_or(0)
            || messages.len() >= GROUP_SYNC_BATCH
        {
            continue;
        }
        if let Some(pubkey) = store.party_line_message_author_pubkey(&msg)? {
            messages.push(party_line_json(&msg, &pubkey));
        }
    }
    let has_more = messages.len() == GROUP_SYNC_BATCH;
    Ok(p2p_transport::Envelope {
        kind: p2p_transport::StatementKind::SyncGroupResponse,
        payload: serde_json::to_vec(&serde_json::json!({
            "version": 1, "group_id": group_id_str(group_id), "has_more": has_more,
            "messages": messages
        }))?,
    })
}

pub(crate) fn handle_sync_group_request(
    store: &StateStore,
    requester: UserId,
    _from_node: &str,
    payload: &[u8],
) -> Result<p2p_transport::Envelope> {
    let json: serde_json::Value =
        serde_json::from_slice(payload).context("invalid group sync request")?;
    let group_id = parse_group_id(
        json.get("group_id")
            .and_then(|v| v.as_str())
            .context("missing group_id")?,
    )?;
    let group = store.get_group(group_id)?.context("unknown group")?;
    let is_member = group.owners.contains(&requester)
        || group.admins.contains(&requester)
        || group.voting_members.contains(&requester)
        || group.non_voting_members.contains(&requester);
    if !is_member {
        bail!("sync requester is not a member of this group");
    }
    let mut inventory = std::collections::HashMap::new();
    for item in json
        .get("inventory")
        .and_then(|v| v.as_array())
        .context("missing inventory")?
    {
        let author = parse_user_ref(
            item.get("author")
                .and_then(|v| v.as_str())
                .context("missing inventory author")?,
        )?;
        let next = item
            .get("next_sequence")
            .and_then(|v| v.as_u64())
            .context("missing inventory cursor")?;
        inventory.insert(author, next);
    }
    sync_group_response(store, group_id, &inventory)
}

pub(crate) fn ingest_sync_group_response(
    store: &StateStore,
    payload: &[u8],
) -> Result<(GroupId, bool, usize)> {
    let json: serde_json::Value =
        serde_json::from_slice(payload).context("invalid group sync response")?;
    let group_id = parse_group_id(
        json.get("group_id")
            .and_then(|v| v.as_str())
            .context("missing group_id")?,
    )?;
    let mut count = 0;
    for message in json
        .get("messages")
        .and_then(|v| v.as_array())
        .context("missing messages")?
    {
        ingest_party_line_json(store, message)?;
        count += 1;
    }
    Ok((
        group_id,
        json.get("has_more")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        count,
    ))
}

pub fn sync_group(store: &StateStore, group_id: &str) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let group = store
        .get_group(group_id)?
        .context("unknown group — ingest it first")?;
    let self_user = self_identity(store)?.0;
    let members = group
        .owners
        .iter()
        .chain(&group.admins)
        .chain(&group.voting_members)
        .chain(&group.non_voting_members)
        .copied()
        .filter(|user| *user != self_user)
        .collect::<Vec<_>>();
    let seed = store
        .get_iroh_keypair_seed()?
        .context("no local Iroh keypair yet — run `sf listen` once")?;
    let transport = p2p_transport::IrohTransport::new(seed, b"social-firewall/1")
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let mut imported = 0;
    for member in members {
        let Some(node_id) = store.get_follow(&member)?.and_then(|f| f.iroh_node_id) else {
            continue;
        };
        loop {
            let mut inventory = Vec::new();
            for msg in store.list_party_line_messages(group_id)? {
                if !inventory.iter().any(|(author, _)| *author == msg.author) {
                    inventory.push((msg.author, 0));
                }
                if let Some(entry) = inventory
                    .iter_mut()
                    .find(|(author, _)| *author == msg.author)
                {
                    entry.1 = entry.1.max(msg.sequence + 1);
                }
            }
            let request = serde_json::json!({"version": 1, "group_id": group_id_str(group_id), "inventory": inventory.iter().map(|(author, next)| serde_json::json!({"author": user_id_str(author), "next_sequence": next})).collect::<Vec<_>>() });
            let response = transport
                .request(
                    &node_id,
                    &p2p_transport::Envelope {
                        kind: p2p_transport::StatementKind::SyncGroupRequest,
                        payload: serde_json::to_vec(&request)?,
                    },
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            if response.kind != p2p_transport::StatementKind::SyncGroupResponse {
                bail!("peer returned the wrong group sync response kind")
            }
            let (_, has_more, count) = ingest_sync_group_response(store, &response.payload)?;
            imported += count;
            if !has_more || count == 0 {
                break;
            }
        }
    }
    println!("sync-group: imported {imported} party-line message(s)");
    Ok(())
}

fn build_and_store_party_line_message(
    store: &StateStore,
    group_id: GroupId,
    body: &str,
    in_reply_to: Option<domain_types::TargetSelector>,
) -> Result<PartyLineMessage> {
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let group = store
        .get_group(group_id)?
        .context("unknown group - ingest it first")?;
    if !group.can_post_party_line(&author) {
        bail!("you don't currently have posting rights on this group's party line (not a member, or the channel is moderated and you're not voiced)");
    }
    let sequence = store.next_party_line_sequence(group_id, &author)?;
    let mut msg = PartyLineMessage {
        group_id,
        author,
        sequence,
        body: body.to_string(),
        in_reply_to,
        issued_at: now_unix(),
        signature: domain_types::SignatureBytes([0; 64]),
    };
    msg.signature = kp.sign(crypto::contexts::PARTY_LINE_MESSAGE, &msg.signing_bytes());
    store.store_party_line_message_with_pubkey(&msg, Some(&kp.public_key()))?;
    Ok(msg)
}

pub(crate) fn post_notification(store: &StateStore, group_id: GroupId, body: &str) -> Result<()> {
    let msg = build_and_store_party_line_message(store, group_id, body, None)?;
    println!("notified group {}: {}", group_id_str(msg.group_id), body);
    Ok(())
}

pub fn ingest_party_line(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_party_line_bytes(store, &bytes)
}

pub(crate) fn ingest_party_line_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = crate::tunnel::parse_maybe_sealed_bytes(store, bytes)?;
    ingest_party_line_json(store, &json)
}

fn ingest_party_line_json(store: &StateStore, json: &serde_json::Value) -> Result<()> {
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let author = parse_user_ref(get_str("author")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let in_reply_to = match (
        json.get("in_reply_to_target_kind").and_then(|v| v.as_str()),
        json.get("in_reply_to_target_value")
            .and_then(|v| v.as_str()),
    ) {
        (Some(kind), Some(value)) => Some(parse_target(kind, value)?),
        _ => None,
    };
    let msg = PartyLineMessage {
        group_id: parse_group_id(get_str("group_id")?)?,
        author,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        body: get_str("body")?.to_string(),
        in_reply_to,
        issued_at: json
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing `issued_at`")?,
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    let group = store
        .get_group(msg.group_id)?
        .context("unknown group — refusing a party-line message")?;
    let is_member = group.owners.contains(&msg.author)
        || group.admins.contains(&msg.author)
        || group.voting_members.contains(&msg.author)
        || group.non_voting_members.contains(&msg.author);
    if !is_member {
        bail!("party-line author is not a current group member — refusing to ingest");
    }
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::PARTY_LINE_MESSAGE,
        &msg.signing_bytes(),
        &msg.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.store_party_line_message_with_pubkey(&msg, Some(&identity_pubkey))?;
    println!(
        "ingested party-line message #{} from {} for group {}",
        msg.sequence,
        user_id_str(&msg.author),
        group_id_str(msg.group_id)
    );
    Ok(())
}

/// The per-voter breakdown behind a group's aggregate stance — an audit
/// view only, never consumed by policy-engine. Lets an owner or any
/// reviewer see who actually voted which way (and whether an expired
/// vote is quietly not counting), the input needed to decide whether an
/// owner should be trusted less personally for admitting careless or
/// bad-faith voters — see `StateStore::group_vote_breakdown_for`'s own
/// doc.
pub fn explain_group_vote(
    store: &StateStore,
    group_id: &str,
    target_kind: &str,
    target_value: &str,
) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let target = parse_target(target_kind, target_value)?;
    let now = now_unix();
    let breakdown = store.group_vote_breakdown_for(group_id, &target, now)?;
    if breakdown.is_empty() {
        println!(
            "unknown group, or no voting members: {}",
            group_id_str(group_id)
        );
        return Ok(());
    }
    println!(
        "vote breakdown for {} on {target_kind} {target_value}:",
        group_id_str(group_id)
    );
    for (voter, vote, counts) in breakdown {
        match vote {
            Some(v) => {
                let status = if counts {
                    "counts"
                } else {
                    "expired, does not count"
                };
                let note = v.reason.note.map(|n| format!(": {n}")).unwrap_or_default();
                // Age is shown purely for the reviewer's judgment —
                // `group_stance_for` itself never treats an old vote
                // differently from a fresh one unless the voter set an
                // explicit `--ttl-seconds` at cast time (see
                // `cast-group-vote`'s own doc on why this is a
                // visibility fix, not an aggregation change).
                println!(
                    "  {} : {:?} ({status}) — {} ({}){note}",
                    user_id_str(&voter),
                    v.stance,
                    reason_code_str(v.reason.code),
                    format_age(now, v.issued_at)
                );
            }
            None => println!("  {} : no vote cast", user_id_str(&voter)),
        }
        // Roll up any block reports against this voter, from any
        // reporter — a voter independently reported by several unrelated
        // routers is exactly the signal an owner needs when deciding
        // whether to keep trusting this group's curation.
        let reports = store.list_group_block_reports_for(group_id, &voter)?;
        if !reports.is_empty() {
            println!(
                "      reported blocked by {} router(s): {}",
                reports.len(),
                reports
                    .iter()
                    .map(|r| reason_code_str(r.reason.code))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(())
}

/// Formats a user the way real IRC/mIRC shows a join/part line: `nick
/// (ident@host)`. `ident` is the peer's `local_id`, truncated to 8 hex
/// chars for display only — never used for lookup or auth. `host` is the
/// peer's federation's own display name if known (see
/// `StateStore::get_federation_display_name`'s own doc on why that's
/// usually only set for this router's home federation — a foreign peer's
/// federation falls back to `<hex>.fed`). `nick` is this router's own
/// address-book label for the user (the follow's `display_name`) if one
/// has been set, else the same truncated ident — matching how real IRC
/// shows an unresolved ident (`Guest1234 (Guest1234@host)`).
/// Just the `nick` portion of `irc_identity` — follow display_name if
/// set, else the same truncated-local_id fallback. Used where the full
/// `nick (ident@host)` triple would be noisy (e.g. a poll's per-stance
/// voter list).
fn nick_only(store: &StateStore, user: &UserId) -> Result<String> {
    let ident = &user.local_id.to_string()[..8];
    Ok(store
        .get_follow(user)?
        .and_then(|f| f.display_name)
        .or(store.get_user_display_name(user)?)
        .unwrap_or_else(|| ident.to_string()))
}

pub(crate) fn irc_identity(store: &StateStore, user: &UserId) -> Result<String> {
    let ident = &user.local_id.to_string()[..8];
    let host = store
        .get_federation_display_name(&user.federation)?
        .unwrap_or_else(|| format!("{}.fed", &user.federation.0.to_string()[..8]));
    let nick = nick_only(store, user)?;
    Ok(format!("{nick} ({ident}@{host})"))
}

/// A compact "poll" summary of a target's current vote breakdown —
/// reuses `group_vote_breakdown_for` (already tracks every current
/// voting member's latest, non-expired vote) rather than any new
/// aggregation logic. An expired or never-cast vote both fold into "no
/// vote" here — this is the *live* tally, not a full audit; use
/// `explain-group-vote` for the distinction between the two.
fn format_poll(
    store: &StateStore,
    group_id: GroupId,
    target: &domain_types::TargetSelector,
    now: i64,
) -> Result<String> {
    let breakdown = store.group_vote_breakdown_for(group_id, target, now)?;
    let mut by_stance: std::collections::BTreeMap<&'static str, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut no_vote: Vec<String> = Vec::new();
    for (voter, vote, counts) in &breakdown {
        let nick = nick_only(store, voter)?;
        match vote {
            Some(v) if *counts => by_stance
                .entry(stance_str(v.stance))
                .or_default()
                .push(nick),
            _ => no_vote.push(nick),
        }
    }
    let mut parts: Vec<String> = by_stance
        .into_iter()
        .map(|(stance, nicks)| format!("{stance} {} ({})", nicks.len(), nicks.join(", ")))
        .collect();
    if !no_vote.is_empty() {
        parts.push(format!("no vote: {}", no_vote.join(", ")));
    }
    Ok(format!("poll: {}", parts.join(" | ")))
}

/// Mirrors `state-store`'s own private `target_to_kv` exactly (including
/// rejecting `ProtoPort`, which isn't persistable in this kind/value
/// shape anywhere in this crate) — needed here purely to build the JSON
/// export for `in_reply_to`, since that conversion isn't exposed publicly.
fn target_to_kind_value(t: &domain_types::TargetSelector) -> Result<(String, String)> {
    use domain_types::TargetSelector;
    match t {
        TargetSelector::Domain(s) => Ok(("domain".to_string(), s.clone())),
        TargetSelector::DomainSuffix(s) => Ok(("domain_suffix".to_string(), s.clone())),
        TargetSelector::Ip(s) => Ok(("ip".to_string(), s.clone())),
        TargetSelector::Cidr(s) => Ok(("cidr".to_string(), s.clone())),
        TargetSelector::Service(s) => Ok(("service".to_string(), s.clone())),
        TargetSelector::ProtoPort { .. } => {
            bail!("a proto/port target cannot be used as a party-line reply target")
        }
    }
}

fn target_str(t: &domain_types::TargetSelector) -> String {
    use domain_types::TargetSelector;
    match t {
        TargetSelector::Domain(s) => format!("domain:{s}"),
        TargetSelector::DomainSuffix(s) => format!("domain_suffix:{s}"),
        TargetSelector::Ip(s) => format!("ip:{s}"),
        TargetSelector::Cidr(s) => format!("cidr:{s}"),
        TargetSelector::Service(s) => format!("service:{s}"),
        TargetSelector::ProtoPort { inner, proto, port } => {
            format!("{}/{proto}:{port}", target_str(inner))
        }
    }
}

/// Merges real messages, the IRC-style join/leave log
/// (`StateStore::list_group_membership_events`), and every cast vote
/// (`StateStore::list_group_votes`) into one chronological timeline —
/// the same way a real IRC client interleaves join/part notices with
/// chat rather than showing them in a separate window. A vote is shown
/// every time it's cast, not deduped to the latest per voter — see
/// `list_group_votes`'s own doc on why that's a real, distinct event.
pub fn list_party_line(store: &StateStore, group_id: &str) -> Result<()> {
    let group_id = resolve_group_id(store, group_id)?;
    if let Some(group) = store.get_group(group_id)? {
        println!("group \"{}\" [{}]", group.name, group_id_str(group_id));
        println!("topic: {}", group.description);
    }
    let messages = store.list_party_line_messages(group_id)?;
    let events = store.list_group_membership_events(group_id)?;
    let votes = store.list_group_votes(group_id)?;
    if messages.is_empty() && events.is_empty() && votes.is_empty() {
        println!("no party-line activity for {}", group_id_str(group_id));
        return Ok(());
    }

    enum Entry {
        Message(PartyLineMessage),
        Event(UserId, state_store::MembershipEventKind),
        Vote(GroupVote),
    }
    let mut timeline: Vec<(i64, Entry)> = Vec::new();
    for m in messages {
        timeline.push((m.issued_at, Entry::Message(m)));
    }
    for (user, kind, at) in events {
        timeline.push((at, Entry::Event(user, kind)));
    }
    for v in votes {
        let at = v.issued_at;
        timeline.push((at, Entry::Vote(v)));
    }
    timeline.sort_by_key(|(at, _)| *at);

    let now = now_unix();
    for (at, entry) in timeline {
        match entry {
            Entry::Message(m) => {
                let reply_note = m
                    .in_reply_to
                    .as_ref()
                    .map(|t| format!(" (re: {})", target_str(t)))
                    .unwrap_or_default();
                println!(
                    "[{at}] {}{reply_note}: {}",
                    irc_identity(store, &m.author)?,
                    m.body
                );
            }
            Entry::Event(user, kind) => {
                let verb = match kind {
                    state_store::MembershipEventKind::Joined => "has joined",
                    state_store::MembershipEventKind::Left => "has left",
                };
                println!(
                    "[{at}] *** {} {verb} the group",
                    irc_identity(store, &user)?
                );
            }
            Entry::Vote(v) => {
                let note = v
                    .reason
                    .note
                    .clone()
                    .map(|n| format!(": {n}"))
                    .unwrap_or_default();
                println!(
                    "[{at}] *** {} voted {} on {} \u{2014} {}{note}",
                    irc_identity(store, &v.voter)?,
                    stance_str(v.stance),
                    target_str(&v.target),
                    reason_code_str(v.reason.code)
                );
                println!("      {}", format_poll(store, group_id, &v.target, now)?);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_group_id_is_deterministic_for_the_same_pubkey() {
        let pk = PublicKeyBytes([7; 32]);
        assert_eq!(self_group_id(&pk), self_group_id(&pk));
    }

    #[test]
    fn self_group_id_differs_across_pubkeys() {
        let a = PublicKeyBytes([7; 32]);
        let b = PublicKeyBytes([9; 32]);
        assert_ne!(self_group_id(&a), self_group_id(&b));
    }

    #[test]
    fn irc_identity_uses_the_self_nickname_and_stable_identity() {
        let store = StateStore::open_in_memory().unwrap();
        let user = UserId {
            federation: domain_types::FederationId(Hash32([1; 32])),
            local_id: Hash32([2; 32]),
        };
        store
            .set_self_identity(user, PublicKeyBytes([3; 32]), &[4; 32], Some("alice"))
            .unwrap();

        let identity = irc_identity(&store, &user).unwrap();
        assert!(identity.starts_with("alice ("), "got: {identity}");
        assert!(identity.contains("@"), "got: {identity}");

        store
            .set_home_federation_display_name(Some("home"))
            .unwrap();
        assert!(irc_identity(&store, &user).unwrap().contains("@home)"));
    }
}
