# Interactive Party-Line Chat Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A web-served, terminal-styled chat over uhttpd/CGI where an operator reads party-line activity (including system-generated notifications for anything awaiting a decision) and issues real `sf` commands from a browser — with zero second implementation of any command's behavior.

**Architecture:** `sf` gains a CGI entry point (`cgi::is_cgi()`/`cgi::run_cgi()`, checked at the top of `main()`) served by uhttpd exactly the way `kestreld`'s own `/cgi-bin/*` endpoints already are. Every GET renders a party-line timeline; every POST re-invokes the `sf` binary itself as a subprocess with real CLI arguments and renders its captured output — the chat and the CLI are never two code paths, only two ways of invoking the same one. A new implicit per-identity "self" group is the destination for notifications with no other home (tunnel/service requests). A small cron-driven `sf notify` command scans for new pending items and posts them as self-signed party-line messages, optionally pushing a summary to `ntfy` over a minimal hand-rolled HTTP/1.1 client.

**Tech Stack:** Rust, existing `clap`/`state-store`/`domain-types`/`crypto` crates, `serde_urlencoded` (new, tiny — CGI query/form parsing), `shell-words` (new, tiny — splitting a typed chat command the way a shell would). No new async runtime, no web framework, no TLS library.

## Global Constraints

- Zero new signed-statement type. Notifications are ordinary `PartyLineMessage`s, self-signed by this router's own identity.
- Commands typed in chat execute via the *exact same* `sf` binary and argument parser as the terminal CLI — never a second grammar or a second implementation of any command's logic.
- Trust boundary is LAN-reachability, the same one this whole project already uses for CLI access and the same one `kestreld`'s own CGI mutation endpoints (`approve-join`, `rotate-password`) already accept — no new app-level auth is introduced.
- The existing read-only dashboard (`crates/dashboard`, `sf serve-dashboard`) is untouched by this plan.
- No real-time/websocket push. No per-group ntfy topic (one global setting). `ntfy` push failures are logged and never block the underlying party-line post from succeeding.
- Only a short summary ever leaves the router via `ntfy` — never a full signed statement payload.

---

## File Structure

```
crates/cli/
  src/
    cgi.rs            # NEW — is_cgi/run_cgi, GET render, POST dispatch, HTML template
    notify.rs         # NEW — notify_pending_items, post_notification helper wiring
    ntfy.rs           # NEW — minimal HTTP/1.1 POST client
    group.rs          # MODIFY — self_group_id, create_self_group, build_and_store_party_line_message refactor
    main.rs           # MODIFY — cgi hook at top of main(), init_identity hook, SetNtfyTopic + Notify commands
  Cargo.toml           # MODIFY — add serde_urlencoded, shell-words

crates/state-store/
  migrations/0021_notified_items.sql   # NEW
  migrations/0022_ntfy_config.sql      # NEW
  src/lib.rs           # MODIFY — has_been_notified/mark_notified, get/set_ntfy_topic_url

install.sh             # MODIFY — sf notify cron entry, /www/cgi-bin/sf-chat symlink + uhttpd cgi_prefix
```

---

### Task 1: The implicit "self" group

**Files:**
- Modify: `crates/cli/src/group.rs`
- Modify: `crates/cli/src/main.rs:962-980` (`init_identity`)

**Interfaces:**
- Produces: `pub(crate) fn self_group_id(pubkey: &domain_types::PublicKeyBytes) -> GroupId`, `pub(crate) fn create_self_group(store: &StateStore, owner: UserId, pubkey: &domain_types::PublicKeyBytes) -> Result<()>` (both in `group.rs`, used by `main.rs`'s `init_identity` in this task and by `notify.rs` in Task 2).

- [ ] **Step 1: Write the failing test for a deterministic, re-derivable self-group id**

Add to `crates/cli/src/group.rs`'s existing `#[cfg(test)] mod tests` (or create one if this file doesn't have one yet — check first; if it does, add alongside the existing tests):

```rust
#[test]
fn self_group_id_is_deterministic_for_the_same_pubkey() {
    let pk = domain_types::PublicKeyBytes([7; 32]);
    assert_eq!(self_group_id(&pk), self_group_id(&pk));
}

#[test]
fn self_group_id_differs_across_pubkeys() {
    let a = domain_types::PublicKeyBytes([7; 32]);
    let b = domain_types::PublicKeyBytes([9; 32]);
    assert_ne!(self_group_id(&a), self_group_id(&b));
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p sf-cli --bin sf -- self_group_id`
Expected: FAIL — `self_group_id` is not defined yet.

- [ ] **Step 3: Implement `self_group_id` and `create_self_group`**

Add to `crates/cli/src/group.rs`, near the existing `build_and_store_group` (around line 113):

```rust
/// Deterministic id for an identity's own implicit "self" group — derived
/// the same domain-separated-hash way `create_group`'s own id is, but
/// keyed to the owner's pubkey instead of a random nonce, so it can be
/// re-derived later (by the notifier, by the CGI default view) without
/// needing separate storage of "which group is my self group."
pub(crate) fn self_group_id(pubkey: &domain_types::PublicKeyBytes) -> GroupId {
    GroupId(crypto::hash(&[b"sf-self-group-v1".as_slice(), &pubkey.0].concat()))
}

/// Creates the implicit single-member "self" group for an identity — the
/// destination for notifications with no natural group (tunnel/service
/// requests). Called once from `init_identity`, and defensively from
/// `notify::notify_pending_items` for any identity that predates this
/// feature. Idempotent: `ingest_group` no-ops on a duplicate
/// `(group_id, sequence)`, so calling this twice for the same identity is
/// harmless.
pub(crate) fn create_self_group(store: &StateStore, owner: UserId, pubkey: &domain_types::PublicKeyBytes) -> Result<()> {
    let group_id = self_group_id(pubkey);
    let template = Group {
        group_id,
        published_by: owner,
        sequence: 0,
        name: "self".to_string(),
        description: "your own notification feed — auto-created, for anything with no other group".to_string(),
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sf-cli --bin sf -- self_group_id`
Expected: 2 tests pass.

- [ ] **Step 5: Hook `create_self_group` into `init_identity`**

In `crates/cli/src/main.rs`, `init_identity` (currently ends at line 980):

```rust
fn init_identity(store: &StateStore, display_name: Option<String>) -> Result<()> {
    if store.get_self_identity()?.is_some() {
        bail!("an identity already exists in this database — refusing to overwrite it");
    }
    let kp = crypto::Keypair::generate();
    let pubkey = kp.public_key();
    let federation_id = FederationId(crypto::hash(&[b"sf-genesis-v1".as_slice(), &pubkey.0].concat()));
    let local_id = crypto::hash(&[b"sf-local-id-v1".as_slice(), &pubkey.0].concat());
    let user = UserId { federation: federation_id, local_id };

    store.set_self_identity(user, pubkey, &kp.seed_bytes(), display_name.as_deref())?;
    group::create_self_group(store, user, &pubkey)?;

    println!("identity created");
    println!("  federation : {}", federation_id.0);
    println!("  local_id   : {}", local_id);
    println!("  public_key : {}", hex::encode(pubkey.0));
    println!("share federation + local_id + public_key with people who want to follow you.");
    Ok(())
}
```

(Only the new `group::create_self_group(store, user, &pubkey)?;` line is added — everything else is unchanged.)

- [ ] **Step 6: Write the failing CLI integration test**

Add to `crates/cli/tests/cli.rs`:

```rust
#[test]
fn init_identity_auto_creates_a_self_group() {
    let dir = tempfile::tempdir().unwrap();
    let init = sf(dir.path(), "alice.sqlite", &["init-identity", "--display-name", "alice"]);
    assert!(init.status.success(), "init-identity failed: {}", stderr(&init));

    let groups = sf(dir.path(), "alice.sqlite", &["list-groups"]);
    assert!(groups.status.success(), "list-groups failed: {}", stderr(&groups));
    let out = stdout(&groups);
    assert!(out.contains("self"), "expected the auto-created \"self\" group to appear in list-groups, got:\n{out}");
}
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cargo test -p sf-cli --test cli init_identity_auto_creates_a_self_group`
Expected: 1 test passes.

- [ ] **Step 8: Run the full existing test suite to confirm no regressions**

Run: `cargo test -p sf-cli --bin sf && cargo test -p sf-cli --test cli`
Expected: all pre-existing tests still pass — `init_identity_twice_refuses_to_overwrite` and every other test that calls `init-identity` must be unaffected by the extra group now being created alongside the identity.

- [ ] **Step 9: Commit**

```bash
git add crates/cli/src/group.rs crates/cli/src/main.rs crates/cli/tests/cli.rs
git commit -m "cli: auto-create an implicit \"self\" group at init-identity"
```

---

### Task 2: Notification tracking, `notify_pending_items`, `sf notify`

**Files:**
- Create: `crates/state-store/migrations/0021_notified_items.sql`
- Create: `crates/cli/src/notify.rs`
- Modify: `crates/state-store/src/lib.rs`
- Modify: `crates/cli/src/group.rs` (extract `build_and_store_party_line_message`, add `post_notification`)
- Modify: `crates/cli/src/main.rs` (register `mod notify;`, new `Notify` command)
- Modify: `install.sh`

**Interfaces:**
- Consumes: `group::self_group_id`, `group::create_self_group` (Task 1).
- Produces: `StateStore::has_been_notified(&self, item_kind: &str, item_key: &str) -> Result<bool, StoreError>`, `StateStore::mark_notified(&self, item_kind: &str, item_key: &str, now: i64) -> Result<(), StoreError>`, `pub(crate) fn post_notification(store: &StateStore, group_id: GroupId, body: &str) -> Result<()>` (in `group.rs`), `pub struct NotifyReport { pub notifications_posted: usize }` and `pub fn notify_pending_items(store: &StateStore) -> Result<NotifyReport>` (in `notify.rs`) — `notify_pending_items` is what Task 3 wires `ntfy` push into.

- [ ] **Step 1: Add the migration**

```sql
-- crates/state-store/migrations/0021_notified_items.sql
-- Idempotency tracking for the background notifier (cli::notify) —
-- prevents re-posting the same "you have a pending X" party-line message
-- every time it runs. item_kind + item_key together identify one pending
-- item uniquely (e.g. kind="group_join", key="<requester>/<sequence>").
CREATE TABLE notified_items (
    item_kind TEXT NOT NULL,
    item_key TEXT NOT NULL,
    notified_at INTEGER NOT NULL,
    PRIMARY KEY (item_kind, item_key)
) STRICT, WITHOUT ROWID;
```

Register it in `crates/state-store/src/lib.rs`'s `MIGRATIONS` constant, immediately after the `(20, ...)` entry:

```rust
    (21, include_str!("../migrations/0021_notified_items.sql")),
```

- [ ] **Step 2: Write the failing tests for the tracking methods**

Add to `crates/state-store/src/lib.rs`'s `mod tests`:

```rust
#[test]
fn notified_items_round_trip() {
    let store = StateStore::open_in_memory().unwrap();
    assert!(!store.has_been_notified("group_join", "abc/0").unwrap());
    store.mark_notified("group_join", "abc/0", 100).unwrap();
    assert!(store.has_been_notified("group_join", "abc/0").unwrap());
    // A different key for the same kind is independent.
    assert!(!store.has_been_notified("group_join", "abc/1").unwrap());
}

#[test]
fn mark_notified_is_idempotent() {
    let store = StateStore::open_in_memory().unwrap();
    store.mark_notified("tunnel_request", "x/0", 100).unwrap();
    store.mark_notified("tunnel_request", "x/0", 200).unwrap(); // must not error
    assert!(store.has_been_notified("tunnel_request", "x/0").unwrap());
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p state-store --lib -- notified_items mark_notified_is_idempotent`
Expected: FAIL — methods don't exist yet.

- [ ] **Step 4: Implement the tracking methods**

Add to `crates/state-store/src/lib.rs`, anywhere alongside the other small standalone-table methods (e.g. near `record_transfer_sample`):

```rust
    /// Has this pending item already been surfaced as a notification?
    /// `item_kind`/`item_key` together are an opaque, caller-defined
    /// composite identity — see `cli::notify` for the concrete kinds and
    /// key shapes in use.
    pub fn has_been_notified(&self, item_kind: &str, item_key: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM notified_items WHERE item_kind = ?1 AND item_key = ?2", params![item_kind, item_key], |_| Ok(()))
            .optional()?
            .is_some())
    }

    pub fn mark_notified(&self, item_kind: &str, item_key: &str, now: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO notified_items (item_kind, item_key, notified_at) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
            params![item_kind, item_key, now],
        )?;
        Ok(())
    }
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p state-store --lib -- notified_items mark_notified_is_idempotent`
Expected: 2 tests pass.

- [ ] **Step 6: Extract `build_and_store_party_line_message` from `publish_party_line`**

In `crates/cli/src/group.rs`, find `publish_party_line` (its current signature is `pub fn publish_party_line(store: &StateStore, group_id: &str, body: &str, in_reply_to: Option<(String, String)>, out_dir: &Path) -> Result<()>`, and it currently signs and stores the message inline before exporting it). Replace its signing/storing prologue with a call to a new shared helper, so `notify.rs` can reuse the same core without duplicating the signing logic:

```rust
/// Signs and stores a party-line message — the shared core behind both
/// `publish_party_line` (an operator-authored message, which also
/// exports/seals a copy per member) and `post_notification` (a
/// system-generated notification, which doesn't export anywhere — it's
/// meant to stay local until the operator decides otherwise). Enforces
/// `can_post_party_line` in both cases, including for the notifier: since
/// the notifier only ever posts to groups this router's own identity owns
/// or admins (see `notify::notify_pending_items`), this check always
/// passes there, but keeping it in the shared core rather than skipping
/// it for notifications means there's exactly one place this rule lives.
fn build_and_store_party_line_message(store: &StateStore, group_id: GroupId, body: &str, in_reply_to: Option<TargetSelector>) -> Result<PartyLineMessage> {
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let group = store.get_group(group_id)?.context("unknown group — ingest it first")?;
    if !group.can_post_party_line(&author) {
        bail!("you don't currently have posting rights on this group's party line (not a member, or the channel is moderated and you're not voiced)");
    }
    let sequence = store.next_party_line_sequence(group_id, &author)?;
    let mut msg = PartyLineMessage { group_id, author, sequence, body: body.to_string(), in_reply_to, issued_at: now_unix(), signature: domain_types::SignatureBytes([0; 64]) };
    let signing_bytes = msg.signing_bytes();
    msg.signature = kp.sign(crypto::contexts::PARTY_LINE_MESSAGE, &signing_bytes);
    store.store_party_line_message(&msg)?;
    Ok(msg)
}
```

Now rewrite `publish_party_line` to call it instead of duplicating the signing logic — replace everything from the start of the function through the `println!("published party-line message ...")` line with:

```rust
pub fn publish_party_line(store: &StateStore, group_id: &str, body: &str, in_reply_to: Option<(String, String)>, out_dir: &Path) -> Result<()> {
    let group_id = parse_group_id(group_id)?;
    let in_reply_to = in_reply_to.map(|(kind, value)| parse_target(&kind, &value)).transpose()?;
    let msg = build_and_store_party_line_message(store, group_id, body, in_reply_to)?;
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    println!("published party-line message #{} to group {}", msg.sequence, group_id_str(group_id));

    // (everything below here — building `plaintext`, the export loop over
    // `all_members`, the `skipped` counter — is UNCHANGED from the
    // existing function body; only the signing/storing prologue above it
    // was replaced. `identity_pubkey` for the export JSON still comes
    // from `kp.public_key()`, exactly as before.)
    ...
```

The rest of the function (building `plaintext` from `msg`, the export loop, the final `Ok(())`) stays exactly as it already is today — do not change any of that logic, only the prologue above it. Read the current full function body first so you copy the unchanged tail forward correctly rather than guessing at it.

Add `post_notification` right after `build_and_store_party_line_message`:

```rust
/// System-generated notification: signs and stores a party-line message
/// on this router's own behalf, with no export step (see
/// `build_and_store_party_line_message`'s doc). Used only by
/// `notify::notify_pending_items`.
pub(crate) fn post_notification(store: &StateStore, group_id: GroupId, body: &str) -> Result<()> {
    let msg = build_and_store_party_line_message(store, group_id, body, None)?;
    println!("notified group {}: {}", group_id_str(msg.group_id), body);
    Ok(())
}
```

- [ ] **Step 7: Run the full existing test suite to confirm the refactor is behavior-preserving**

Run: `cargo test -p sf-cli --bin sf && cargo test -p sf-cli --test cli`
Expected: all pre-existing tests pass unchanged, especially `list_party_line_shows_a_structured_reply_comment_on_a_vote` and `party_line_moderation_and_voice_gate_posting_correctly` (both exercise `publish_party_line` end-to-end and must show byte-identical behavior).

- [ ] **Step 8: Write the failing test for `notify_pending_items`**

Create `crates/cli/src/notify.rs`:

```rust
//! Scans for pending items awaiting an operator decision and posts each
//! one, once, as a self-signed party-line notification — see the design
//! spec's "Notifications" section. Group-scoped pending items (join
//! requests) post into that group's own party line; anything with no
//! natural group (tunnel/service requests) posts into the implicit
//! "self" group (see `crate::group::self_group_id`). Idempotent via
//! `StateStore::has_been_notified`/`mark_notified` — safe to run
//! repeatedly (e.g. every 5 minutes from cron).

use crate::group::{self_group_id, post_notification};
use crate::tunnel::user_id_str;
use crate::{group, now_unix};
use anyhow::{Context, Result};
use state_store::StateStore;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NotifyReport {
    pub notifications_posted: usize,
}

pub fn notify_pending_items(store: &StateStore) -> Result<NotifyReport> {
    let (self_user, self_pubkey) = store.get_self_identity()?.context("no identity yet — run init-identity first")?;
    let mut report = NotifyReport::default();
    let self_group = self_group_id(&self_pubkey);
    // Defensive: an identity created before this feature shipped won't
    // have a self group yet. Create it on first use rather than failing.
    if store.get_group(self_group)?.is_none() {
        group::create_self_group(store, self_user, &self_pubkey)?;
    }

    for g in store.list_groups()? {
        if !g.can_manage_membership(&self_user) {
            continue;
        }
        for req in store.list_pending_group_join_requests(g.group_id)? {
            let key = format!("{}/{}", user_id_str(&req.requester), req.sequence);
            if store.has_been_notified("group_join", &key)? {
                continue;
            }
            let body = format!(
                "{} wants to join \"{}\" — /approve-group-join --group {} --requester {} --sequence {} --voting",
                user_id_str(&req.requester),
                g.name,
                group::group_id_str(g.group_id),
                user_id_str(&req.requester),
                req.sequence
            );
            post_notification(store, g.group_id, &body)?;
            store.mark_notified("group_join", &key, now_unix())?;
            report.notifications_posted += 1;
        }
    }

    for req in store.list_pending_tunnel_connection_requests()? {
        if req.advertisement.author != self_user {
            continue;
        }
        let key = format!("{}/{}", user_id_str(&req.requester), req.sequence);
        if store.has_been_notified("tunnel_request", &key)? {
            continue;
        }
        let body = format!(
            "{} requested your tunnel — /accept-tunnel-request --requester {} --sequence {}",
            user_id_str(&req.requester),
            user_id_str(&req.requester),
            req.sequence
        );
        post_notification(store, self_group, &body)?;
        store.mark_notified("tunnel_request", &key, now_unix())?;
        report.notifications_posted += 1;
    }

    for req in store.list_tunnel_service_requests()? {
        if req.requester == self_user {
            continue;
        }
        let key = format!("{}/{}", user_id_str(&req.requester), req.sequence);
        if store.has_been_notified("tunnel_service_request", &key)? {
            continue;
        }
        let body = format!(
            "{} is looking for a tunnel: \"{}\" — respond with `offer-tunnel --in-response-to {}/{}`",
            user_id_str(&req.requester),
            req.description,
            user_id_str(&req.requester),
            req.sequence
        );
        post_notification(store, self_group, &body)?;
        store.mark_notified("tunnel_service_request", &key, now_unix())?;
        report.notifications_posted += 1;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::{FederationId, Hash32, MessagingPublicKeyBytes, PublicKeyBytes, StatementRef, TargetSelector, TunnelConnectionRequest, UserId, Visibility, WgPublicKeyBytes};

    fn user(byte: u8) -> UserId {
        UserId { federation: FederationId(Hash32([byte; 32])), local_id: Hash32([byte.wrapping_add(100); 32]) }
    }

    fn store_with_self_identity() -> (StateStore, UserId) {
        let store = StateStore::open_in_memory().unwrap();
        let self_user = user(1);
        let kp = crypto::Keypair::generate();
        store.set_self_identity(self_user, kp.public_key(), &kp.seed_bytes(), None).unwrap();
        group::create_self_group(&store, self_user, &kp.public_key()).unwrap();
        (store, self_user)
    }

    #[test]
    fn notify_pending_items_posts_a_notification_for_a_new_tunnel_request_and_is_idempotent() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pk) = crate::tunnel::build_and_store_own_advertisement(&store, "self's own ad", None, vec![TargetSelector::Domain("example.com".into())], Vec::new(), None, None, Visibility::Public, None).unwrap();
        let bob = user(2);
        store
            .store_tunnel_connection_request(&TunnelConnectionRequest {
                requester: bob,
                sequence: 0,
                advertisement: StatementRef { author: self_user, sequence: 0 },
                requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
                requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
                requested_at: 0,
                signature: domain_types::SignatureBytes([0; 64]),
            })
            .unwrap();

        let report = notify_pending_items(&store).unwrap();
        assert_eq!(report.notifications_posted, 1);

        let (_, self_pubkey) = store.get_self_identity().unwrap().unwrap();
        let self_group = group::self_group_id(&self_pubkey);
        let messages = store.list_party_line_messages(self_group).unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].body.contains("requested your tunnel"), "got: {}", messages[0].body);

        // Second run must not re-notify.
        let report2 = notify_pending_items(&store).unwrap();
        assert_eq!(report2.notifications_posted, 0);
        assert_eq!(store.list_party_line_messages(self_group).unwrap().len(), 1);
    }

    #[test]
    fn notify_pending_items_lazily_creates_a_missing_self_group() {
        // Simulates an identity created before this feature shipped: no
        // self group exists yet.
        let store = StateStore::open_in_memory().unwrap();
        let self_user = user(1);
        let kp = crypto::Keypair::generate();
        store.set_self_identity(self_user, kp.public_key(), &kp.seed_bytes(), None).unwrap();
        // Deliberately do NOT call create_self_group here.

        let report = notify_pending_items(&store).unwrap();
        assert_eq!(report.notifications_posted, 0); // nothing pending, but must not error
        let self_group = group::self_group_id(&kp.public_key());
        assert!(store.get_group(self_group).unwrap().is_some(), "the self group must have been created lazily");
    }
}
```

- [ ] **Step 9: Run the tests to verify they fail, then implement, then pass**

Run: `cargo test -p sf-cli --bin sf -- notify::` — expect FAIL (module not registered / functions not visible yet).

Add `mod notify;` to `crates/cli/src/main.rs`'s existing `mod` block (alongside `mod device; mod group; mod list; mod tunnel;`). Verify `group::group_id_str` and `group::self_group_id`/`group::create_self_group`/`group::post_notification` are all `pub(crate)` (not private) so `notify.rs` can call them — check `group.rs` and widen visibility from private to `pub(crate)` for any of these that aren't already, since `group_id_str` in particular may currently be private (`fn group_id_str`, not `pub(crate) fn`) given it was originally only used within `group.rs` itself.

Run: `cargo test -p sf-cli --bin sf -- notify::`
Expected: 2 tests pass.

- [ ] **Step 10: Add the `sf notify` CLI command**

In `crates/cli/src/main.rs`, add a new `Command` variant (place it near `SyncTunnels`):

```rust
    /// Scan for pending items (group joins, tunnel requests, tunnel
    /// service requests) and post a notification for each new one into
    /// the relevant party line. Idempotent — safe to run from cron.
    Notify,
```

Add the dispatch arm near `SyncTunnels`'s:

```rust
        Command::Notify => {
            let report = notify::notify_pending_items(&store)?;
            println!("posted {} notification(s)", report.notifications_posted);
        }
```

- [ ] **Step 11: Manually verify against the real binary**

```bash
cargo build -p sf-cli
rm -f /tmp/notify_verify.sqlite
target/debug/sf --db /tmp/notify_verify.sqlite init-identity --display-name test
target/debug/sf --db /tmp/notify_verify.sqlite notify
target/debug/sf --db /tmp/notify_verify.sqlite list-party-line --group "$(target/debug/sf --db /tmp/notify_verify.sqlite list-groups | grep -oE '[0-9a-f]{64}' | head -1)"
rm -f /tmp/notify_verify.sqlite
```
Expected: `notify` prints "posted 0 notification(s)" (nothing pending yet), and `list-groups`/`list-party-line` both work against the auto-created self group without error.

- [ ] **Step 12: Wire `sf notify` into `install.sh`'s cron section**

In `install.sh`, right after the existing cron block (the `cat >>"$CRONTAB" <<EOF ... EOF` for `sf apply`, ending around line 72), add a second idempotent tag-based cron entry using the exact same pattern:

```sh
NOTIFY_CRON_TAG="social-firewall-notify"
sed -i "/# ${NOTIFY_CRON_TAG}\$/d" "$CRONTAB"
cat >>"$CRONTAB" <<EOF
*/5 * * * * /usr/bin/sf --db $STORE notify >/tmp/social-firewall-notify.log 2>&1  # ${NOTIFY_CRON_TAG}
EOF
```

Also update the `remove` handler at the top of the script (currently only strips `# ${CRON_TAG}$` lines) to also strip `# ${NOTIFY_CRON_TAG}$` lines — add `sed -i "/# social-firewall-notify\$/d" "$CRONTAB" 2>/dev/null || true` right next to the existing `sed -i "/# ${CRON_TAG}\$/d" "$CRONTAB"` line in that block.

- [ ] **Step 13: Commit**

```bash
git add crates/state-store crates/cli install.sh
git commit -m "cli: notify_pending_items, sf notify, cron wiring"
```

---

### Task 3: Optional `ntfy` push

**Files:**
- Create: `crates/state-store/migrations/0022_ntfy_config.sql`
- Create: `crates/cli/src/ntfy.rs`
- Modify: `crates/state-store/src/lib.rs`
- Modify: `crates/cli/src/main.rs` (`mod ntfy;`, `SetNtfyTopic` command)
- Modify: `crates/cli/src/notify.rs` (wire the push in)

**Interfaces:**
- Consumes: `notify_pending_items`'s per-notification loop (Task 2).
- Produces: `StateStore::get_ntfy_topic_url(&self) -> Result<Option<String>, StoreError>`, `StateStore::set_ntfy_topic_url(&self, url: Option<&str>) -> Result<(), StoreError>`, `pub fn ntfy::push(topic_url: &str, message: &str) -> Result<()>`.

- [ ] **Step 1: Add the migration**

```sql
-- crates/state-store/migrations/0022_ntfy_config.sql
-- Optional global ntfy push target (see the design spec's "Optional ntfy
-- push" section — one setting, not per-group). NULL means disabled.
-- Lives on the `is_self` row, same storage convention as the various
-- `*_secret_seed` columns.
ALTER TABLE users ADD COLUMN ntfy_topic_url TEXT;
```

Register as `(22, include_str!("../migrations/0022_ntfy_config.sql"))` in `MIGRATIONS`, after the `(21, ...)` entry.

- [ ] **Step 2: Write the failing tests for the config methods**

Add to `crates/state-store/src/lib.rs`'s `mod tests`:

```rust
#[test]
fn ntfy_topic_url_round_trips() {
    let store = StateStore::open_in_memory().unwrap();
    store.set_self_identity(user(1, 1), PublicKeyBytes([1; 32]), &[4; 32], None).unwrap();
    assert_eq!(store.get_ntfy_topic_url().unwrap(), None);
    store.set_ntfy_topic_url(Some("http://ntfy.example.lan/social-firewall")).unwrap();
    assert_eq!(store.get_ntfy_topic_url().unwrap().as_deref(), Some("http://ntfy.example.lan/social-firewall"));
    store.set_ntfy_topic_url(None).unwrap();
    assert_eq!(store.get_ntfy_topic_url().unwrap(), None);
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `cargo test -p state-store --lib -- ntfy_topic_url_round_trips`
Expected: FAIL — methods don't exist yet.

- [ ] **Step 4: Implement the config methods**

Add to `crates/state-store/src/lib.rs`, mirroring `set_wg_keypair_seed`/`get_wg_keypair_seed`'s exact shape:

```rust
    pub fn set_ntfy_topic_url(&self, url: Option<&str>) -> Result<(), StoreError> {
        let rows = self.conn.execute("UPDATE users SET ntfy_topic_url = ?1 WHERE is_self = 1", params![url])?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_ntfy_topic_url(&self) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row("SELECT ntfy_topic_url FROM users WHERE is_self = 1", [], |row| row.get::<_, Option<String>>(0))
            .optional()?
            .flatten()
            .map(Ok)
            .transpose()
    }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p state-store --lib -- ntfy_topic_url_round_trips`
Expected: 1 test passes.

- [ ] **Step 6: Write the failing test for the HTTP client, using a real loopback TCP server**

Create `crates/cli/src/ntfy.rs`:

```rust
//! Minimal, dependency-free HTTP/1.1 client for pushing a short summary
//! to a self-hosted `ntfy` topic (see the design spec's "Optional ntfy
//! push" section). Deliberately plain HTTP only, no TLS: this project's
//! stated primary case is a self-hosted `ntfy` server on the same LAN,
//! consistent with this whole feature's own LAN-trust-boundary model. An
//! HTTPS-only endpoint (e.g. the public ntfy.sh) is out of scope for this
//! minimal client — put a plain-HTTP reverse proxy in front of it, or
//! extend this module, as a future addition.

use anyhow::{bail, Context, Result};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// `topic_url` is a plain `http://` URL including the topic path, e.g.
/// `http://ntfy.example.lan/social-firewall`. Posts `message` as the raw
/// request body — `ntfy`'s own simplest publish API treats a bare POST
/// body as the notification text.
pub fn push(topic_url: &str, message: &str) -> Result<()> {
    let url = topic_url.strip_prefix("http://").context("ntfy topic URL must start with http:// (plain HTTP only — see this module's doc comment)")?;
    let (host_port, path) = match url.split_once('/') {
        Some((h, p)) => (h, format!("/{p}")),
        None => (url, "/".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().context("invalid port in ntfy topic URL")?),
        None => (host_port, 80u16),
    };

    let mut stream = TcpStream::connect((host, port)).with_context(|| format!("connecting to {host}:{port}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let body = message.as_bytes();
    let request = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(request.as_bytes())?;
    stream.write_all(body)?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let response_text = String::from_utf8_lossy(&response);
    let status_line = response_text.lines().next().unwrap_or("");
    let status_code: u16 = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok()).context("could not parse HTTP status line from ntfy response")?;
    if !(200..300).contains(&status_code) {
        bail!("ntfy push failed with HTTP status {status_code}: {status_line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufRead;
    use std::net::TcpListener;

    /// A real loopback TCP server (no real network, no mocking library)
    /// that reads one HTTP request, asserts on its body, and writes back
    /// a canned response — this is the actual protocol being exercised,
    /// just against a fake local peer instead of a real ntfy server.
    fn spawn_fake_ntfy_server(expected_body: &'static str, response_status_line: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut reader = std::io::BufReader::new(conn.try_clone().unwrap());
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.strip_prefix("Content-Length: ") {
                    content_length = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).unwrap();
            assert_eq!(String::from_utf8_lossy(&body), expected_body);
            conn.write_all(format!("{response_status_line}\r\nContent-Length: 0\r\n\r\n").as_bytes()).unwrap();
        });
        (format!("http://{addr}/social-firewall"), handle)
    }

    #[test]
    fn push_sends_the_message_as_the_raw_post_body_and_succeeds_on_200() {
        let (url, handle) = spawn_fake_ntfy_server("bob wants to join neighborhood watch", "HTTP/1.1 200 OK");
        push(&url, "bob wants to join neighborhood watch").unwrap();
        handle.join().unwrap();
    }

    #[test]
    fn push_fails_on_a_non_2xx_status() {
        let (url, handle) = spawn_fake_ntfy_server("hello", "HTTP/1.1 500 Internal Server Error");
        let err = push(&url, "hello").unwrap_err();
        assert!(err.to_string().contains("500"), "expected the error to mention the status code, got: {err}");
        handle.join().unwrap();
    }

    #[test]
    fn push_rejects_a_non_http_url() {
        let err = push("https://ntfy.sh/topic", "hello").unwrap_err();
        assert!(err.to_string().contains("http://"), "got: {err}");
    }
}
```

- [ ] **Step 7: Run the tests to verify they fail, then pass**

Run: `cargo test -p sf-cli --bin sf -- ntfy::` — first confirm it fails to compile/run since `mod ntfy;` isn't registered yet (add `mod ntfy;` to `main.rs`'s `mod` block now), then re-run.

Expected: 3 tests pass.

- [ ] **Step 8: Wire `ntfy::push` into `notify_pending_items`**

In `crates/cli/src/notify.rs`, add a small helper and call it after each successful `post_notification`:

```rust
fn maybe_push_ntfy(store: &StateStore, body: &str) {
    let Ok(Some(topic_url)) = store.get_ntfy_topic_url() else { return };
    if let Err(e) = crate::ntfy::push(&topic_url, body) {
        eprintln!("ntfy push failed (party-line notification was still recorded): {e}");
    }
}
```

Call `maybe_push_ntfy(store, &body);` right after each of the three `post_notification(...)?;` calls in `notify_pending_items` (three call sites: group join, tunnel request, tunnel service request) — after the `mark_notified` call, so a failed `ntfy` push never affects idempotency tracking either.

- [ ] **Step 9: Write the failing test proving an ntfy failure never blocks the notification**

Add to `crates/cli/src/notify.rs`'s test module:

```rust
#[test]
fn a_failed_ntfy_push_does_not_block_the_underlying_notification() {
    let (store, self_user) = store_with_self_identity();
    // Point at a topic URL nothing is listening on — push() will fail.
    store.set_ntfy_topic_url(Some("http://127.0.0.1:1")).unwrap();
    let (_ad, _pk) = crate::tunnel::build_and_store_own_advertisement(&store, "self's own ad", None, vec![TargetSelector::Domain("example.com".into())], Vec::new(), None, None, Visibility::Public, None).unwrap();
    let bob = user(2);
    store
        .store_tunnel_connection_request(&TunnelConnectionRequest {
            requester: bob,
            sequence: 0,
            advertisement: StatementRef { author: self_user, sequence: 0 },
            requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
            requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
            requested_at: 0,
            signature: domain_types::SignatureBytes([0; 64]),
        })
        .unwrap();

    let report = notify_pending_items(&store).unwrap();
    assert_eq!(report.notifications_posted, 1, "the notification must still be recorded even though the ntfy push to a dead port fails");
}
```

- [ ] **Step 10: Run the test to verify it passes**

Run: `cargo test -p sf-cli --bin sf -- notify::a_failed_ntfy_push`
Expected: 1 test passes. (Port 1 is a privileged, essentially-never-listening port — connection should fail fast; if this proves flaky in practice, an alternative is binding a real `TcpListener` and dropping it immediately before calling `push`, guaranteeing a connection-refused. Use your judgment if the first approach is unreliable in the test environment.)

- [ ] **Step 11: Add the `sf set-ntfy-topic` command**

In `crates/cli/src/main.rs`, add a `Command` variant near `SetFollowNodeId`:

```rust
    /// Set (or, with no --url, clear) the ntfy topic notifications are
    /// optionally pushed to. Plain http:// only — see `ntfy::push`'s doc.
    SetNtfyTopic {
        #[arg(long)]
        url: Option<String>,
    },
```

Dispatch arm:

```rust
        Command::SetNtfyTopic { url } => {
            store.set_ntfy_topic_url(url.as_deref())?;
            match url {
                Some(u) => println!("ntfy notifications will be pushed to {u}"),
                None => println!("ntfy push disabled"),
            }
        }
```

- [ ] **Step 12: Manually verify against the real binary**

```bash
cargo build -p sf-cli
rm -f /tmp/ntfy_verify.sqlite
target/debug/sf --db /tmp/ntfy_verify.sqlite init-identity --display-name test
target/debug/sf --db /tmp/ntfy_verify.sqlite set-ntfy-topic --url http://127.0.0.1:9999/test
target/debug/sf --db /tmp/ntfy_verify.sqlite set-ntfy-topic
rm -f /tmp/ntfy_verify.sqlite
```
Expected: first command prints the "will be pushed to" confirmation, second prints "ntfy push disabled".

- [ ] **Step 13: Run the full workspace test suite**

Run: `cargo test --workspace`
Expected: all tests pass, no regressions.

- [ ] **Step 14: Commit**

```bash
git add crates/state-store crates/cli
git commit -m "cli: optional ntfy push for notifications"
```

---

### Task 4: CGI skeleton and the GET (read) path

**Files:**
- Create: `crates/cli/src/cgi.rs`
- Modify: `crates/cli/src/main.rs` (hook at top of `main()`, `mod cgi;`)
- Modify: `crates/cli/Cargo.toml` (add `serde_urlencoded`)

**Interfaces:**
- Consumes: `group::self_group_id` (Task 1), `StateStore::open` (existing).
- Produces: `pub fn is_cgi() -> bool`, `pub fn run_cgi()` (both in `cgi.rs`, called from `main()`). Internal (not consumed elsewhere): `render_page(store: &StateStore, group_id: GroupId, body_html: &str) -> String`.

- [ ] **Step 1: Add the dependency**

```toml
# crates/cli/Cargo.toml — add to [dependencies]
serde_urlencoded = "0.7"
```

- [ ] **Step 2: Write the failing test for the HTML page shell**

Create `crates/cli/src/cgi.rs`:

```rust
//! CGI entry point for the interactive party-line chat, served via
//! uhttpd exactly the way `kestreld`'s own `/cgi-bin/*` endpoints already
//! are (see `networks/kestreld-rs/src/cgi.rs` and its `install.sh`
//! deployment) — `install.sh` symlinks this binary into
//! `/www/cgi-bin/sf-chat`, and uhttpd runs it fresh per request. No new
//! listener, no new port, no new TLS story.
//!
//! Deliberately does NOT reuse any in-process command-dispatch logic for
//! mutations (see Task 5's `handle_post`) — every POST re-invokes this
//! same `sf` binary as a subprocess with the real CLI arguments a human
//! would type, and renders its captured output. This guarantees "no
//! second implementation of any command's behavior" as literally as
//! possible: the chat and the CLI are never two code paths, only two ways
//! of invoking the same one. GET rendering reads the store directly
//! in-process (read-only, no reason to shell out for structured data like
//! the group list) but still shells out to `list-party-line` for the
//! timeline itself, reusing its exact existing text formatting rather
//! than re-implementing the message/join-leave/vote merge a second time.

use domain_types::GroupId;
use state_store::StateStore;
use std::path::Path;

const DB_PATH: &str = "/etc/kestrel/social-firewall/social-firewall.sqlite";

pub fn is_cgi() -> bool {
    std::env::var("REQUEST_METHOD").is_ok()
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

const STYLE: &str = "body{background:#0b0b0b;color:#c8c8c8;font-family:\"Fixedsys Excelsior\",\"Terminus\",ui-monospace,monospace;margin:1.5em;max-width:70em}h1{color:#e0e0e0;margin-bottom:0.2em}.note{color:#888;font-size:0.85em;margin-top:0}pre.timeline{background:#000;border:1px solid #333;padding:1em;overflow-x:auto;white-space:pre-wrap;word-break:break-word}nav a{color:#8ab4ff;margin-right:1em;text-decoration:none}nav a:hover{text-decoration:underline}form{margin-top:1em}input[type=text]{background:#111;color:#c8c8c8;border:1px solid #444;font-family:inherit;padding:0.4em;width:80%}button{background:#222;color:#c8c8c8;border:1px solid #444;font-family:inherit;padding:0.4em 0.8em}.error{color:#ff6b6b;white-space:pre-wrap}";

fn render_page(store: &StateStore, group_id: GroupId, timeline_text: &str, command_result: Option<(bool, String)>) -> String {
    let groups = store.list_groups().unwrap_or_default();
    let mut nav = String::new();
    for g in &groups {
        nav.push_str(&format!("<a href=\"?group={}\">{}</a>", crate::group::group_id_str(g.group_id), escape_html(&g.name)));
    }
    let result_html = match command_result {
        Some((true, out)) => format!("<pre>{}</pre>", escape_html(&out)),
        Some((false, out)) => format!("<pre class=\"error\">{}</pre>", escape_html(&out)),
        None => String::new(),
    };
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>social-firewall chat</title><style>{STYLE}</style></head><body>\
         <h1>social-firewall</h1><p class=\"note\">party-line chat — LAN-reachable, same privilege as the CLI</p>\
         <nav>{nav}</nav>\
         <pre class=\"timeline\">{}</pre>\
         {result_html}\
         <form method=\"POST\" action=\"?group={group}\">\
         <input type=\"hidden\" name=\"group\" value=\"{group}\">\
         <input type=\"text\" name=\"input\" placeholder=\"message, or /command --flags\" autofocus>\
         <button type=\"submit\">send</button>\
         </form></body></html>",
        escape_html(timeline_text),
        group = crate::group::group_id_str(group_id),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::{FederationId, Hash32, PublicKeyBytes, UserId};

    fn store_with_self() -> (StateStore, GroupId) {
        let store = StateStore::open_in_memory().unwrap();
        let user = UserId { federation: FederationId(Hash32([1; 32])), local_id: Hash32([2; 32]) };
        store.set_self_identity(user, PublicKeyBytes([1; 32]), &[4; 32], None).unwrap();
        crate::group::create_self_group(&store, user, &PublicKeyBytes([1; 32])).unwrap();
        let gid = crate::group::self_group_id(&PublicKeyBytes([1; 32]));
        (store, gid)
    }

    #[test]
    fn render_page_includes_the_group_nav_and_the_timeline_text() {
        let (store, gid) = store_with_self();
        let html = render_page(&store, gid, "*** alice has joined the group", None);
        assert!(html.contains("self"), "expected the self group to appear in nav, got:\n{html}");
        assert!(html.contains("alice has joined the group"));
        assert!(html.contains("<form method=\"POST\""));
    }

    #[test]
    fn render_page_escapes_a_maliciously_crafted_group_name() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = UserId { federation: FederationId(Hash32([9; 32])), local_id: Hash32([9; 32]) };
        store.set_self_identity(owner, PublicKeyBytes([9; 32]), &[9; 32], None).unwrap();
        crate::group::create_self_group(&store, owner, &PublicKeyBytes([9; 32])).unwrap();
        // A group whose name is peer-controlled and hostile, ingested the
        // normal way — reusing an existing group-construction helper is
        // out of scope here, so build+sign one directly via the same
        // ingest path other tests already use.
        let group_id = domain_types::GroupId(Hash32([2; 32]));
        let mut g = domain_types::Group {
            group_id,
            published_by: owner,
            sequence: 0,
            name: "<script>alert(1)</script>".into(),
            description: "d".into(),
            join_prompt: None,
            party_line_moderated: false,
            voiced_members: vec![],
            owners: vec![owner],
            admins: vec![],
            voting_members: vec![owner],
            non_voting_members: vec![],
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: domain_types::SignatureBytes([0; 64]),
        };
        let _ = &mut g;
        store.ingest_group(&g).unwrap();

        let self_group = crate::group::self_group_id(&PublicKeyBytes([9; 32]));
        let html = render_page(&store, self_group, "", None);
        assert!(!html.contains("<script>alert(1)</script>"), "a peer-controlled group name must never be emitted unescaped");
        assert!(html.contains("&lt;script&gt;"));
    }
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p sf-cli --bin sf -- cgi::`
Expected: FAIL to compile — `mod cgi;` isn't registered in `main.rs` yet. Add `mod cgi;` to the existing `mod` block.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p sf-cli --bin sf -- cgi::`
Expected: 2 tests pass.

- [ ] **Step 5: Implement `run_cgi`'s GET path**

Add to `crates/cli/src/cgi.rs`, replacing the module doc's forward reference with real code:

```rust
#[derive(serde::Deserialize, Default)]
struct ChatQuery {
    group: Option<String>,
}

pub fn run_cgi() {
    let store = match StateStore::open(Path::new(DB_PATH)) {
        Ok(s) => s,
        Err(e) => {
            print!("Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nfailed to open state store: {e}");
            return;
        }
    };
    let method = std::env::var("REQUEST_METHOD").unwrap_or_default();
    let query = std::env::var("QUERY_STRING").unwrap_or_default();
    let parsed_query: ChatQuery = serde_urlencoded::from_str(&query).unwrap_or_default();

    let group_id = match resolve_group(&store, parsed_query.group.as_deref()) {
        Ok(g) => g,
        Err(e) => {
            print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\n{e}");
            return;
        }
    };

    match method.as_str() {
        "GET" => {
            let timeline = run_sf_subprocess(&["list-party-line", "--group", &crate::group::group_id_str(group_id)]);
            let body = render_page(&store, group_id, &timeline.output, None);
            print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{body}");
        }
        "POST" => handle_post(&store, group_id),
        _ => print!("Status: 405 Method Not Allowed\r\nContent-Type: text/plain\r\n\r\nmethod not allowed"),
    }
}

/// Resolves the `?group=` query param to a real `GroupId`, defaulting to
/// this identity's own "self" group when absent.
fn resolve_group(store: &StateStore, requested: Option<&str>) -> anyhow::Result<GroupId> {
    match requested {
        Some(hex) => crate::group::parse_group_id(hex),
        None => {
            let (_, pubkey) = store.get_self_identity()?.ok_or_else(|| anyhow::anyhow!("no identity yet — run init-identity first"))?;
            Ok(crate::group::self_group_id(&pubkey))
        }
    }
}

struct SubprocessOutput {
    success: bool,
    output: String,
}

/// Re-invokes this same `sf` binary as a subprocess with `--db` pointing
/// at the fixed CGI database path, plus whatever real CLI arguments are
/// passed — see this module's own doc comment on why. Combines stdout and
/// stderr into one string (matching what a human at a terminal sees).
fn run_sf_subprocess(args: &[&str]) -> SubprocessOutput {
    let exe = std::env::current_exe().unwrap_or_else(|_| Path::new("/usr/bin/sf").to_path_buf());
    let output = std::process::Command::new(exe).arg("--db").arg(DB_PATH).args(args).output();
    match output {
        Ok(out) => {
            let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
            combined.push_str(&String::from_utf8_lossy(&out.stderr));
            SubprocessOutput { success: out.status.success(), output: combined }
        }
        Err(e) => SubprocessOutput { success: false, output: format!("failed to invoke sf: {e}") },
    }
}
```

`parse_group_id` and `group_id_str` already exist in `group.rs` as `pub(crate) fn parse_group_id` / a private `fn group_id_str` — widen `group_id_str` to `pub(crate)` if it isn't already (Task 2's Step 9 may have already done this for `notify.rs`'s sake; if so, this is a no-op).

`handle_post` is a forward reference to Task 5 — for this task, add a temporary stub so the module compiles:

```rust
fn handle_post(_store: &StateStore, _group_id: GroupId) {
    print!("Status: 501 Not Implemented\r\nContent-Type: text/plain\r\n\r\nPOST not implemented yet");
}
```

(Task 5 replaces this stub with the real implementation — do not leave it as-is once Task 5 is done.)

- [ ] **Step 6: Manually verify the GET path against the real binary**

```bash
cargo build -p sf-cli
rm -f /tmp/cgi_verify.sqlite
target/debug/sf --db /tmp/cgi_verify.sqlite init-identity --display-name test
REQUEST_METHOD=GET QUERY_STRING="" \
  DB_OVERRIDE_NOTE="this manual check can't easily point run_cgi at /tmp — see note below" \
  true
```

Since `DB_PATH` is a compile-time constant pointing at `/etc/kestrel/social-firewall/...`, a full manual CGI invocation isn't practical outside a real router filesystem in this step. Instead, verify indirectly: confirm the binary builds and the unit tests (Step 4) exercise `render_page`/`resolve_group` directly. Real end-to-end CGI verification (uhttpd actually invoking this) is a Task 6 concern once `install.sh` wiring exists — note this explicitly rather than skipping the check silently.

- [ ] **Step 7: Commit**

```bash
git add crates/cli
git commit -m "cli: CGI skeleton, GET rendering of the party-line timeline"
```

---

### Task 5: CGI POST (commands + messages) and `main()`/`install.sh` wiring

**Files:**
- Modify: `crates/cli/src/cgi.rs` (replace the `handle_post` stub)
- Modify: `crates/cli/src/main.rs` (the CGI hook at the top of `main()`)
- Modify: `crates/cli/Cargo.toml` (add `shell-words`)
- Modify: `install.sh` (cgi-bin symlink + `uhttpd.main.cgi_prefix`)

**Interfaces:**
- Consumes: `run_sf_subprocess`, `render_page`, `resolve_group` (Task 4).
- Produces: nothing consumed by a later task — this is the last piece of the CGI surface itself.

- [ ] **Step 1: Add the dependency**

```toml
# crates/cli/Cargo.toml — add to [dependencies]
shell-words = "1"
```

- [ ] **Step 2: Write the failing test for command-vs-message routing**

Add to `crates/cli/src/cgi.rs`'s test module:

```rust
#[test]
fn build_argv_treats_a_slash_prefixed_input_as_a_command() {
    let argv = build_argv("/list-groups", "deadbeef".repeat(8).as_str()).unwrap();
    assert_eq!(argv, vec!["list-groups"]);
}

#[test]
fn build_argv_shell_tokenizes_a_slash_command_with_quoted_args() {
    let argv = build_argv("/publish-party-line --group abc --body \"hello world\"", "deadbeef").unwrap();
    assert_eq!(argv, vec!["publish-party-line", "--group", "abc", "--body", "hello world"]);
}

#[test]
fn build_argv_treats_plain_text_as_a_party_line_post_to_the_current_group() {
    let group_hex = "ab".repeat(32);
    let argv = build_argv("hello everyone", &group_hex).unwrap();
    assert_eq!(argv, vec!["publish-party-line", "--group", group_hex.as_str(), "--body", "hello everyone", "--out-dir", CHAT_OUT_DIR]);
}

#[test]
fn build_argv_rejects_unmatched_quotes_cleanly() {
    let err = build_argv("/publish-party-line --body \"unterminated", "abc").unwrap_err();
    assert!(!err.to_string().is_empty());
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `cargo test -p sf-cli --bin sf -- cgi::build_argv`
Expected: FAIL — `build_argv`/`CHAT_OUT_DIR` don't exist yet.

- [ ] **Step 4: Implement `build_argv` and replace the `handle_post` stub**

Add near the top of `crates/cli/src/cgi.rs`:

```rust
const CHAT_OUT_DIR: &str = "/etc/kestrel/social-firewall/chat-out";
```

Add `build_argv`:

```rust
/// Turns one chat-box submission into the argv `sf` would see if a human
/// typed it at a terminal. A leading `/` means "this is a command" — the
/// rest is shell-tokenized (so quoted values with spaces work) and used
/// as-is. Anything else is shorthand for posting a plain message to the
/// current group.
fn build_argv(input: &str, current_group_hex: &str) -> anyhow::Result<Vec<String>> {
    if let Some(command_text) = input.strip_prefix('/') {
        Ok(shell_words::split(command_text)?)
    } else {
        Ok(vec!["publish-party-line".to_string(), "--group".to_string(), current_group_hex.to_string(), "--body".to_string(), input.to_string(), "--out-dir".to_string(), CHAT_OUT_DIR.to_string()])
    }
}
```

Replace the `handle_post` stub with:

```rust
#[derive(serde::Deserialize)]
struct ChatForm {
    input: String,
}

fn handle_post(store: &StateStore, group_id: GroupId) {
    let body = read_stdin_body();
    let form: ChatForm = match serde_urlencoded::from_str(&body) {
        Ok(f) => f,
        Err(e) => {
            print!("Status: 400 Bad Request\r\nContent-Type: text/plain\r\n\r\ninvalid form body: {e}");
            return;
        }
    };
    let group_hex = crate::group::group_id_str(group_id);
    let argv = match build_argv(&form.input, &group_hex) {
        Ok(a) => a,
        Err(e) => {
            let html = render_page(store, group_id, "", Some((false, format!("could not parse: {e}"))));
            print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
            return;
        }
    };
    let args: Vec<&str> = argv.iter().map(String::as_str).collect();
    let result = run_sf_subprocess(&args);
    let timeline = run_sf_subprocess(&["list-party-line", "--group", &group_hex]);
    let html = render_page(store, group_id, &timeline.output, Some((result.success, result.output)));
    print!("Status: 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n{html}");
}

/// Read the POST body from stdin, honoring CONTENT_LENGTH when present —
/// same shape as kestreld's own `read_body()` (`networks/kestreld-rs/src/cgi.rs`).
fn read_stdin_body() -> String {
    use std::io::Read;
    let len: usize = std::env::var("CONTENT_LENGTH").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let mut buf = Vec::new();
    if len > 0 {
        buf.resize(len, 0);
        if std::io::stdin().read_exact(&mut buf).is_err() {
            buf.clear();
        }
    } else {
        let _ = std::io::stdin().read_to_end(&mut buf);
    }
    String::from_utf8_lossy(&buf).into_owned()
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test -p sf-cli --bin sf -- cgi::`
Expected: all `cgi::` tests pass (the 4 new `build_argv` tests plus the 2 from Task 4).

- [ ] **Step 6: Hook `cgi::run_cgi` into `main()`**

In `crates/cli/src/main.rs`, find `fn main() -> Result<()> {` (currently line 690) and add the CGI check as the very first line, before `Cli::parse()`:

```rust
fn main() -> Result<()> {
    if cgi::is_cgi() {
        cgi::run_cgi();
        return Ok(());
    }
    let cli = Cli::parse();
    // ... rest of main() unchanged
```

- [ ] **Step 7: Run the full existing test suite to confirm the hook doesn't affect normal CLI invocation**

Run: `cargo test -p sf-cli --bin sf && cargo test -p sf-cli --test cli`
Expected: all pre-existing tests pass unchanged — none of them set `REQUEST_METHOD` in their environment, so `cgi::is_cgi()` is `false` for every existing test and `main()` proceeds exactly as before.

- [ ] **Step 8: Wire `install.sh`'s cgi-bin deployment**

In `install.sh`, add a new section after the existing cron section (after Task 2's Step 12 additions), mirroring kestreld's exact deployment pattern (`ln -sf` + idempotent `uci` guard):

```sh
# ── CGI (interactive party-line chat) ───────────────────────────────────────
# uhttpd runs this fresh per request, same as any other CGI script; no
# daemon, no extra port, no reverse proxy needed — see
# networks/kestreld-rs/install.sh for the identical precedent this mirrors.

mkdir -p /www/cgi-bin
ln -sf /usr/bin/sf /www/cgi-bin/sf-chat

if ! uci -q get uhttpd.main.cgi_prefix >/dev/null 2>&1; then
    uci set uhttpd.main.cgi_prefix=/cgi-bin
    uci commit uhttpd
    /etc/init.d/uhttpd restart 2>/dev/null || true
fi
```

Add this right before the final `echo "Installed."` block, and extend that block to also print the chat URL:

```sh
echo "  Chat: http://<router-ip>/cgi-bin/sf-chat"
```

- [ ] **Step 9: Commit**

```bash
git add crates/cli install.sh
git commit -m "cli: CGI POST handler (commands + messages), install.sh cgi-bin wiring"
```

---

### Task 6: Full verification and plan-file update

**Files:** none (verification only)

- [ ] **Step 1: Full workspace build and test**

Run: `cargo build --workspace --all-targets && cargo test --workspace`
Expected: builds clean, every test passes.

- [ ] **Step 2: Clippy**

Run: `cargo clippy --workspace --all-targets 2>&1 | grep warning`
Expected: only the pre-existing baseline warnings from before this plan (see the p2p-transport plan's own documented baseline, unchanged by this plan) plus nothing new. If something new appears, report it rather than silently fixing it outside this task's own verification scope — flag it for the final whole-branch review.

- [ ] **Step 3: Manual end-to-end verification against the real binary**

```bash
cargo build -p sf-cli
rm -f /tmp/e2e_chat.sqlite
target/debug/sf --db /tmp/e2e_chat.sqlite init-identity --display-name alice
target/debug/sf --db /tmp/e2e_chat.sqlite set-ntfy-topic --url http://127.0.0.1:9/none
target/debug/sf --db /tmp/e2e_chat.sqlite notify
GROUP=$(target/debug/sf --db /tmp/e2e_chat.sqlite list-groups | grep -oE '[0-9a-f]{64}' | head -1)
target/debug/sf --db /tmp/e2e_chat.sqlite list-party-line --group "$GROUP"
rm -f /tmp/e2e_chat.sqlite
```
Expected: every command succeeds; `list-party-line` runs cleanly against the auto-created self group (empty timeline is fine — no pending items exist in this fresh scratch database).

- [ ] **Step 4: Update the persistent project plan file**

Add a new numbered item to `/home/traph/.claude/plans/floofy-skipping-cerf.md`'s "Future work" list (matching the style/density of the existing items — read a couple of the most recent ones first, e.g. items 13-16, to match voice), covering: the implicit "self" group, the idempotent notifier and its three pending-item sources (group joins, tunnel requests, tunnel service requests — and explicitly note that "votes needing attention" from the original design spec was left out of the notifier's scope, since there's no well-defined "a vote is needed" event in the current data model to key off — that would need its own "call for votes" statement type, not built here), the minimal ntfy HTTP/1.1 client and its plain-HTTP-only scope, and the CGI chat surface's subprocess-re-invocation architecture (a deliberate refinement from the original spec's sketch of in-process `Command::parse_from` dispatch, chosen because this codebase's CLI commands all `println!` directly with no injectable output sink, and re-invoking the real binary avoids a large, risky refactor while still guaranteeing zero duplicated command logic).

- [ ] **Step 5: Final commit**

```bash
git add -A -- ':!target' ':!../networks'
git status
git commit -m "interactive party-line: verification pass"
```

(Review `git status` before committing — confirm nothing outside `social-firewall/` is staged, matching this whole plan's own established discipline around the shared parent repo.)

---

## Self-Review Notes

- **Spec coverage:** Serving (uhttpd/CGI) — Tasks 4-5. Commands reuse the CLI's own parser — Task 5, refined to subprocess re-invocation (documented deviation, see below). Notifications land in *some* party line, no exceptions — Task 1 (self group) + Task 2 (the three pending-item sources), with one explicit, reasoned scope reduction (vote notifications — see Task 6 Step 4). Optional ntfy push — Task 3. Styling — Task 4's `STYLE` const. Error handling (malformed/unauthorized command surfaces the CLI's own error; ntfy failure never blocks the post) — Task 5's `handle_post` renders `result.output` regardless of `success`; Task 3's `maybe_push_ntfy` never propagates a `Result`. Testing — every task has real, behavior-verifying tests (a real loopback TCP server for `ntfy`, a real subprocess for the CLI regression test, real signed round-trips for the notifier).
- **Documented deviation from the spec:** the spec's Data Flow section sketches in-process `Command::parse_from` dispatch for POST. This plan uses subprocess re-invocation of the `sf` binary instead (Task 4/5), because every existing CLI command handler writes directly to stdout via `println!` with no injectable output sink — refactoring dozens of handlers to accept a generic writer would be a large, invasive change far outside this feature's own scope, and would risk exactly the kind of cross-cutting regression the p2p-transport plan's final review found costly to catch after the fact. Subprocess re-invocation achieves the same "no second implementation of any command's behavior" goal with zero changes to any existing command handler.
- **Type consistency:** `GroupId`, `group::group_id_str`, `group::parse_group_id`, `group::self_group_id` are used identically across `notify.rs` (Task 2) and `cgi.rs` (Tasks 4-5). `NotifyReport` (Task 2) is not consumed by any later task's types, only printed — no drift risk. `build_argv`'s return type (`Vec<String>`) matches `run_sf_subprocess`'s expected `&[&str]` via the `.iter().map(String::as_str).collect()` conversion shown explicitly in Task 5 Step 4.
