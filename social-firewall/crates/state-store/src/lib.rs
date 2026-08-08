//! SQLite-backed local state. Everything here is either the owner's own
//! private data (follows, overrides, own opinions) or a rebuildable local
//! cache/replica of synced data (ingested opinions, federation statements,
//! effective-policy cache) — never the authoritative copy of anyone else's
//! signed record, which always lives in its author's own log first.
//!
//! Deliberately `rusqlite`, not `sqlx`: this is a local-only, single-writer
//! embedded store. `sqlx`'s multi-backend `Any` driver is the right tool
//! *if and when* real MySQL/Postgres pluggability is wanted for a
//! federation-side relay component — a separate, later decision, out of
//! scope for this router-local skeleton.
//!
//! Operational practices baked in at `open()`: WAL mode (so readers never
//! block the single writer), `synchronous=NORMAL` (durable enough, easier
//! on flash write-wear than FULL), `foreign_keys=ON`. Forward-only
//! migrations, applied in a transaction each. Corruption recovery
//! (`PRAGMA integrity_check` + quarantine-and-rebuild of cache tables) is a
//! documented next step, not yet implemented here.

use domain_types::{
    Contribution, DeviceApprovalOpinion, DeviceId, DevicePresenceObservation, DirectMessage,
    FederationId, FederationStatement, FederationTrustRule, FingerprintComment,
    FingerprintObservation, Group, GroupBlockReport, GroupId, GroupJoinRequest, GroupTrustRule,
    GroupVote, Hash32, LocalOverride, LocalProfile, LocalRouteProfile, LocalTrustRule,
    MessagingPublicKeyBytes, NodeId, OpinionRef, OverrideKind, PartyLineMessage, PolicyAction,
    PolicyEntry, PolicyOpinion, PolicyVote, PublicKeyBytes, Reason, ReasonCode, SharedPolicy,
    SharedRuleEntry, SharedRuleList, SignatureBytes, Stance, StatementAuthor, StatementRef,
    TargetSelector, TunnelAdvertisement, TunnelConnectionAccept, TunnelConnectionRequest,
    TunnelServiceRequest, TunnelTrustRule, UserId, Visibility, WgPublicKeyBytes,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::path::Path;

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_init.sql")),
    (2, include_str!("../migrations/0002_nft_enforcement.sql")),
    (3, include_str!("../migrations/0003_tunnels.sql")),
    (4, include_str!("../migrations/0004_shared_rule_lists.sql")),
    (
        5,
        include_str!("../migrations/0005_enforced_decision_contributors.sql"),
    ),
    (
        6,
        include_str!("../migrations/0006_follow_display_names.sql"),
    ),
    (7, include_str!("../migrations/0007_tunnel_tags.sql")),
    (8, include_str!("../migrations/0008_tunnel_limits.sql")),
    (9, include_str!("../migrations/0009_groups.sql")),
    (
        10,
        include_str!("../migrations/0010_group_contributions.sql"),
    ),
    (11, include_str!("../migrations/0011_device_approvals.sql")),
    (
        12,
        include_str!("../migrations/0012_group_join_features.sql"),
    ),
    (
        13,
        include_str!("../migrations/0013_group_block_reports.sql"),
    ),
    (
        14,
        include_str!("../migrations/0014_group_party_line_voice.sql"),
    ),
    (15, include_str!("../migrations/0015_tunnel_ipv6.sql")),
    (
        16,
        include_str!("../migrations/0016_group_membership_events.sql"),
    ),
    (
        17,
        include_str!("../migrations/0017_tunnel_transfer_totals.sql"),
    ),
    (
        18,
        include_str!("../migrations/0018_tunnel_reciprocity.sql"),
    ),
    (
        19,
        include_str!("../migrations/0019_party_line_reply_target.sql"),
    ),
    (20, include_str!("../migrations/0020_iroh_addressing.sql")),
    (21, include_str!("../migrations/0021_notified_items.sql")),
    (22, include_str!("../migrations/0022_ntfy_config.sql")),
    (23, include_str!("../migrations/0023_outbox.sql")),
    (
        24,
        include_str!("../migrations/0024_party_line_author_keys.sql"),
    ),
    (25, include_str!("../migrations/0025_shared_policies.sql")),
    (26, include_str!("../migrations/0026_policy_votes.sql")),
    (
        27,
        include_str!("../migrations/0027_fingerprint_group_data.sql"),
    ),
    (28, include_str!("../migrations/0028_local_profiles.sql")),
    (29, include_str!("../migrations/0029_route_profiles.sql")),
    (
        30,
        include_str!("../migrations/0030_group_fingerprint_keys.sql"),
    ),
    (31, include_str!("../migrations/0031_device_presence.sql")),
    (
        32,
        include_str!("../migrations/0032_reticulum_addresses.sql"),
    ),
    (
        33,
        include_str!("../migrations/0033_party_line_received_at.sql"),
    ),
    (34, include_str!("../migrations/0034_local_irc_history.sql")),
    (35, include_str!("../migrations/0035_direct_messages.sql")),
];

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("corrupt stored data: {0}")]
    Encoding(String),
    #[error("{0} is not a followed user — refusing to ingest")]
    NotFollowed(String),
    #[error("no self identity exists yet — run init-identity first")]
    NoSelfIdentity,
    #[error("{0}")]
    Unauthorized(String),
    #[error("{0}")]
    InvalidGroup(String),
    #[error("{0}")]
    InvalidPresence(String),
}

pub struct StateStore {
    conn: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxEnvelope {
    pub id: i64,
    pub destination_node_id: String,
    pub statement_kind: i64,
    pub payload: Vec<u8>,
    pub attempts: i64,
    pub next_retry: i64,
    pub last_error: Option<String>,
    pub delivered: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerTransportAddress {
    pub peer: UserId,
    pub transport: String,
    pub address: String,
    pub enabled: bool,
    pub verified: bool,
    pub updated_at: i64,
}

impl StateStore {
    pub fn enqueue_outbox(
        &self,
        destination_node_id: &str,
        statement_kind: i64,
        payload: &[u8],
        next_retry: i64,
    ) -> Result<i64, StoreError> {
        self.conn.execute(
            "INSERT INTO outbound_outbox (destination_node_id, statement_kind, payload, next_retry, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![destination_node_id, statement_kind, payload, next_retry, now_unix()],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn list_due_outbox(&self, now: i64) -> Result<Vec<OutboxEnvelope>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT outbox_id, destination_node_id, statement_kind, payload, attempts, next_retry, last_error, delivered FROM outbound_outbox WHERE delivered = 0 AND next_retry <= ?1 ORDER BY outbox_id",
        )?;
        let rows = stmt.query_map(params![now], |row| {
            Ok(OutboxEnvelope {
                id: row.get(0)?,
                destination_node_id: row.get(1)?,
                statement_kind: row.get(2)?,
                payload: row.get(3)?,
                attempts: row.get(4)?,
                next_retry: row.get(5)?,
                last_error: row.get(6)?,
                delivered: row.get::<_, i64>(7)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn mark_outbox_success(&self, id: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE outbound_outbox SET delivered = 1, last_error = NULL WHERE outbox_id = ?1",
            params![id],
        )?;
        Ok(())
    }

    pub fn mark_outbox_failure(&self, id: i64, error: &str, now: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE outbound_outbox SET attempts = attempts + 1, next_retry = ?2 + (1 << MIN(attempts, 10)), last_error = ?, delivered = 0 WHERE outbox_id = ?1",
            params![id, now, error],
        )?;
        Ok(())
    }

    /// Opens (creating if absent) a SQLite database at `path` and applies
    /// any outstanding migrations. `path` must be on persistent storage —
    /// this never opens on tmpfs, and it's the caller's job to pass a real
    /// path (e.g. under `/etc/kestrel/social-firewall/`, not `/tmp`).
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA wal_autocheckpoint = 1000;",
        )?;
        let store = Self { conn };
        store.run_migrations()?;
        Ok(store)
    }

    /// In-memory database — for tests only, never for real router state
    /// (nothing is persisted across process restarts).
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        let store = Self { conn };
        store.run_migrations()?;
        Ok(store)
    }

    fn run_migrations(&self) -> Result<(), StoreError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version INTEGER PRIMARY KEY,
                 applied_at INTEGER NOT NULL
             );",
        )?;
        let current: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )?;
        for (version, sql) in MIGRATIONS {
            if *version <= current {
                continue;
            }
            self.conn.execute_batch(sql)?;
            self.conn.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
                params![version, now_unix()],
            )?;
        }
        Ok(())
    }

    // ── Self identity ────────────────────────────────────────────────────

    pub fn set_self_identity(
        &self,
        user: UserId,
        pubkey: PublicKeyBytes,
        seed: &[u8; 32],
        display_name: Option<&str>,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO federations (federation_id, display_name, genesis_blob, joined_at, is_home)
             VALUES (?1, ?2, X'', ?3, 1)
             ON CONFLICT(federation_id) DO NOTHING",
            params![user.federation.0 .0.as_slice(), user.federation.0.to_string(), now_unix()],
        )?;
        self.conn.execute(
            "INSERT INTO users (federation_id, local_id, current_pubkey, display_name, is_self, secret_seed)
             VALUES (?1, ?2, ?3, ?4, 1, ?5)
             ON CONFLICT(federation_id, local_id) DO UPDATE SET current_pubkey = excluded.current_pubkey, display_name = excluded.display_name, secret_seed = excluded.secret_seed",
            params![
                user.federation.0 .0.as_slice(),
                user.local_id.0.as_slice(),
                pubkey.0.as_slice(),
                display_name,
                seed.as_slice(),
            ],
        )?;
        Ok(())
    }

    pub fn get_self_seed(&self) -> Result<Option<[u8; 32]>, StoreError> {
        self.conn
            .query_row(
                "SELECT secret_seed FROM users WHERE is_self = 1 LIMIT 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .map(|bytes| bytes_to_32(&bytes))
            .transpose()
    }

    pub fn get_self_identity(&self) -> Result<Option<(UserId, PublicKeyBytes)>, StoreError> {
        self.conn
            .query_row(
                "SELECT federation_id, local_id, current_pubkey FROM users WHERE is_self = 1 LIMIT 1",
                [],
                |row| {
                    let fed: Vec<u8> = row.get(0)?;
                    let local: Vec<u8> = row.get(1)?;
                    let pk: Vec<u8> = row.get(2)?;
                    Ok((fed, local, pk))
                },
            )
            .optional()?
            .map(|(fed, local, pk)| -> Result<_, StoreError> {
                Ok((
                    UserId { federation: FederationId(bytes_to_hash32(&fed)?), local_id: bytes_to_hash32(&local)? },
                    PublicKeyBytes(bytes_to_32(&pk)?),
                ))
            })
            .transpose()
    }

    /// Returns the locally stored public nickname for a known user. For the
    /// local identity this is the name supplied to `init-identity`; foreign
    /// users may have a value if a future identity/profile exchange stores
    /// one. Local follow labels remain separate and take precedence in the
    /// CLI display layer.
    pub fn get_user_display_name(&self, user: &UserId) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row(
                "SELECT display_name FROM users WHERE federation_id = ?1 AND local_id = ?2",
                params![user.federation.0 .0.as_slice(), user.local_id.0.as_slice()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map(|name| name.flatten())
            .map_err(Into::into)
    }

    pub fn set_self_display_name(&self, display_name: Option<&str>) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE users SET display_name = ?1 WHERE is_self = 1",
            params![display_name],
        )?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn has_been_notified(&self, item_kind: &str, item_key: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT 1 FROM notified_items WHERE item_kind = ?1 AND item_key = ?2",
                params![item_kind, item_key],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn append_local_irc_message(
        &self,
        nickname: &str,
        body: &str,
        issued_at: i64,
        max_age_seconds: i64,
        max_messages: i64,
        max_bytes: i64,
    ) -> Result<(), StoreError> {
        self.prune_local_irc_history(issued_at, max_age_seconds, max_messages, max_bytes)?;
        self.conn.execute(
            "INSERT INTO local_irc_history (nickname, body, issued_at, byte_len) VALUES (?1, ?2, ?3, ?4)",
            params![nickname, body, issued_at, body.len() as i64],
        )?;
        self.prune_local_irc_history(issued_at, max_age_seconds, max_messages, max_bytes)
    }

    pub fn prune_local_irc_history(
        &self,
        now: i64,
        max_age_seconds: i64,
        max_messages: i64,
        max_bytes: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM local_irc_history WHERE issued_at < ?1",
            params![now.saturating_sub(max_age_seconds)],
        )?;
        loop {
            let (count, bytes): (i64, i64) = self.conn.query_row(
                "SELECT COUNT(*), COALESCE(SUM(byte_len), 0) FROM local_irc_history",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if count <= max_messages && bytes <= max_bytes {
                break;
            }
            self.conn.execute(
                "DELETE FROM local_irc_history WHERE message_id = (SELECT message_id FROM local_irc_history ORDER BY issued_at, message_id LIMIT 1)",
                [],
            )?;
        }
        Ok(())
    }

    pub fn list_local_irc_messages(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, i64)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT nickname, body, issued_at FROM local_irc_history ORDER BY issued_at DESC, message_id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
        let mut messages = rows.collect::<Result<Vec<_>, _>>()?;
        messages.reverse();
        Ok(messages)
    }

    pub fn next_direct_message_sequence(&self, sender: &UserId) -> Result<u64, StoreError> {
        let sequence: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(sequence) FROM direct_messages WHERE sender_federation_id = ?1 AND sender_local_id = ?2",
                params![sender.federation.0 .0.as_slice(), sender.local_id.0.as_slice()],
                |row| row.get(0),
            )?;
        Ok(sequence.unwrap_or(-1).saturating_add(1) as u64)
    }

    pub fn store_direct_message(&self, message: &DirectMessage) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO direct_messages (sender_federation_id, sender_local_id, recipient_federation_id, recipient_local_id, sequence, body, issued_at, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) ON CONFLICT(sender_federation_id, sender_local_id, sequence) DO NOTHING",
            params![
                message.sender.federation.0 .0.as_slice(),
                message.sender.local_id.0.as_slice(),
                message.recipient.federation.0 .0.as_slice(),
                message.recipient.local_id.0.as_slice(),
                message.sequence as i64,
                message.body,
                message.issued_at,
                message.signature.0.as_slice(),
            ],
        )?;
        Ok(())
    }

    pub fn list_direct_messages_for(
        &self,
        recipient: &UserId,
    ) -> Result<Vec<DirectMessage>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT sender_federation_id, sender_local_id, sequence, body, issued_at, signature FROM direct_messages WHERE recipient_federation_id = ?1 AND recipient_local_id = ?2 ORDER BY issued_at, sequence",
        )?;
        let rows = stmt.query_map(
            params![
                recipient.federation.0 .0.as_slice(),
                recipient.local_id.0.as_slice()
            ],
            |row| {
                let sender_federation: Vec<u8> = row.get(0)?;
                let sender_local: Vec<u8> = row.get(1)?;
                let signature: Vec<u8> = row.get(5)?;
                Ok((
                    sender_federation,
                    sender_local,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    signature,
                ))
            },
        )?;
        let mut messages = Vec::new();
        for row in rows {
            let (federation, local, sequence, body, issued_at, signature) = row?;
            let federation: [u8; 32] = federation.try_into().map_err(|_| {
                StoreError::Encoding("invalid direct-message sender federation".into())
            })?;
            let local: [u8; 32] = local.try_into().map_err(|_| {
                StoreError::Encoding("invalid direct-message sender local ID".into())
            })?;
            let signature: [u8; 64] = signature
                .try_into()
                .map_err(|_| StoreError::Encoding("invalid direct-message signature".into()))?;
            messages.push(DirectMessage {
                sender: UserId {
                    federation: FederationId(Hash32(federation)),
                    local_id: Hash32(local),
                },
                recipient: *recipient,
                sequence,
                body,
                issued_at,
                signature: SignatureBytes(signature),
            });
        }
        Ok(messages)
    }

    pub fn mark_notified(
        &self,
        item_kind: &str,
        item_key: &str,
        now: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO notified_items (item_kind, item_key, notified_at) VALUES (?1, ?2, ?3) ON CONFLICT DO NOTHING",
            params![item_kind, item_key, now],
        )?;
        Ok(())
    }

    pub fn set_ntfy_topic_url(&self, url: Option<&str>) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE users SET ntfy_topic_url = ?1 WHERE is_self = 1",
            params![url],
        )?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_ntfy_topic_url(&self) -> Result<Option<String>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT ntfy_topic_url FROM users WHERE is_self = 1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn next_own_sequence(&self) -> Result<u64, StoreError> {
        let max: Option<i64> =
            self.conn
                .query_row("SELECT MAX(sequence) FROM own_opinion_log", [], |row| {
                    row.get(0)
                })?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Same MAX-based counter pattern as `next_own_sequence`, scoped to
    /// this router's own rows in `tunnel_advertisements` — each is a
    /// distinct per-author sequence, same as opinions.
    pub fn next_tunnel_advertisement_sequence(&self, author: &UserId) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM tunnel_advertisements WHERE provider_federation_id = ?1 AND provider_local_id = ?2",
            params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    pub fn next_tunnel_service_request_sequence(&self, author: &UserId) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM tunnel_service_requests WHERE requester_federation_id = ?1 AND requester_local_id = ?2",
            params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    pub fn next_tunnel_connection_request_sequence(
        &self,
        author: &UserId,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM tunnel_connection_requests WHERE requester_federation_id = ?1 AND requester_local_id = ?2",
            params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    // ── Follows / trust ──────────────────────────────────────────────────

    pub fn upsert_follow(&self, rule: &LocalTrustRule) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO follows (federation_id, local_id, allow_weight, deny_weight, advisory_only, excluded, category_filter, display_name, iroh_node_id, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(federation_id, local_id) DO UPDATE SET
                allow_weight = excluded.allow_weight,
                deny_weight = excluded.deny_weight,
                advisory_only = excluded.advisory_only,
                excluded = excluded.excluded,
                category_filter = excluded.category_filter,
                display_name = excluded.display_name,
                iroh_node_id = excluded.iroh_node_id,
                expires_at = excluded.expires_at",
            params![
                rule.user.federation.0 .0.as_slice(),
                rule.user.local_id.0.as_slice(),
                rule.allow_weight,
                rule.deny_weight,
                rule.advisory_only,
                rule.excluded,
                rule.category_filter,
                rule.display_name,
                rule.iroh_node_id,
                rule.expires_at,
                rule.created_at,
            ],
        )?;
        Ok(())
    }

    /// `federations` today only ever has a row for this router's own home
    /// federation (populated by `set_self_identity`) — a foreign
    /// federation a followed peer belongs to has no known display name at
    /// all yet, so `None` here is the common case, not an edge case.
    /// Callers (see the IRC-style party-line formatting in `cli`) are
    /// expected to fall back to the raw hex id when this returns `None`.
    pub fn get_federation_display_name(
        &self,
        federation: &FederationId,
    ) -> Result<Option<String>, StoreError> {
        self.conn
            .query_row(
                "SELECT display_name FROM federations WHERE federation_id = ?1",
                params![federation.0 .0.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn set_home_federation_display_name(
        &self,
        display_name: Option<&str>,
    ) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE federations
             SET display_name = CASE WHEN ?1 IS NULL THEN lower(hex(federation_id)) ELSE ?1 END
             WHERE is_home = 1",
            params![display_name],
        )?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_follow(&self, user: &UserId) -> Result<Option<LocalTrustRule>, StoreError> {
        self.conn
            .query_row(
                "SELECT allow_weight, deny_weight, advisory_only, excluded, category_filter, display_name, iroh_node_id, expires_at, created_at
                 FROM follows WHERE federation_id = ?1 AND local_id = ?2",
                params![user.federation.0 .0.as_slice(), user.local_id.0.as_slice()],
                |row| row_to_trust_rule(row, *user),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_follows(&self) -> Result<Vec<LocalTrustRule>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT federation_id, local_id, allow_weight, deny_weight, advisory_only, excluded, category_filter, display_name, iroh_node_id, expires_at, created_at FROM follows",
        )?;
        let rows = stmt.query_map([], |row| {
            let fed: Vec<u8> = row.get(0)?;
            let local: Vec<u8> = row.get(1)?;
            Ok((
                fed,
                local,
                row.get::<_, f64>(2)?,
                row.get::<_, f64>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, i64>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                allow_weight,
                deny_weight,
                advisory_only,
                excluded,
                category_filter,
                display_name,
                iroh_node_id,
                expires_at,
                created_at,
            ) = r?;
            let user = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            out.push(LocalTrustRule {
                user,
                allow_weight,
                deny_weight,
                advisory_only,
                excluded,
                category_filter,
                display_name,
                iroh_node_id,
                expires_at,
                created_at,
            });
        }
        Ok(out)
    }

    /// Resolves a locally-assigned follow label back to the `UserId` it
    /// names, scoped to one federation — the lookup half of
    /// `LocalTrustRule::display_name`'s address-book model. `None` if no
    /// follow in this federation has been given exactly this name.
    pub fn resolve_user_by_name(
        &self,
        federation: &FederationId,
        name: &str,
    ) -> Result<Option<UserId>, StoreError> {
        self.conn
            .query_row(
                "SELECT local_id FROM follows WHERE federation_id = ?1 AND display_name = ?2",
                params![federation.0 .0.as_slice(), name],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|local| {
                Ok(UserId {
                    federation: *federation,
                    local_id: bytes_to_hash32(&local)?,
                })
            })
            .transpose()
    }

    /// Reverse lookup of `LocalTrustRule::iroh_node_id`: given an Iroh
    /// node id observed on an inbound connection, which followed user
    /// (if any) does it belong to? `None` means nobody this router
    /// follows has claimed that node id, which is the network path's
    /// equivalent of "a stranger handed you a file" — `cli::tunnel::
    /// listen` refuses to dispatch in that case.
    ///
    /// Not scoped to a federation, unlike `resolve_user_by_name`: a node
    /// id is a global cryptographic identity, not a per-federation label.
    pub fn find_follow_by_iroh_node_id(&self, node_id: &str) -> Result<Option<UserId>, StoreError> {
        self.conn
            .query_row(
                "SELECT federation_id, local_id FROM follows WHERE iroh_node_id = ?1",
                params![node_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(fed, local)| {
                Ok(UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                })
            })
            .transpose()
    }

    /// Reverse lookup of a configured peer transport address. Transport
    /// identities are only accepted for users this router already follows.
    pub fn find_follow_by_transport_address(
        &self,
        transport: &str,
        address: &str,
    ) -> Result<Option<UserId>, StoreError> {
        self.conn
            .query_row(
                "SELECT addresses.federation_id, addresses.local_id
                 FROM peer_transport_addresses AS addresses
                 INNER JOIN follows
                   ON follows.federation_id = addresses.federation_id
                  AND follows.local_id = addresses.local_id
                 WHERE addresses.transport = ?1
                   AND addresses.address = ?2
                   AND addresses.enabled = 1",
                params![transport, address],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(fed, local)| {
                Ok(UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                })
            })
            .transpose()
    }

    pub fn upsert_federation_trust(&self, rule: &FederationTrustRule) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO federation_trust_rules (federation_id, allow_weight, deny_weight, via_relay_full_membership, category_filter, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(federation_id) DO UPDATE SET
                allow_weight = excluded.allow_weight,
                deny_weight = excluded.deny_weight,
                via_relay_full_membership = excluded.via_relay_full_membership,
                category_filter = excluded.category_filter,
                expires_at = excluded.expires_at",
            params![
                rule.federation.0 .0.as_slice(),
                rule.allow_weight,
                rule.deny_weight,
                rule.via_relay_full_membership,
                rule.category_filter,
                rule.expires_at,
                rule.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_federation_trust(
        &self,
        federation: &FederationId,
    ) -> Result<Option<FederationTrustRule>, StoreError> {
        self.conn
            .query_row(
                "SELECT allow_weight, deny_weight, via_relay_full_membership, category_filter, expires_at, created_at
                 FROM federation_trust_rules WHERE federation_id = ?1",
                params![federation.0 .0.as_slice()],
                |row| {
                    Ok(FederationTrustRule {
                        federation: *federation,
                        allow_weight: row.get(0)?,
                        deny_weight: row.get(1)?,
                        via_relay_full_membership: row.get(2)?,
                        category_filter: row.get(3)?,
                        expires_at: row.get(4)?,
                        created_at: row.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    // ── Local overrides ──────────────────────────────────────────────────

    pub fn set_local_override(&self, o: &LocalOverride) -> Result<(), StoreError> {
        let (kind, value) = target_to_kv(&o.target)?;
        self.conn.execute(
            "INSERT INTO local_overrides (target_kind, target_value, stance, kind, note, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(target_kind, target_value) DO UPDATE SET
                stance = excluded.stance,
                kind = excluded.kind,
                note = excluded.note,
                created_at = excluded.created_at,
                expires_at = excluded.expires_at",
            params![kind, value, stance_to_i64(o.stance), override_kind_to_i64(o.kind), o.note, o.created_at, o.expires_at],
        )?;
        Ok(())
    }

    pub fn clear_local_override(&self, target: &TargetSelector) -> Result<(), StoreError> {
        let (kind, value) = target_to_kv(target)?;
        self.conn.execute(
            "DELETE FROM local_overrides WHERE target_kind = ?1 AND target_value = ?2",
            params![kind, value],
        )?;
        Ok(())
    }

    /// At most one row, by construction (natural-key primary key) — a
    /// `Vec` here purely so it slots directly into `policy_engine::PolicyInputs`
    /// without an extra `Option`-to-slice conversion at every call site.
    pub fn get_local_overrides_for(
        &self,
        target: &TargetSelector,
    ) -> Result<Vec<LocalOverride>, StoreError> {
        let (kind, value) = target_to_kv(target)?;
        let row = self
            .conn
            .query_row(
                "SELECT stance, kind, note, created_at, expires_at FROM local_overrides WHERE target_kind = ?1 AND target_value = ?2",
                params![kind, value],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(vec![]),
            Some((stance, kind, note, created_at, expires_at)) => Ok(vec![LocalOverride {
                target: target.clone(),
                stance: stance_from_i64(stance)?,
                kind: override_kind_from_i64(kind)?,
                note,
                created_at,
                expires_at,
            }]),
        }
    }

    // ── Own opinion log ──────────────────────────────────────────────────

    pub fn append_own_opinion(&self, o: &PolicyOpinion) -> Result<(), StoreError> {
        let (kind, value) = target_to_kv(&o.target)?;
        self.conn.execute(
            "INSERT INTO own_opinion_log (sequence, target_kind, target_value, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, supersedes_sequence, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                o.sequence as i64,
                kind,
                value,
                stance_to_i64(o.stance),
                reason_code_to_i64(o.reason.code),
                o.reason.note,
                encode_evidence(&o.reason.evidence),
                o.issued_at,
                o.expires_at,
                o.supersedes.map(|s| s.sequence as i64),
                o.signature.0.as_slice(),
            ],
        )?;
        Ok(())
    }

    pub fn list_own_opinions_for(
        &self,
        target: &TargetSelector,
    ) -> Result<Vec<PolicyOpinion>, StoreError> {
        let self_id = self.get_self_identity()?.map(|(u, _)| u);
        let (kind, value) = target_to_kv(target)?;
        let mut stmt = self.conn.prepare(
            "SELECT sequence, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, supersedes_sequence, signature
             FROM own_opinion_log WHERE target_kind = ?1 AND target_value = ?2",
        )?;
        let rows = stmt.query_map(params![kind, value], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                sequence,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                expires_at,
                supersedes_sequence,
                signature,
            ) = r?;
            out.push(PolicyOpinion {
                author: self_id
                    .ok_or_else(|| StoreError::Encoding("no self identity set".into()))?,
                sequence: sequence as u64,
                target: target.clone(),
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                expires_at,
                supersedes: supersedes_sequence.map(|s| OpinionRef {
                    author: self_id.unwrap(),
                    sequence: s as u64,
                }),
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    // ── Ingested opinions from followed users ───────────────────────────

    pub fn ingest_opinion(&self, o: &PolicyOpinion) -> Result<(), StoreError> {
        let (kind, value) = target_to_kv(&o.target)?;
        self.conn.execute(
            "INSERT INTO opinions (author_federation_id, author_local_id, sequence, target_kind, target_value, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, supersedes_sequence, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(author_federation_id, author_local_id, sequence) DO NOTHING",
            params![
                o.author.federation.0 .0.as_slice(),
                o.author.local_id.0.as_slice(),
                o.sequence as i64,
                kind,
                value,
                stance_to_i64(o.stance),
                reason_code_to_i64(o.reason.code),
                o.reason.note,
                encode_evidence(&o.reason.evidence),
                o.issued_at,
                o.expires_at,
                o.supersedes.map(|s| s.sequence as i64),
                o.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    pub fn list_followed_opinions_for(
        &self,
        target: &TargetSelector,
    ) -> Result<Vec<(PolicyOpinion, Option<LocalTrustRule>)>, StoreError> {
        let (kind, value) = target_to_kv(target)?;
        let mut stmt = self.conn.prepare(
            "SELECT author_federation_id, author_local_id, sequence, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, supersedes_sequence, signature
             FROM opinions WHERE target_kind = ?1 AND target_value = ?2",
        )?;
        let rows = stmt.query_map(params![kind, value], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, i64>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Vec<u8>>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                sequence,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                expires_at,
                supersedes_sequence,
                signature,
            ) = r?;
            let author = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            let opinion = PolicyOpinion {
                author,
                sequence: sequence as u64,
                target: target.clone(),
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                expires_at,
                supersedes: supersedes_sequence.map(|s| OpinionRef {
                    author,
                    sequence: s as u64,
                }),
                signature: SignatureBytes(bytes_to_64(&signature)?),
            };
            let trust = self.get_follow(&author)?;
            out.push((opinion, trust));
        }
        Ok(out)
    }

    // ── Federation statements ────────────────────────────────────────────

    pub fn ingest_federation_statement(&self, s: &FederationStatement) -> Result<(), StoreError> {
        let (kind, value) = target_to_kv(&s.target)?;
        self.conn.execute(
            "INSERT INTO federation_statements (federation_id, sequence, target_kind, target_value, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, supersedes_sequence, commitment, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(federation_id, sequence) DO NOTHING",
            params![
                s.federation.0 .0.as_slice(),
                s.sequence as i64,
                kind,
                value,
                stance_to_i64(s.stance),
                reason_code_to_i64(s.reason.code),
                s.reason.note,
                encode_evidence(&s.reason.evidence),
                s.issued_at,
                s.expires_at,
                s.supersedes.map(|x| x as i64),
                s.commitment,
                now_unix(),
            ],
        )?;
        Ok(())
    }

    pub fn list_federation_statements_for(
        &self,
        target: &TargetSelector,
    ) -> Result<Vec<(FederationStatement, Option<FederationTrustRule>)>, StoreError> {
        let (kind, value) = target_to_kv(target)?;
        let mut stmt = self.conn.prepare(
            "SELECT federation_id, sequence, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, supersedes_sequence, commitment
             FROM federation_statements WHERE target_kind = ?1 AND target_value = ?2",
        )?;
        let rows = stmt.query_map(params![kind, value], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, Vec<u8>>(9)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                sequence,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                expires_at,
                supersedes_sequence,
                commitment,
            ) = r?;
            let federation = FederationId(bytes_to_hash32(&fed)?);
            let statement = FederationStatement {
                federation,
                sequence: sequence as u64,
                target: target.clone(),
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                expires_at,
                supersedes: supersedes_sequence.map(|s| s as u64),
                commitment,
            };
            let trust = self.get_federation_trust(&federation)?;
            out.push((statement, trust));
        }
        Ok(out)
    }

    /// Every target with any local signal at all — a local override, an
    /// opinion the owner has published, an opinion ingested from someone
    /// followed, or a federation statement. This is what `social-firewall`'s
    /// `sf apply` enumerates before evaluating and enforcing each one; there
    /// is no other way to discover "what should I have an opinion about"
    /// short of scanning every table that can carry a target.
    pub fn list_evaluatable_targets(&self) -> Result<Vec<TargetSelector>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT target_kind, target_value FROM local_overrides
             UNION SELECT target_kind, target_value FROM own_opinion_log
             UNION SELECT target_kind, target_value FROM opinions
             UNION SELECT target_kind, target_value FROM federation_statements
             UNION SELECT target_kind, target_value FROM shared_rule_list_entries",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (kind, value) = r?;
            if let Some(target) = kv_to_target(&kind, &value) {
                out.push(target);
            }
        }
        Ok(out)
    }

    // ── Tunnel advertising ───────────────────────────────────────────────

    /// This router's own messaging (X25519) keypair seed, stored on the
    /// `is_self` row the same way `secret_seed` already stores the
    /// Ed25519 seed — same at-rest caveat noted on that column. Generated
    /// lazily by the caller on first use, not here.
    pub fn set_messaging_keypair_seed(&self, seed: &[u8; 32]) -> Result<(), StoreError> {
        // Checked, not ignored: an `UPDATE ... WHERE is_self = 1` against
        // a store with no self-identity row yet silently affects zero
        // rows — that would make this look like it succeeded while
        // actually persisting nothing, so every subsequent
        // `get_messaging_keypair_seed` call would keep returning `None`
        // and a caller like `ensure_interface_and_keypair` would silently
        // regenerate a fresh key every single time it's called instead of
        // reusing one. Fail loudly instead.
        let rows = self.conn.execute(
            "UPDATE users SET messaging_secret_seed = ?1 WHERE is_self = 1",
            params![seed.as_slice()],
        )?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_messaging_keypair_seed(&self) -> Result<Option<[u8; 32]>, StoreError> {
        self.conn
            .query_row(
                "SELECT messaging_secret_seed FROM users WHERE is_self = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .map(|v| bytes_to_32(&v))
            .transpose()
    }

    /// This router's own WireGuard keypair seed — a distinct column and
    /// a distinct key from the messaging keypair above, per both types'
    /// own module docs on key-purpose separation.
    pub fn set_wg_keypair_seed(&self, seed: &[u8; 32]) -> Result<(), StoreError> {
        // See `set_messaging_keypair_seed`'s comment — same silent-no-op
        // risk, same fix.
        let rows = self.conn.execute(
            "UPDATE users SET wg_secret_seed = ?1 WHERE is_self = 1",
            params![seed.as_slice()],
        )?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_wg_keypair_seed(&self) -> Result<Option<[u8; 32]>, StoreError> {
        self.conn
            .query_row(
                "SELECT wg_secret_seed FROM users WHERE is_self = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .map(|v| bytes_to_32(&v))
            .transpose()
    }

    /// This router's own Iroh keypair seed — see
    /// `0020_iroh_addressing.sql`'s own doc on why this is a fourth,
    /// dedicated key rather than reusing an existing one.
    pub fn set_iroh_keypair_seed(&self, seed: &[u8; 32]) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE users SET iroh_secret_seed = ?1 WHERE is_self = 1",
            params![seed.as_slice()],
        )?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_iroh_keypair_seed(&self) -> Result<Option<[u8; 32]>, StoreError> {
        self.conn
            .query_row(
                "SELECT iroh_secret_seed FROM users WHERE is_self = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .map(|v| bytes_to_32(&v))
            .transpose()
    }

    /// Reticulum's identity seed is deliberately separate from every other
    /// transport and application key.
    pub fn set_reticulum_identity_seed(&self, seed: &[u8; 32]) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE users SET reticulum_secret_seed = ?1 WHERE is_self = 1",
            params![seed.as_slice()],
        )?;
        if rows == 0 {
            return Err(StoreError::NoSelfIdentity);
        }
        Ok(())
    }

    pub fn get_reticulum_identity_seed(&self) -> Result<Option<[u8; 32]>, StoreError> {
        self.conn
            .query_row(
                "SELECT reticulum_secret_seed FROM users WHERE is_self = 1",
                [],
                |row| row.get::<_, Option<Vec<u8>>>(0),
            )
            .optional()?
            .flatten()
            .map(|value| bytes_to_32(&value))
            .transpose()
    }

    pub fn set_peer_transport_address(
        &self,
        peer: UserId,
        transport: &str,
        address: &str,
        enabled: bool,
        verified: bool,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO peer_transport_addresses (federation_id, local_id, transport, address, enabled, verified, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(federation_id, local_id, transport) DO UPDATE SET
               address = excluded.address, enabled = excluded.enabled,
               verified = excluded.verified, updated_at = excluded.updated_at",
            params![
                peer.federation.0 .0.as_slice(),
                peer.local_id.0.as_slice(),
                transport,
                address,
                enabled as i64,
                verified as i64,
                now_unix()
            ],
        )?;
        Ok(())
    }

    pub fn peer_transport_address(
        &self,
        peer: UserId,
        transport: &str,
    ) -> Result<Option<PeerTransportAddress>, StoreError> {
        self.conn
            .query_row(
                "SELECT address, enabled, verified, updated_at
                 FROM peer_transport_addresses
                 WHERE federation_id = ?1 AND local_id = ?2 AND transport = ?3",
                params![
                    peer.federation.0 .0.as_slice(),
                    peer.local_id.0.as_slice(),
                    transport
                ],
                |row| {
                    Ok(PeerTransportAddress {
                        peer,
                        transport: transport.to_string(),
                        address: row.get(0)?,
                        enabled: row.get::<_, i64>(1)? != 0,
                        verified: row.get::<_, i64>(2)? != 0,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn delete_peer_transport_address(
        &self,
        peer: UserId,
        transport: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM peer_transport_addresses
             WHERE federation_id = ?1 AND local_id = ?2 AND transport = ?3",
            params![
                peer.federation.0 .0.as_slice(),
                peer.local_id.0.as_slice(),
                transport
            ],
        )?;
        Ok(())
    }

    /// Rejects outright (not just zero-weight, the way an unfollowed
    /// opinion is) unless `ad.provider` is already a followed user — the
    /// flood-resistance gate: acting on a tunnel ad has real resource/
    /// security cost, not just a weighted vote.
    pub fn ingest_tunnel_advertisement(&self, ad: &TunnelAdvertisement) -> Result<(), StoreError> {
        if self.get_follow(&ad.provider)?.is_none() {
            return Err(StoreError::NotFollowed(format!(
                "{}/{}",
                ad.provider.federation.0, ad.provider.local_id
            )));
        }
        self.store_tunnel_advertisement_row(ad)
    }

    /// This router's *own* advertisement, just published under its own
    /// identity — no follow-gate, the same distinction `append_own_opinion`
    /// already draws from `ingest_opinion`: a person doesn't need to
    /// follow themselves for their own content to count. Conflating the
    /// two here was a real bug caught during manual end-to-end testing
    /// (offering a tunnel failed with "not a followed user" — about
    /// yourself).
    pub fn store_own_tunnel_advertisement(
        &self,
        ad: &TunnelAdvertisement,
    ) -> Result<(), StoreError> {
        self.store_tunnel_advertisement_row(ad)
    }

    fn store_tunnel_advertisement_row(&self, ad: &TunnelAdvertisement) -> Result<(), StoreError> {
        let (in_resp_fed, in_resp_local, in_resp_seq): (Option<&[u8]>, Option<&[u8]>, Option<i64>) =
            match &ad.in_response_to {
                Some(r) => (
                    Some(r.author.federation.0 .0.as_slice()),
                    Some(r.author.local_id.0.as_slice()),
                    Some(r.sequence as i64),
                ),
                None => (None, None, None),
            };
        self.conn.execute(
            "INSERT INTO tunnel_advertisements (provider_federation_id, provider_local_id, sequence, description, limitations, visibility, in_response_to_federation_id, in_response_to_local_id, in_response_to_sequence, messaging_pubkey, wg_pubkey, endpoint_hint, max_connections, max_bandwidth_kbps, issued_at, expires_at, supersedes_sequence, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)
             ON CONFLICT(provider_federation_id, provider_local_id, sequence) DO NOTHING",
            params![
                ad.provider.federation.0 .0.as_slice(),
                ad.provider.local_id.0.as_slice(),
                ad.sequence as i64,
                ad.description,
                ad.limitations,
                visibility_to_i64(ad.visibility),
                in_resp_fed,
                in_resp_local,
                in_resp_seq,
                ad.messaging_pubkey.0.as_slice(),
                ad.wg_pubkey.0.as_slice(),
                ad.endpoint_hint,
                ad.max_connections,
                ad.max_bandwidth_kbps.map(|v| v as i64),
                ad.issued_at,
                ad.expires_at,
                ad.supersedes.map(|s| s as i64),
                ad.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        for t in &ad.route_scope {
            let (kind, value) = target_to_kv(t)?;
            self.conn.execute(
                "INSERT INTO tunnel_advertisement_targets (provider_federation_id, provider_local_id, sequence, target_kind, target_value)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
                params![ad.provider.federation.0 .0.as_slice(), ad.provider.local_id.0.as_slice(), ad.sequence as i64, kind, value],
            )?;
        }
        for tag in &ad.tags {
            self.conn.execute(
                "INSERT INTO tunnel_advertisement_tags (provider_federation_id, provider_local_id, sequence, tag)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                params![ad.provider.federation.0 .0.as_slice(), ad.provider.local_id.0.as_slice(), ad.sequence as i64, tag],
            )?;
        }
        Ok(())
    }

    pub fn get_tunnel_advertisement(
        &self,
        provider: UserId,
        sequence: u64,
    ) -> Result<Option<TunnelAdvertisement>, StoreError> {
        let row = self.conn.query_row(
            "SELECT description, limitations, visibility, in_response_to_federation_id, in_response_to_local_id, in_response_to_sequence, messaging_pubkey, wg_pubkey, endpoint_hint, max_connections, max_bandwidth_kbps, issued_at, expires_at, supersedes_sequence, signature
             FROM tunnel_advertisements WHERE provider_federation_id = ?1 AND provider_local_id = ?2 AND sequence = ?3",
            params![provider.federation.0 .0.as_slice(), provider.local_id.0.as_slice(), sequence as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                    row.get::<_, i64>(11)?,
                    row.get::<_, Option<i64>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, Vec<u8>>(14)?,
                ))
            },
        ).optional()?;
        let Some((
            description,
            limitations,
            visibility,
            ir_fed,
            ir_local,
            ir_seq,
            messaging_pubkey,
            wg_pubkey,
            endpoint_hint,
            max_connections,
            max_bandwidth_kbps,
            issued_at,
            expires_at,
            supersedes,
            signature,
        )) = row
        else {
            return Ok(None);
        };
        let route_scope = self.tunnel_advertisement_targets(&provider, sequence)?;
        let tags = self.tunnel_advertisement_tags(&provider, sequence)?;
        let in_response_to = match (ir_fed, ir_local, ir_seq) {
            (Some(f), Some(l), Some(s)) => Some(StatementRef {
                author: UserId {
                    federation: FederationId(bytes_to_hash32(&f)?),
                    local_id: bytes_to_hash32(&l)?,
                },
                sequence: s as u64,
            }),
            _ => None,
        };
        Ok(Some(TunnelAdvertisement {
            provider,
            sequence,
            description,
            limitations,
            visibility: visibility_from_i64(visibility)?,
            in_response_to,
            messaging_pubkey: MessagingPublicKeyBytes(bytes_to_32(&messaging_pubkey)?),
            wg_pubkey: WgPublicKeyBytes(bytes_to_32(&wg_pubkey)?),
            endpoint_hint,
            route_scope,
            tags,
            max_connections: max_connections.map(|v| v as u32),
            max_bandwidth_kbps: max_bandwidth_kbps.map(|v| v as u64),
            issued_at,
            expires_at,
            supersedes: supersedes.map(|s| s as u64),
            signature: SignatureBytes(bytes_to_64(&signature)?),
        }))
    }

    fn tunnel_advertisement_tags(
        &self,
        provider: &UserId,
        sequence: u64,
    ) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT tag FROM tunnel_advertisement_tags WHERE provider_federation_id = ?1 AND provider_local_id = ?2 AND sequence = ?3",
        )?;
        let rows = stmt.query_map(
            params![
                provider.federation.0 .0.as_slice(),
                provider.local_id.0.as_slice(),
                sequence as i64
            ],
            |row| row.get::<_, String>(0),
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn tunnel_advertisement_targets(
        &self,
        provider: &UserId,
        sequence: u64,
    ) -> Result<Vec<TargetSelector>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT target_kind, target_value FROM tunnel_advertisement_targets WHERE provider_federation_id = ?1 AND provider_local_id = ?2 AND sequence = ?3",
        )?;
        let rows = stmt.query_map(
            params![
                provider.federation.0 .0.as_slice(),
                provider.local_id.0.as_slice(),
                sequence as i64
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (kind, value) = r?;
            if let Some(t) = kv_to_target(&kind, &value) {
                out.push(t);
            }
        }
        Ok(out)
    }

    /// Every known advertisement — the browsing surface `list-tunnels`
    /// draws from.
    pub fn list_tunnel_advertisements(&self) -> Result<Vec<TunnelAdvertisement>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT provider_federation_id, provider_local_id, sequence FROM tunnel_advertisements",
        )?;
        let keys: Vec<(Vec<u8>, Vec<u8>, i64)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for (fed, local, seq) in keys {
            let provider = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            if let Some(ad) = self.get_tunnel_advertisement(provider, seq as u64)? {
                out.push(ad);
            }
        }
        Ok(out)
    }

    /// Same flood-resistance gate as `ingest_tunnel_advertisement`, for
    /// the same reason — acting on a want-ad (auto-responding with an
    /// advertisement) has real effect, not just zero weight.
    pub fn ingest_tunnel_service_request(
        &self,
        req: &TunnelServiceRequest,
    ) -> Result<(), StoreError> {
        if self.get_follow(&req.requester)?.is_none() {
            return Err(StoreError::NotFollowed(format!(
                "{}/{}",
                req.requester.federation.0, req.requester.local_id
            )));
        }
        self.store_tunnel_service_request_row(req)
    }

    /// This router's own service request — no follow-gate, same reason
    /// as `store_own_tunnel_advertisement` above.
    pub fn store_own_tunnel_service_request(
        &self,
        req: &TunnelServiceRequest,
    ) -> Result<(), StoreError> {
        self.store_tunnel_service_request_row(req)
    }

    fn store_tunnel_service_request_row(
        &self,
        req: &TunnelServiceRequest,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO tunnel_service_requests (requester_federation_id, requester_local_id, sequence, description, visibility, issued_at, expires_at, supersedes_sequence, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(requester_federation_id, requester_local_id, sequence) DO NOTHING",
            params![
                req.requester.federation.0 .0.as_slice(),
                req.requester.local_id.0.as_slice(),
                req.sequence as i64,
                req.description,
                visibility_to_i64(req.visibility),
                req.issued_at,
                req.expires_at,
                req.supersedes.map(|s| s as i64),
                req.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        for t in &req.desired_route_scope {
            let (kind, value) = target_to_kv(t)?;
            self.conn.execute(
                "INSERT INTO tunnel_service_request_targets (requester_federation_id, requester_local_id, sequence, target_kind, target_value)
                 VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING",
                params![req.requester.federation.0 .0.as_slice(), req.requester.local_id.0.as_slice(), req.sequence as i64, kind, value],
            )?;
        }
        Ok(())
    }

    /// Every known service request — including this router's own
    /// published ones alongside ones ingested from others, same as how
    /// `list_tunnel_advertisements` doesn't distinguish self-authored from
    /// ingested.
    pub fn list_tunnel_service_requests(&self) -> Result<Vec<TunnelServiceRequest>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT requester_federation_id, requester_local_id, sequence, description, visibility, issued_at, expires_at, supersedes_sequence, signature FROM tunnel_service_requests",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<i64>>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                seq,
                description,
                visibility,
                issued_at,
                expires_at,
                supersedes,
                signature,
            ) = r?;
            let requester = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            let desired_route_scope = {
                let mut stmt = self.conn.prepare(
                    "SELECT target_kind, target_value FROM tunnel_service_request_targets WHERE requester_federation_id = ?1 AND requester_local_id = ?2 AND sequence = ?3",
                )?;
                let target_rows = stmt
                    .query_map(params![fed.as_slice(), local.as_slice(), seq], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?;
                let mut targets = Vec::new();
                for tr in target_rows {
                    let (kind, value) = tr?;
                    if let Some(t) = kv_to_target(&kind, &value) {
                        targets.push(t);
                    }
                }
                targets
            };
            out.push(TunnelServiceRequest {
                requester,
                sequence: seq as u64,
                description,
                desired_route_scope,
                visibility: visibility_from_i64(visibility)?,
                issued_at,
                expires_at,
                supersedes: supersedes.map(|s| s as u64),
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    /// Stores a connection request — used both when this router creates
    /// its own outgoing request and when it ingests one from someone
    /// else against its own advertisement. Deliberately **not**
    /// follow-gated like advertisements/service requests: a connection
    /// request is inherently a response to something this router itself
    /// published, and whether to actually honor it is `TunnelTrustRule`'s
    /// job at reconciliation time (Phase E), not ingest time.
    pub fn store_tunnel_connection_request(
        &self,
        req: &TunnelConnectionRequest,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO tunnel_connection_requests (requester_federation_id, requester_local_id, sequence, advertisement_provider_federation_id, advertisement_provider_local_id, advertisement_sequence, requester_wg_pubkey, requester_messaging_pubkey, requested_at, signature, ingested_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'pending')
             ON CONFLICT(requester_federation_id, requester_local_id, sequence) DO NOTHING",
            params![
                req.requester.federation.0 .0.as_slice(),
                req.requester.local_id.0.as_slice(),
                req.sequence as i64,
                req.advertisement.author.federation.0 .0.as_slice(),
                req.advertisement.author.local_id.0.as_slice(),
                req.advertisement.sequence as i64,
                req.requester_wg_pubkey.0.as_slice(),
                req.requester_messaging_pubkey.0.as_slice(),
                req.requested_at,
                req.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    pub fn get_tunnel_connection_request(
        &self,
        requester: &UserId,
        sequence: u64,
    ) -> Result<Option<TunnelConnectionRequest>, StoreError> {
        self.conn
            .query_row(
                "SELECT advertisement_provider_federation_id, advertisement_provider_local_id, advertisement_sequence, requester_wg_pubkey, requester_messaging_pubkey, requested_at, signature
                 FROM tunnel_connection_requests WHERE requester_federation_id = ?1 AND requester_local_id = ?2 AND sequence = ?3",
                params![requester.federation.0 .0.as_slice(), requester.local_id.0.as_slice(), sequence as i64],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?
            .map(|(a_fed, a_local, a_seq, wg_pk, msg_pk, requested_at, signature)| {
                Ok(TunnelConnectionRequest {
                    requester: *requester,
                    sequence,
                    advertisement: StatementRef { author: UserId { federation: FederationId(bytes_to_hash32(&a_fed)?), local_id: bytes_to_hash32(&a_local)? }, sequence: a_seq as u64 },
                    requester_wg_pubkey: WgPublicKeyBytes(bytes_to_32(&wg_pk)?),
                    requester_messaging_pubkey: MessagingPublicKeyBytes(bytes_to_32(&msg_pk)?),
                    requested_at,
                    signature: SignatureBytes(bytes_to_64(&signature)?),
                })
            })
            .transpose()
    }

    /// Whether `requester` has already sent a connection request against
    /// this specific advertisement — the idempotency check
    /// `sync-tunnels`'s auto-consume step needs before requesting a
    /// trusted provider's tunnel automatically, so a repeated
    /// reconciliation run never sends a second, duplicate request for
    /// something already requested (accepted, pending, or otherwise).
    pub fn has_tunnel_connection_request_for(
        &self,
        requester: &UserId,
        advertisement: &StatementRef,
    ) -> Result<bool, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tunnel_connection_requests
             WHERE requester_federation_id = ?1 AND requester_local_id = ?2
               AND advertisement_provider_federation_id = ?3 AND advertisement_provider_local_id = ?4 AND advertisement_sequence = ?5",
            params![
                requester.federation.0 .0.as_slice(),
                requester.local_id.0.as_slice(),
                advertisement.author.federation.0 .0.as_slice(),
                advertisement.author.local_id.0.as_slice(),
                advertisement.sequence as i64,
            ],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    pub fn list_pending_tunnel_connection_requests(
        &self,
    ) -> Result<Vec<TunnelConnectionRequest>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT requester_federation_id, requester_local_id, sequence, advertisement_provider_federation_id, advertisement_provider_local_id, advertisement_sequence, requester_wg_pubkey, requester_messaging_pubkey, requested_at, signature
             FROM tunnel_connection_requests WHERE status = 'pending'",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Vec<u8>>(9)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                r_fed,
                r_local,
                r_seq,
                a_fed,
                a_local,
                a_seq,
                wg_pk,
                msg_pk,
                requested_at,
                signature,
            ) = r?;
            out.push(TunnelConnectionRequest {
                requester: UserId {
                    federation: FederationId(bytes_to_hash32(&r_fed)?),
                    local_id: bytes_to_hash32(&r_local)?,
                },
                sequence: r_seq as u64,
                advertisement: StatementRef {
                    author: UserId {
                        federation: FederationId(bytes_to_hash32(&a_fed)?),
                        local_id: bytes_to_hash32(&a_local)?,
                    },
                    sequence: a_seq as u64,
                },
                requester_wg_pubkey: WgPublicKeyBytes(bytes_to_32(&wg_pk)?),
                requester_messaging_pubkey: MessagingPublicKeyBytes(bytes_to_32(&msg_pk)?),
                requested_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    pub fn set_tunnel_connection_request_status(
        &self,
        requester: &UserId,
        sequence: u64,
        status: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE tunnel_connection_requests SET status = ?1 WHERE requester_federation_id = ?2 AND requester_local_id = ?3 AND sequence = ?4",
            params![status, requester.federation.0 .0.as_slice(), requester.local_id.0.as_slice(), sequence as i64],
        )?;
        Ok(())
    }

    pub fn store_tunnel_connection_accept(
        &self,
        accept: &TunnelConnectionAccept,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO tunnel_connection_accepts (provider_federation_id, provider_local_id, request_requester_federation_id, request_requester_local_id, request_sequence, assigned_tunnel_ip, assigned_tunnel_ip6, accepted_at, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(request_requester_federation_id, request_requester_local_id, request_sequence) DO NOTHING",
            params![
                accept.provider.federation.0 .0.as_slice(),
                accept.provider.local_id.0.as_slice(),
                accept.request_ref.author.federation.0 .0.as_slice(),
                accept.request_ref.author.local_id.0.as_slice(),
                accept.request_ref.sequence as i64,
                accept.assigned_tunnel_ip,
                accept.assigned_tunnel_ip6,
                accept.accepted_at,
                accept.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    pub fn get_tunnel_connection_accept_for(
        &self,
        requester: &UserId,
        sequence: u64,
    ) -> Result<Option<TunnelConnectionAccept>, StoreError> {
        self.conn
            .query_row(
                "SELECT provider_federation_id, provider_local_id, assigned_tunnel_ip, assigned_tunnel_ip6, accepted_at, signature FROM tunnel_connection_accepts
                 WHERE request_requester_federation_id = ?1 AND request_requester_local_id = ?2 AND request_sequence = ?3",
                params![requester.federation.0 .0.as_slice(), requester.local_id.0.as_slice(), sequence as i64],
                |row| {
                    Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?, row.get::<_, i64>(4)?, row.get::<_, Vec<u8>>(5)?))
                },
            )
            .optional()?
            .map(|(provider_fed, provider_local, assigned_tunnel_ip, assigned_tunnel_ip6, accepted_at, signature)| -> Result<TunnelConnectionAccept, StoreError> {
                Ok(TunnelConnectionAccept {
                    provider: UserId { federation: FederationId(bytes_to_hash32(&provider_fed)?), local_id: bytes_to_hash32(&provider_local)? },
                    request_ref: StatementRef { author: *requester, sequence },
                    assigned_tunnel_ip,
                    assigned_tunnel_ip6,
                    accepted_at,
                    signature: SignatureBytes(bytes_to_64(&signature)?),
                })
            })
            .transpose()
    }

    pub fn upsert_tunnel_trust_rule(&self, rule: &TunnelTrustRule) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO tunnel_trust_rules (federation_id, local_id, auto_accept_requests, auto_consume_advertisements, auto_respond_to_service_requests, excluded, tag_filter, min_reciprocity_ratio, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(federation_id, local_id) DO UPDATE SET
                auto_accept_requests = excluded.auto_accept_requests,
                auto_consume_advertisements = excluded.auto_consume_advertisements,
                auto_respond_to_service_requests = excluded.auto_respond_to_service_requests,
                excluded = excluded.excluded,
                tag_filter = excluded.tag_filter,
                min_reciprocity_ratio = excluded.min_reciprocity_ratio,
                expires_at = excluded.expires_at",
            params![
                rule.user.federation.0 .0.as_slice(),
                rule.user.local_id.0.as_slice(),
                rule.auto_accept_requests,
                rule.auto_consume_advertisements,
                rule.auto_respond_to_service_requests,
                rule.excluded,
                rule.tag_filter,
                rule.min_reciprocity_ratio,
                rule.expires_at,
                rule.created_at,
            ],
        )?;
        Ok(())
    }

    pub fn get_tunnel_trust_rule(
        &self,
        user: &UserId,
    ) -> Result<Option<TunnelTrustRule>, StoreError> {
        self.conn
            .query_row(
                "SELECT auto_accept_requests, auto_consume_advertisements, auto_respond_to_service_requests, excluded, tag_filter, min_reciprocity_ratio, expires_at, created_at
                 FROM tunnel_trust_rules WHERE federation_id = ?1 AND local_id = ?2",
                params![user.federation.0 .0.as_slice(), user.local_id.0.as_slice()],
                |row| {
                    Ok(TunnelTrustRule {
                        user: *user,
                        auto_accept_requests: row.get(0)?,
                        auto_consume_advertisements: row.get(1)?,
                        auto_respond_to_service_requests: row.get(2)?,
                        excluded: row.get(3)?,
                        tag_filter: row.get(4)?,
                        min_reciprocity_ratio: row.get(5)?,
                        expires_at: row.get(6)?,
                        created_at: row.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(StoreError::from)
    }

    pub fn list_tunnel_trust_rules(&self) -> Result<Vec<TunnelTrustRule>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT federation_id, local_id, auto_accept_requests, auto_consume_advertisements, auto_respond_to_service_requests, excluded, tag_filter, min_reciprocity_ratio, expires_at, created_at FROM tunnel_trust_rules",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, bool>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, bool>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Option<f64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
                row.get::<_, i64>(9)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                auto_accept,
                auto_consume,
                auto_respond,
                excluded,
                tag_filter,
                min_reciprocity_ratio,
                expires_at,
                created_at,
            ) = r?;
            out.push(TunnelTrustRule {
                user: UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                },
                auto_accept_requests: auto_accept,
                auto_consume_advertisements: auto_consume,
                auto_respond_to_service_requests: auto_respond,
                excluded,
                tag_filter,
                min_reciprocity_ratio,
                expires_at,
                created_at,
            });
        }
        Ok(out)
    }

    /// Hands out the next unused fwmark/route-table pair from this
    /// router's own reserved range (see the migration's own comment on
    /// `tunnel_resource_allocator` for why a disjoint range from
    /// `split-routing`'s hand-picked ones matters — fwmarks/route tables
    /// are a single kernel-wide namespace). Persisted so a restart never
    /// double-assigns a slot a still-active tunnel is using.
    pub fn allocate_fwmark_and_route_table(&self) -> Result<(i64, i64), StoreError> {
        const RESERVED_FWMARK_START: i64 = 0x1000;
        const RESERVED_ROUTE_TABLE_START: i64 = 200;

        self.conn.execute(
            "INSERT INTO tunnel_resource_allocator (id, next_fwmark, next_route_table) VALUES (0, ?1, ?2)
             ON CONFLICT(id) DO NOTHING",
            params![RESERVED_FWMARK_START, RESERVED_ROUTE_TABLE_START],
        )?;
        let (fwmark, route_table): (i64, i64) = self.conn.query_row(
            "SELECT next_fwmark, next_route_table FROM tunnel_resource_allocator WHERE id = 0",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        self.conn.execute(
            "UPDATE tunnel_resource_allocator SET next_fwmark = ?1, next_route_table = ?2 WHERE id = 0",
            params![fwmark + 1, route_table + 1],
        )?;
        Ok((fwmark, route_table))
    }
}

// ── Shared rule lists ────────────────────────────────────────────────────

impl StateStore {
    pub fn next_shared_policy_sequence(
        &self,
        author: &UserId,
        policy_id: &Hash32,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM shared_policies
             WHERE author_federation_id = ?1 AND author_local_id = ?2 AND policy_id = ?3",
            params![
                author.federation.0 .0.as_slice(),
                author.local_id.0.as_slice(),
                policy_id.0.as_slice()
            ],
            |row| row.get(0),
        )?;
        Ok(max.map(|value| value as u64 + 1).unwrap_or(0))
    }

    pub fn store_own_shared_policy(&self, policy: &SharedPolicy) -> Result<(), StoreError> {
        self.store_shared_policy_row(policy)
    }

    pub fn ingest_shared_policy(&self, policy: &SharedPolicy) -> Result<(), StoreError> {
        if self.get_follow(&policy.author)?.is_none() {
            return Err(StoreError::NotFollowed(format!(
                "{}/{}",
                policy.author.federation.0, policy.author.local_id
            )));
        }
        self.store_shared_policy_row(policy)
    }

    fn store_shared_policy_row(&self, policy: &SharedPolicy) -> Result<(), StoreError> {
        let author_fed = policy.author.federation.0 .0.as_slice();
        let author_local = policy.author.local_id.0.as_slice();
        let policy_id = policy.policy_id.0.as_slice();
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM shared_policies
             WHERE author_federation_id = ?1 AND author_local_id = ?2 AND policy_id = ?3",
            params![author_fed, author_local, policy_id],
            |row| row.get(0),
        )?;
        if max.is_some_and(|value| (policy.sequence as i64) < value) {
            return Err(StoreError::Encoding(format!(
                "shared policy sequence {} rolls back from {}",
                policy.sequence,
                max.unwrap()
            )));
        }

        if let Some(existing) =
            self.get_shared_policy(policy.policy_id, policy.author, policy.sequence)?
        {
            if existing == *policy {
                return Ok(());
            }
            return Err(StoreError::Encoding(
                "conflicting shared policy at the same sequence".into(),
            ));
        }
        if policy.supersedes.is_some_and(|old| old >= policy.sequence) {
            return Err(StoreError::Encoding(
                "shared policy supersedes a non-older sequence".into(),
            ));
        }

        self.conn.execute(
            "INSERT INTO shared_policies
             (author_federation_id, author_local_id, policy_id, sequence, name, description,
              visibility, issued_at, expires_at, supersedes_sequence, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                author_fed,
                author_local,
                policy_id,
                policy.sequence as i64,
                policy.name,
                policy.description,
                visibility_to_i64(policy.visibility),
                policy.issued_at,
                policy.expires_at,
                policy.supersedes.map(|value| value as i64),
                policy.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        for (ordinal, category) in policy.categories.iter().enumerate() {
            self.conn.execute(
                "INSERT INTO shared_policy_categories
                 (author_federation_id, author_local_id, policy_id, sequence, ordinal, category)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    author_fed,
                    author_local,
                    policy_id,
                    policy.sequence as i64,
                    ordinal as i64,
                    category
                ],
            )?;
        }
        for (ordinal, entry) in policy.entries.iter().enumerate() {
            let (target_kind, target_value) = target_to_kv(&entry.target)?;
            let (action_kind, action_value, action_ttl) = policy_action_to_columns(&entry.action);
            self.conn.execute(
                "INSERT INTO shared_policy_entries
                 (author_federation_id, author_local_id, policy_id, sequence, ordinal, entry_id,
                  target_kind, target_value, action_kind, action_value, action_ttl_seconds,
                  category, reason_code, reason_note, reason_evidence, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                params![
                    author_fed,
                    author_local,
                    policy_id,
                    policy.sequence as i64,
                    ordinal as i64,
                    entry.entry_id.0.as_slice(),
                    target_kind,
                    target_value,
                    action_kind,
                    action_value,
                    action_ttl,
                    entry.category,
                    reason_code_to_i64(entry.reason.code),
                    entry.reason.note,
                    encode_evidence(&entry.reason.evidence),
                    entry.expires_at,
                ],
            )?;
        }
        if let Some(old_sequence) = policy.supersedes {
            self.conn.execute(
                "DELETE FROM shared_policies
                 WHERE author_federation_id = ?1 AND author_local_id = ?2 AND policy_id = ?3 AND sequence = ?4",
                params![author_fed, author_local, policy_id, old_sequence as i64],
            )?;
        }
        Ok(())
    }

    pub fn get_shared_policy(
        &self,
        policy_id: Hash32,
        author: UserId,
        sequence: u64,
    ) -> Result<Option<SharedPolicy>, StoreError> {
        let metadata = self.conn.query_row(
            "SELECT name, description, visibility, issued_at, expires_at, supersedes_sequence, signature
             FROM shared_policies
             WHERE author_federation_id = ?1 AND author_local_id = ?2 AND policy_id = ?3 AND sequence = ?4",
            params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice(), policy_id.0.as_slice(), sequence as i64],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, Option<i64>>(4)?, row.get::<_, Option<i64>>(5)?, row.get::<_, Vec<u8>>(6)?)),
        ).optional()?;
        let Some((name, description, visibility, issued_at, expires_at, supersedes, signature)) =
            metadata
        else {
            return Ok(None);
        };
        let categories = self.conn.prepare(
            "SELECT category FROM shared_policy_categories
             WHERE author_federation_id = ?1 AND author_local_id = ?2 AND policy_id = ?3 AND sequence = ?4
             ORDER BY ordinal",
        )?.query_map(params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice(), policy_id.0.as_slice(), sequence as i64], |row| row.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?;
        let mut stmt = self.conn.prepare(
            "SELECT entry_id, target_kind, target_value, action_kind, action_value, action_ttl_seconds,
                    category, reason_code, reason_note, reason_evidence, expires_at
             FROM shared_policy_entries
             WHERE author_federation_id = ?1 AND author_local_id = ?2 AND policy_id = ?3 AND sequence = ?4
             ORDER BY ordinal",
        )?;
        let rows = stmt.query_map(
            params![
                author.federation.0 .0.as_slice(),
                author.local_id.0.as_slice(),
                policy_id.0.as_slice(),
                sequence as i64
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<String>>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            },
        )?;
        let mut entries = Vec::new();
        for row in rows {
            let (
                entry_id,
                target_kind,
                target_value,
                action_kind,
                action_value,
                action_ttl,
                category,
                reason_code,
                reason_note,
                reason_evidence,
                entry_expires,
            ) = row?;
            let target = kv_to_target(&target_kind, &target_value).ok_or_else(|| {
                StoreError::Encoding(format!("invalid policy target kind {target_kind}"))
            })?;
            entries.push(PolicyEntry {
                entry_id: bytes_to_hash32(&entry_id)?,
                target,
                action: policy_action_from_columns(&action_kind, action_value, action_ttl)?,
                category,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                expires_at: entry_expires,
            });
        }
        Ok(Some(SharedPolicy {
            policy_id,
            author,
            sequence,
            name,
            description,
            categories,
            visibility: visibility_from_i64(visibility)?,
            entries,
            issued_at,
            expires_at,
            supersedes: supersedes.map(|value| value as u64),
            signature: SignatureBytes(bytes_to_64(&signature)?),
        }))
    }

    pub fn list_shared_policies(&self) -> Result<Vec<SharedPolicy>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT author_federation_id, author_local_id, policy_id, sequence
             FROM shared_policies ORDER BY author_federation_id, author_local_id, policy_id, sequence",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut policies = Vec::new();
        for row in rows {
            let (fed, local, id, sequence) = row?;
            let author = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            if let Some(policy) =
                self.get_shared_policy(bytes_to_hash32(&id)?, author, sequence as u64)?
            {
                policies.push(policy);
            }
        }
        Ok(policies)
    }

    pub fn create_local_profile(&self, profile: &LocalProfile) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO local_profiles (profile_id, name, description, active) VALUES (?1, ?2, ?3, ?4)",
            params![profile.profile_id.0.as_slice(), profile.name, profile.description, profile.active as i64],
        )?;
        for policy_id in &profile.policy_ids {
            self.conn.execute(
                "INSERT INTO local_profile_policies (profile_id, policy_id) VALUES (?1, ?2)",
                params![profile.profile_id.0.as_slice(), policy_id.0.as_slice()],
            )?;
        }
        Ok(())
    }

    pub fn list_local_profiles(&self) -> Result<Vec<LocalProfile>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT profile_id, name, description, active FROM local_profiles ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut profiles = Vec::new();
        for row in rows {
            let (id, name, description, active) = row?;
            let profile_id = bytes_to_hash32(&id)?;
            let mut policies = self.conn.prepare("SELECT policy_id FROM local_profile_policies WHERE profile_id = ?1 ORDER BY policy_id")?;
            let policy_bytes = policies
                .query_map(params![profile_id.0.as_slice()], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let policy_ids = policy_bytes
                .iter()
                .map(|bytes| bytes_to_hash32(bytes))
                .collect::<Result<Vec<_>, _>>()?;
            profiles.push(LocalProfile {
                profile_id,
                name,
                description,
                active: active != 0,
                policy_ids,
            });
        }
        Ok(profiles)
    }

    pub fn add_policy_to_profile(
        &self,
        profile_id: Hash32,
        policy_id: Hash32,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO local_profile_policies (profile_id, policy_id) VALUES (?1, ?2)",
            params![profile_id.0.as_slice(), policy_id.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn set_active_profile(&self, profile_id: Hash32) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("UPDATE local_profiles SET active = 0", [])?;
        let changed = tx.execute(
            "UPDATE local_profiles SET active = 1 WHERE profile_id = ?1",
            params![profile_id.0.as_slice()],
        )?;
        if changed != 1 {
            return Err(StoreError::Encoding("unknown local profile".into()));
        }
        tx.commit()?;
        Ok(())
    }

    pub fn active_local_profile(&self) -> Result<Option<LocalProfile>, StoreError> {
        Ok(self
            .list_local_profiles()?
            .into_iter()
            .find(|profile| profile.active))
    }

    pub fn upsert_device_presence(
        &self,
        observation: &DevicePresenceObservation,
    ) -> Result<(), StoreError> {
        observation
            .validate()
            .map_err(StoreError::InvalidPresence)?;
        self.conn.execute(
            "INSERT INTO device_presence_observations (observation_id, device_id, observer_node_id, network, source, first_seen, last_seen, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(observation_id) DO UPDATE SET
                device_id = COALESCE(excluded.device_id, device_presence_observations.device_id),
                observer_node_id = excluded.observer_node_id,
                network = excluded.network,
                source = excluded.source,
                first_seen = MIN(device_presence_observations.first_seen, excluded.first_seen),
                last_seen = MAX(device_presence_observations.last_seen, excluded.last_seen),
                expires_at = excluded.expires_at",
            params![
                observation.observation_id.0.as_slice(),
                observation.device_id.map(|id| id.0 .0.to_vec()),
                observation.observer.0 .0.as_slice(),
                observation.network,
                observation.source,
                observation.first_seen,
                observation.last_seen,
                observation.expires_at,
            ],
        )?;
        Ok(())
    }

    pub fn list_device_presence(&self) -> Result<Vec<DevicePresenceObservation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT observation_id, device_id, observer_node_id, network, source, first_seen, last_seen, expires_at
             FROM device_presence_observations ORDER BY last_seen DESC, observation_id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<Vec<u8>>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
            ))
        })?;
        rows.map(|row| {
            let (
                observation_id,
                device_id,
                observer,
                network,
                source,
                first_seen,
                last_seen,
                expires_at,
            ) = row?;
            Ok(DevicePresenceObservation {
                observation_id: bytes_to_hash32(&observation_id)?,
                device_id: device_id
                    .as_deref()
                    .map(bytes_to_hash32)
                    .transpose()?
                    .map(DeviceId),
                observer: NodeId(bytes_to_hash32(&observer)?),
                network,
                source,
                first_seen,
                last_seen,
                expires_at,
            })
        })
        .collect()
    }

    pub fn delete_device_presence(&self, observation_id: Hash32) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM device_presence_observations WHERE observation_id = ?1",
            params![observation_id.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn upsert_local_route_profile(
        &self,
        profile: &LocalRouteProfile,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO local_route_profiles (name, table_id, interface, enabled, vpn)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(name) DO UPDATE SET table_id = excluded.table_id,
               interface = excluded.interface, enabled = excluded.enabled, vpn = excluded.vpn",
            params![
                profile.name,
                profile.table as i64,
                profile.interface,
                profile.enabled as i64,
                profile.vpn as i64
            ],
        )?;
        Ok(())
    }

    pub fn list_local_route_profiles(&self) -> Result<Vec<LocalRouteProfile>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT name, table_id, interface, enabled, vpn FROM local_route_profiles ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(LocalRouteProfile {
                name: row.get(0)?,
                table: row.get::<_, i64>(1)? as u32,
                interface: row.get(2)?,
                enabled: row.get::<_, i64>(3)? != 0,
                vpn: row.get::<_, i64>(4)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StoreError::from)
    }

    pub fn local_route_profile(&self, name: &str) -> Result<Option<LocalRouteProfile>, StoreError> {
        Ok(self
            .list_local_route_profiles()?
            .into_iter()
            .find(|p| p.name == name))
    }

    pub fn list_active_shared_policies(&self) -> Result<Vec<SharedPolicy>, StoreError> {
        let Some(profile) = self.active_local_profile()? else {
            return Ok(Vec::new());
        };
        let policies = self.list_shared_policies()?;
        Ok(policies
            .into_iter()
            .filter(|policy| profile.policy_ids.contains(&policy.policy_id))
            .collect())
    }

    pub fn next_policy_vote_sequence(
        &self,
        policy_id: Hash32,
        entry_id: Hash32,
        policy_sequence: u64,
        group_id: GroupId,
        voter: &UserId,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM policy_votes
             WHERE policy_id = ?1 AND entry_id = ?2 AND policy_sequence = ?3
               AND group_id = ?4 AND voter_federation_id = ?5 AND voter_local_id = ?6",
            params![
                policy_id.0.as_slice(),
                entry_id.0.as_slice(),
                policy_sequence as i64,
                group_id.0 .0.as_slice(),
                voter.federation.0 .0.as_slice(),
                voter.local_id.0.as_slice(),
            ],
            |row| row.get(0),
        )?;
        Ok(max.map(|value| value as u64 + 1).unwrap_or(0))
    }

    /// Policy votes are never gated at ingest. Whether a vote counts is
    /// determined from the group's current voting membership by the helper
    /// methods below, just like `GroupVote`.
    pub fn store_policy_vote(&self, vote: &PolicyVote) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO policy_votes
             (policy_id, entry_id, policy_sequence, group_id, voter_federation_id,
              voter_local_id, sequence, stance, reason_code, reason_note,
              reason_evidence, issued_at, expires_at, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(policy_id, entry_id, policy_sequence, group_id,
                         voter_federation_id, voter_local_id, sequence) DO NOTHING",
            params![
                vote.policy_id.0.as_slice(),
                vote.entry_id.0.as_slice(),
                vote.policy_sequence as i64,
                vote.group_id.0 .0.as_slice(),
                vote.voter.federation.0 .0.as_slice(),
                vote.voter.local_id.0.as_slice(),
                vote.sequence as i64,
                stance_to_i64(vote.stance),
                reason_code_to_i64(vote.reason.code),
                vote.reason.note,
                encode_evidence(&vote.reason.evidence),
                vote.issued_at,
                vote.expires_at,
                vote.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    pub fn list_policy_votes(
        &self,
        policy_id: Hash32,
        entry_id: Hash32,
        group_id: GroupId,
    ) -> Result<Vec<PolicyVote>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT policy_sequence, voter_federation_id, voter_local_id, sequence,
                    stance, reason_code, reason_note, reason_evidence, issued_at,
                    expires_at, signature
             FROM policy_votes
             WHERE policy_id = ?1 AND entry_id = ?2 AND group_id = ?3
             ORDER BY issued_at ASC, policy_sequence ASC, sequence ASC",
        )?;
        let rows = stmt.query_map(
            params![
                policy_id.0.as_slice(),
                entry_id.0.as_slice(),
                group_id.0 .0.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (
                policy_sequence,
                voter_fed,
                voter_local,
                sequence,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                expires_at,
                signature,
            ) = row?;
            out.push(PolicyVote {
                policy_id,
                entry_id,
                policy_sequence: policy_sequence as u64,
                group_id,
                voter: UserId {
                    federation: FederationId(bytes_to_hash32(&voter_fed)?),
                    local_id: bytes_to_hash32(&voter_local)?,
                },
                sequence: sequence as u64,
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                expires_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    /// The latest vote from each current voting member for one policy entry.
    /// The boolean says whether that vote is non-expired at `now`.
    pub fn policy_vote_breakdown_for(
        &self,
        policy_id: Hash32,
        entry_id: Hash32,
        policy_sequence: u64,
        group_id: GroupId,
        now: i64,
    ) -> Result<Vec<(UserId, Option<PolicyVote>, bool)>, StoreError> {
        let Some(group) = self.get_group(group_id)? else {
            return Ok(vec![]);
        };
        let mut out = Vec::new();
        for member in &group.voting_members {
            let vote = self
                .list_policy_votes(policy_id, entry_id, group_id)?
                .into_iter()
                .filter(|vote| vote.policy_sequence == policy_sequence && vote.voter == *member)
                .max_by_key(|vote| vote.sequence);
            let counts = vote.as_ref().is_some_and(|vote| !vote.is_expired(now));
            out.push((*member, vote, counts));
        }
        Ok(out)
    }

    pub fn policy_stance_for(
        &self,
        policy_id: Hash32,
        entry_id: Hash32,
        policy_sequence: u64,
        group_id: GroupId,
        now: i64,
    ) -> Result<Option<(Stance, usize, usize)>, StoreError> {
        let mut allow = 0;
        let mut deny = 0;
        for (_, vote, counts) in
            self.policy_vote_breakdown_for(policy_id, entry_id, policy_sequence, group_id, now)?
        {
            if !counts {
                continue;
            }
            match vote.map(|vote| vote.stance) {
                Some(Stance::Allow) => allow += 1,
                Some(Stance::Deny) => deny += 1,
                Some(Stance::Ask) | None => {}
            }
        }
        match allow.cmp(&deny) {
            std::cmp::Ordering::Greater => Ok(Some((Stance::Allow, allow, deny))),
            std::cmp::Ordering::Less => Ok(Some((Stance::Deny, allow, deny))),
            _ => Ok(None),
        }
    }
}

/// One list entry alongside the context `policy-engine` needs to weigh
/// it: the list's author (whose `LocalTrustRule` applies), the list's
/// own categories (so `category_filter` can be checked), and that
/// author's current follow/trust rule (`None` if not followed at all).
pub type ListEntryContext = (SharedRuleEntry, UserId, Vec<String>, Option<LocalTrustRule>);

impl StateStore {
    /// Same MAX-based counter pattern as `next_tunnel_advertisement_sequence`
    /// — one monotonic id space per author, shared across every list name
    /// they publish (a new version of an existing list and a brand-new
    /// differently-named list both just get the next unused sequence).
    pub fn next_shared_rule_list_sequence(&self, author: &UserId) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM shared_rule_lists WHERE author_federation_id = ?1 AND author_local_id = ?2",
            params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Follow-gated the same way `ingest_tunnel_advertisement` is —
    /// adopting a subscribed list has real effect on this router's
    /// policy via `policy-engine`'s trust-weighted aggregation, not just
    /// a zero-weighted data point, so an unfollowed author's list is
    /// rejected outright rather than silently stored at no weight.
    pub fn ingest_shared_rule_list(&self, list: &SharedRuleList) -> Result<(), StoreError> {
        if self.get_follow(&list.author)?.is_none() {
            return Err(StoreError::NotFollowed(format!(
                "{}/{}",
                list.author.federation.0, list.author.local_id
            )));
        }
        self.store_shared_rule_list_row(list)
    }

    /// This router's own list, published under its own identity — no
    /// follow-gate, same distinction `store_own_tunnel_advertisement`
    /// draws from `ingest_tunnel_advertisement`.
    pub fn store_own_shared_rule_list(&self, list: &SharedRuleList) -> Result<(), StoreError> {
        self.store_shared_rule_list_row(list)
    }

    fn store_shared_rule_list_row(&self, list: &SharedRuleList) -> Result<(), StoreError> {
        // Version-replace, not accumulate: a new version physically
        // replaces the version it supersedes (cascading to that version's
        // own entries/categories), the same wholesale-replace shape
        // `kestreld`'s `replace_threat_feed`/`replace_oui` already use —
        // not a growing history of full-entry-copies per version.
        if let Some(old_seq) = list.supersedes {
            self.conn.execute(
                "DELETE FROM shared_rule_lists WHERE author_federation_id = ?1 AND author_local_id = ?2 AND sequence = ?3",
                params![list.author.federation.0 .0.as_slice(), list.author.local_id.0.as_slice(), old_seq as i64],
            )?;
        }
        self.conn.execute(
            "INSERT INTO shared_rule_lists (author_federation_id, author_local_id, sequence, name, description, visibility, issued_at, expires_at, supersedes_sequence, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(author_federation_id, author_local_id, sequence) DO NOTHING",
            params![
                list.author.federation.0 .0.as_slice(),
                list.author.local_id.0.as_slice(),
                list.sequence as i64,
                list.name,
                list.description,
                visibility_to_i64(list.visibility),
                list.issued_at,
                list.expires_at,
                list.supersedes.map(|s| s as i64),
                list.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        for category in &list.categories {
            self.conn.execute(
                "INSERT INTO shared_rule_list_categories (author_federation_id, author_local_id, sequence, category)
                 VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING",
                params![list.author.federation.0 .0.as_slice(), list.author.local_id.0.as_slice(), list.sequence as i64, category],
            )?;
        }
        for entry in &list.entries {
            let (kind, value) = target_to_kv(&entry.target)?;
            self.conn.execute(
                "INSERT INTO shared_rule_list_entries (author_federation_id, author_local_id, sequence, target_kind, target_value, stance, reason_code, reason_note, reason_evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT DO NOTHING",
                params![
                    list.author.federation.0 .0.as_slice(),
                    list.author.local_id.0.as_slice(),
                    list.sequence as i64,
                    kind,
                    value,
                    stance_to_i64(entry.stance),
                    reason_code_to_i64(entry.reason.code),
                    entry.reason.note,
                    encode_evidence(&entry.reason.evidence),
                ],
            )?;
        }
        Ok(())
    }

    pub fn get_shared_rule_list(
        &self,
        author: UserId,
        sequence: u64,
    ) -> Result<Option<SharedRuleList>, StoreError> {
        let meta = self
            .conn
            .query_row(
                "SELECT name, description, visibility, issued_at, expires_at, supersedes_sequence, signature
                 FROM shared_rule_lists WHERE author_federation_id = ?1 AND author_local_id = ?2 AND sequence = ?3",
                params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice(), sequence as i64],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                        row.get::<_, Option<i64>>(5)?,
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            name,
            description,
            visibility,
            issued_at,
            expires_at,
            supersedes_sequence,
            signature,
        )) = meta
        else {
            return Ok(None);
        };
        Ok(Some(SharedRuleList {
            author,
            sequence,
            name,
            description,
            categories: self.shared_rule_list_categories(&author, sequence)?,
            visibility: visibility_from_i64(visibility)?,
            entries: self.shared_rule_list_entries_for_list(&author, sequence)?,
            issued_at,
            expires_at,
            supersedes: supersedes_sequence.map(|s| s as u64),
            signature: SignatureBytes(bytes_to_64(&signature)?),
        }))
    }

    /// **Known limitation**: this is a `WITHOUT ROWID` child table keyed
    /// (among other things) by `category` itself, so rows come back in
    /// primary-key order, not original-publish order — same reordering
    /// risk `tunnel_advertisement_targets`' `route_scope` reconstruction
    /// already has. Harmless today (nothing re-verifies a signature
    /// against a value reconstructed from storage — verification happens
    /// once, against the freshly-parsed wire format, before it's ever
    /// stored), but worth a real ordinal column if that ever changes.
    fn shared_rule_list_categories(
        &self,
        author: &UserId,
        sequence: u64,
    ) -> Result<Vec<String>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT category FROM shared_rule_list_categories WHERE author_federation_id = ?1 AND author_local_id = ?2 AND sequence = ?3",
        )?;
        let rows = stmt.query_map(
            params![
                author.federation.0 .0.as_slice(),
                author.local_id.0.as_slice(),
                sequence as i64
            ],
            |row| row.get::<_, String>(0),
        )?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    fn shared_rule_list_entries_for_list(
        &self,
        author: &UserId,
        sequence: u64,
    ) -> Result<Vec<SharedRuleEntry>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT target_kind, target_value, stance, reason_code, reason_note, reason_evidence
             FROM shared_rule_list_entries WHERE author_federation_id = ?1 AND author_local_id = ?2 AND sequence = ?3",
        )?;
        let rows = stmt.query_map(
            params![
                author.federation.0 .0.as_slice(),
                author.local_id.0.as_slice(),
                sequence as i64
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (kind, value, stance, reason_code, reason_note, reason_evidence) = r?;
            let Some(target) = kv_to_target(&kind, &value) else {
                continue;
            };
            out.push(SharedRuleEntry {
                target,
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
            });
        }
        Ok(out)
    }

    pub fn list_shared_rule_lists(&self) -> Result<Vec<SharedRuleList>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT author_federation_id, author_local_id, sequence FROM shared_rule_lists",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut refs = Vec::new();
        for r in rows {
            let (fed, local, sequence) = r?;
            refs.push((
                UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                },
                sequence as u64,
            ));
        }
        let mut out = Vec::new();
        for (author, sequence) in refs {
            if let Some(list) = self.get_shared_rule_list(author, sequence)? {
                out.push(list);
            }
        }
        Ok(out)
    }

    /// The list-derived analogue of `list_followed_opinions_for`: every
    /// entry, across every currently-known list version, that targets
    /// `target` — paired with that list's author, that list's categories
    /// (so a caller can apply `LocalTrustRule.category_filter`), and that
    /// author's current follow/trust rule.
    /// Unlike `PolicyOpinion` (which carries its own `expires_at` and
    /// leaves expiry filtering to `policy-engine`, matching every other
    /// input there), a `SharedRuleEntry` has no expiry of its own — only
    /// the *list* does. Filtered here, at the source, rather than
    /// threading the list's `expires_at` through the returned tuple: an
    /// expired list is expected to get republished as a fresh version
    /// (lists are wholesale-regenerated, not incrementally maintained the
    /// way individual opinions are), so "stop counting an expired list's
    /// entries" is a storage-layer concern here, not something
    /// `policy-engine`'s explanation needs to narrate per-entry.
    pub fn list_entries_for(
        &self,
        target: &TargetSelector,
        now: i64,
    ) -> Result<Vec<ListEntryContext>, StoreError> {
        let (kind, value) = target_to_kv(target)?;
        let mut stmt = self.conn.prepare(
            "SELECT e.author_federation_id, e.author_local_id, e.sequence, e.stance, e.reason_code, e.reason_note, e.reason_evidence
             FROM shared_rule_list_entries e
             JOIN shared_rule_lists l
               ON l.author_federation_id = e.author_federation_id AND l.author_local_id = e.author_local_id AND l.sequence = e.sequence
             WHERE e.target_kind = ?1 AND e.target_value = ?2 AND (l.expires_at IS NULL OR l.expires_at > ?3)",
        )?;
        let rows = stmt.query_map(params![kind, value, now], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (fed, local, sequence, stance, reason_code, reason_note, reason_evidence) = r?;
            let author = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            let entry = SharedRuleEntry {
                target: target.clone(),
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
            };
            let categories = self.shared_rule_list_categories(&author, sequence as u64)?;
            let trust = self.get_follow(&author)?;
            out.push((entry, author, categories, trust));
        }
        Ok(out)
    }
}

/// The last nftables ruleset this node actually applied successfully —
/// consulted by `nft-enforcer` for the idempotency comparison (`digest`)
/// and as a rollback-of-last-resort text if a live re-snapshot isn't
/// available. See `nft-enforcer`'s `NftablesController::apply`, which
/// re-snapshots the *live* ruleset fresh on every apply attempt rather
/// than trusting this row for the actual rollback target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedRulesetState {
    pub digest: String,
    pub ruleset_text: String,
    pub revision: i64,
    pub updated_at: i64,
}

impl StateStore {
    pub fn get_applied_ruleset(&self) -> Result<Option<AppliedRulesetState>, StoreError> {
        self.conn
            .query_row(
                "SELECT digest, ruleset_text, revision, updated_at FROM applied_ruleset_state WHERE id = 0",
                [],
                |row| {
                    Ok(AppliedRulesetState {
                        digest: row.get(0)?,
                        ruleset_text: row.get(1)?,
                        revision: row.get(2)?,
                        updated_at: row.get(3)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn save_applied_ruleset(&self, state: &AppliedRulesetState) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO applied_ruleset_state (id, digest, ruleset_text, revision, updated_at) VALUES (0, ?1, ?2, ?3, ?4)
             ON CONFLICT(id) DO UPDATE SET digest = excluded.digest, ruleset_text = excluded.ruleset_text, revision = excluded.revision, updated_at = excluded.updated_at",
            params![state.digest, state.ruleset_text, state.revision, state.updated_at],
        )?;
        Ok(())
    }

    pub fn append_apply_log(
        &self,
        revision: i64,
        digest: &str,
        decision_count: i64,
        summary: &str,
        outcome: &str,
        applied_at: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO apply_log (revision, digest, decision_count, summary, outcome, applied_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![revision, digest, decision_count, summary, outcome, applied_at],
        )?;
        Ok(())
    }

    /// Wipes the entire "why is this rule active" snapshot — the first
    /// step of every real `sf apply` run, since it's about to be
    /// completely repopulated from a fresh evaluation pass over every
    /// target. Never called from a dry run (see `apply_all`'s own
    /// dry-run branch, which never touches state at all).
    pub fn clear_enforced_decision_contributors(&self) -> Result<(), StoreError> {
        self.conn
            .execute("DELETE FROM enforced_decision_contributors", [])?;
        Ok(())
    }

    /// Records every contributing source behind one target's enforced
    /// decision — called once per enforced target, after
    /// `clear_enforced_decision_contributors`, while repopulating the
    /// snapshot for a fresh `sf apply` run.
    pub fn record_enforced_decision_contributors(
        &self,
        target: &TargetSelector,
        contributing: &[Contribution],
    ) -> Result<(), StoreError> {
        let (kind, value) = target_to_kv(target)?;
        for c in contributing {
            let (source_kind, source_fed, source_local): (&str, &[u8], Option<&[u8]>) =
                match &c.source {
                    StatementAuthor::User(u) => (
                        "user",
                        u.federation.0 .0.as_slice(),
                        Some(u.local_id.0.as_slice()),
                    ),
                    StatementAuthor::Federation(f) => ("federation", f.0 .0.as_slice(), None),
                    StatementAuthor::Group(g) => ("group", g.0 .0.as_slice(), None),
                };
            self.conn.execute(
                "INSERT INTO enforced_decision_contributors (target_kind, target_value, source_kind, source_federation_id, source_local_id, stance, weight, reason_code, reason_note, reason_evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![kind, value, source_kind, source_fed, source_local, stance_to_i64(c.stance), c.weight, reason_code_to_i64(c.reason.code), c.reason.note, encode_evidence(&c.reason.evidence)],
            )?;
        }
        Ok(())
    }

    /// Every contributing source behind `target`'s currently-enforced
    /// decision — the `sf explain-enforced` lookup. Empty if `target`
    /// isn't currently enforced, or its decision came from a tier that
    /// doesn't have contributors at all (a `LocalOverride`/owner-opinion
    /// decision, which `policy-engine` never populates `contributing` for).
    pub fn enforced_decision_contributors_for(
        &self,
        target: &TargetSelector,
    ) -> Result<Vec<Contribution>, StoreError> {
        let (kind, value) = target_to_kv(target)?;
        let mut stmt = self.conn.prepare(
            "SELECT source_kind, source_federation_id, source_local_id, stance, weight, reason_code, reason_note, reason_evidence
             FROM enforced_decision_contributors WHERE target_kind = ?1 AND target_value = ?2",
        )?;
        let rows = stmt.query_map(params![kind, value], Self::row_to_contribution)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r??);
        }
        Ok(out)
    }

    /// Every currently-enforced target with at least one contributor,
    /// paired with its contributors — the "browse everything" surface,
    /// `sf list-enforced-decisions`.
    pub fn list_all_enforced_decision_contributors(
        &self,
    ) -> Result<Vec<(TargetSelector, Contribution)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT target_kind, target_value, source_kind, source_federation_id, source_local_id, stance, weight, reason_code, reason_note, reason_evidence
             FROM enforced_decision_contributors",
        )?;
        let rows = stmt.query_map([], |row| {
            let kind: String = row.get(0)?;
            let value: String = row.get(1)?;
            let contribution = Self::row_to_contribution_from(row, 2)?;
            Ok((kind, value, contribution))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (kind, value, contribution) = r?;
            let Some(target) = kv_to_target(&kind, &value) else {
                continue;
            };
            out.push((target, contribution?));
        }
        Ok(out)
    }

    fn row_to_contribution(
        row: &rusqlite::Row,
    ) -> rusqlite::Result<Result<Contribution, StoreError>> {
        Self::row_to_contribution_from(row, 0)
    }

    fn row_to_contribution_from(
        row: &rusqlite::Row,
        offset: usize,
    ) -> rusqlite::Result<Result<Contribution, StoreError>> {
        let source_kind: String = row.get(offset)?;
        let source_fed: Vec<u8> = row.get(offset + 1)?;
        let source_local: Option<Vec<u8>> = row.get(offset + 2)?;
        let stance: i64 = row.get(offset + 3)?;
        let weight: f64 = row.get(offset + 4)?;
        let reason_code: i64 = row.get(offset + 5)?;
        let reason_note: Option<String> = row.get(offset + 6)?;
        let reason_evidence: Vec<u8> = row.get(offset + 7)?;

        Ok((|| -> Result<Contribution, StoreError> {
            let source = match source_kind.as_str() {
                "federation" => {
                    StatementAuthor::Federation(FederationId(bytes_to_hash32(&source_fed)?))
                }
                "group" => StatementAuthor::Group(GroupId(bytes_to_hash32(&source_fed)?)),
                _ => {
                    let local = source_local.ok_or_else(|| {
                        StoreError::Encoding("user contribution row missing source_local_id".into())
                    })?;
                    StatementAuthor::User(UserId {
                        federation: FederationId(bytes_to_hash32(&source_fed)?),
                        local_id: bytes_to_hash32(&local)?,
                    })
                }
            };
            Ok(Contribution {
                source,
                stance: stance_from_i64(stance)?,
                weight,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
            })
        })())
    }
}

/// Which side of a tunnel relationship this router is on — `wg-tunnel`'s
/// reconciliation target, the same role `AppliedRulesetState` plays for
/// `nft-enforcer`. Rebuildable from the handshake tables in principle,
/// but tracked explicitly here since it's what real `wg`/`ip` state gets
/// diffed against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelDirection {
    /// This router offered the tunnel; `peer` is the consumer.
    Providing,
    /// This router is using someone else's tunnel; `peer` is the provider.
    Consuming,
}

impl TunnelDirection {
    fn as_str(self) -> &'static str {
        match self {
            TunnelDirection::Providing => "providing",
            TunnelDirection::Consuming => "consuming",
        }
    }
    fn from_str(s: &str) -> Result<Self, StoreError> {
        match s {
            "providing" => Ok(TunnelDirection::Providing),
            "consuming" => Ok(TunnelDirection::Consuming),
            other => Err(StoreError::Encoding(format!(
                "invalid tunnel direction {other}"
            ))),
        }
    }
}

/// See `StateStore::list_tunnel_balances`'s own doc, including its
/// documented limitation for a peer this router both provides to and
/// consumes from simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelBalance {
    pub peer: UserId,
    pub given_to: u64,
    pub taken_from: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionedTunnel {
    pub peer: UserId,
    pub direction: TunnelDirection,
    /// Needed to actually manage this peer via `wg` — reconciliation has
    /// no other way to know which live WireGuard peer this row is about.
    pub peer_wg_pubkey: WgPublicKeyBytes,
    pub interface_name: String,
    pub fwmark: i64,
    pub route_table: i64,
    pub tunnel_ip: String,
    /// Tunnel-internal IPv6 address, alongside `tunnel_ip` — see
    /// `0015_tunnel_ipv6.sql`'s own doc on why this exists and why it's
    /// nullable (pre-IPv6-support rows) rather than required.
    pub tunnel_ip6: Option<String>,
    pub status: String,
    pub created_at: i64,
    /// Back-reference to the advertisement this tunnel was consumed
    /// from — `None` for a `Providing` row (the provider doesn't need
    /// this) and for anything predating this field. Lets reconciliation
    /// look up that advertisement's `max_connections`/`max_bandwidth_kbps`
    /// at `provision_routing` time.
    pub advertisement_sequence: Option<u64>,
}

impl StateStore {
    pub fn upsert_provisioned_tunnel(&self, t: &ProvisionedTunnel) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO provisioned_tunnels (peer_federation_id, peer_local_id, direction, peer_wg_pubkey, interface_name, fwmark, route_table, tunnel_ip, tunnel_ip6, status, created_at, advertisement_sequence)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(peer_federation_id, peer_local_id, direction) DO UPDATE SET
                peer_wg_pubkey = excluded.peer_wg_pubkey, interface_name = excluded.interface_name, fwmark = excluded.fwmark, route_table = excluded.route_table,
                tunnel_ip = excluded.tunnel_ip, tunnel_ip6 = excluded.tunnel_ip6, status = excluded.status, advertisement_sequence = excluded.advertisement_sequence",
            params![
                t.peer.federation.0 .0.as_slice(),
                t.peer.local_id.0.as_slice(),
                t.direction.as_str(),
                t.peer_wg_pubkey.0.as_slice(),
                t.interface_name,
                t.fwmark,
                t.route_table,
                t.tunnel_ip,
                t.tunnel_ip6,
                t.status,
                t.created_at,
                t.advertisement_sequence.map(|s| s as i64),
            ],
        )?;
        Ok(())
    }

    pub fn get_provisioned_tunnel(
        &self,
        peer: &UserId,
        direction: TunnelDirection,
    ) -> Result<Option<ProvisionedTunnel>, StoreError> {
        self.conn
            .query_row(
                "SELECT peer_wg_pubkey, interface_name, fwmark, route_table, tunnel_ip, tunnel_ip6, status, created_at, advertisement_sequence FROM provisioned_tunnels
                 WHERE peer_federation_id = ?1 AND peer_local_id = ?2 AND direction = ?3",
                params![peer.federation.0 .0.as_slice(), peer.local_id.0.as_slice(), direction.as_str()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, i64>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                    ))
                },
            )
            .optional()?
            .map(|(wg_pubkey, interface_name, fwmark, route_table, tunnel_ip, tunnel_ip6, status, created_at, advertisement_sequence)| {
                Ok(ProvisionedTunnel {
                    peer: *peer,
                    direction,
                    peer_wg_pubkey: WgPublicKeyBytes(bytes_to_32(&wg_pubkey)?),
                    interface_name,
                    fwmark,
                    route_table,
                    tunnel_ip,
                    tunnel_ip6,
                    status,
                    created_at,
                    advertisement_sequence: advertisement_sequence.map(|s| s as u64),
                })
            })
            .transpose()
    }

    pub fn remove_provisioned_tunnel(
        &self,
        peer: &UserId,
        direction: TunnelDirection,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM provisioned_tunnels WHERE peer_federation_id = ?1 AND peer_local_id = ?2 AND direction = ?3",
            params![peer.federation.0 .0.as_slice(), peer.local_id.0.as_slice(), direction.as_str()],
        )?;
        Ok(())
    }

    pub fn list_provisioned_tunnels(&self) -> Result<Vec<ProvisionedTunnel>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT peer_federation_id, peer_local_id, direction, peer_wg_pubkey, interface_name, fwmark, route_table, tunnel_ip, tunnel_ip6, status, created_at, advertisement_sequence FROM provisioned_tunnels",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, i64>(10)?,
                row.get::<_, Option<i64>>(11)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                direction,
                wg_pubkey,
                interface_name,
                fwmark,
                route_table,
                tunnel_ip,
                tunnel_ip6,
                status,
                created_at,
                advertisement_sequence,
            ) = r?;
            out.push(ProvisionedTunnel {
                peer: UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                },
                direction: TunnelDirection::from_str(&direction)?,
                peer_wg_pubkey: WgPublicKeyBytes(bytes_to_32(&wg_pubkey)?),
                interface_name,
                fwmark,
                route_table,
                tunnel_ip,
                tunnel_ip6,
                status,
                created_at,
                advertisement_sequence: advertisement_sequence.map(|s| s as u64),
            });
        }
        Ok(out)
    }

    /// Accumulates one WireGuard transfer sample for a (peer, direction)
    /// pair — see `0017_tunnel_transfer_totals.sql`'s own doc. `raw_rx`/
    /// `raw_tx` are the *current* cumulative-since-interface-creation
    /// counters straight from `wg show <iface> dump`; this method turns
    /// them into a delta against the last-seen sample and adds it to a
    /// running total that survives the raw counter resetting (interface
    /// recreated, router rebooted): if the new raw value is lower than
    /// what was last seen, the whole new value is treated as a fresh
    /// delta rather than going negative.
    pub fn record_transfer_sample(
        &self,
        peer: &UserId,
        direction: TunnelDirection,
        raw_rx: u64,
        raw_tx: u64,
        now: i64,
    ) -> Result<(), StoreError> {
        let existing: Option<(i64, i64, i64, i64)> = self
            .conn
            .query_row(
                "SELECT last_raw_rx, last_raw_tx, cumulative_rx, cumulative_tx FROM tunnel_transfer_totals WHERE peer_federation_id = ?1 AND peer_local_id = ?2 AND direction = ?3",
                params![peer.federation.0 .0.as_slice(), peer.local_id.0.as_slice(), direction.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let (last_raw_rx, last_raw_tx, cumulative_rx, cumulative_tx) =
            existing.unwrap_or((0, 0, 0, 0));
        let raw_rx = raw_rx as i64;
        let raw_tx = raw_tx as i64;
        let delta_rx = if raw_rx >= last_raw_rx {
            raw_rx - last_raw_rx
        } else {
            raw_rx
        };
        let delta_tx = if raw_tx >= last_raw_tx {
            raw_tx - last_raw_tx
        } else {
            raw_tx
        };
        self.conn.execute(
            "INSERT INTO tunnel_transfer_totals (peer_federation_id, peer_local_id, direction, last_raw_rx, last_raw_tx, cumulative_rx, cumulative_tx, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(peer_federation_id, peer_local_id, direction) DO UPDATE SET
                last_raw_rx = excluded.last_raw_rx, last_raw_tx = excluded.last_raw_tx,
                cumulative_rx = excluded.cumulative_rx, cumulative_tx = excluded.cumulative_tx, updated_at = excluded.updated_at",
            params![peer.federation.0 .0.as_slice(), peer.local_id.0.as_slice(), direction.as_str(), raw_rx, raw_tx, cumulative_rx + delta_rx, cumulative_tx + delta_tx, now],
        )?;
        Ok(())
    }

    /// The tunnel-reciprocity signal: for each peer with at least one
    /// transfer sample, `given_to` is the total bytes (rx+tx combined,
    /// not just tx) recorded on this router's *providing*-direction row
    /// for them, and `taken_from` is the same on the *consuming*-direction
    /// row. Combined rx+tx, not tx-only/rx-only, because a provider's
    /// real resource cost is relaying traffic in both directions (the
    /// consumer's outbound bytes arriving as rx, the responses going back
    /// out as tx), not just one leg of it.
    ///
    /// **Known limitation, stated rather than silently overclaimed**: if
    /// this router simultaneously provides to *and* consumes from the
    /// same peer, both directions share the exact same underlying
    /// WireGuard peer entry (this router has exactly one persistent wg
    /// keypair, and so does the peer — see `ensure_interface_and_keypair`
    /// — so `wg show dump` reports one combined rx/tx pair for that
    /// peer, not two). In that case `given_to` and `taken_from` are both
    /// fed from the same combined counters and cannot be separated by
    /// role; a caller comparing them for a mutual peer is comparing the
    /// same number to itself, not a real distinction.
    pub fn list_tunnel_balances(&self) -> Result<Vec<TunnelBalance>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT peer_federation_id, peer_local_id, direction, cumulative_rx, cumulative_tx FROM tunnel_transfer_totals")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut by_peer: std::collections::HashMap<UserId, (u64, u64)> =
            std::collections::HashMap::new();
        for r in rows {
            let (fed, local, direction, cumulative_rx, cumulative_tx) = r?;
            let peer = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            let total = (cumulative_rx + cumulative_tx) as u64;
            let entry = by_peer.entry(peer).or_insert((0, 0));
            match TunnelDirection::from_str(&direction)? {
                TunnelDirection::Providing => entry.0 = total,
                TunnelDirection::Consuming => entry.1 = total,
            }
        }
        Ok(by_peer
            .into_iter()
            .map(|(peer, (given_to, taken_from))| TunnelBalance {
                peer,
                given_to,
                taken_from,
            })
            .collect())
    }

    /// Wholesale-replaces the selected-target list for a consuming
    /// tunnel — same "new version replaces the old one" idiom used
    /// elsewhere, appropriate here since selection is always "here is the
    /// full current set," not an incremental diff.
    pub fn set_provisioned_tunnel_selected_targets(
        &self,
        peer: &UserId,
        direction: TunnelDirection,
        targets: &[TargetSelector],
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM provisioned_tunnel_selected_targets WHERE peer_federation_id = ?1 AND peer_local_id = ?2 AND direction = ?3",
            params![peer.federation.0 .0.as_slice(), peer.local_id.0.as_slice(), direction.as_str()],
        )?;
        for t in targets {
            let (kind, value) = target_to_kv(t)?;
            self.conn.execute(
                "INSERT INTO provisioned_tunnel_selected_targets (peer_federation_id, peer_local_id, direction, target_kind, target_value)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![peer.federation.0 .0.as_slice(), peer.local_id.0.as_slice(), direction.as_str(), kind, value],
            )?;
        }
        Ok(())
    }

    pub fn get_provisioned_tunnel_selected_targets(
        &self,
        peer: &UserId,
        direction: TunnelDirection,
    ) -> Result<Vec<TargetSelector>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT target_kind, target_value FROM provisioned_tunnel_selected_targets WHERE peer_federation_id = ?1 AND peer_local_id = ?2 AND direction = ?3",
        )?;
        let rows = stmt.query_map(
            params![
                peer.federation.0 .0.as_slice(),
                peer.local_id.0.as_slice(),
                direction.as_str()
            ],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (kind, value) = r?;
            if let Some(t) = kv_to_target(&kind, &value) {
                out.push(t);
            }
        }
        Ok(out)
    }
}

// ── Groups ───────────────────────────────────────────────────────────────

/// A tally of every join-request decision this router has recorded for a
/// group — see `StateStore::group_join_track_record`'s own doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GroupJoinTrackRecord {
    pub approved: u64,
    pub rejected: u64,
    pub blocked: u64,
    pub pending: u64,
}

/// See `StateStore::network_health_summary`'s own doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkHealthSummary {
    pub owned_groups_total: usize,
    pub owned_groups_single_owner: usize,
    pub own_votes_total: usize,
    pub own_votes_expired: usize,
    /// A lower bound, not a complete count — see
    /// `network_health_summary`'s own doc on why. Unlike the other two
    /// fields folded into `attention_items`, this one is never complete
    /// local ground truth, only "what's reached this router so far."
    pub trusted_peers_with_block_reports: usize,
    pub follows_total: usize,
    pub follows_with_display_name: usize,
}

impl NetworkHealthSummary {
    /// One composite count, as requested — but every contributing number
    /// is individually visible on the struct too, so nothing here is
    /// opaque the way a weighted score would be. `trusted_peers_with_block_reports`
    /// is included in the sum (the "one number" ask), but callers
    /// displaying this should label that specific contribution as a
    /// lower bound rather than presenting all three as equally certain.
    pub fn attention_items(&self) -> usize {
        self.owned_groups_single_owner
            + self.own_votes_expired
            + self.trusted_peers_with_block_reports
    }
}

/// See `StateStore::list_group_membership_events`'s own doc. `Left` is
/// deliberately one neutral event, not distinguished from a kick/removal —
/// there's no live protocol here to tell a self-initiated departure apart
/// from an owner dropping someone, and inventing that distinction would
/// mean guessing at a motive the stored data doesn't actually carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipEventKind {
    Joined,
    Left,
}

impl StateStore {
    /// MAX-based counter, scoped to this *group* (not an author) — any
    /// current owner/admin can publish the next version, unlike every
    /// other sequence in this crate.
    pub fn next_group_sequence(&self, group_id: GroupId) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM groups WHERE group_id = ?1",
            params![group_id.0 .0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Accepts a new group version — validated (never zero owners) and,
    /// unless this is a brand-new `group_id`, authorized: `published_by`
    /// must be an owner or admin of the *currently stored* version (not
    /// the new one — otherwise anyone could publish a new version making
    /// themselves owner unilaterally). A brand-new group instead requires
    /// `published_by` to be among *this* version's own owners, so a
    /// group can't be created naming an uninvolved party as its sole
    /// owner. Version-replace, not accumulate, same as
    /// `ingest_shared_rule_list`: a new version physically replaces the
    /// one it supersedes (cascading to that version's owners/admins/
    /// members via `ON DELETE CASCADE`).
    pub fn ingest_group(&self, group: &Group) -> Result<(), StoreError> {
        group.validate().map_err(StoreError::InvalidGroup)?;
        // Populated only when this is an update to an existing group (a
        // brand-new group's initial membership never synthesizes "joined"
        // events — the same convention real IRC uses: you don't see
        // backfilled joins for people already in the channel when you
        // arrive). Computed here, before the previous version's row is
        // deleted below, since this is the one moment the old membership
        // list is still available to diff against.
        let mut membership_events: Vec<(UserId, &'static str)> = Vec::new();
        match self.get_group(group.group_id)? {
            Some(current) => {
                if !current.can_manage_membership(&group.published_by) {
                    return Err(StoreError::Unauthorized(format!(
                        "{}/{} is not an owner or admin of this group — refusing to accept this update",
                        group.published_by.federation.0, group.published_by.local_id
                    )));
                }
                // Admins can manage membership/voting rights, but only an
                // owner may change *who the owners are* — the one
                // distinction `can_manage_membership` deliberately
                // doesn't draw (it treats owners/admins as equally able
                // to publish an update at all), so it has to be checked
                // here as a second, narrower condition.
                if !current.is_owner(&group.published_by) {
                    let mut current_owners = current.owners.clone();
                    let mut new_owners = group.owners.clone();
                    current_owners.sort();
                    new_owners.sort();
                    if current_owners != new_owners {
                        return Err(StoreError::Unauthorized("only an owner may change the group's owners — an admin's update must leave the owners list untouched".to_string()));
                    }
                }
                // "Membership" here is the same union `Group::is_member`
                // uses (owners ∪ admins ∪ voting ∪ non-voting) — a pure
                // role change (e.g. voting -> non-voting, or gaining
                // admin) within that union is not a join or a leave.
                let previous_members: HashSet<UserId> = [
                    &current.owners,
                    &current.admins,
                    &current.voting_members,
                    &current.non_voting_members,
                ]
                .into_iter()
                .flatten()
                .copied()
                .collect();
                let new_members: HashSet<UserId> = [
                    &group.owners,
                    &group.admins,
                    &group.voting_members,
                    &group.non_voting_members,
                ]
                .into_iter()
                .flatten()
                .copied()
                .collect();
                for u in new_members.difference(&previous_members) {
                    membership_events.push((*u, "joined"));
                }
                for u in previous_members.difference(&new_members) {
                    membership_events.push((*u, "left"));
                }
            }
            None => {
                if !group.owners.contains(&group.published_by) {
                    return Err(StoreError::Unauthorized(
                        "a brand-new group's publisher must be one of its own listed owners"
                            .to_string(),
                    ));
                }
            }
        }
        if let Some(old_seq) = group.supersedes {
            self.conn.execute(
                "DELETE FROM groups WHERE group_id = ?1 AND sequence = ?2",
                params![group.group_id.0 .0.as_slice(), old_seq as i64],
            )?;
        }
        self.conn.execute(
            "INSERT INTO groups (group_id, sequence, published_by_federation_id, published_by_local_id, name, description, join_prompt, party_line_moderated, issued_at, expires_at, supersedes_sequence, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(group_id, sequence) DO NOTHING",
            params![
                group.group_id.0 .0.as_slice(),
                group.sequence as i64,
                group.published_by.federation.0 .0.as_slice(),
                group.published_by.local_id.0.as_slice(),
                group.name,
                group.description,
                group.join_prompt,
                group.party_line_moderated,
                group.issued_at,
                group.expires_at,
                group.supersedes.map(|s| s as i64),
                group.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        for (table, users) in [
            ("group_owners", &group.owners),
            ("group_admins", &group.admins),
            ("group_voting_members", &group.voting_members),
            ("group_non_voting_members", &group.non_voting_members),
            ("group_voiced_members", &group.voiced_members),
        ] {
            for u in users {
                self.conn.execute(
                    &format!("INSERT INTO {table} (group_id, sequence, user_federation_id, user_local_id) VALUES (?1, ?2, ?3, ?4) ON CONFLICT DO NOTHING"),
                    params![group.group_id.0 .0.as_slice(), group.sequence as i64, u.federation.0 .0.as_slice(), u.local_id.0.as_slice()],
                )?;
            }
        }
        for (user, kind) in &membership_events {
            self.conn.execute(
                "INSERT INTO group_membership_events (group_id, user_federation_id, user_local_id, kind, at) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![group.group_id.0 .0.as_slice(), user.federation.0 .0.as_slice(), user.local_id.0.as_slice(), *kind, group.issued_at],
            )?;
        }
        Ok(())
    }

    /// The party-line's IRC-style join/leave log for a group — see
    /// `ingest_group`'s own doc on where these are derived from. Ordered
    /// chronologically so a caller can merge this with
    /// `list_party_line_messages` into one timeline, same as a real IRC
    /// client interleaves join/part notices with chat.
    pub fn list_group_membership_events(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<(UserId, MembershipEventKind, i64)>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT user_federation_id, user_local_id, kind, at FROM group_membership_events WHERE group_id = ?1 ORDER BY at ASC, id ASC")?;
        let rows = stmt.query_map(params![group_id.0 .0.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (fed, local, kind, at) = r?;
            let user = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            let kind = match kind.as_str() {
                "joined" => MembershipEventKind::Joined,
                _ => MembershipEventKind::Left,
            };
            out.push((user, kind, at));
        }
        Ok(out)
    }

    pub fn get_group(&self, group_id: GroupId) -> Result<Option<Group>, StoreError> {
        let latest_sequence: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM groups WHERE group_id = ?1",
            params![group_id.0 .0.as_slice()],
            |row| row.get(0),
        )?;
        let Some(sequence) = latest_sequence else {
            return Ok(None);
        };
        let row = self
            .conn
            .query_row(
                "SELECT published_by_federation_id, published_by_local_id, name, description, join_prompt, party_line_moderated, issued_at, expires_at, supersedes_sequence, signature
                 FROM groups WHERE group_id = ?1 AND sequence = ?2",
                params![group_id.0 .0.as_slice(), sequence],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, bool>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, Option<i64>>(7)?,
                        row.get::<_, Option<i64>>(8)?,
                        row.get::<_, Vec<u8>>(9)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            pb_fed,
            pb_local,
            name,
            description,
            join_prompt,
            party_line_moderated,
            issued_at,
            expires_at,
            supersedes,
            signature,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(Group {
            group_id,
            published_by: UserId {
                federation: FederationId(bytes_to_hash32(&pb_fed)?),
                local_id: bytes_to_hash32(&pb_local)?,
            },
            sequence: sequence as u64,
            name,
            description,
            join_prompt,
            owners: self.group_members(group_id, sequence, "group_owners")?,
            admins: self.group_members(group_id, sequence, "group_admins")?,
            voting_members: self.group_members(group_id, sequence, "group_voting_members")?,
            non_voting_members: self.group_members(
                group_id,
                sequence,
                "group_non_voting_members",
            )?,
            party_line_moderated,
            voiced_members: self.group_members(group_id, sequence, "group_voiced_members")?,
            issued_at,
            expires_at,
            supersedes: supersedes.map(|s| s as u64),
            signature: SignatureBytes(bytes_to_64(&signature)?),
        }))
    }

    fn group_members(
        &self,
        group_id: GroupId,
        sequence: i64,
        table: &str,
    ) -> Result<Vec<UserId>, StoreError> {
        let mut stmt = self.conn.prepare(&format!("SELECT user_federation_id, user_local_id FROM {table} WHERE group_id = ?1 AND sequence = ?2"))?;
        let rows = stmt.query_map(params![group_id.0 .0.as_slice(), sequence], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (fed, local) = r?;
            out.push(UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            });
        }
        Ok(out)
    }

    pub fn list_groups(&self) -> Result<Vec<Group>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT group_id FROM groups")?;
        let ids: Vec<Vec<u8>> = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let mut out = Vec::new();
        for id in ids {
            if let Some(g) = self.get_group(GroupId(bytes_to_hash32(&id)?))? {
                out.push(g);
            }
        }
        Ok(out)
    }

    pub fn next_group_join_request_sequence(&self, requester: &UserId) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM group_join_requests WHERE requester_federation_id = ?1 AND requester_local_id = ?2",
            params![requester.federation.0 .0.as_slice(), requester.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Never gated — anyone can *ask* to join; that's the whole point of
    /// a request-and-approve model instead of open self-add. Approval is
    /// a separate act: an owner/admin republishing the group with the
    /// requester added, then marking this request approved.
    /// Never gated at ingest (same as `store_group_vote`) — the one
    /// exception is a requester already on this group's block list (see
    /// `block_group_user`): their request is still stored (so it's
    /// visible on review, not silently dropped) but lands as `'blocked'`
    /// instead of `'pending'`, so a blocked user's repeat attempts never
    /// need the owner to reject them by hand each time.
    pub fn store_group_join_request(&self, req: &GroupJoinRequest) -> Result<(), StoreError> {
        let status = if self.is_group_user_blocked(req.group_id, &req.requester)? {
            "blocked"
        } else {
            "pending"
        };
        self.conn.execute(
            "INSERT INTO group_join_requests (requester_federation_id, requester_local_id, sequence, group_id, answer, issued_at, signature, ingested_at, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(requester_federation_id, requester_local_id, sequence) DO NOTHING",
            params![
                req.requester.federation.0 .0.as_slice(),
                req.requester.local_id.0.as_slice(),
                req.sequence as i64,
                req.group_id.0 .0.as_slice(),
                req.answer,
                req.issued_at,
                req.signature.0.as_slice(),
                now_unix(),
                status,
            ],
        )?;
        Ok(())
    }

    pub fn list_pending_group_join_requests(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<GroupJoinRequest>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT requester_federation_id, requester_local_id, sequence, answer, issued_at, signature
             FROM group_join_requests WHERE group_id = ?1 AND status = 'pending'",
        )?;
        let rows = stmt.query_map(params![group_id.0 .0.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (fed, local, sequence, answer, issued_at, signature) = r?;
            out.push(GroupJoinRequest {
                requester: UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                },
                group_id,
                sequence: sequence as u64,
                answer,
                issued_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    pub fn set_group_join_request_status(
        &self,
        requester: &UserId,
        sequence: u64,
        status: &str,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE group_join_requests SET status = ?1 WHERE requester_federation_id = ?2 AND requester_local_id = ?3 AND sequence = ?4",
            params![status, requester.federation.0 .0.as_slice(), requester.local_id.0.as_slice(), sequence as i64],
        )?;
        Ok(())
    }

    /// A tally over `group_join_requests.status` for `group_id` — every
    /// decision this router has ever made or seen for this group's join
    /// requests, already sitting in the table, just never counted. Most
    /// meaningful from the owner's own router (the only one that sees
    /// every decision it made), where it's a self-audit: a careless
    /// owner can see their own approve/reject/block pattern the same way
    /// `explain-group-vote` already lets them see block reports against
    /// a voter. Not (yet) something a prospective member on a different
    /// router can query remotely — that would need the owner to actively
    /// export it, which this doesn't do.
    pub fn group_join_track_record(
        &self,
        group_id: GroupId,
    ) -> Result<GroupJoinTrackRecord, StoreError> {
        let mut record = GroupJoinTrackRecord::default();
        let mut stmt = self.conn.prepare(
            "SELECT status, COUNT(*) FROM group_join_requests WHERE group_id = ?1 GROUP BY status",
        )?;
        let rows = stmt.query_map(params![group_id.0 .0.as_slice()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for r in rows {
            let (status, count) = r?;
            match status.as_str() {
                "approved" => record.approved = count as u64,
                "rejected" => record.rejected = count as u64,
                "blocked" => record.blocked = count as u64,
                "pending" => record.pending = count as u64,
                _ => {}
            }
        }
        Ok(record)
    }

    // ── Group blocking ────────────────────────────────────────────────

    /// Permanently blocks `user` from `group_id` — a router-local
    /// moderation decision (not part of the signed `Group` state, same
    /// reasoning that already keeps a plain "rejected" status local-only:
    /// this is whichever router is reviewing requests unilaterally
    /// deciding, not a group-wide fact needing republication). Requires a
    /// `Reason` — a block with no reason is just an opaque veto, the same
    /// "reason required" principle `PolicyOpinion`/`GroupVote` already
    /// enforce. This is the purely local enforcement half; see
    /// `store_group_block_report` for the signed, exportable,
    /// attributable counterpart that actually surfaces *why* to the
    /// group's owner. Any *currently pending* request from this user is
    /// immediately flipped to `'blocked'` too (an owner blocking someone
    /// in response to their live request shouldn't need a separate reject
    /// step first), and any future `GroupJoinRequest` from them for this
    /// group is auto-stored as `'blocked'` rather than `'pending'` from
    /// then on — see `store_group_join_request`.
    pub fn block_group_user(
        &self,
        group_id: GroupId,
        user: &UserId,
        reason: &Reason,
        now: i64,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO group_blocked_users (group_id, user_federation_id, user_local_id, blocked_at, reason_code, reason_note, reason_evidence) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(group_id, user_federation_id, user_local_id) DO UPDATE SET blocked_at = excluded.blocked_at, reason_code = excluded.reason_code, reason_note = excluded.reason_note, reason_evidence = excluded.reason_evidence",
            params![
                group_id.0 .0.as_slice(),
                user.federation.0 .0.as_slice(),
                user.local_id.0.as_slice(),
                now,
                reason_code_to_i64(reason.code),
                reason.note,
                encode_evidence(&reason.evidence),
            ],
        )?;
        self.conn.execute(
            "UPDATE group_join_requests SET status = 'blocked'
             WHERE group_id = ?1 AND requester_federation_id = ?2 AND requester_local_id = ?3 AND status = 'pending'",
            params![group_id.0 .0.as_slice(), user.federation.0 .0.as_slice(), user.local_id.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn unblock_group_user(&self, group_id: GroupId, user: &UserId) -> Result<(), StoreError> {
        self.conn.execute(
            "DELETE FROM group_blocked_users WHERE group_id = ?1 AND user_federation_id = ?2 AND user_local_id = ?3",
            params![group_id.0 .0.as_slice(), user.federation.0 .0.as_slice(), user.local_id.0.as_slice()],
        )?;
        Ok(())
    }

    pub fn is_group_user_blocked(
        &self,
        group_id: GroupId,
        user: &UserId,
    ) -> Result<bool, StoreError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM group_blocked_users WHERE group_id = ?1 AND user_federation_id = ?2 AND user_local_id = ?3",
            params![group_id.0 .0.as_slice(), user.federation.0 .0.as_slice(), user.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Every user this router itself has blocked from `group_id`, paired
    /// with the reason given at block time.
    pub fn list_blocked_group_users(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<(UserId, Reason)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT user_federation_id, user_local_id, reason_code, reason_note, reason_evidence FROM group_blocked_users WHERE group_id = ?1",
        )?;
        let rows = stmt.query_map(params![group_id.0 .0.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (fed, local, reason_code, reason_note, reason_evidence) = r?;
            let user = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            let reason = Reason {
                code: reason_code_from_i64(reason_code)?,
                note: reason_note,
                evidence: decode_evidence(&reason_evidence)?,
            };
            out.push((user, reason));
        }
        Ok(out)
    }

    // ── Group block reports (signed, attributable, exportable) ─────────

    pub fn next_group_block_report_sequence(
        &self,
        group_id: GroupId,
        reporter: &UserId,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM group_block_reports WHERE group_id = ?1 AND reporter_federation_id = ?2 AND reporter_local_id = ?3",
            params![group_id.0 .0.as_slice(), reporter.federation.0 .0.as_slice(), reporter.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Never gated at ingest (same as `store_group_vote`) — anyone can
    /// report a block against anyone. Ingesting one from another router
    /// is purely informational: it is never consulted by
    /// `is_group_user_blocked`/`store_group_join_request`'s auto-reject
    /// logic, which only ever looks at *this* router's own
    /// `group_blocked_users` rows. Surfacing reports (e.g. to a group's
    /// owner, via `list_group_block_reports_for`) is a separate, explicit
    /// read — never automatic enforcement.
    pub fn store_group_block_report(&self, report: &GroupBlockReport) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO group_block_reports (group_id, reporter_federation_id, reporter_local_id, sequence, blocked_user_federation_id, blocked_user_local_id, reason_code, reason_note, reason_evidence, issued_at, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(group_id, reporter_federation_id, reporter_local_id, sequence) DO NOTHING",
            params![
                report.group_id.0 .0.as_slice(),
                report.reporter.federation.0 .0.as_slice(),
                report.reporter.local_id.0.as_slice(),
                report.sequence as i64,
                report.blocked_user.federation.0 .0.as_slice(),
                report.blocked_user.local_id.0.as_slice(),
                reason_code_to_i64(report.reason.code),
                report.reason.note,
                encode_evidence(&report.reason.evidence),
                report.issued_at,
                report.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    /// Every known report (from any reporter, including this router's own)
    /// that `blocked_user` has been blocked from `group_id` — the "roll
    /// up into attribution" view: an owner or reviewer can see how many
    /// independent routers have reported this same user, and why.
    pub fn list_group_block_reports_for(
        &self,
        group_id: GroupId,
        blocked_user: &UserId,
    ) -> Result<Vec<GroupBlockReport>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT reporter_federation_id, reporter_local_id, sequence, reason_code, reason_note, reason_evidence, issued_at, signature
             FROM group_block_reports WHERE group_id = ?1 AND blocked_user_federation_id = ?2 AND blocked_user_local_id = ?3",
        )?;
        let rows = stmt.query_map(
            params![
                group_id.0 .0.as_slice(),
                blocked_user.federation.0 .0.as_slice(),
                blocked_user.local_id.0.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                sequence,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                signature,
            ) = r?;
            out.push(GroupBlockReport {
                group_id,
                reporter: UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                },
                sequence: sequence as u64,
                blocked_user: *blocked_user,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    /// The "browse everything" counterpart to `list_group_block_reports_for`
    /// (which is scoped to one group + one blocked user) — used by
    /// `network_health_summary` to check block reports against *any*
    /// followed peer across *any* group, not just one specific pairing.
    pub fn list_all_group_block_reports(&self) -> Result<Vec<GroupBlockReport>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, reporter_federation_id, reporter_local_id, sequence, blocked_user_federation_id, blocked_user_local_id, reason_code, reason_note, reason_evidence, issued_at, signature
             FROM group_block_reports",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Vec<u8>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Vec<u8>>(10)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                group_id,
                reporter_fed,
                reporter_local,
                sequence,
                blocked_fed,
                blocked_local,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                signature,
            ) = r?;
            out.push(GroupBlockReport {
                group_id: GroupId(bytes_to_hash32(&group_id)?),
                reporter: UserId {
                    federation: FederationId(bytes_to_hash32(&reporter_fed)?),
                    local_id: bytes_to_hash32(&reporter_local)?,
                },
                sequence: sequence as u64,
                blocked_user: UserId {
                    federation: FederationId(bytes_to_hash32(&blocked_fed)?),
                    local_id: bytes_to_hash32(&blocked_local)?,
                },
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    pub fn next_group_vote_sequence(
        &self,
        group_id: GroupId,
        voter: &UserId,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM group_votes WHERE group_id = ?1 AND voter_federation_id = ?2 AND voter_local_id = ?3",
            params![group_id.0 .0.as_slice(), voter.federation.0 .0.as_slice(), voter.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Never gated at ingest (same as `store_tunnel_connection_request`)
    /// — whether a vote actually counts is decided at aggregation time
    /// (`group_stance_for`), by checking *current* voting membership,
    /// not here.
    pub fn store_group_vote(&self, vote: &GroupVote) -> Result<(), StoreError> {
        let (kind, value) = target_to_kv(&vote.target)?;
        self.conn.execute(
            "INSERT INTO group_votes (group_id, voter_federation_id, voter_local_id, sequence, target_kind, target_value, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(group_id, voter_federation_id, voter_local_id, sequence) DO NOTHING",
            params![
                vote.group_id.0 .0.as_slice(),
                vote.voter.federation.0 .0.as_slice(),
                vote.voter.local_id.0.as_slice(),
                vote.sequence as i64,
                kind,
                value,
                stance_to_i64(vote.stance),
                reason_code_to_i64(vote.reason.code),
                vote.reason.note,
                encode_evidence(&vote.reason.evidence),
                vote.issued_at,
                vote.expires_at,
                vote.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    /// This router's own latest vote per (group, target) — a superseded
    /// re-affirmation of the same vote doesn't count as a second, separate
    /// vote here, only the current one does. Used by
    /// `network_health_summary` to report how many of *your own* votes
    /// have gone stale, not how many votes you've ever cast.
    pub fn list_latest_own_votes(&self, self_user: &UserId) -> Result<Vec<GroupVote>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, sequence, target_kind, target_value, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, signature
             FROM group_votes gv1
             WHERE voter_federation_id = ?1 AND voter_local_id = ?2
               AND sequence = (
                   SELECT MAX(sequence) FROM group_votes gv2
                   WHERE gv2.group_id = gv1.group_id AND gv2.voter_federation_id = gv1.voter_federation_id
                     AND gv2.voter_local_id = gv1.voter_local_id AND gv2.target_kind = gv1.target_kind AND gv2.target_value = gv1.target_value
               )",
        )?;
        let rows = stmt.query_map(
            params![
                self_user.federation.0 .0.as_slice(),
                self_user.local_id.0.as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Vec<u8>>(10)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for r in rows {
            let (
                group_id,
                sequence,
                target_kind,
                target_value,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                expires_at,
                signature,
            ) = r?;
            let Some(target) = kv_to_target(&target_kind, &target_value) else {
                continue;
            };
            out.push(GroupVote {
                group_id: GroupId(bytes_to_hash32(&group_id)?),
                voter: *self_user,
                sequence: sequence as u64,
                target,
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                expires_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    /// The latest non-expired vote, if any, from each of a group's
    /// *current* voting members for `target` — majority-aggregated into
    /// one collective stance. A tie, or no votes at all, is `None` (no
    /// contribution either way, not a coin flip — same "no signal" ethos
    /// `policy-engine` already applies everywhere else).
    pub fn group_stance_for(
        &self,
        group_id: GroupId,
        target: &TargetSelector,
        now: i64,
    ) -> Result<Option<(Stance, usize, usize)>, StoreError> {
        let Some(group) = self.get_group(group_id)? else {
            return Ok(None);
        };
        let (kind, value) = target_to_kv(target)?;
        let mut allow = 0usize;
        let mut deny = 0usize;
        for member in &group.voting_members {
            let row = self
                .conn
                .query_row(
                    "SELECT stance, expires_at FROM group_votes
                     WHERE group_id = ?1 AND voter_federation_id = ?2 AND voter_local_id = ?3 AND target_kind = ?4 AND target_value = ?5
                     ORDER BY sequence DESC LIMIT 1",
                    params![group_id.0 .0.as_slice(), member.federation.0 .0.as_slice(), member.local_id.0.as_slice(), kind, value],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
                )
                .optional()?;
            let Some((stance, expires_at)) = row else {
                continue;
            };
            if matches!(expires_at, Some(exp) if exp <= now) {
                continue;
            }
            match stance_from_i64(stance)? {
                Stance::Allow => allow += 1,
                Stance::Deny => deny += 1,
                Stance::Ask => {}
            }
        }
        match allow.cmp(&deny) {
            std::cmp::Ordering::Greater => Ok(Some((Stance::Allow, allow, deny))),
            std::cmp::Ordering::Less => Ok(Some((Stance::Deny, allow, deny))),
            std::cmp::Ordering::Equal if allow == 0 => Ok(None),
            std::cmp::Ordering::Equal => Ok(None), // a genuine tie — no clear majority, not a coin flip
        }
    }

    /// The per-voter breakdown behind `group_stance_for`'s tally — every
    /// *current* voting member of the group, paired with their latest
    /// vote for `target` (if any) and whether that vote actually counts
    /// toward the aggregate right now (`false` for an expired vote — it
    /// still shows up here so a reviewer can see it existed, but
    /// `group_stance_for` itself never falls back to it). Never
    /// consumed by `policy-engine` — this is purely an audit/explanation
    /// view, the same role `enforced_decision_contributors_for` plays
    /// one layer up (which *peer* drove a decision); this is one layer
    /// down (which *voting member* drove a group's stance). Surfacing
    /// this is what lets a router hold a `LocalTrustRule` on a group's
    /// owner personally, informed by whether they've been admitting
    /// careless or bad-faith voters — no new trust dimension needed for
    /// that, just visibility into data already stored.
    /// Every vote ever cast in this group, across every target, in
    /// chronological order — the party-line's view of votes (see
    /// `list-party-line`'s CLI doc), not a stance-aggregation input.
    /// Unlike `group_vote_breakdown_for` this is never deduped to "only
    /// the latest per voter" — a vote being re-cast is a real, distinct
    /// event worth showing in an activity timeline, the same way IRC
    /// shows every message ever sent rather than collapsing to the
    /// latest one per person.
    pub fn list_group_votes(&self, group_id: GroupId) -> Result<Vec<GroupVote>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT voter_federation_id, voter_local_id, sequence, target_kind, target_value, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, signature
             FROM group_votes WHERE group_id = ?1 ORDER BY issued_at ASC",
        )?;
        let rows = stmt.query_map(params![group_id.0 .0.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, Vec<u8>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                sequence,
                target_kind,
                target_value,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                expires_at,
                signature,
            ) = r?;
            let Some(target) = kv_to_target(&target_kind, &target_value) else {
                continue;
            };
            out.push(GroupVote {
                group_id,
                voter: UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                },
                sequence: sequence as u64,
                target,
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                expires_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    pub fn group_vote_breakdown_for(
        &self,
        group_id: GroupId,
        target: &TargetSelector,
        now: i64,
    ) -> Result<Vec<(UserId, Option<GroupVote>, bool)>, StoreError> {
        let Some(group) = self.get_group(group_id)? else {
            return Ok(vec![]);
        };
        let (kind, value) = target_to_kv(target)?;
        let mut out = Vec::new();
        for member in &group.voting_members {
            let row = self
                .conn
                .query_row(
                    "SELECT sequence, stance, reason_code, reason_note, reason_evidence, issued_at, expires_at, signature
                     FROM group_votes
                     WHERE group_id = ?1 AND voter_federation_id = ?2 AND voter_local_id = ?3 AND target_kind = ?4 AND target_value = ?5
                     ORDER BY sequence DESC LIMIT 1",
                    params![group_id.0 .0.as_slice(), member.federation.0 .0.as_slice(), member.local_id.0.as_slice(), kind, value],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, Option<String>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, Option<i64>>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                        ))
                    },
                )
                .optional()?;
            let Some((
                sequence,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                issued_at,
                expires_at,
                signature,
            )) = row
            else {
                out.push((*member, None, false));
                continue;
            };
            let vote = GroupVote {
                group_id,
                voter: *member,
                sequence: sequence as u64,
                target: target.clone(),
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                issued_at,
                expires_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            };
            let counts = !matches!(expires_at, Some(exp) if exp <= now);
            out.push((*member, Some(vote), counts));
        }
        Ok(out)
    }

    /// Every trusted group's aggregate contribution for `target` — the
    /// group-derived analogue of `list_followed_opinions_for`/
    /// `list_entries_for`. `(group_id, stance, allow_votes, deny_votes,
    /// trust_rule)`; the vote counts let a caller build a human-readable
    /// reason ("3 of 4 voting members voted Deny").
    #[allow(clippy::type_complexity)]
    pub fn list_group_contributions_for(
        &self,
        target: &TargetSelector,
        now: i64,
    ) -> Result<Vec<(GroupId, Stance, usize, usize, GroupTrustRule)>, StoreError> {
        let mut out = Vec::new();
        for rule in self.list_group_trust_rules()? {
            if rule.excluded || rule.is_expired(now) {
                continue;
            }
            if let Some((stance, allow, deny)) =
                self.group_stance_for(rule.group_id, target, now)?
            {
                out.push((rule.group_id, stance, allow, deny, rule));
            }
        }
        Ok(out)
    }

    pub fn upsert_group_trust_rule(&self, rule: &GroupTrustRule) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO group_trust_rules (group_id, allow_weight, deny_weight, excluded, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(group_id) DO UPDATE SET allow_weight = excluded.allow_weight, deny_weight = excluded.deny_weight, excluded = excluded.excluded, expires_at = excluded.expires_at",
            params![rule.group_id.0 .0.as_slice(), rule.allow_weight, rule.deny_weight, rule.excluded, rule.expires_at, rule.created_at],
        )?;
        Ok(())
    }

    pub fn get_group_trust_rule(
        &self,
        group_id: GroupId,
    ) -> Result<Option<GroupTrustRule>, StoreError> {
        self.conn
            .query_row(
                "SELECT allow_weight, deny_weight, excluded, expires_at, created_at FROM group_trust_rules WHERE group_id = ?1",
                params![group_id.0 .0.as_slice()],
                |row| Ok(GroupTrustRule { group_id, allow_weight: row.get(0)?, deny_weight: row.get(1)?, excluded: row.get(2)?, expires_at: row.get(3)?, created_at: row.get(4)? }),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn list_group_trust_rules(&self) -> Result<Vec<GroupTrustRule>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT group_id, allow_weight, deny_weight, excluded, expires_at, created_at FROM group_trust_rules")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, f64>(1)?,
                row.get::<_, f64>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, Option<i64>>(4)?,
                row.get::<_, i64>(5)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (id, allow_weight, deny_weight, excluded, expires_at, created_at) = r?;
            out.push(GroupTrustRule {
                group_id: GroupId(bytes_to_hash32(&id)?),
                allow_weight,
                deny_weight,
                excluded,
                expires_at,
                created_at,
            });
        }
        Ok(out)
    }

    pub fn next_party_line_sequence(
        &self,
        group_id: GroupId,
        author: &UserId,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM party_line_messages WHERE group_id = ?1 AND author_federation_id = ?2 AND author_local_id = ?3",
            params![group_id.0 .0.as_slice(), author.federation.0 .0.as_slice(), author.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    pub fn store_party_line_message(&self, msg: &PartyLineMessage) -> Result<(), StoreError> {
        self.store_party_line_message_with_pubkey(msg, None)
    }

    pub fn store_party_line_message_with_pubkey(
        &self,
        msg: &PartyLineMessage,
        author_pubkey: Option<&PublicKeyBytes>,
    ) -> Result<(), StoreError> {
        let reply_target = msg.in_reply_to.as_ref().map(target_to_kv).transpose()?;
        self.conn.execute(
            "INSERT INTO party_line_messages (group_id, author_federation_id, author_local_id, sequence, body, in_reply_to_target_kind, in_reply_to_target_value, issued_at, signature, ingested_at, author_pubkey, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(group_id, author_federation_id, author_local_id, sequence) DO NOTHING",
            params![
                msg.group_id.0 .0.as_slice(),
                msg.author.federation.0 .0.as_slice(),
                msg.author.local_id.0.as_slice(),
                msg.sequence as i64,
                msg.body,
                reply_target.as_ref().map(|(k, _)| k.as_str()),
                reply_target.as_ref().map(|(_, v)| v.as_str()),
                msg.issued_at,
                msg.signature.0.as_slice(),
                now_unix(),
                author_pubkey.map(|key| key.0.as_slice()),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    pub fn party_line_message_author_pubkey(
        &self,
        msg: &PartyLineMessage,
    ) -> Result<Option<PublicKeyBytes>, StoreError> {
        self.conn.query_row(
            "SELECT author_pubkey FROM party_line_messages WHERE group_id = ?1 AND author_federation_id = ?2 AND author_local_id = ?3 AND sequence = ?4",
            params![msg.group_id.0 .0.as_slice(), msg.author.federation.0 .0.as_slice(), msg.author.local_id.0.as_slice(), msg.sequence as i64],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        ).optional()?.flatten().map(|bytes| bytes_to_32(&bytes).map(PublicKeyBytes)).transpose()
    }

    pub fn party_line_message_received_at(
        &self,
        msg: &PartyLineMessage,
    ) -> Result<Option<i64>, StoreError> {
        self.conn
            .query_row(
                "SELECT received_at FROM party_line_messages WHERE group_id = ?1 AND author_federation_id = ?2 AND author_local_id = ?3 AND sequence = ?4",
                params![
                    msg.group_id.0 .0.as_slice(),
                    msg.author.federation.0 .0.as_slice(),
                    msg.author.local_id.0.as_slice(),
                    msg.sequence as i64,
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(StoreError::from)
    }

    /// Filters against the group's *current* posting permissions
    /// (`Group::can_post_party_line`) — the same "current state wins,
    /// history doesn't grandfather anything in" principle
    /// `group_stance_for` already applies to votes: a message from
    /// someone since removed from the group, or devoiced after posting
    /// while a moderated party line was in effect, simply stops showing
    /// up. Storage itself (`store_party_line_message`) is deliberately
    /// ungated, same as votes/join-requests — this is where permission
    /// is actually enforced, at read time. An unknown group filters to
    /// nothing, the same safe-default `group_stance_for` uses.
    pub fn list_party_line_messages(
        &self,
        group_id: GroupId,
    ) -> Result<Vec<PartyLineMessage>, StoreError> {
        let Some(group) = self.get_group(group_id)? else {
            return Ok(vec![]);
        };
        let mut stmt = self.conn.prepare(
            "SELECT author_federation_id, author_local_id, sequence, body, in_reply_to_target_kind, in_reply_to_target_value, issued_at, signature FROM party_line_messages WHERE group_id = ?1 ORDER BY issued_at ASC",
        )?;
        let rows = stmt.query_map(params![group_id.0 .0.as_slice()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (fed, local, sequence, body, reply_kind, reply_value, issued_at, signature) = r?;
            let author = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            if !group.can_post_party_line(&author) {
                continue;
            }
            let in_reply_to = match (reply_kind, reply_value) {
                (Some(k), Some(v)) => kv_to_target(&k, &v),
                _ => None,
            };
            out.push(PartyLineMessage {
                group_id,
                author,
                sequence: sequence as u64,
                body,
                in_reply_to,
                issued_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    /// A composite "is anything worth my attention" summary, built
    /// entirely from data already stored — no new signal, just
    /// aggregating what "make invisible information visible" work has
    /// already surfaced individually (succession risk on `list-groups`,
    /// vote age on `explain-group-vote`, block reports on the same). See
    /// `NetworkHealthSummary::attention_items`'s own doc for why
    /// `trusted_peers_with_block_reports` is deliberately kept out of a
    /// simple sum with the other two.
    pub fn network_health_summary(&self, now: i64) -> Result<NetworkHealthSummary, StoreError> {
        let self_user = self.get_self_identity()?.map(|(u, _)| u);

        let (owned_groups_total, owned_groups_single_owner) = match self_user {
            Some(u) => {
                let owned: Vec<Group> = self
                    .list_groups()?
                    .into_iter()
                    .filter(|g| g.owners.contains(&u))
                    .collect();
                (
                    owned.len(),
                    owned.iter().filter(|g| g.owners.len() == 1).count(),
                )
            }
            None => (0, 0),
        };

        let own_votes = match self_user {
            Some(u) => self.list_latest_own_votes(&u)?,
            None => Vec::new(),
        };
        let own_votes_total = own_votes.len();
        let own_votes_expired = own_votes.iter().filter(|v| v.is_expired(now)).count();

        let follows = self.list_follows()?;
        let follows_total = follows.len();
        let follows_with_display_name = follows.iter().filter(|f| f.display_name.is_some()).count();

        // A lower bound, not a count: only reports this router has
        // actually been handed (no live sync — see this crate's own
        // "no P2P in this pass" scoping). A follow with zero reports here
        // means "none reached this router," not "none exist."
        let all_reports = self.list_all_group_block_reports()?;
        let trusted_peers_with_block_reports = follows
            .iter()
            .filter(|f| all_reports.iter().any(|r| r.blocked_user == f.user))
            .count();

        Ok(NetworkHealthSummary {
            owned_groups_total,
            owned_groups_single_owner,
            own_votes_total,
            own_votes_expired,
            trusted_peers_with_block_reports,
            follows_total,
            follows_with_display_name,
        })
    }

    // ── Device-approval opinions ─────────────────────────────────────────

    /// Same MAX-based counter pattern used for every other per-author
    /// sequence (see `next_tunnel_advertisement_sequence`).
    pub fn next_device_approval_opinion_sequence(
        &self,
        author: &UserId,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM device_approval_opinions WHERE author_federation_id = ?1 AND author_local_id = ?2",
            params![author.federation.0 .0.as_slice(), author.local_id.0.as_slice()],
            |row| row.get(0),
        )?;
        Ok(max.map(|m| m as u64 + 1).unwrap_or(0))
    }

    /// Rejects outright (not just zero-weight) unless `o.author` is
    /// already a followed user — the same flood-resistance gate
    /// `ingest_tunnel_advertisement` uses: a device-approval opinion is
    /// meant to eventually inform a real join-approval decision, not just
    /// contribute a weighted data point, so an unfollowed stranger's
    /// opinion about some MAC address is refused, not silently stored at
    /// zero weight.
    pub fn ingest_device_approval_opinion(
        &self,
        o: &DeviceApprovalOpinion,
    ) -> Result<(), StoreError> {
        if self.get_follow(&o.author)?.is_none() {
            return Err(StoreError::NotFollowed(format!(
                "{}/{}",
                o.author.federation.0, o.author.local_id
            )));
        }
        self.store_device_approval_opinion_row(o)
    }

    /// This router's own opinion, published under its own identity — no
    /// follow-gate, the same distinction `store_own_tunnel_advertisement`
    /// draws from `ingest_tunnel_advertisement`.
    pub fn store_own_device_approval_opinion(
        &self,
        o: &DeviceApprovalOpinion,
    ) -> Result<(), StoreError> {
        self.store_device_approval_opinion_row(o)
    }

    fn store_device_approval_opinion_row(
        &self,
        o: &DeviceApprovalOpinion,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO device_approval_opinions (author_federation_id, author_local_id, sequence, mac, stance, reason_code, reason_note, reason_evidence, device_label, issued_at, expires_at, supersedes_sequence, signature, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(author_federation_id, author_local_id, sequence) DO NOTHING",
            params![
                o.author.federation.0 .0.as_slice(),
                o.author.local_id.0.as_slice(),
                o.sequence as i64,
                o.mac,
                stance_to_i64(o.stance),
                reason_code_to_i64(o.reason.code),
                o.reason.note,
                encode_evidence(&o.reason.evidence),
                o.device_label,
                o.issued_at,
                o.expires_at,
                o.supersedes.map(|s| s as i64),
                o.signature.0.as_slice(),
                now_unix(),
            ],
        )?;
        Ok(())
    }

    /// Every stored opinion about `mac`, paired with the author's
    /// `LocalTrustRule` if this router follows them — the device-approval
    /// analogue of `list_followed_opinions_for`.
    pub fn list_device_approval_opinions_for(
        &self,
        mac: &str,
    ) -> Result<Vec<(DeviceApprovalOpinion, Option<LocalTrustRule>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT author_federation_id, author_local_id, sequence, stance, reason_code, reason_note, reason_evidence, device_label, issued_at, expires_at, supersedes_sequence, signature
             FROM device_approval_opinions WHERE mac = ?1",
        )?;
        let rows = stmt.query_map(params![mac], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Vec<u8>>(6)?,
                row.get::<_, Option<String>>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, Option<i64>>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Vec<u8>>(11)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                sequence,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                device_label,
                issued_at,
                expires_at,
                supersedes_sequence,
                signature,
            ) = r?;
            let author = UserId {
                federation: FederationId(bytes_to_hash32(&fed)?),
                local_id: bytes_to_hash32(&local)?,
            };
            let opinion = DeviceApprovalOpinion {
                author,
                sequence: sequence as u64,
                mac: mac.to_string(),
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                device_label,
                issued_at,
                expires_at,
                supersedes: supersedes_sequence.map(|s| s as u64),
                signature: SignatureBytes(bytes_to_64(&signature)?),
            };
            let trust = self.get_follow(&author)?;
            out.push((opinion, trust));
        }
        Ok(out)
    }

    /// A trust-weighted aggregate stance for `mac`, mirroring
    /// `policy-engine::evaluate_trust_weighted`'s threshold-crossing logic
    /// exactly (allow/deny weight totals compared against `threshold`) —
    /// deliberately duplicated in miniature here rather than routed
    /// through `PolicyInputs`/`policy-engine`, since a device isn't a
    /// `TargetSelector` and this is explicitly an advisory signal, never
    /// an enforced nft decision. Intended consumer: a human reviewing a
    /// pending kestreld join request, or (future work, not this pass) a
    /// real bridge feeding kestreld's own approval UI as one more
    /// suggestion — never an auto-write of `join_approved`/`join_denied`.
    pub fn device_approval_stance_for(
        &self,
        mac: &str,
        now: i64,
        threshold: f64,
    ) -> Result<(domain_types::Decision, f64, f64), StoreError> {
        let mut allow_total = 0.0f64;
        let mut deny_total = 0.0f64;
        for (opinion, rule) in self.list_device_approval_opinions_for(mac)? {
            if opinion.is_expired(now) {
                continue;
            }
            let Some(rule) = rule else { continue };
            if rule.excluded || rule.is_expired(now) || rule.advisory_only {
                continue;
            }
            match opinion.stance {
                Stance::Allow => allow_total += rule.allow_weight,
                Stance::Deny => deny_total += rule.deny_weight,
                Stance::Ask => {}
            }
        }
        let allow_crosses = allow_total >= threshold;
        let deny_crosses = deny_total >= threshold;
        let decision = match (allow_crosses, deny_crosses) {
            (true, false) => domain_types::Decision::Allow,
            (false, true) => domain_types::Decision::Deny,
            (true, true) => domain_types::Decision::Ask,
            (false, false) => domain_types::Decision::NoDecision,
        };
        Ok((decision, allow_total, deny_total))
    }

    /// Every stored device-approval opinion across every MAC — the
    /// dashboard's "browse everything" entry point, the same role
    /// `list_all_enforced_decision_contributors` plays for contributors.
    pub fn list_all_device_approval_opinions(
        &self,
    ) -> Result<Vec<DeviceApprovalOpinion>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT author_federation_id, author_local_id, sequence, mac, stance, reason_code, reason_note, reason_evidence, device_label, issued_at, expires_at, supersedes_sequence, signature
             FROM device_approval_opinions ORDER BY mac, sequence",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Option<String>>(6)?,
                row.get::<_, Vec<u8>>(7)?,
                row.get::<_, Option<String>>(8)?,
                row.get::<_, i64>(9)?,
                row.get::<_, Option<i64>>(10)?,
                row.get::<_, Option<i64>>(11)?,
                row.get::<_, Vec<u8>>(12)?,
            ))
        })?;
        let mut out = Vec::new();
        for r in rows {
            let (
                fed,
                local,
                sequence,
                mac,
                stance,
                reason_code,
                reason_note,
                reason_evidence,
                device_label,
                issued_at,
                expires_at,
                supersedes_sequence,
                signature,
            ) = r?;
            out.push(DeviceApprovalOpinion {
                author: UserId {
                    federation: FederationId(bytes_to_hash32(&fed)?),
                    local_id: bytes_to_hash32(&local)?,
                },
                sequence: sequence as u64,
                mac,
                stance: stance_from_i64(stance)?,
                reason: Reason {
                    code: reason_code_from_i64(reason_code)?,
                    note: reason_note,
                    evidence: decode_evidence(&reason_evidence)?,
                },
                device_label,
                issued_at,
                expires_at,
                supersedes: supersedes_sequence.map(|s| s as u64),
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }
}

// ── Fingerprint group data ─────────────────────────────────────────────────

impl StateStore {
    pub fn store_fingerprint_observation(
        &self,
        observation: &FingerprintObservation,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO fingerprint_observations
             (group_id, fingerprint_id, fingerprint_revision, observer_federation_id,
              observer_local_id, signal_family, evidence_digest, confidence, issued_at,
              expires_at, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(group_id, fingerprint_id, fingerprint_revision,
                         observer_federation_id, observer_local_id, signal_family)
             DO NOTHING",
            params![
                observation.group_id.0 .0.as_slice(),
                observation.fingerprint_id.0.as_slice(),
                observation.fingerprint_revision as i64,
                observation.observer.federation.0 .0.as_slice(),
                observation.observer.local_id.0.as_slice(),
                observation.signal_family,
                observation.evidence_digest.0.as_slice(),
                observation.confidence as i64,
                observation.issued_at,
                observation.expires_at,
                observation.signature.0.as_slice(),
            ],
        )?;
        Ok(())
    }

    pub fn list_fingerprint_observations(
        &self,
        group_id: GroupId,
        fingerprint_id: Hash32,
        fingerprint_revision: u64,
    ) -> Result<Vec<FingerprintObservation>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT observer_federation_id, observer_local_id, signal_family,
                    evidence_digest, confidence, issued_at, expires_at, signature
             FROM fingerprint_observations
             WHERE group_id = ?1 AND fingerprint_id = ?2 AND fingerprint_revision = ?3
             ORDER BY issued_at, observer_federation_id, observer_local_id, signal_family",
        )?;
        let rows = stmt.query_map(
            params![
                group_id.0 .0.as_slice(),
                fingerprint_id.0.as_slice(),
                fingerprint_revision as i64
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (
                observer_fed,
                observer_local,
                signal_family,
                evidence_digest,
                confidence,
                issued_at,
                expires_at,
                signature,
            ) = row?;
            out.push(FingerprintObservation {
                group_id,
                fingerprint_id,
                fingerprint_revision,
                observer: UserId {
                    federation: FederationId(bytes_to_hash32(&observer_fed)?),
                    local_id: bytes_to_hash32(&observer_local)?,
                },
                signal_family,
                evidence_digest: bytes_to_hash32(&evidence_digest)?,
                confidence: u8::try_from(confidence).map_err(|_| {
                    StoreError::Encoding(format!("invalid fingerprint confidence {confidence}"))
                })?,
                issued_at,
                expires_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }

    pub fn set_group_fingerprint_key(
        &self,
        group_id: GroupId,
        key: &[u8; 32],
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO group_fingerprint_keys (group_id, key) VALUES (?1, ?2)
             ON CONFLICT(group_id) DO UPDATE SET key = excluded.key",
            params![group_id.0 .0.as_slice(), key.as_slice()],
        )?;
        Ok(())
    }

    pub fn group_fingerprint_key(&self, group_id: GroupId) -> Result<Option<[u8; 32]>, StoreError> {
        let key = self
            .conn
            .query_row(
                "SELECT key FROM group_fingerprint_keys WHERE group_id = ?1",
                params![group_id.0 .0.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        key.map(|bytes| {
            bytes.try_into().map_err(|_| {
                StoreError::Encoding("group fingerprint key must be exactly 32 bytes".into())
            })
        })
        .transpose()
    }

    pub fn next_fingerprint_comment_sequence(
        &self,
        group_id: GroupId,
        fingerprint_id: Hash32,
        fingerprint_revision: u64,
        author: &UserId,
    ) -> Result<u64, StoreError> {
        let max: Option<i64> = self.conn.query_row(
            "SELECT MAX(sequence) FROM fingerprint_comments
             WHERE group_id = ?1 AND fingerprint_id = ?2 AND fingerprint_revision = ?3
               AND author_federation_id = ?4 AND author_local_id = ?5",
            params![
                group_id.0 .0.as_slice(),
                fingerprint_id.0.as_slice(),
                fingerprint_revision as i64,
                author.federation.0 .0.as_slice(),
                author.local_id.0.as_slice(),
            ],
            |row| row.get(0),
        )?;
        Ok(max.map(|value| value as u64 + 1).unwrap_or(0))
    }

    pub fn store_fingerprint_comment(
        &self,
        comment: &FingerprintComment,
    ) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO fingerprint_comments
             (group_id, fingerprint_id, fingerprint_revision, author_federation_id,
              author_local_id, sequence, body, issued_at, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(group_id, fingerprint_id, fingerprint_revision,
                         author_federation_id, author_local_id, sequence)
             DO NOTHING",
            params![
                comment.group_id.0 .0.as_slice(),
                comment.fingerprint_id.0.as_slice(),
                comment.fingerprint_revision as i64,
                comment.author.federation.0 .0.as_slice(),
                comment.author.local_id.0.as_slice(),
                comment.sequence as i64,
                comment.body,
                comment.issued_at,
                comment.signature.0.as_slice(),
            ],
        )?;
        Ok(())
    }

    pub fn list_fingerprint_comments(
        &self,
        group_id: GroupId,
        fingerprint_id: Hash32,
        fingerprint_revision: u64,
    ) -> Result<Vec<FingerprintComment>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT author_federation_id, author_local_id, sequence, body, issued_at, signature
             FROM fingerprint_comments
             WHERE group_id = ?1 AND fingerprint_id = ?2 AND fingerprint_revision = ?3
             ORDER BY issued_at, author_federation_id, author_local_id, sequence",
        )?;
        let rows = stmt.query_map(
            params![
                group_id.0 .0.as_slice(),
                fingerprint_id.0.as_slice(),
                fingerprint_revision as i64
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            },
        )?;
        let mut out = Vec::new();
        for row in rows {
            let (author_fed, author_local, sequence, body, issued_at, signature) = row?;
            out.push(FingerprintComment {
                group_id,
                fingerprint_id,
                fingerprint_revision,
                author: UserId {
                    federation: FederationId(bytes_to_hash32(&author_fed)?),
                    local_id: bytes_to_hash32(&author_local)?,
                },
                sequence: sequence as u64,
                body,
                issued_at,
                signature: SignatureBytes(bytes_to_64(&signature)?),
            });
        }
        Ok(out)
    }
}

fn row_to_trust_rule(row: &rusqlite::Row, user: UserId) -> rusqlite::Result<LocalTrustRule> {
    Ok(LocalTrustRule {
        user,
        allow_weight: row.get(0)?,
        deny_weight: row.get(1)?,
        advisory_only: row.get(2)?,
        excluded: row.get(3)?,
        category_filter: row.get(4)?,
        display_name: row.get(5)?,
        iroh_node_id: row.get(6)?,
        expires_at: row.get(7)?,
        created_at: row.get(8)?,
    })
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn visibility_to_i64(v: Visibility) -> i64 {
    match v {
        Visibility::Public => 0,
        Visibility::Restricted => 1,
    }
}

fn visibility_from_i64(v: i64) -> Result<Visibility, StoreError> {
    match v {
        0 => Ok(Visibility::Public),
        1 => Ok(Visibility::Restricted),
        other => Err(StoreError::Encoding(format!(
            "invalid visibility value {other}"
        ))),
    }
}

fn policy_action_to_columns(action: &PolicyAction) -> (&'static str, Option<String>, Option<i64>) {
    match action {
        PolicyAction::Block => ("block", None, None),
        PolicyAction::Allow => ("allow", None, None),
        PolicyAction::Route { profile } => ("route", Some(profile.clone()), None),
        PolicyAction::DnsBlock => ("dns_block", None, None),
        PolicyAction::DnsRedirect { address } => ("dns_redirect", Some(address.clone()), None),
        PolicyAction::DnsRecord {
            record_type,
            value,
            ttl_seconds,
        } => (
            "dns_record",
            Some(format!("{record_type}\n{value}")),
            Some(*ttl_seconds as i64),
        ),
    }
}

fn policy_action_from_columns(
    kind: &str,
    value: Option<String>,
    ttl_seconds: Option<i64>,
) -> Result<PolicyAction, StoreError> {
    match kind {
        "block" => Ok(PolicyAction::Block),
        "allow" => Ok(PolicyAction::Allow),
        "route" => Ok(PolicyAction::Route {
            profile: value
                .ok_or_else(|| StoreError::Encoding("route action has no profile".into()))?,
        }),
        "dns_block" => Ok(PolicyAction::DnsBlock),
        "dns_redirect" => Ok(PolicyAction::DnsRedirect {
            address: value
                .ok_or_else(|| StoreError::Encoding("dns_redirect action has no address".into()))?,
        }),
        "dns_record" => {
            let encoded = value.ok_or_else(|| {
                StoreError::Encoding("dns_record action has no record type/value".into())
            })?;
            let (record_type, value) = encoded.split_once('\n').ok_or_else(|| {
                StoreError::Encoding("dns_record action has no record type".into())
            })?;
            Ok(PolicyAction::DnsRecord {
                record_type: record_type.to_string(),
                value: value.to_string(),
                ttl_seconds: ttl_seconds
                    .ok_or_else(|| StoreError::Encoding("dns_record action has no TTL".into()))?
                    .try_into()
                    .map_err(|_| StoreError::Encoding("dns_record TTL is out of range".into()))?,
            })
        }
        other => Err(StoreError::Encoding(format!(
            "invalid policy action kind {other}"
        ))),
    }
}

fn stance_to_i64(s: Stance) -> i64 {
    match s {
        Stance::Allow => 0,
        Stance::Deny => 1,
        Stance::Ask => 2,
    }
}

fn stance_from_i64(v: i64) -> Result<Stance, StoreError> {
    match v {
        0 => Ok(Stance::Allow),
        1 => Ok(Stance::Deny),
        2 => Ok(Stance::Ask),
        other => Err(StoreError::Encoding(format!(
            "invalid stance discriminant {other}"
        ))),
    }
}

fn override_kind_to_i64(k: OverrideKind) -> i64 {
    match k {
        OverrideKind::Normal => 0,
        OverrideKind::Emergency => 1,
    }
}

fn override_kind_from_i64(v: i64) -> Result<OverrideKind, StoreError> {
    match v {
        0 => Ok(OverrideKind::Normal),
        1 => Ok(OverrideKind::Emergency),
        other => Err(StoreError::Encoding(format!(
            "invalid override kind discriminant {other}"
        ))),
    }
}

fn reason_code_to_i64(c: ReasonCode) -> i64 {
    match c {
        ReasonCode::Malware => 0,
        ReasonCode::Phishing => 1,
        ReasonCode::Tracker => 2,
        ReasonCode::Surveillance => 3,
        ReasonCode::AbusiveContent => 4,
        ReasonCode::KnownGoodCdn => 5,
        ReasonCode::KnownGoodService => 6,
        ReasonCode::PersonalPreference => 7,
        ReasonCode::AbuseReport => 8,
        ReasonCode::Other => 9,
    }
}

fn reason_code_from_i64(v: i64) -> Result<ReasonCode, StoreError> {
    match v {
        0 => Ok(ReasonCode::Malware),
        1 => Ok(ReasonCode::Phishing),
        2 => Ok(ReasonCode::Tracker),
        3 => Ok(ReasonCode::Surveillance),
        4 => Ok(ReasonCode::AbusiveContent),
        5 => Ok(ReasonCode::KnownGoodCdn),
        6 => Ok(ReasonCode::KnownGoodService),
        7 => Ok(ReasonCode::PersonalPreference),
        8 => Ok(ReasonCode::AbuseReport),
        9 => Ok(ReasonCode::Other),
        other => Err(StoreError::Encoding(format!(
            "invalid reason code discriminant {other}"
        ))),
    }
}

/// `(kind, value)` storage key for a target. Only the five simple
/// variants are supported for persistence today — `ProtoPort` wraps
/// another selector and needs a real recursive/escaped encoding, which is
/// out of scope for this skeleton (same category of deferred work as
/// domain-suffix/CIDR containment matching in `policy-engine`).
fn target_to_kv(target: &TargetSelector) -> Result<(String, String), StoreError> {
    match target {
        TargetSelector::Domain(s) => Ok(("domain".into(), s.clone())),
        TargetSelector::DomainSuffix(s) => Ok(("domain_suffix".into(), s.clone())),
        TargetSelector::Ip(s) => Ok(("ip".into(), s.clone())),
        TargetSelector::Cidr(s) => Ok(("cidr".into(), s.clone())),
        TargetSelector::Service(s) => Ok(("service".into(), s.clone())),
        TargetSelector::ProtoPort { .. } => Err(StoreError::Encoding(
            "ProtoPort target persistence is not yet implemented".into(),
        )),
    }
}

/// Reverse of `target_to_kv`, for reconstructing a target from stored
/// `(target_kind, target_value)` columns (`list_evaluatable_targets`'s only
/// caller). Returns `None` for anything that isn't one of the kinds
/// `target_to_kv` can produce — `"proto_port"` never reaches storage in the
/// first place (see `target_to_kv`'s own error path), and an unrecognized
/// string is corrupt/foreign data, not a target to silently misconstruct.
fn kv_to_target(kind: &str, value: &str) -> Option<TargetSelector> {
    match kind {
        "domain" => Some(TargetSelector::Domain(value.to_string())),
        "domain_suffix" => Some(TargetSelector::DomainSuffix(value.to_string())),
        "ip" => Some(TargetSelector::Ip(value.to_string())),
        "cidr" => Some(TargetSelector::Cidr(value.to_string())),
        "service" => Some(TargetSelector::Service(value.to_string())),
        _ => None,
    }
}

fn encode_evidence(evidence: &[Hash32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(evidence.len() * 32);
    for h in evidence {
        out.extend_from_slice(&h.0);
    }
    out
}

fn decode_evidence(bytes: &[u8]) -> Result<Vec<Hash32>, StoreError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(StoreError::Encoding(
            "evidence blob length not a multiple of 32".into(),
        ));
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|c| Hash32(c.try_into().unwrap()))
        .collect())
}

fn bytes_to_hash32(bytes: &[u8]) -> Result<Hash32, StoreError> {
    Ok(Hash32(bytes_to_32(bytes)?))
}

fn bytes_to_32(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Encoding(format!("expected 32 bytes, got {}", bytes.len())))
}

fn bytes_to_64(bytes: &[u8]) -> Result<[u8; 64], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Encoding(format!("expected 64 bytes, got {}", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::Hash32;

    fn fed(n: u8) -> FederationId {
        FederationId(Hash32([n; 32]))
    }
    fn user(fed_n: u8, local_n: u8) -> UserId {
        UserId {
            federation: fed(fed_n),
            local_id: Hash32([local_n; 32]),
        }
    }
    fn target() -> TargetSelector {
        TargetSelector::Domain("ads.example".into())
    }

    #[test]
    fn fingerprint_group_data_round_trips_and_is_scoped_by_revision() {
        let store = StateStore::open_in_memory().unwrap();
        let group = GroupId(Hash32([3; 32]));
        let fingerprint = Hash32([4; 32]);
        let observer = user(1, 2);
        let observation = FingerprintObservation {
            group_id: group,
            fingerprint_id: fingerprint,
            fingerprint_revision: 7,
            observer,
            signal_family: "dhcp_vendor".into(),
            evidence_digest: Hash32([5; 32]),
            confidence: 88,
            issued_at: 100,
            expires_at: Some(200),
            signature: SignatureBytes([6; 64]),
        };
        store.store_fingerprint_observation(&observation).unwrap();
        store.store_fingerprint_observation(&observation).unwrap();

        assert_eq!(
            store
                .list_fingerprint_observations(group, fingerprint, 7)
                .unwrap(),
            vec![observation]
        );
        assert!(store
            .list_fingerprint_observations(group, fingerprint, 8)
            .unwrap()
            .is_empty());
        assert!(store
            .list_fingerprint_observations(GroupId(Hash32([9; 32])), fingerprint, 7)
            .unwrap()
            .is_empty());

        let comment = FingerprintComment {
            group_id: group,
            fingerprint_id: fingerprint,
            fingerprint_revision: 7,
            author: observer,
            sequence: store
                .next_fingerprint_comment_sequence(group, fingerprint, 7, &observer)
                .unwrap(),
            body: "confirmed device".into(),
            issued_at: 101,
            signature: SignatureBytes([7; 64]),
        };
        assert_eq!(comment.sequence, 0);
        store.store_fingerprint_comment(&comment).unwrap();
        assert_eq!(
            store
                .next_fingerprint_comment_sequence(group, fingerprint, 7, &observer)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .list_fingerprint_comments(group, fingerprint, 7)
                .unwrap(),
            vec![comment]
        );
        assert_eq!(
            store
                .next_fingerprint_comment_sequence(group, fingerprint, 8, &observer)
                .unwrap(),
            0
        );
        assert!(store
            .list_fingerprint_comments(GroupId(Hash32([9; 32])), fingerprint, 7)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn group_fingerprint_keys_round_trip_and_are_scoped() {
        let store = StateStore::open_in_memory().unwrap();
        let first = GroupId(Hash32([11; 32]));
        let second = GroupId(Hash32([12; 32]));
        let key = [13; 32];
        assert!(store.group_fingerprint_key(first).unwrap().is_none());
        store.set_group_fingerprint_key(first, &key).unwrap();
        assert_eq!(store.group_fingerprint_key(first).unwrap(), Some(key));
        assert!(store.group_fingerprint_key(second).unwrap().is_none());
        let replacement = [14; 32];
        store
            .set_group_fingerprint_key(first, &replacement)
            .unwrap();
        assert_eq!(
            store.group_fingerprint_key(first).unwrap(),
            Some(replacement)
        );
    }

    #[test]
    fn migrations_apply_cleanly_on_a_fresh_database() {
        let store = StateStore::open_in_memory().unwrap();
        let count: i64 = store
            .conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, MIGRATIONS.len() as i64);
    }

    #[test]
    fn notified_items_round_trip() {
        let store = StateStore::open_in_memory().unwrap();
        assert!(!store.has_been_notified("group_join", "abc/0").unwrap());
        store.mark_notified("group_join", "abc/0", 100).unwrap();
        assert!(store.has_been_notified("group_join", "abc/0").unwrap());
        assert!(!store.has_been_notified("group_join", "abc/1").unwrap());
    }

    #[test]
    fn mark_notified_is_idempotent() {
        let store = StateStore::open_in_memory().unwrap();
        store.mark_notified("tunnel_request", "x/0", 100).unwrap();
        store.mark_notified("tunnel_request", "x/0", 200).unwrap();
        assert!(store.has_been_notified("tunnel_request", "x/0").unwrap());
    }

    #[test]
    fn ntfy_topic_url_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .set_self_identity(user(1, 1), PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();
        assert_eq!(store.get_ntfy_topic_url().unwrap(), None);
        store
            .set_ntfy_topic_url(Some("http://ntfy.example.lan/social-firewall"))
            .unwrap();
        assert_eq!(
            store.get_ntfy_topic_url().unwrap().as_deref(),
            Some("http://ntfy.example.lan/social-firewall")
        );
        store.set_ntfy_topic_url(None).unwrap();
        assert_eq!(store.get_ntfy_topic_url().unwrap(), None);
    }

    #[test]
    fn self_identity_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        let u = user(1, 2);
        store
            .set_self_identity(u, PublicKeyBytes([9; 32]), &[3; 32], Some("me"))
            .unwrap();
        let (got_user, got_pk) = store.get_self_identity().unwrap().unwrap();
        assert_eq!(got_user, u);
        assert_eq!(got_pk, PublicKeyBytes([9; 32]));
        assert_eq!(
            store.get_user_display_name(&u).unwrap().as_deref(),
            Some("me")
        );
    }

    #[test]
    fn local_identity_and_home_federation_names_can_be_changed_or_cleared() {
        let store = StateStore::open_in_memory().unwrap();
        let u = user(3, 4);
        store
            .set_self_identity(u, PublicKeyBytes([8; 32]), &[7; 32], Some("router"))
            .unwrap();

        store.set_self_display_name(Some("demo")).unwrap();
        store
            .set_home_federation_display_name(Some("home"))
            .unwrap();
        assert_eq!(
            store.get_user_display_name(&u).unwrap().as_deref(),
            Some("demo")
        );
        assert_eq!(
            store
                .get_federation_display_name(&u.federation)
                .unwrap()
                .as_deref(),
            Some("home")
        );

        store.set_self_display_name(None).unwrap();
        store.set_home_federation_display_name(None).unwrap();
        assert_eq!(store.get_user_display_name(&u).unwrap(), None);
        assert_eq!(
            store
                .get_federation_display_name(&u.federation)
                .unwrap()
                .as_deref(),
            Some(u.federation.0.to_string().as_str())
        );
    }

    #[test]
    fn get_federation_display_name_resolves_the_home_federation_set_at_self_identity_time() {
        let store = StateStore::open_in_memory().unwrap();
        let u = user(1, 2);
        store
            .set_self_identity(u, PublicKeyBytes([9; 32]), &[3; 32], None)
            .unwrap();
        // set_self_identity defaults a federation's display_name to its
        // own hex id when no explicit federation name was chosen.
        assert_eq!(
            store
                .get_federation_display_name(&u.federation)
                .unwrap()
                .as_deref(),
            Some(u.federation.0.to_string().as_str())
        );
    }

    #[test]
    fn get_federation_display_name_is_none_for_an_unknown_federation() {
        let store = StateStore::open_in_memory().unwrap();
        let stranger_federation = FederationId(Hash32([7; 32]));
        assert_eq!(
            store
                .get_federation_display_name(&stranger_federation)
                .unwrap(),
            None
        );
    }

    #[test]
    fn local_override_upsert_is_idempotent_and_natural_keyed() {
        let store = StateStore::open_in_memory().unwrap();
        let o1 = LocalOverride {
            target: target(),
            stance: Stance::Allow,
            kind: OverrideKind::Normal,
            note: None,
            created_at: 1,
            expires_at: None,
        };
        let o2 = LocalOverride {
            target: target(),
            stance: Stance::Deny,
            kind: OverrideKind::Normal,
            note: Some("changed my mind".into()),
            created_at: 2,
            expires_at: None,
        };
        store.set_local_override(&o1).unwrap();
        store.set_local_override(&o2).unwrap();
        let got = store.get_local_overrides_for(&target()).unwrap();
        assert_eq!(
            got.len(),
            1,
            "natural key must prevent two active overrides for the same target"
        );
        assert_eq!(got[0].stance, Stance::Deny);
    }

    #[test]
    fn follow_upsert_updates_weights_in_place() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: alice,
                allow_weight: 0.5,
                deny_weight: 0.5,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .upsert_follow(&LocalTrustRule {
                user: alice,
                allow_weight: 0.9,
                deny_weight: 0.1,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let got = store.get_follow(&alice).unwrap().unwrap();
        assert_eq!(got.allow_weight, 0.9);
        assert_eq!(store.list_follows().unwrap().len(), 1);
    }

    fn named_follow(u: UserId, name: &str) -> LocalTrustRule {
        LocalTrustRule {
            user: u,
            allow_weight: 1.0,
            deny_weight: 1.0,
            advisory_only: false,
            excluded: false,
            category_filter: None,
            display_name: Some(name.to_string()),
            iroh_node_id: None,
            expires_at: None,
            created_at: 0,
        }
    }

    #[test]
    fn follow_display_name_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store.upsert_follow(&named_follow(alice, "alice")).unwrap();

        assert_eq!(
            store
                .get_follow(&alice)
                .unwrap()
                .unwrap()
                .display_name
                .as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn resolve_user_by_name_finds_the_named_follow() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store.upsert_follow(&named_follow(alice, "alice")).unwrap();

        assert_eq!(
            store.resolve_user_by_name(&fed(1), "alice").unwrap(),
            Some(alice)
        );
        assert_eq!(store.resolve_user_by_name(&fed(1), "nobody").unwrap(), None);
    }

    #[test]
    fn resolve_user_by_name_is_scoped_to_the_federation() {
        let store = StateStore::open_in_memory().unwrap();
        let alice_in_fed1 = user(1, 1);
        store
            .upsert_follow(&named_follow(alice_in_fed1, "alice"))
            .unwrap();

        // Same name, different federation — must not resolve at all, not
        // accidentally cross-match `alice_in_fed1`.
        assert_eq!(store.resolve_user_by_name(&fed(2), "alice").unwrap(), None);
    }

    #[test]
    fn the_same_name_can_be_reused_across_different_federations() {
        let store = StateStore::open_in_memory().unwrap();
        let alice_in_fed1 = user(1, 1);
        let alice_in_fed2 = user(2, 2);
        store
            .upsert_follow(&named_follow(alice_in_fed1, "alice"))
            .unwrap();

        // "Not globally unique" is the point — this must succeed.
        store
            .upsert_follow(&named_follow(alice_in_fed2, "alice"))
            .unwrap();

        assert_eq!(
            store.resolve_user_by_name(&fed(1), "alice").unwrap(),
            Some(alice_in_fed1)
        );
        assert_eq!(
            store.resolve_user_by_name(&fed(2), "alice").unwrap(),
            Some(alice_in_fed2)
        );
    }

    #[test]
    fn two_different_local_ids_in_the_same_federation_cannot_share_a_name() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let mallory = user(1, 2);
        store.upsert_follow(&named_follow(alice, "alice")).unwrap();

        let err = store
            .upsert_follow(&named_follow(mallory, "alice"))
            .unwrap_err();
        assert!(matches!(err, StoreError::Sqlite(_)), "a duplicate name within one federation must be rejected, not silently accepted: {err:?}");
    }

    #[test]
    fn relabeling_the_same_follow_to_its_own_current_name_is_not_a_conflict() {
        // Re-running `upsert_follow` with the same name (e.g. re-issuing
        // `add-follow --name alice` idempotently) must not trip the
        // unique-index conflict against itself.
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store.upsert_follow(&named_follow(alice, "alice")).unwrap();
        store.upsert_follow(&named_follow(alice, "alice")).unwrap();
        assert_eq!(
            store
                .get_follow(&alice)
                .unwrap()
                .unwrap()
                .display_name
                .as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn multiple_unnamed_follows_in_the_same_federation_are_never_a_conflict() {
        // The partial index only constrains rows where `display_name IS
        // NOT NULL` — most follows have no name at all, and that must
        // never collide with anything.
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let bob = user(1, 2);
        store
            .upsert_follow(&LocalTrustRule {
                user: alice,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .upsert_follow(&LocalTrustRule {
                user: bob,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        assert_eq!(store.list_follows().unwrap().len(), 2);
    }

    #[test]
    fn own_opinion_log_appends_and_lists_by_target() {
        let store = StateStore::open_in_memory().unwrap();
        let me = user(1, 1);
        store
            .set_self_identity(me, PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();
        let seq = store.next_own_sequence().unwrap();
        assert_eq!(seq, 0);
        let opinion = PolicyOpinion {
            author: me,
            sequence: seq,
            target: target(),
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Tracker,
                note: None,
                evidence: vec![],
            },
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        };
        store.append_own_opinion(&opinion).unwrap();
        let got = store.list_own_opinions_for(&target()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].stance, Stance::Deny);
        assert_eq!(store.next_own_sequence().unwrap(), 1);
    }

    #[test]
    fn ingest_opinion_is_idempotent_on_duplicate_sequence() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let opinion = PolicyOpinion {
            author: alice,
            sequence: 1,
            target: target(),
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Malware,
                note: None,
                evidence: vec![Hash32([7; 32])],
            },
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([1; 64]),
        };
        store.ingest_opinion(&opinion).unwrap();
        store.ingest_opinion(&opinion).unwrap();
        let got = store.list_followed_opinions_for(&target()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.reason.evidence, vec![Hash32([7; 32])]);
    }

    #[test]
    fn followed_opinion_carries_trust_rule_when_present() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: alice,
                allow_weight: 0.2,
                deny_weight: 0.8,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let opinion = PolicyOpinion {
            author: alice,
            sequence: 1,
            target: target(),
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Malware,
                note: None,
                evidence: vec![],
            },
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([1; 64]),
        };
        store.ingest_opinion(&opinion).unwrap();
        let got = store.list_followed_opinions_for(&target()).unwrap();
        assert_eq!(got[0].1.as_ref().unwrap().deny_weight, 0.8);
    }

    #[test]
    fn unfollowed_author_opinion_has_no_trust_rule() {
        let store = StateStore::open_in_memory().unwrap();
        let stranger = user(1, 99);
        let opinion = PolicyOpinion {
            author: stranger,
            sequence: 1,
            target: target(),
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Malware,
                note: None,
                evidence: vec![],
            },
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([1; 64]),
        };
        store.ingest_opinion(&opinion).unwrap();
        let got = store.list_followed_opinions_for(&target()).unwrap();
        assert!(got[0].1.is_none());
    }

    #[test]
    fn proto_port_target_persistence_is_rejected_not_silently_wrong() {
        let store = StateStore::open_in_memory().unwrap();
        let target = TargetSelector::ProtoPort {
            inner: Box::new(TargetSelector::Domain("x".into())),
            proto: "tcp".into(),
            port: 443,
        };
        let result = store.get_local_overrides_for(&target);
        assert!(result.is_err());
    }

    #[test]
    fn list_evaluatable_targets_is_empty_on_a_fresh_store() {
        let store = StateStore::open_in_memory().unwrap();
        assert!(store.list_evaluatable_targets().unwrap().is_empty());
    }

    #[test]
    fn list_evaluatable_targets_discovers_a_target_from_each_source_table() {
        let store = StateStore::open_in_memory().unwrap();
        let me = user(1, 1);
        store
            .set_self_identity(me, PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();

        let override_target = TargetSelector::Ip("203.0.113.1".into());
        store
            .set_local_override(&LocalOverride {
                target: override_target.clone(),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();

        let own_opinion_target = TargetSelector::Domain("own.example".into());
        store
            .append_own_opinion(&PolicyOpinion {
                author: me,
                sequence: 0,
                target: own_opinion_target.clone(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 100,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let ingested_target = TargetSelector::Cidr("198.51.100.0/24".into());
        let alice = user(1, 2);
        store
            .ingest_opinion(&PolicyOpinion {
                author: alice,
                sequence: 1,
                target: ingested_target.clone(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Malware,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 100,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([1; 64]),
            })
            .unwrap();

        let federation_target = TargetSelector::Domain("fed.example".into());
        store
            .ingest_federation_statement(&FederationStatement {
                federation: fed(9),
                sequence: 1,
                target: federation_target.clone(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Malware,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 100,
                expires_at: None,
                supersedes: None,
                commitment: vec![1, 2, 3],
            })
            .unwrap();

        let list_target = TargetSelector::Domain("list-only.example".into());
        let bob = user(1, 3);
        store
            .upsert_follow(&LocalTrustRule {
                user: bob,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_shared_rule_list(&SharedRuleList {
                author: bob,
                sequence: 0,
                name: "bob's list".into(),
                description: "".into(),
                categories: vec![],
                visibility: Visibility::Public,
                entries: vec![SharedRuleEntry {
                    target: list_target.clone(),
                    stance: Stance::Deny,
                    reason: Reason {
                        code: ReasonCode::Tracker,
                        note: None,
                        evidence: vec![],
                    },
                }],
                issued_at: 0,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let mut got = store.list_evaluatable_targets().unwrap();
        got.sort();
        let mut want = vec![
            override_target,
            own_opinion_target,
            ingested_target,
            federation_target,
            list_target,
        ];
        want.sort();
        assert_eq!(
            got, want,
            "a target that only appears in a subscribed shared rule list must still be discovered"
        );
    }

    #[test]
    fn list_evaluatable_targets_collapses_the_same_target_across_tables() {
        let store = StateStore::open_in_memory().unwrap();
        let me = user(1, 1);
        store
            .set_self_identity(me, PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();
        let shared = target();
        store
            .set_local_override(&LocalOverride {
                target: shared.clone(),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 1,
                expires_at: None,
            })
            .unwrap();
        store
            .append_own_opinion(&PolicyOpinion {
                author: me,
                sequence: 0,
                target: shared.clone(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 100,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let got = store.list_evaluatable_targets().unwrap();
        assert_eq!(
            got,
            vec![shared],
            "the same target signaled from two tables must appear once, not twice"
        );
    }

    #[test]
    fn applied_ruleset_state_starts_absent_and_upserts_in_place() {
        let store = StateStore::open_in_memory().unwrap();
        assert_eq!(store.get_applied_ruleset().unwrap(), None);

        let v1 = AppliedRulesetState {
            digest: "abc".into(),
            ruleset_text: "table inet social_firewall {}".into(),
            revision: 1,
            updated_at: 1000,
        };
        store.save_applied_ruleset(&v1).unwrap();
        assert_eq!(store.get_applied_ruleset().unwrap(), Some(v1));

        let v2 = AppliedRulesetState {
            digest: "def".into(),
            ruleset_text: "table inet social_firewall { ... }".into(),
            revision: 2,
            updated_at: 2000,
        };
        store.save_applied_ruleset(&v2).unwrap();
        assert_eq!(store.get_applied_ruleset().unwrap(), Some(v2));
    }

    #[test]
    fn apply_log_appends_without_overwriting() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .append_apply_log(1, "abc", 3, "deny x.example", "applied", 1000)
            .unwrap();
        store
            .append_apply_log(2, "def", 1, "deny y.example", "rolled_back", 2000)
            .unwrap();
        let conn = &store.conn;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM apply_log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    // ── Tunnel advertising ───────────────────────────────────────────────

    fn advertisement(provider: UserId) -> TunnelAdvertisement {
        TunnelAdvertisement {
            provider,
            sequence: 0,
            description: "EU exit, low latency".into(),
            limitations: Some("500GB/month".into()),
            visibility: Visibility::Public,
            in_response_to: None,
            messaging_pubkey: MessagingPublicKeyBytes([2; 32]),
            wg_pubkey: WgPublicKeyBytes([3; 32]),
            endpoint_hint: "203.0.113.9:51820".into(),
            route_scope: vec![
                TargetSelector::Domain("example.com".into()),
                TargetSelector::DomainSuffix(".ads.example".into()),
            ],
            tags: vec!["streaming".into()],
            max_connections: Some(50),
            max_bandwidth_kbps: Some(10_000),
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([9; 64]),
        }
    }

    #[test]
    fn ingest_tunnel_advertisement_rejects_a_non_followed_provider() {
        let store = StateStore::open_in_memory().unwrap();
        let result = store.ingest_tunnel_advertisement(&advertisement(user(1, 1)));
        assert!(matches!(result, Err(StoreError::NotFollowed(_))));
    }

    #[test]
    fn ingest_tunnel_advertisement_round_trips_including_route_scope() {
        let store = StateStore::open_in_memory().unwrap();
        let provider = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: provider,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();

        let ad = advertisement(provider);
        store.ingest_tunnel_advertisement(&ad).unwrap();

        let got = store
            .get_tunnel_advertisement(provider, 0)
            .unwrap()
            .unwrap();
        assert_eq!(got.description, ad.description);
        assert_eq!(got.limitations, ad.limitations);
        assert_eq!(got.visibility, Visibility::Public);
        assert_eq!(got.messaging_pubkey, ad.messaging_pubkey);
        assert_eq!(got.wg_pubkey, ad.wg_pubkey);
        assert_eq!(got.endpoint_hint, ad.endpoint_hint);
        let mut scope = got.route_scope.clone();
        scope.sort();
        let mut want = ad.route_scope.clone();
        want.sort();
        assert_eq!(scope, want);
        assert_eq!(got.tags, ad.tags);
        assert_eq!(got.max_connections, ad.max_connections);
        assert_eq!(got.max_bandwidth_kbps, ad.max_bandwidth_kbps);
    }

    #[test]
    fn ingest_tunnel_advertisement_is_idempotent_on_the_same_sequence() {
        let store = StateStore::open_in_memory().unwrap();
        let provider = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: provider,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let ad = advertisement(provider);
        store.ingest_tunnel_advertisement(&ad).unwrap();
        store.ingest_tunnel_advertisement(&ad).unwrap();
        assert_eq!(store.list_tunnel_advertisements().unwrap().len(), 1);
    }

    #[test]
    fn list_tunnel_advertisements_returns_every_known_one() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let bob = user(1, 2);
        for u in [alice, bob] {
            store
                .upsert_follow(&LocalTrustRule {
                    user: u,
                    allow_weight: 1.0,
                    deny_weight: 1.0,
                    advisory_only: false,
                    excluded: false,
                    category_filter: None,
                    display_name: None,
                    iroh_node_id: None,
                    expires_at: None,
                    created_at: 0,
                })
                .unwrap();
            store
                .ingest_tunnel_advertisement(&advertisement(u))
                .unwrap();
        }
        assert_eq!(store.list_tunnel_advertisements().unwrap().len(), 2);
    }

    #[test]
    fn ingest_tunnel_service_request_rejects_a_non_followed_requester() {
        let store = StateStore::open_in_memory().unwrap();
        let req = TunnelServiceRequest {
            requester: user(1, 1),
            sequence: 0,
            description: "need an EU exit".into(),
            desired_route_scope: vec![TargetSelector::Domain("example.com".into())],
            visibility: Visibility::Public,
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        };
        assert!(matches!(
            store.ingest_tunnel_service_request(&req),
            Err(StoreError::NotFollowed(_))
        ));
    }

    #[test]
    fn ingest_tunnel_service_request_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        let requester = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: requester,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let req = TunnelServiceRequest {
            requester,
            sequence: 0,
            description: "need an EU exit".into(),
            desired_route_scope: vec![TargetSelector::Domain("example.com".into())],
            visibility: Visibility::Public,
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        };
        store.ingest_tunnel_service_request(&req).unwrap();
        let got = store.list_tunnel_service_requests().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].description, "need an EU exit");
        assert_eq!(
            got[0].desired_route_scope,
            vec![TargetSelector::Domain("example.com".into())]
        );
    }

    #[test]
    fn tunnel_connection_request_defaults_to_pending_and_can_be_listed() {
        let store = StateStore::open_in_memory().unwrap();
        let req = TunnelConnectionRequest {
            requester: user(2, 1),
            sequence: 0,
            advertisement: StatementRef {
                author: user(1, 1),
                sequence: 0,
            },
            requester_wg_pubkey: WgPublicKeyBytes([4; 32]),
            requester_messaging_pubkey: MessagingPublicKeyBytes([5; 32]),
            requested_at: 200,
            signature: SignatureBytes([0; 64]),
        };
        store.store_tunnel_connection_request(&req).unwrap();
        let pending = store.list_pending_tunnel_connection_requests().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requester, user(2, 1));

        store
            .set_tunnel_connection_request_status(&user(2, 1), 0, "accepted")
            .unwrap();
        assert!(store
            .list_pending_tunnel_connection_requests()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn has_tunnel_connection_request_for_is_true_only_after_storing_one_against_that_advertisement()
    {
        let store = StateStore::open_in_memory().unwrap();
        let ad_ref = StatementRef {
            author: user(1, 1),
            sequence: 0,
        };
        assert!(!store
            .has_tunnel_connection_request_for(&user(2, 1), &ad_ref)
            .unwrap());

        store
            .store_tunnel_connection_request(&TunnelConnectionRequest {
                requester: user(2, 1),
                sequence: 0,
                advertisement: ad_ref,
                requester_wg_pubkey: WgPublicKeyBytes([4; 32]),
                requester_messaging_pubkey: MessagingPublicKeyBytes([5; 32]),
                requested_at: 200,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        assert!(store
            .has_tunnel_connection_request_for(&user(2, 1), &ad_ref)
            .unwrap());
        // A different requester having requested nothing against this ad
        // must not be conflated with `user(2, 1)`'s own request.
        assert!(!store
            .has_tunnel_connection_request_for(&user(3, 1), &ad_ref)
            .unwrap());
    }

    #[test]
    fn tunnel_connection_accept_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        // Deliberately different local_ids (not just different
        // federations) — see the comment below on why that distinction
        // matters for this specific assertion.
        let requester = user(2, 9);
        let provider = user(1, 1);
        let accept = TunnelConnectionAccept {
            provider,
            request_ref: StatementRef {
                author: requester,
                sequence: 0,
            },
            assigned_tunnel_ip: "10.99.0.4".into(),
            assigned_tunnel_ip6: Some("fd99::c8:4".into()),
            accepted_at: 300,
            signature: SignatureBytes([0; 64]),
        };
        store.store_tunnel_connection_accept(&accept).unwrap();
        let got = store
            .get_tunnel_connection_accept_for(&requester, 0)
            .unwrap()
            .unwrap();
        assert_eq!(got.assigned_tunnel_ip, "10.99.0.4");
        assert_eq!(got.assigned_tunnel_ip6.as_deref(), Some("fd99::c8:4"));
        // Full UserId equality, not just `.federation` — a real bug (this
        // reconstructing the *requester's* local_id instead of the
        // provider's own, since the table was originally missing a
        // `provider_local_id` column) slipped through here before because
        // this assertion only checked `.federation`, which the bug never
        // touched. Caught via manual end-to-end CLI testing instead.
        assert_eq!(got.provider, provider);
    }

    #[test]
    fn get_tunnel_connection_accept_for_is_none_when_absent() {
        let store = StateStore::open_in_memory().unwrap();
        assert!(store
            .get_tunnel_connection_accept_for(&user(2, 1), 0)
            .unwrap()
            .is_none());
    }

    #[test]
    fn tunnel_trust_rule_round_trips_and_upsert_replaces_in_place() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: alice,
                auto_accept_requests: true,
                auto_consume_advertisements: false,
                auto_respond_to_service_requests: false,
                excluded: false,
                tag_filter: None,
                min_reciprocity_ratio: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let got = store.get_tunnel_trust_rule(&alice).unwrap().unwrap();
        assert!(got.auto_accept_requests);
        assert!(!got.auto_consume_advertisements);

        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: alice,
                auto_accept_requests: false,
                auto_consume_advertisements: true,
                auto_respond_to_service_requests: true,
                excluded: false,
                tag_filter: None,
                min_reciprocity_ratio: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let got = store.get_tunnel_trust_rule(&alice).unwrap().unwrap();
        assert!(!got.auto_accept_requests);
        assert!(got.auto_consume_advertisements);
        assert!(got.auto_respond_to_service_requests);
        assert_eq!(
            store.list_tunnel_trust_rules().unwrap().len(),
            1,
            "upsert must replace in place, not add a second row"
        );
    }

    #[test]
    fn tunnel_trust_rule_tag_filter_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: alice,
                auto_accept_requests: false,
                auto_consume_advertisements: true,
                auto_respond_to_service_requests: false,
                excluded: false,
                tag_filter: Some("streaming".into()),
                min_reciprocity_ratio: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        assert_eq!(
            store
                .get_tunnel_trust_rule(&alice)
                .unwrap()
                .unwrap()
                .tag_filter
                .as_deref(),
            Some("streaming")
        );
    }

    #[test]
    fn tunnel_trust_rule_excluded_is_a_distinct_flag() {
        let store = StateStore::open_in_memory().unwrap();
        let bob = user(1, 2);
        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: bob,
                auto_accept_requests: false,
                auto_consume_advertisements: false,
                auto_respond_to_service_requests: false,
                excluded: true,
                tag_filter: None,
                min_reciprocity_ratio: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        assert!(store.get_tunnel_trust_rule(&bob).unwrap().unwrap().excluded);
    }

    #[test]
    fn allocate_fwmark_and_route_table_never_reissues_the_same_pair() {
        let store = StateStore::open_in_memory().unwrap();
        let (fwmark1, table1) = store.allocate_fwmark_and_route_table().unwrap();
        let (fwmark2, table2) = store.allocate_fwmark_and_route_table().unwrap();
        let (fwmark3, table3) = store.allocate_fwmark_and_route_table().unwrap();
        assert_ne!(fwmark1, fwmark2);
        assert_ne!(fwmark2, fwmark3);
        assert_ne!(table1, table2);
        assert_ne!(table2, table3);
    }

    #[test]
    fn messaging_keypair_seed_round_trips_on_the_self_row() {
        let store = StateStore::open_in_memory().unwrap();
        assert_eq!(store.get_messaging_keypair_seed().unwrap(), None);
        store
            .set_self_identity(user(1, 1), PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();
        assert_eq!(
            store.get_messaging_keypair_seed().unwrap(),
            None,
            "no messaging seed set yet"
        );
        store.set_messaging_keypair_seed(&[7; 32]).unwrap();
        assert_eq!(store.get_messaging_keypair_seed().unwrap(), Some([7; 32]));
    }

    #[test]
    fn set_messaging_keypair_seed_fails_loudly_with_no_self_identity_yet() {
        let store = StateStore::open_in_memory().unwrap();
        assert!(matches!(
            store.set_messaging_keypair_seed(&[7; 32]),
            Err(StoreError::NoSelfIdentity)
        ));
    }

    #[test]
    fn wg_keypair_seed_round_trips_on_the_self_row() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .set_self_identity(user(1, 1), PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();
        assert_eq!(store.get_wg_keypair_seed().unwrap(), None);
        store.set_wg_keypair_seed(&[8; 32]).unwrap();
        assert_eq!(store.get_wg_keypair_seed().unwrap(), Some([8; 32]));
    }

    #[test]
    fn set_wg_keypair_seed_fails_loudly_with_no_self_identity_yet() {
        let store = StateStore::open_in_memory().unwrap();
        assert!(matches!(
            store.set_wg_keypair_seed(&[8; 32]),
            Err(StoreError::NoSelfIdentity)
        ));
    }

    #[test]
    fn iroh_keypair_seed_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .set_self_identity(user(1, 1), PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();
        assert_eq!(store.get_iroh_keypair_seed().unwrap(), None);
        store.set_iroh_keypair_seed(&[8; 32]).unwrap();
        assert_eq!(store.get_iroh_keypair_seed().unwrap(), Some([8; 32]));
    }

    #[test]
    fn set_iroh_keypair_seed_fails_loudly_with_no_self_identity_yet() {
        let store = StateStore::open_in_memory().unwrap();
        assert!(matches!(
            store.set_iroh_keypair_seed(&[8; 32]),
            Err(StoreError::NoSelfIdentity)
        ));
    }

    #[test]
    fn reticulum_identity_seed_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .set_self_identity(user(1, 1), PublicKeyBytes([1; 32]), &[4; 32], None)
            .unwrap();
        assert_eq!(store.get_reticulum_identity_seed().unwrap(), None);
        store.set_reticulum_identity_seed(&[9; 32]).unwrap();
        assert_eq!(store.get_reticulum_identity_seed().unwrap(), Some([9; 32]));
    }

    #[test]
    fn peer_transport_address_round_trips_and_deletes() {
        let store = StateStore::open_in_memory().unwrap();
        let peer = user(1, 2);
        store
            .set_peer_transport_address(peer, "reticulum", "0123456789abcdef", true, true)
            .unwrap();
        let address = store
            .peer_transport_address(peer, "reticulum")
            .unwrap()
            .unwrap();
        assert_eq!(address.address, "0123456789abcdef");
        assert!(address.enabled);
        assert!(address.verified);
        store
            .delete_peer_transport_address(peer, "reticulum")
            .unwrap();
        assert!(store
            .peer_transport_address(peer, "reticulum")
            .unwrap()
            .is_none());
    }

    #[test]
    fn follow_iroh_node_id_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let mut rule = follow(alice, 1.0, 1.0);
        rule.iroh_node_id = Some("deadbeef".repeat(8));
        store.upsert_follow(&rule).unwrap();
        assert_eq!(
            store
                .get_follow(&alice)
                .unwrap()
                .unwrap()
                .iroh_node_id
                .as_deref(),
            Some(rule.iroh_node_id.unwrap().as_str())
        );
    }

    #[test]
    fn find_follow_by_iroh_node_id_resolves_only_a_node_id_a_follow_actually_claimed() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let node_id = "deadbeef".repeat(8);
        assert_eq!(
            store.find_follow_by_iroh_node_id(&node_id).unwrap(),
            None,
            "nothing is known before any follow claims it"
        );

        let mut rule = follow(alice, 1.0, 1.0);
        rule.iroh_node_id = Some(node_id.clone());
        store.upsert_follow(&rule).unwrap();

        assert_eq!(
            store.find_follow_by_iroh_node_id(&node_id).unwrap(),
            Some(alice)
        );
        assert_eq!(
            store
                .find_follow_by_iroh_node_id(&"beefdead".repeat(8))
                .unwrap(),
            None,
            "an unrelated node id must not resolve"
        );
    }

    #[test]
    fn find_follow_by_iroh_node_id_ignores_follows_with_no_node_id() {
        let store = StateStore::open_in_memory().unwrap();
        // A follow with `iroh_node_id = NULL` must not be matched by any
        // lookup — `WHERE iroh_node_id = ?1` never matches NULL in SQL,
        // but this pins that behavior rather than assuming it.
        store.upsert_follow(&follow(user(1, 1), 1.0, 1.0)).unwrap();
        assert_eq!(store.find_follow_by_iroh_node_id("").unwrap(), None);
        assert_eq!(
            store.find_follow_by_iroh_node_id(&"aa".repeat(32)).unwrap(),
            None
        );
    }

    #[test]
    fn provisioned_tunnel_round_trips_including_selected_targets() {
        let store = StateStore::open_in_memory().unwrap();
        let peer = user(1, 1);
        let t = ProvisionedTunnel {
            peer,
            direction: TunnelDirection::Consuming,
            peer_wg_pubkey: WgPublicKeyBytes([7; 32]),
            interface_name: "sf_tun0".into(),
            fwmark: 0x1000,
            route_table: 200,
            tunnel_ip: "10.99.0.4".into(),
            tunnel_ip6: Some("fd99::c8:4".into()),
            status: "active".into(),
            created_at: 100,
            advertisement_sequence: Some(0),
        };
        store.upsert_provisioned_tunnel(&t).unwrap();
        let got = store
            .get_provisioned_tunnel(&peer, TunnelDirection::Consuming)
            .unwrap()
            .unwrap();
        assert_eq!(got, t);
        assert_eq!(store.list_provisioned_tunnels().unwrap(), vec![t]);

        let targets = vec![TargetSelector::Domain("example.com".into())];
        store
            .set_provisioned_tunnel_selected_targets(&peer, TunnelDirection::Consuming, &targets)
            .unwrap();
        assert_eq!(
            store
                .get_provisioned_tunnel_selected_targets(&peer, TunnelDirection::Consuming)
                .unwrap(),
            targets
        );

        store
            .remove_provisioned_tunnel(&peer, TunnelDirection::Consuming)
            .unwrap();
        assert!(store
            .get_provisioned_tunnel(&peer, TunnelDirection::Consuming)
            .unwrap()
            .is_none());
    }

    #[test]
    fn record_transfer_sample_accumulates_deltas_across_samples() {
        let store = StateStore::open_in_memory().unwrap();
        let peer = user(1, 1);
        store
            .record_transfer_sample(&peer, TunnelDirection::Providing, 1000, 500, 100)
            .unwrap();
        store
            .record_transfer_sample(&peer, TunnelDirection::Providing, 1500, 900, 200)
            .unwrap();
        let balances = store.list_tunnel_balances().unwrap();
        assert_eq!(
            balances,
            vec![TunnelBalance {
                peer,
                given_to: (1500 - 1000) + (900 - 500) + 1000 + 500,
                taken_from: 0
            }]
        );
    }

    #[test]
    fn record_transfer_sample_treats_a_lower_raw_counter_as_a_fresh_delta_not_negative() {
        let store = StateStore::open_in_memory().unwrap();
        let peer = user(1, 1);
        store
            .record_transfer_sample(&peer, TunnelDirection::Consuming, 5000, 2000, 100)
            .unwrap();
        // Interface recreated (reboot) — wg's own raw counters reset to 0
        // then climb again; this must never be interpreted as negative
        // traffic, the whole new value is a fresh delta.
        store
            .record_transfer_sample(&peer, TunnelDirection::Consuming, 300, 100, 200)
            .unwrap();
        let balances = store.list_tunnel_balances().unwrap();
        assert_eq!(
            balances,
            vec![TunnelBalance {
                peer,
                given_to: 0,
                taken_from: 5000 + 2000 + 300 + 100
            }]
        );
    }

    #[test]
    fn list_tunnel_balances_reports_given_and_taken_independently_per_direction() {
        let store = StateStore::open_in_memory().unwrap();
        let provider_peer = user(1, 1);
        let consumer_peer = user(1, 2);
        store
            .record_transfer_sample(
                &provider_peer,
                TunnelDirection::Providing,
                10_000,
                20_000,
                100,
            )
            .unwrap();
        store
            .record_transfer_sample(
                &consumer_peer,
                TunnelDirection::Consuming,
                3_000,
                1_000,
                100,
            )
            .unwrap();
        let mut balances = store.list_tunnel_balances().unwrap();
        balances.sort_by_key(|b| b.peer.local_id.0[0]);
        assert_eq!(
            balances,
            vec![
                TunnelBalance {
                    peer: provider_peer,
                    given_to: 30_000,
                    taken_from: 0
                },
                TunnelBalance {
                    peer: consumer_peer,
                    given_to: 0,
                    taken_from: 4_000
                },
            ]
        );
    }

    #[test]
    fn providing_and_consuming_directions_for_the_same_peer_are_independent_rows() {
        let store = StateStore::open_in_memory().unwrap();
        let peer = user(1, 1);
        store
            .upsert_provisioned_tunnel(&ProvisionedTunnel {
                peer,
                direction: TunnelDirection::Providing,
                peer_wg_pubkey: WgPublicKeyBytes([1; 32]),
                interface_name: "sf_tun0".into(),
                fwmark: 0x1000,
                route_table: 200,
                tunnel_ip: "10.99.0.1".into(),
                tunnel_ip6: None,
                status: "active".into(),
                created_at: 0,
                advertisement_sequence: None,
            })
            .unwrap();
        store
            .upsert_provisioned_tunnel(&ProvisionedTunnel {
                peer,
                direction: TunnelDirection::Consuming,
                peer_wg_pubkey: WgPublicKeyBytes([2; 32]),
                interface_name: "sf_tun0".into(),
                fwmark: 0x1001,
                route_table: 201,
                tunnel_ip: "10.99.0.2".into(),
                tunnel_ip6: Some("fd99::c9:2".into()),
                status: "active".into(),
                created_at: 0,
                advertisement_sequence: Some(0),
            })
            .unwrap();
        assert_eq!(store.list_provisioned_tunnels().unwrap().len(), 2);
    }

    #[test]
    fn tunnel_sequence_counters_start_at_zero_and_increment_after_ingest() {
        let store = StateStore::open_in_memory().unwrap();
        let me = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: me,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();

        assert_eq!(store.next_tunnel_advertisement_sequence(&me).unwrap(), 0);
        store
            .ingest_tunnel_advertisement(&advertisement(me))
            .unwrap();
        assert_eq!(store.next_tunnel_advertisement_sequence(&me).unwrap(), 1);

        assert_eq!(store.next_tunnel_service_request_sequence(&me).unwrap(), 0);
        store
            .ingest_tunnel_service_request(&TunnelServiceRequest {
                requester: me,
                sequence: 0,
                description: "x".into(),
                desired_route_scope: vec![],
                visibility: Visibility::Public,
                issued_at: 0,
                expires_at: None,
                supersedes: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert_eq!(store.next_tunnel_service_request_sequence(&me).unwrap(), 1);

        assert_eq!(
            store.next_tunnel_connection_request_sequence(&me).unwrap(),
            0
        );
        store
            .store_tunnel_connection_request(&TunnelConnectionRequest {
                requester: me,
                sequence: 0,
                advertisement: StatementRef {
                    author: me,
                    sequence: 0,
                },
                requester_wg_pubkey: WgPublicKeyBytes([1; 32]),
                requester_messaging_pubkey: MessagingPublicKeyBytes([2; 32]),
                requested_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert_eq!(
            store.next_tunnel_connection_request_sequence(&me).unwrap(),
            1
        );
    }

    fn shared_list(
        author: UserId,
        sequence: u64,
        categories: Vec<&str>,
        entries: Vec<SharedRuleEntry>,
    ) -> SharedRuleList {
        SharedRuleList {
            author,
            sequence,
            name: "known trackers".into(),
            description: "domains I've personally confirmed track users".into(),
            categories: categories.into_iter().map(String::from).collect(),
            visibility: Visibility::Public,
            entries,
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }

    fn shared_policy(author: UserId, sequence: u64) -> SharedPolicy {
        let actions = vec![
            PolicyAction::Block,
            PolicyAction::Allow,
            PolicyAction::Route {
                profile: "vpn-eu".into(),
            },
            PolicyAction::DnsBlock,
            PolicyAction::DnsRedirect {
                address: "192.0.2.1".into(),
            },
            PolicyAction::DnsRecord {
                record_type: "AAAA".into(),
                value: "2001:db8::1".into(),
                ttl_seconds: 300,
            },
        ];
        SharedPolicy {
            policy_id: Hash32([8; 32]),
            author,
            sequence,
            name: "router policy".into(),
            description: "test policy".into(),
            categories: vec!["privacy".into(), "dns".into()],
            visibility: Visibility::Restricted,
            entries: actions
                .into_iter()
                .enumerate()
                .map(|(ordinal, action)| PolicyEntry {
                    entry_id: Hash32([ordinal as u8 + 20; 32]),
                    target: TargetSelector::Domain(format!("{}.example", ordinal)),
                    action,
                    category: Some("test".into()),
                    reason: Reason {
                        code: ReasonCode::PersonalPreference,
                        note: Some("stored reason".into()),
                        evidence: vec![Hash32([42; 32])],
                    },
                    expires_at: Some(900 + ordinal as i64),
                })
                .collect(),
            issued_at: 100,
            expires_at: Some(1000),
            supersedes: None,
            signature: SignatureBytes([7; 64]),
        }
    }

    #[test]
    fn shared_policy_round_trips_metadata_entries_actions_and_expiry() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(4, 4);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let policy = shared_policy(author, 0);
        store.ingest_shared_policy(&policy).unwrap();
        assert_eq!(
            store
                .get_shared_policy(policy.policy_id, author, 0)
                .unwrap(),
            Some(policy.clone())
        );
        assert_eq!(store.list_shared_policies().unwrap(), vec![policy]);
        assert_eq!(
            store
                .next_shared_policy_sequence(&author, &Hash32([8; 32]))
                .unwrap(),
            1
        );
    }

    #[test]
    fn shared_policy_ingest_is_idempotent_and_rejects_rollback() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(5, 5);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let policy = shared_policy(author, 2);
        store.ingest_shared_policy(&policy).unwrap();
        store.ingest_shared_policy(&policy).unwrap();
        let mut rollback = shared_policy(author, 1);
        rollback.signature = SignatureBytes([9; 64]);
        assert!(matches!(
            store.ingest_shared_policy(&rollback),
            Err(StoreError::Encoding(_))
        ));
    }

    fn sample_entry() -> SharedRuleEntry {
        SharedRuleEntry {
            target: target(),
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Tracker,
                note: Some("phones home".into()),
                evidence: vec![],
            },
        }
    }

    #[test]
    fn ingest_shared_rule_list_rejects_a_non_followed_author() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        let err = store
            .ingest_shared_rule_list(&shared_list(
                author,
                0,
                vec!["privacy"],
                vec![sample_entry()],
            ))
            .unwrap_err();
        assert!(matches!(err, StoreError::NotFollowed(_)));
    }

    #[test]
    fn shared_rule_list_round_trips_including_entries_and_categories() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();

        let list = shared_list(author, 0, vec!["privacy", "ads"], vec![sample_entry()]);
        store.ingest_shared_rule_list(&list).unwrap();

        let got = store.get_shared_rule_list(author, 0).unwrap().unwrap();
        assert_eq!(got.name, "known trackers");
        let mut categories = got.categories.clone();
        categories.sort();
        assert_eq!(categories, vec!["ads".to_string(), "privacy".to_string()]);
        assert_eq!(got.entries, vec![sample_entry()]);
    }

    #[test]
    fn list_shared_rule_lists_returns_every_known_one() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_shared_rule_list(&shared_list(
                author,
                0,
                vec!["privacy"],
                vec![sample_entry()],
            ))
            .unwrap();
        assert_eq!(store.list_shared_rule_lists().unwrap().len(), 1);
    }

    #[test]
    fn list_entries_for_finds_entries_and_pairs_with_categories_and_trust() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 2.0,
                deny_weight: 3.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_shared_rule_list(&shared_list(
                author,
                0,
                vec!["privacy", "ads"],
                vec![sample_entry()],
            ))
            .unwrap();

        let got = store.list_entries_for(&target(), 0).unwrap();
        assert_eq!(got.len(), 1);
        let (entry, entry_author, categories, trust) = &got[0];
        assert_eq!(*entry, sample_entry());
        assert_eq!(*entry_author, author);
        let mut sorted_categories = categories.clone();
        sorted_categories.sort();
        assert_eq!(
            sorted_categories,
            vec!["ads".to_string(), "privacy".to_string()]
        );
        assert_eq!(trust.as_ref().unwrap().allow_weight, 2.0);
    }

    #[test]
    fn list_entries_for_is_empty_for_an_unrelated_target() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .ingest_shared_rule_list(&shared_list(
                author,
                0,
                vec!["privacy"],
                vec![sample_entry()],
            ))
            .unwrap();

        assert!(store
            .list_entries_for(&TargetSelector::Domain("unrelated.example".into()), 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn list_entries_for_excludes_entries_from_an_expired_list() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        let mut list = shared_list(author, 0, vec!["privacy"], vec![sample_entry()]);
        list.expires_at = Some(100);
        store.ingest_shared_rule_list(&list).unwrap();

        assert_eq!(
            store.list_entries_for(&target(), 50).unwrap().len(),
            1,
            "not yet expired"
        );
        assert!(store.list_entries_for(&target(), 100).unwrap().is_empty(), "expiry is inclusive of the boundary, matching every other is_expired check in this crate");
        assert!(store.list_entries_for(&target(), 200).unwrap().is_empty());
    }

    #[test]
    fn ingesting_a_new_version_replaces_the_old_versions_entries_not_merges_with_them() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();

        let v1_entry = SharedRuleEntry {
            target: TargetSelector::Domain("v1-only.example".into()),
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Tracker,
                note: None,
                evidence: vec![],
            },
        };
        store
            .ingest_shared_rule_list(&shared_list(
                author,
                0,
                vec!["privacy"],
                vec![v1_entry.clone()],
            ))
            .unwrap();

        let v2_entry = SharedRuleEntry {
            target: TargetSelector::Domain("v2-only.example".into()),
            stance: Stance::Deny,
            reason: Reason {
                code: ReasonCode::Tracker,
                note: None,
                evidence: vec![],
            },
        };
        let mut v2 = shared_list(
            author,
            1,
            vec!["privacy", "new-category"],
            vec![v2_entry.clone()],
        );
        v2.supersedes = Some(0);
        store.ingest_shared_rule_list(&v2).unwrap();

        // v1's row (and its entries/categories, via ON DELETE CASCADE) must
        // be gone entirely — replaced, not kept alongside v2.
        assert!(
            store.get_shared_rule_list(author, 0).unwrap().is_none(),
            "the superseded version must be physically removed"
        );
        assert!(
            store
                .list_entries_for(&TargetSelector::Domain("v1-only.example".into()), 0)
                .unwrap()
                .is_empty(),
            "v1's entry must no longer be found"
        );
        assert_eq!(
            store
                .list_entries_for(&TargetSelector::Domain("v2-only.example".into()), 0)
                .unwrap()
                .len(),
            1,
            "v2's entry must be found"
        );
        assert_eq!(
            store.list_shared_rule_lists().unwrap().len(),
            1,
            "only the current version should remain"
        );
    }

    #[test]
    fn shared_rule_list_sequence_starts_at_zero_and_increments_after_ingest() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store
            .upsert_follow(&LocalTrustRule {
                user: author,
                allow_weight: 1.0,
                deny_weight: 1.0,
                advisory_only: false,
                excluded: false,
                category_filter: None,
                display_name: None,
                iroh_node_id: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();

        assert_eq!(store.next_shared_rule_list_sequence(&author).unwrap(), 0);
        store
            .ingest_shared_rule_list(&shared_list(
                author,
                0,
                vec!["privacy"],
                vec![sample_entry()],
            ))
            .unwrap();
        assert_eq!(store.next_shared_rule_list_sequence(&author).unwrap(), 1);
    }

    #[test]
    fn store_own_shared_rule_list_has_no_follow_gate() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        // No `upsert_follow` — a person doesn't need to follow themselves.
        store
            .store_own_shared_rule_list(&shared_list(
                author,
                0,
                vec!["privacy"],
                vec![sample_entry()],
            ))
            .unwrap();
        assert!(store.get_shared_rule_list(author, 0).unwrap().is_some());
    }

    fn user_contribution(u: UserId, stance: Stance, weight: f64) -> Contribution {
        Contribution {
            source: StatementAuthor::User(u),
            stance,
            weight,
            reason: Reason {
                code: ReasonCode::Tracker,
                note: Some("phones home".into()),
                evidence: vec![],
            },
        }
    }

    #[test]
    fn enforced_decision_contributors_round_trip_for_a_target() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let contributing = vec![user_contribution(alice, Stance::Deny, 0.75)];

        store
            .record_enforced_decision_contributors(&target(), &contributing)
            .unwrap();

        let got = store.enforced_decision_contributors_for(&target()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].source, StatementAuthor::User(alice));
        assert_eq!(got[0].stance, Stance::Deny);
        assert_eq!(got[0].weight, 0.75);
        assert_eq!(got[0].reason.code, ReasonCode::Tracker);
    }

    #[test]
    fn enforced_decision_contributors_supports_a_federation_source() {
        let store = StateStore::open_in_memory().unwrap();
        let contributing = vec![Contribution {
            source: StatementAuthor::Federation(fed(9)),
            stance: Stance::Deny,
            weight: 1.0,
            reason: Reason {
                code: ReasonCode::Malware,
                note: None,
                evidence: vec![],
            },
        }];

        store
            .record_enforced_decision_contributors(&target(), &contributing)
            .unwrap();

        let got = store.enforced_decision_contributors_for(&target()).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].source, StatementAuthor::Federation(fed(9)));
    }

    #[test]
    fn clear_enforced_decision_contributors_removes_everything() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .record_enforced_decision_contributors(
                &target(),
                &[user_contribution(user(1, 1), Stance::Deny, 1.0)],
            )
            .unwrap();

        store.clear_enforced_decision_contributors().unwrap();

        assert!(store
            .enforced_decision_contributors_for(&target())
            .unwrap()
            .is_empty());
        assert!(store
            .list_all_enforced_decision_contributors()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn list_all_enforced_decision_contributors_covers_multiple_targets() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let other_target = TargetSelector::Ip("203.0.113.9".into());
        store
            .record_enforced_decision_contributors(
                &target(),
                &[user_contribution(alice, Stance::Deny, 1.0)],
            )
            .unwrap();
        store
            .record_enforced_decision_contributors(
                &other_target,
                &[user_contribution(alice, Stance::Allow, 1.0)],
            )
            .unwrap();

        let got = store.list_all_enforced_decision_contributors().unwrap();
        assert_eq!(got.len(), 2);
        assert!(got.iter().any(|(t, _)| *t == target()));
        assert!(got.iter().any(|(t, _)| *t == other_target));
    }

    // ── Groups ───────────────────────────────────────────────────────────

    fn group_id() -> GroupId {
        GroupId(Hash32([42; 32]))
    }

    fn new_group(owner: UserId, voting_members: Vec<UserId>) -> Group {
        Group {
            group_id: group_id(),
            published_by: owner,
            sequence: 0,
            name: "neighborhood watch".into(),
            description: "local trusted operators".into(),
            join_prompt: None,
            owners: vec![owner],
            admins: vec![],
            voting_members,
            non_voting_members: vec![],
            party_line_moderated: false,
            voiced_members: vec![],
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }

    #[test]
    fn ingest_group_creates_a_brand_new_group() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();
        let got = store.get_group(group_id()).unwrap().unwrap();
        assert_eq!(got.owners, vec![owner]);
        assert_eq!(store.list_groups().unwrap().len(), 1);
    }

    #[test]
    fn ingest_group_rejects_zero_owners() {
        let store = StateStore::open_in_memory().unwrap();
        let mut g = new_group(user(1, 1), vec![]);
        g.owners.clear();
        let err = store.ingest_group(&g).unwrap_err();
        assert!(matches!(err, StoreError::InvalidGroup(_)));
    }

    #[test]
    fn ingest_group_rejects_a_new_group_not_published_by_one_of_its_own_owners() {
        let store = StateStore::open_in_memory().unwrap();
        let mut g = new_group(user(1, 1), vec![]);
        g.published_by = user(1, 9); // not in owners
        let err = store.ingest_group(&g).unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized(_)));
    }

    #[test]
    fn ingest_group_synthesizes_no_join_events_for_a_brand_new_groups_initial_members() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let member = user(1, 2);
        store
            .ingest_group(&new_group(owner, vec![owner, member]))
            .unwrap();
        assert!(
            store
                .list_group_membership_events(group_id())
                .unwrap()
                .is_empty(),
            "arriving to find people already in the channel is not a join, same as real IRC"
        );
    }

    #[test]
    fn ingest_group_synthesizes_a_joined_event_when_a_member_is_added() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let newcomer = user(1, 2);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();

        let mut v2 = new_group(owner, vec![owner, newcomer]);
        v2.sequence = 1;
        v2.supersedes = Some(0);
        v2.issued_at = 500;
        store.ingest_group(&v2).unwrap();

        let events = store.list_group_membership_events(group_id()).unwrap();
        assert_eq!(events, vec![(newcomer, MembershipEventKind::Joined, 500)]);
    }

    #[test]
    fn ingest_group_synthesizes_a_left_event_when_a_member_is_removed() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let member = user(1, 2);
        store
            .ingest_group(&new_group(owner, vec![owner, member]))
            .unwrap();

        let mut v2 = new_group(owner, vec![owner]);
        v2.sequence = 1;
        v2.supersedes = Some(0);
        v2.issued_at = 500;
        store.ingest_group(&v2).unwrap();

        let events = store.list_group_membership_events(group_id()).unwrap();
        assert_eq!(events, vec![(member, MembershipEventKind::Left, 500)]);
    }

    #[test]
    fn ingest_group_role_change_within_membership_is_not_a_join_or_a_leave() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let member = user(1, 2);
        store
            .ingest_group(&new_group(owner, vec![owner, member]))
            .unwrap();

        // member moves from voting to non-voting — still a member throughout.
        let mut v2 = new_group(owner, vec![owner]);
        v2.non_voting_members = vec![member];
        v2.sequence = 1;
        v2.supersedes = Some(0);
        v2.issued_at = 500;
        store.ingest_group(&v2).unwrap();

        assert!(store
            .list_group_membership_events(group_id())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ingest_group_accepts_an_update_from_a_current_owner_and_replaces_the_old_version() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let newcomer = user(1, 2);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();

        let mut v2 = new_group(owner, vec![owner, newcomer]);
        v2.sequence = 1;
        v2.supersedes = Some(0);
        store.ingest_group(&v2).unwrap();

        let got = store.get_group(group_id()).unwrap().unwrap();
        assert_eq!(got.sequence, 1);
        assert_eq!(got.voting_members, vec![owner, newcomer]);
        // The superseded version must be physically gone (version-replace,
        // not accumulate — same pattern `shared_rule_lists` already uses).
        let count: i64 = store
            .conn
            .query_row(
                "SELECT COUNT(*) FROM groups WHERE group_id = ?1",
                params![group_id().0 .0.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn ingest_group_rejects_an_update_from_someone_who_is_not_an_owner_or_admin() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let stranger = user(1, 9);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();

        let mut v2 = new_group(owner, vec![owner]);
        v2.published_by = stranger;
        v2.sequence = 1;
        v2.supersedes = Some(0);
        let err = store.ingest_group(&v2).unwrap_err();
        assert!(matches!(err, StoreError::Unauthorized(_)));
        // The original version must be untouched.
        assert_eq!(store.get_group(group_id()).unwrap().unwrap().sequence, 0);
    }

    #[test]
    fn ingest_group_accepts_an_update_from_an_admin_not_just_an_owner() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let admin = user(1, 2);
        let mut v1 = new_group(owner, vec![owner]);
        v1.admins = vec![admin];
        store.ingest_group(&v1).unwrap();

        let mut v2 = new_group(owner, vec![owner]);
        v2.admins = vec![admin];
        v2.published_by = admin;
        v2.sequence = 1;
        v2.supersedes = Some(0);
        store.ingest_group(&v2).unwrap();
        assert_eq!(store.get_group(group_id()).unwrap().unwrap().sequence, 1);
    }

    #[test]
    fn ingest_group_rejects_an_admin_trying_to_change_the_owners_list() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let admin = user(1, 2);
        let mut v1 = new_group(owner, vec![owner]);
        v1.admins = vec![admin];
        store.ingest_group(&v1).unwrap();

        // The admin publishes an update that adds themself as a
        // co-owner — membership/voting-rights changes are fine for an
        // admin, but touching the owners list is not.
        let mut v2 = new_group(owner, vec![owner]);
        v2.admins = vec![admin];
        v2.owners = vec![owner, admin];
        v2.published_by = admin;
        v2.sequence = 1;
        v2.supersedes = Some(0);
        let result = store.ingest_group(&v2);
        assert!(
            matches!(result, Err(StoreError::Unauthorized(_))),
            "an admin must never be able to change the owners list"
        );
        assert_eq!(
            store.get_group(group_id()).unwrap().unwrap().sequence,
            0,
            "the rejected update must not have replaced the current version"
        );
    }

    #[test]
    fn ingest_group_accepts_an_admin_update_that_leaves_owners_untouched() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let admin = user(1, 2);
        let new_member = user(1, 3);
        let mut v1 = new_group(owner, vec![owner]);
        v1.admins = vec![admin];
        store.ingest_group(&v1).unwrap();

        let mut v2 = new_group(owner, vec![owner, new_member]);
        v2.admins = vec![admin];
        v2.published_by = admin;
        v2.sequence = 1;
        v2.supersedes = Some(0);
        store.ingest_group(&v2).unwrap();
        assert_eq!(
            store.get_group(group_id()).unwrap().unwrap().voting_members,
            vec![owner, new_member]
        );
    }

    #[test]
    fn ingest_group_lets_an_owner_freely_change_the_owners_list() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let co_owner = user(1, 2);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();

        let mut v2 = new_group(owner, vec![owner]);
        v2.owners = vec![owner, co_owner];
        v2.sequence = 1;
        v2.supersedes = Some(0);
        store.ingest_group(&v2).unwrap();
        assert_eq!(
            store.get_group(group_id()).unwrap().unwrap().owners,
            vec![owner, co_owner]
        );
    }

    #[test]
    fn group_join_request_defaults_to_pending_and_can_be_approved() {
        let store = StateStore::open_in_memory().unwrap();
        let requester = user(2, 1);
        store
            .store_group_join_request(&GroupJoinRequest {
                requester,
                group_id: group_id(),
                sequence: 0,
                answer: Some("let me in".into()),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let pending = store.list_pending_group_join_requests(group_id()).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requester, requester);

        store
            .set_group_join_request_status(&requester, 0, "approved")
            .unwrap();
        assert!(store
            .list_pending_group_join_requests(group_id())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn group_join_track_record_is_all_zero_with_no_requests() {
        let store = StateStore::open_in_memory().unwrap();
        assert_eq!(
            store.group_join_track_record(group_id()).unwrap(),
            GroupJoinTrackRecord::default()
        );
    }

    #[test]
    fn group_join_track_record_tallies_every_status() {
        let store = StateStore::open_in_memory().unwrap();
        let a = user(2, 1);
        let b = user(2, 2);
        let c = user(2, 3);
        let d = user(2, 4);
        store
            .store_group_join_request(&GroupJoinRequest {
                requester: a,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_group_join_request(&GroupJoinRequest {
                requester: b,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_group_join_request(&GroupJoinRequest {
                requester: c,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_group_join_request(&GroupJoinRequest {
                requester: d,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .set_group_join_request_status(&a, 0, "approved")
            .unwrap();
        store
            .set_group_join_request_status(&b, 0, "rejected")
            .unwrap();
        store
            .set_group_join_request_status(&c, 0, "rejected")
            .unwrap();
        // d stays pending.

        let record = store.group_join_track_record(group_id()).unwrap();
        assert_eq!(
            record,
            GroupJoinTrackRecord {
                approved: 1,
                rejected: 2,
                blocked: 0,
                pending: 1
            }
        );
    }

    #[test]
    fn group_join_track_record_counts_an_auto_blocked_request() {
        let store = StateStore::open_in_memory().unwrap();
        let blocked_user = user(2, 1);
        store
            .block_group_user(group_id(), &blocked_user, &sample_block_reason(), 1000)
            .unwrap();
        store
            .store_group_join_request(&GroupJoinRequest {
                requester: blocked_user,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let record = store.group_join_track_record(group_id()).unwrap();
        assert_eq!(record.blocked, 1);
        assert_eq!(record.pending, 0);
    }

    #[test]
    fn group_join_prompt_round_trips_through_ingest() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let mut g = new_group(owner, vec![owner]);
        g.join_prompt = Some("please share a contact email".into());
        store.ingest_group(&g).unwrap();

        let got = store.get_group(group_id()).unwrap().unwrap();
        assert_eq!(
            got.join_prompt.as_deref(),
            Some("please share a contact email")
        );
    }

    #[test]
    fn group_without_a_join_prompt_round_trips_as_none() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();
        assert_eq!(
            store.get_group(group_id()).unwrap().unwrap().join_prompt,
            None
        );
    }

    fn sample_block_reason() -> Reason {
        Reason {
            code: ReasonCode::AbuseReport,
            note: Some("spammed the party line".into()),
            evidence: vec![],
        }
    }

    #[test]
    fn blocking_a_user_marks_their_pending_request_as_blocked() {
        let store = StateStore::open_in_memory().unwrap();
        let requester = user(2, 1);
        store
            .store_group_join_request(&GroupJoinRequest {
                requester,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert_eq!(
            store
                .list_pending_group_join_requests(group_id())
                .unwrap()
                .len(),
            1
        );

        store
            .block_group_user(group_id(), &requester, &sample_block_reason(), 1000)
            .unwrap();
        assert!(
            store
                .list_pending_group_join_requests(group_id())
                .unwrap()
                .is_empty(),
            "a blocked user's pending request must no longer show up as pending"
        );
    }

    #[test]
    fn a_blocked_users_future_join_request_is_auto_rejected_not_pending() {
        let store = StateStore::open_in_memory().unwrap();
        let requester = user(2, 1);
        store
            .block_group_user(group_id(), &requester, &sample_block_reason(), 1000)
            .unwrap();

        store
            .store_group_join_request(&GroupJoinRequest {
                requester,
                group_id: group_id(),
                sequence: 0,
                answer: Some("please let me in".into()),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert!(
            store
                .list_pending_group_join_requests(group_id())
                .unwrap()
                .is_empty(),
            "a blocked user's new request must never land as pending"
        );
    }

    #[test]
    fn unblocking_a_user_lets_future_requests_land_as_pending_again() {
        let store = StateStore::open_in_memory().unwrap();
        let requester = user(2, 1);
        store
            .block_group_user(group_id(), &requester, &sample_block_reason(), 1000)
            .unwrap();
        store.unblock_group_user(group_id(), &requester).unwrap();

        store
            .store_group_join_request(&GroupJoinRequest {
                requester,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert_eq!(
            store
                .list_pending_group_join_requests(group_id())
                .unwrap()
                .len(),
            1,
            "an unblocked user's request must land as pending again"
        );
    }

    #[test]
    fn list_blocked_group_users_reflects_block_and_unblock_and_carries_the_reason() {
        let store = StateStore::open_in_memory().unwrap();
        let a = user(2, 1);
        let b = user(2, 2);
        store
            .block_group_user(group_id(), &a, &sample_block_reason(), 1000)
            .unwrap();
        store
            .block_group_user(group_id(), &b, &sample_block_reason(), 1000)
            .unwrap();
        assert_eq!(store.list_blocked_group_users(group_id()).unwrap().len(), 2);

        store.unblock_group_user(group_id(), &a).unwrap();
        let remaining = store.list_blocked_group_users(group_id()).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, b);
        assert_eq!(remaining[0].1.code, ReasonCode::AbuseReport);
    }

    #[test]
    fn ingesting_a_foreign_block_report_never_triggers_local_enforcement() {
        let store = StateStore::open_in_memory().unwrap();
        let reporter = user(9, 9);
        let blocked = user(2, 1);
        store
            .store_group_block_report(&GroupBlockReport {
                group_id: group_id(),
                reporter,
                sequence: 0,
                blocked_user: blocked,
                reason: sample_block_reason(),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        assert!(
            !store.is_group_user_blocked(group_id(), &blocked).unwrap(),
            "ingesting someone else's report must never cause local enforcement"
        );
        store
            .store_group_join_request(&GroupJoinRequest {
                requester: blocked,
                group_id: group_id(),
                sequence: 0,
                answer: None,
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert_eq!(
            store
                .list_pending_group_join_requests(group_id())
                .unwrap()
                .len(),
            1,
            "a foreign report alone must not auto-reject a join request"
        );
    }

    #[test]
    fn list_group_block_reports_for_rolls_up_reports_from_multiple_reporters() {
        let store = StateStore::open_in_memory().unwrap();
        let reporter_a = user(9, 1);
        let reporter_b = user(9, 2);
        let blocked = user(2, 1);
        store
            .store_group_block_report(&GroupBlockReport {
                group_id: group_id(),
                reporter: reporter_a,
                sequence: 0,
                blocked_user: blocked,
                reason: sample_block_reason(),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_group_block_report(&GroupBlockReport {
                group_id: group_id(),
                reporter: reporter_b,
                sequence: 0,
                blocked_user: blocked,
                reason: sample_block_reason(),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let reports = store
            .list_group_block_reports_for(group_id(), &blocked)
            .unwrap();
        assert_eq!(
            reports.len(),
            2,
            "an owner reviewing this user must see reports from every independent reporter"
        );
    }

    #[test]
    fn next_group_block_report_sequence_increments_per_reporter() {
        let store = StateStore::open_in_memory().unwrap();
        let reporter = user(9, 1);
        assert_eq!(
            store
                .next_group_block_report_sequence(group_id(), &reporter)
                .unwrap(),
            0
        );
        store
            .store_group_block_report(&GroupBlockReport {
                group_id: group_id(),
                reporter,
                sequence: 0,
                blocked_user: user(2, 1),
                reason: sample_block_reason(),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert_eq!(
            store
                .next_group_block_report_sequence(group_id(), &reporter)
                .unwrap(),
            1
        );
    }

    #[test]
    fn list_group_votes_returns_every_vote_chronologically_not_deduped() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let bob = user(1, 2);
        store
            .ingest_group(&new_group(owner, vec![owner, bob]))
            .unwrap();
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter: owner,
                sequence: 0,
                target: target(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Malware,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 100,
                expires_at: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter: bob,
                sequence: 0,
                target: target(),
                stance: Stance::Allow,
                reason: Reason {
                    code: ReasonCode::KnownGoodCdn,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 200,
                expires_at: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        // owner re-casts — a real, distinct event, must not be collapsed.
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter: owner,
                sequence: 1,
                target: target(),
                stance: Stance::Allow,
                reason: Reason {
                    code: ReasonCode::PersonalPreference,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 300,
                expires_at: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let votes = store.list_group_votes(group_id()).unwrap();
        assert_eq!(
            votes.len(),
            3,
            "a re-cast vote is a distinct event, not a dedup target"
        );
        assert_eq!(
            votes.iter().map(|v| v.issued_at).collect::<Vec<_>>(),
            vec![100, 200, 300],
            "must be chronological"
        );
        assert_eq!(votes[2].stance, Stance::Allow);
    }

    fn policy_vote(
        policy_id: Hash32,
        entry_id: Hash32,
        policy_sequence: u64,
        voter: UserId,
        sequence: u64,
        stance: Stance,
        expires_at: Option<i64>,
    ) -> PolicyVote {
        PolicyVote {
            policy_id,
            entry_id,
            policy_sequence,
            group_id: group_id(),
            voter,
            sequence,
            stance,
            reason: Reason {
                code: ReasonCode::Tracker,
                note: None,
                evidence: vec![],
            },
            issued_at: sequence as i64,
            expires_at,
            signature: SignatureBytes([0; 64]),
        }
    }

    #[test]
    fn policy_votes_round_trip_and_allocate_sequences_per_poll_and_voter() {
        let store = StateStore::open_in_memory().unwrap();
        let policy_id = Hash32([7; 32]);
        let entry_id = Hash32([8; 32]);
        let voter = user(1, 1);
        assert_eq!(
            store
                .next_policy_vote_sequence(policy_id, entry_id, 0, group_id(), &voter)
                .unwrap(),
            0
        );
        let vote = policy_vote(policy_id, entry_id, 0, voter, 0, Stance::Deny, None);
        store.store_policy_vote(&vote).unwrap();
        store.store_policy_vote(&vote).unwrap();
        assert_eq!(
            store
                .next_policy_vote_sequence(policy_id, entry_id, 0, group_id(), &voter)
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .list_policy_votes(policy_id, entry_id, group_id())
                .unwrap(),
            vec![vote]
        );
    }

    #[test]
    fn policy_vote_aggregate_uses_current_members_and_latest_nonexpired_vote() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let bob = user(1, 2);
        let removed = user(1, 3);
        store
            .ingest_group(&new_group(owner, vec![owner, bob]))
            .unwrap();
        let policy_id = Hash32([7; 32]);
        let entry_id = Hash32([8; 32]);
        store
            .store_policy_vote(&policy_vote(
                policy_id,
                entry_id,
                0,
                owner,
                0,
                Stance::Allow,
                Some(10),
            ))
            .unwrap();
        store
            .store_policy_vote(&policy_vote(
                policy_id,
                entry_id,
                0,
                owner,
                1,
                Stance::Deny,
                None,
            ))
            .unwrap();
        store
            .store_policy_vote(&policy_vote(
                policy_id,
                entry_id,
                0,
                bob,
                0,
                Stance::Deny,
                None,
            ))
            .unwrap();
        store
            .store_policy_vote(&policy_vote(
                policy_id,
                entry_id,
                0,
                removed,
                0,
                Stance::Deny,
                None,
            ))
            .unwrap();

        assert_eq!(
            store
                .policy_stance_for(policy_id, entry_id, 0, group_id(), 100)
                .unwrap(),
            Some((Stance::Deny, 0, 2))
        );
        let breakdown = store
            .policy_vote_breakdown_for(policy_id, entry_id, 0, group_id(), 100)
            .unwrap();
        assert_eq!(breakdown.len(), 2);
        assert!(breakdown
            .iter()
            .all(|(_, vote, counts)| vote.is_some() && *counts));
    }

    fn store_with_self(seed: u8) -> (StateStore, UserId) {
        let store = StateStore::open_in_memory().unwrap();
        let me = user(seed, seed);
        store
            .set_self_identity(me, PublicKeyBytes([seed; 32]), &[seed; 32], None)
            .unwrap();
        (store, me)
    }

    #[test]
    fn network_health_summary_is_all_zero_with_no_data() {
        let (store, _me) = store_with_self(1);
        let summary = store.network_health_summary(1000).unwrap();
        assert_eq!(summary, NetworkHealthSummary::default());
        assert_eq!(summary.attention_items(), 0);
    }

    #[test]
    fn network_health_summary_flags_a_single_owner_group_but_not_a_co_owned_one() {
        let (store, me) = store_with_self(1);
        let co_owner = user(9, 9);
        store.ingest_group(&new_group(me, vec![me])).unwrap();
        let mut co_owned = new_group(me, vec![me]);
        co_owned.group_id = GroupId(Hash32([99; 32]));
        co_owned.owners.push(co_owner);
        store.ingest_group(&co_owned).unwrap();

        let summary = store.network_health_summary(1000).unwrap();
        assert_eq!(summary.owned_groups_total, 2);
        assert_eq!(
            summary.owned_groups_single_owner, 1,
            "only the sole-owner group should count as succession risk"
        );
        assert_eq!(summary.attention_items(), 1);
    }

    #[test]
    fn network_health_summary_counts_only_the_latest_vote_per_target_and_flags_expiry() {
        let (store, me) = store_with_self(1);
        store.ingest_group(&new_group(me, vec![me])).unwrap();
        // A superseded re-affirmation of the same vote — only the later,
        // still-valid one should count, not two separate votes.
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter: me,
                sequence: 0,
                target: target(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: Some(50),
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter: me,
                sequence: 1,
                target: target(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: Some(100),
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let summary = store.network_health_summary(75).unwrap();
        assert_eq!(
            summary.own_votes_total, 1,
            "a superseded vote on the same target must not be double-counted"
        );
        assert_eq!(
            summary.own_votes_expired, 0,
            "the latest vote (expires at 100) has not expired yet at t=75"
        );

        let summary_later = store.network_health_summary(150).unwrap();
        assert_eq!(summary_later.own_votes_expired, 1);
        // attention_items is 2 here, not 1 — `new_group` makes `me` the
        // sole owner, so this also legitimately trips succession risk;
        // that combination is exactly the point (independent signals sum
        // correctly), not a bug in either one.
        assert_eq!(summary_later.attention_items(), 2);
    }

    #[test]
    fn network_health_summary_flags_a_block_report_against_a_trusted_peer_as_a_lower_bound() {
        let (store, me) = store_with_self(1);
        let trusted = user(2, 2);
        let stranger = user(3, 3);
        store.upsert_follow(&follow(trusted, 1.0, 1.0)).unwrap();
        // A report against someone this router does NOT follow must not count.
        store
            .store_group_block_report(&GroupBlockReport {
                group_id: group_id(),
                reporter: user(9, 1),
                sequence: 0,
                blocked_user: stranger,
                reason: sample_block_reason(),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        let summary = store.network_health_summary(1000).unwrap();
        assert_eq!(summary.trusted_peers_with_block_reports, 0);

        store
            .store_group_block_report(&GroupBlockReport {
                group_id: group_id(),
                reporter: user(9, 1),
                sequence: 1,
                blocked_user: trusted,
                reason: sample_block_reason(),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        // A second, independent report against the same trusted peer must
        // not inflate the count — this counts *peers*, not *reports*.
        store
            .store_group_block_report(&GroupBlockReport {
                group_id: group_id(),
                reporter: user(9, 2),
                sequence: 0,
                blocked_user: trusted,
                reason: sample_block_reason(),
                issued_at: 0,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        let summary = store.network_health_summary(1000).unwrap();
        assert_eq!(summary.trusted_peers_with_block_reports, 1);
        assert_eq!(summary.attention_items(), 1);
        let _ = me;
    }

    #[test]
    fn network_health_summary_reports_follow_coverage() {
        let (store, _me) = store_with_self(1);
        store.upsert_follow(&follow(user(2, 2), 1.0, 1.0)).unwrap();
        store
            .upsert_follow(&LocalTrustRule {
                display_name: Some("alice".into()),
                ..follow(user(3, 3), 1.0, 1.0)
            })
            .unwrap();

        let summary = store.network_health_summary(1000).unwrap();
        assert_eq!(summary.follows_total, 2);
        assert_eq!(
            summary.follows_with_display_name, 1,
            "coverage is informational only, never folded into attention_items"
        );
        assert_eq!(summary.attention_items(), 0);
    }

    fn cast_vote(store: &StateStore, voter: UserId, sequence: u64, stance: Stance) {
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter,
                sequence,
                target: target(),
                stance,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: None,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
    }

    #[test]
    fn group_stance_for_is_none_with_no_votes() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .ingest_group(&new_group(user(1, 1), vec![user(1, 1)]))
            .unwrap();
        assert_eq!(
            store.group_stance_for(group_id(), &target(), 1000).unwrap(),
            None
        );
    }

    #[test]
    fn group_stance_for_reflects_a_simple_majority() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let bob = user(1, 2);
        let carol = user(1, 3);
        store
            .ingest_group(&new_group(owner, vec![owner, bob, carol]))
            .unwrap();
        cast_vote(&store, owner, 0, Stance::Deny);
        cast_vote(&store, bob, 0, Stance::Deny);
        cast_vote(&store, carol, 0, Stance::Allow);

        assert_eq!(
            store.group_stance_for(group_id(), &target(), 1000).unwrap(),
            Some((Stance::Deny, 1, 2))
        );
    }

    #[test]
    fn group_stance_for_is_none_on_a_genuine_tie() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let bob = user(1, 2);
        store
            .ingest_group(&new_group(owner, vec![owner, bob]))
            .unwrap();
        cast_vote(&store, owner, 0, Stance::Deny);
        cast_vote(&store, bob, 0, Stance::Allow);

        assert_eq!(
            store.group_stance_for(group_id(), &target(), 1000).unwrap(),
            None,
            "a genuine tie must not silently pick a winner"
        );
    }

    #[test]
    fn group_stance_for_only_counts_current_voting_members() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let removed = user(1, 2);
        // `removed` votes while still a voting member...
        store
            .ingest_group(&new_group(owner, vec![owner, removed]))
            .unwrap();
        cast_vote(&store, removed, 0, Stance::Deny);
        cast_vote(&store, owner, 0, Stance::Allow);
        assert_eq!(
            store.group_stance_for(group_id(), &target(), 1000).unwrap(),
            None,
            "tied 1-1 while still a member"
        );

        // ...then gets removed from voting membership in a new version.
        let mut v2 = new_group(owner, vec![owner]);
        v2.sequence = 1;
        v2.supersedes = Some(0);
        store.ingest_group(&v2).unwrap();

        assert_eq!(
            store.group_stance_for(group_id(), &target(), 1000).unwrap(),
            Some((Stance::Allow, 1, 0)),
            "a removed member's vote must no longer count"
        );
    }

    #[test]
    fn group_stance_for_ignores_an_expired_vote_without_falling_back_to_an_older_one() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();
        cast_vote(&store, owner, 0, Stance::Deny);
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter: owner,
                sequence: 1,
                target: target(),
                stance: Stance::Allow,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: Some(100),
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        assert_eq!(
            store.group_stance_for(group_id(), &target(), 200).unwrap(),
            None,
            "the latest vote is expired — must not fall back to the older Deny vote"
        );
    }

    #[test]
    fn group_vote_breakdown_for_lists_every_voting_member_including_non_voters() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let bob = user(1, 2);
        let carol = user(1, 3);
        store
            .ingest_group(&new_group(owner, vec![owner, bob, carol]))
            .unwrap();
        cast_vote(&store, owner, 0, Stance::Deny);
        cast_vote(&store, bob, 0, Stance::Allow);
        // carol never votes at all.

        let breakdown = store
            .group_vote_breakdown_for(group_id(), &target(), 1000)
            .unwrap();
        assert_eq!(
            breakdown.len(),
            3,
            "every current voting member must appear, voted or not"
        );

        let entry = |voter: UserId| {
            breakdown
                .iter()
                .find(|(v, _, _)| *v == voter)
                .unwrap()
                .clone()
        };
        let (_, owner_vote, owner_counts) = entry(owner);
        assert_eq!(owner_vote.unwrap().stance, Stance::Deny);
        assert!(owner_counts);

        let (_, bob_vote, bob_counts) = entry(bob);
        assert_eq!(bob_vote.unwrap().stance, Stance::Allow);
        assert!(bob_counts);

        let (_, carol_vote, carol_counts) = entry(carol);
        assert!(
            carol_vote.is_none(),
            "a member who never voted must show up with no vote, not be omitted"
        );
        assert!(!carol_counts);
    }

    #[test]
    fn group_vote_breakdown_for_shows_an_expired_vote_but_marks_it_as_not_counting() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();
        store
            .store_group_vote(&GroupVote {
                group_id: group_id(),
                voter: owner,
                sequence: 0,
                target: target(),
                stance: Stance::Deny,
                reason: Reason {
                    code: ReasonCode::Tracker,
                    note: None,
                    evidence: vec![],
                },
                issued_at: 0,
                expires_at: Some(100),
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let breakdown = store
            .group_vote_breakdown_for(group_id(), &target(), 200)
            .unwrap();
        assert_eq!(breakdown.len(), 1);
        let (_, vote, counts) = &breakdown[0];
        assert_eq!(
            vote.as_ref().unwrap().stance,
            Stance::Deny,
            "the expired vote must still be visible for review"
        );
        assert!(
            !counts,
            "an expired vote must be marked as not currently counting"
        );
    }

    #[test]
    fn group_vote_breakdown_for_excludes_a_member_removed_from_voting_membership() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let removed = user(1, 2);
        store
            .ingest_group(&new_group(owner, vec![owner, removed]))
            .unwrap();
        cast_vote(&store, removed, 0, Stance::Deny);

        let mut v2 = new_group(owner, vec![owner]);
        v2.sequence = 1;
        v2.supersedes = Some(0);
        store.ingest_group(&v2).unwrap();

        let breakdown = store
            .group_vote_breakdown_for(group_id(), &target(), 1000)
            .unwrap();
        assert_eq!(
            breakdown.len(),
            1,
            "a member removed from voting rights must no longer appear in the breakdown"
        );
        assert_eq!(breakdown[0].0, owner);
    }

    #[test]
    fn list_group_contributions_for_respects_excluded_and_expiry() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();
        cast_vote(&store, owner, 0, Stance::Deny);
        store
            .upsert_group_trust_rule(&GroupTrustRule {
                group_id: group_id(),
                allow_weight: 1.0,
                deny_weight: 1.0,
                excluded: false,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();

        let got = store.list_group_contributions_for(&target(), 1000).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, group_id());
        assert_eq!(got[0].1, Stance::Deny);

        store
            .upsert_group_trust_rule(&GroupTrustRule {
                group_id: group_id(),
                allow_weight: 1.0,
                deny_weight: 1.0,
                excluded: true,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        assert!(
            store
                .list_group_contributions_for(&target(), 1000)
                .unwrap()
                .is_empty(),
            "an excluded group must not contribute"
        );
    }

    #[test]
    fn party_line_messages_round_trip_in_issued_order() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let bob = user(1, 2);
        store
            .ingest_group(&new_group(alice, vec![alice, bob]))
            .unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: alice,
                sequence: 0,
                body: "hello".into(),
                in_reply_to: None,
                issued_at: 100,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: bob,
                sequence: 0,
                body: "hi back".into(),
                in_reply_to: None,
                issued_at: 200,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let got = store.list_party_line_messages(group_id()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].body, "hello");
        assert_eq!(got[1].body, "hi back");
    }

    #[test]
    fn party_line_message_in_reply_to_round_trips() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: owner,
                sequence: 0,
                body: "this is our CDN, not malware".into(),
                in_reply_to: Some(target()),
                issued_at: 100,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: owner,
                sequence: 1,
                body: "plain message".into(),
                in_reply_to: None,
                issued_at: 200,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let got = store.list_party_line_messages(group_id()).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0].in_reply_to,
            Some(target()),
            "a reply target must round-trip exactly"
        );
        assert_eq!(
            got[1].in_reply_to, None,
            "a plain message must round-trip with no reply target"
        );
    }

    #[test]
    fn list_party_line_messages_filters_out_a_non_member() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let stranger = user(1, 9);
        store.ingest_group(&new_group(owner, vec![owner])).unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: owner,
                sequence: 0,
                body: "welcome".into(),
                in_reply_to: None,
                issued_at: 100,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: stranger,
                sequence: 0,
                body: "spam".into(),
                in_reply_to: None,
                issued_at: 200,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        let got = store.list_party_line_messages(group_id()).unwrap();
        assert_eq!(
            got.len(),
            1,
            "a non-member's message must never surface, even though storage itself is ungated"
        );
        assert_eq!(got[0].body, "welcome");
    }

    #[test]
    fn list_party_line_messages_filters_out_an_unvoiced_member_once_moderated() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let member = user(1, 2);
        store
            .ingest_group(&new_group(owner, vec![owner, member]))
            .unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: member,
                sequence: 0,
                body: "hi".into(),
                in_reply_to: None,
                issued_at: 100,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();
        assert_eq!(
            store.list_party_line_messages(group_id()).unwrap().len(),
            1,
            "unmoderated: any current member may post"
        );

        let mut moderated = new_group(owner, vec![owner, member]);
        moderated.sequence = 1;
        moderated.supersedes = Some(0);
        moderated.party_line_moderated = true;
        store.ingest_group(&moderated).unwrap();

        assert!(store.list_party_line_messages(group_id()).unwrap().is_empty(), "once moderated, a member's un-voiced message must stop counting — current state wins, same as votes");
    }

    #[test]
    fn list_party_line_messages_includes_a_voiced_member_while_moderated() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let member = user(1, 2);
        let mut moderated = new_group(owner, vec![owner, member]);
        moderated.party_line_moderated = true;
        moderated.voiced_members = vec![member];
        store.ingest_group(&moderated).unwrap();
        store
            .store_party_line_message(&PartyLineMessage {
                group_id: group_id(),
                author: member,
                sequence: 0,
                body: "hi".into(),
                in_reply_to: None,
                issued_at: 100,
                signature: SignatureBytes([0; 64]),
            })
            .unwrap();

        assert_eq!(
            store.list_party_line_messages(group_id()).unwrap().len(),
            1,
            "an explicitly voiced member must be able to post while moderated"
        );
    }

    fn device_opinion(
        author: UserId,
        sequence: u64,
        mac: &str,
        stance: Stance,
    ) -> DeviceApprovalOpinion {
        DeviceApprovalOpinion {
            author,
            sequence,
            mac: mac.to_string(),
            stance,
            reason: Reason {
                code: ReasonCode::Malware,
                note: None,
                evidence: vec![],
            },
            device_label: Some("some-iot-thing".into()),
            issued_at: 100,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }
    fn follow(user: UserId, allow_weight: f64, deny_weight: f64) -> LocalTrustRule {
        LocalTrustRule {
            user,
            allow_weight,
            deny_weight,
            advisory_only: false,
            excluded: false,
            category_filter: None,
            display_name: None,
            iroh_node_id: None,
            expires_at: None,
            created_at: 0,
        }
    }

    #[test]
    fn ingest_device_approval_opinion_rejects_an_unfollowed_author() {
        let store = StateStore::open_in_memory().unwrap();
        let stranger = user(1, 1);
        let result = store.ingest_device_approval_opinion(&device_opinion(
            stranger,
            0,
            "aa:bb:cc:dd:ee:ff",
            Stance::Deny,
        ));
        assert!(matches!(result, Err(StoreError::NotFollowed(_))));
    }

    #[test]
    fn ingest_device_approval_opinion_accepts_a_followed_author() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store.upsert_follow(&follow(alice, 1.0, 1.0)).unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                alice,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Deny,
            ))
            .unwrap();

        let got = store
            .list_device_approval_opinions_for("aa:bb:cc:dd:ee:ff")
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0.stance, Stance::Deny);
        assert!(
            got[0].1.is_some(),
            "a followed author's opinion must carry its trust rule"
        );
    }

    #[test]
    fn store_own_device_approval_opinion_needs_no_follow() {
        let store = StateStore::open_in_memory().unwrap();
        let me = user(1, 1);
        store
            .store_own_device_approval_opinion(&device_opinion(
                me,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Allow,
            ))
            .unwrap();
        assert_eq!(
            store
                .list_device_approval_opinions_for("aa:bb:cc:dd:ee:ff")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn device_approval_stance_for_is_no_decision_with_no_opinions() {
        let store = StateStore::open_in_memory().unwrap();
        let (decision, allow, deny) = store
            .device_approval_stance_for("aa:bb:cc:dd:ee:ff", 1000, 1.0)
            .unwrap();
        assert_eq!(decision, domain_types::Decision::NoDecision);
        assert_eq!(allow, 0.0);
        assert_eq!(deny, 0.0);
    }

    #[test]
    fn device_approval_stance_for_reflects_a_trusted_deny_crossing_threshold() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store.upsert_follow(&follow(alice, 1.0, 1.0)).unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                alice,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Deny,
            ))
            .unwrap();

        let (decision, allow, deny) = store
            .device_approval_stance_for("aa:bb:cc:dd:ee:ff", 1000, 1.0)
            .unwrap();
        assert_eq!(decision, domain_types::Decision::Deny);
        assert_eq!(allow, 0.0);
        assert_eq!(deny, 1.0);
    }

    #[test]
    fn device_approval_stance_for_ignores_an_excluded_followed_author() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let mut rule = follow(alice, 1.0, 1.0);
        rule.excluded = true;
        store.upsert_follow(&rule).unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                alice,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Deny,
            ))
            .unwrap();

        let (decision, _, _) = store
            .device_approval_stance_for("aa:bb:cc:dd:ee:ff", 1000, 1.0)
            .unwrap();
        assert_eq!(
            decision,
            domain_types::Decision::NoDecision,
            "an excluded author's opinion must not contribute"
        );
    }

    #[test]
    fn device_approval_stance_for_is_ask_on_a_genuine_conflict() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        let bob = user(1, 2);
        store.upsert_follow(&follow(alice, 1.0, 1.0)).unwrap();
        store.upsert_follow(&follow(bob, 1.0, 1.0)).unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                alice,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Allow,
            ))
            .unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                bob,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Deny,
            ))
            .unwrap();

        let (decision, allow, deny) = store
            .device_approval_stance_for("aa:bb:cc:dd:ee:ff", 1000, 1.0)
            .unwrap();
        assert_eq!(decision, domain_types::Decision::Ask);
        assert_eq!(allow, 1.0);
        assert_eq!(deny, 1.0);
    }

    #[test]
    fn device_approval_opinions_are_scoped_per_mac() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store.upsert_follow(&follow(alice, 1.0, 1.0)).unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                alice,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Deny,
            ))
            .unwrap();

        assert!(store
            .list_device_approval_opinions_for("11:22:33:44:55:66")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn list_all_device_approval_opinions_covers_every_mac() {
        let store = StateStore::open_in_memory().unwrap();
        let alice = user(1, 1);
        store.upsert_follow(&follow(alice, 1.0, 1.0)).unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                alice,
                0,
                "aa:bb:cc:dd:ee:ff",
                Stance::Deny,
            ))
            .unwrap();
        store
            .ingest_device_approval_opinion(&device_opinion(
                alice,
                1,
                "11:22:33:44:55:66",
                Stance::Allow,
            ))
            .unwrap();

        let got = store.list_all_device_approval_opinions().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(
            got[0].mac, "11:22:33:44:55:66",
            "expected mac-ordered output"
        );
        assert_eq!(got[1].mac, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn outbox_retries_with_deterministic_exponential_backoff() {
        let store = StateStore::open_in_memory().unwrap();
        let id = store.enqueue_outbox("node-b", 5, b"payload", 100).unwrap();
        assert_eq!(store.list_due_outbox(99).unwrap().len(), 0);
        assert_eq!(store.list_due_outbox(100).unwrap()[0].attempts, 0);
        store.mark_outbox_failure(id, "offline", 100).unwrap();
        let due = store.list_due_outbox(101).unwrap();
        assert_eq!(due[0].attempts, 1);
        assert_eq!(due[0].last_error.as_deref(), Some("offline"));
        store.mark_outbox_success(id).unwrap();
        assert!(store.list_due_outbox(10_000).unwrap().is_empty());
    }

    #[test]
    fn device_presence_round_trips_updates_and_deletion() {
        let store = StateStore::open_in_memory().unwrap();
        let observation = DevicePresenceObservation {
            observation_id: Hash32([21; 32]),
            device_id: Some(DeviceId(Hash32([22; 32]))),
            observer: NodeId(Hash32([23; 32])),
            network: "guest".into(),
            source: "dhcp".into(),
            first_seen: 10,
            last_seen: 20,
            expires_at: Some(100),
        };
        store.upsert_device_presence(&observation).unwrap();
        let mut update = observation.clone();
        update.first_seen = 5;
        update.last_seen = 30;
        store.upsert_device_presence(&update).unwrap();

        let got = store.list_device_presence().unwrap();
        assert_eq!(got, vec![update]);
        store
            .delete_device_presence(observation.observation_id)
            .unwrap();
        assert!(store.list_device_presence().unwrap().is_empty());
    }

    #[test]
    fn local_irc_history_is_bounded_by_age_count_and_bytes() {
        let store = StateStore::open_in_memory().unwrap();
        store
            .append_local_irc_message("alice", "old", 1, 10, 500, 1024)
            .unwrap();
        store
            .append_local_irc_message("bob", "new", 20, 10, 500, 1024)
            .unwrap();
        assert_eq!(
            store.list_local_irc_messages(500).unwrap(),
            vec![("bob".into(), "new".into(), 20)]
        );

        store
            .append_local_irc_message("carol", "12345", 30, 100, 2, 5)
            .unwrap();
        store
            .append_local_irc_message("dave", "67890", 31, 100, 2, 5)
            .unwrap();
        assert_eq!(
            store.list_local_irc_messages(500).unwrap(),
            vec![("dave".into(), "67890".into(), 31)]
        );
    }
}
