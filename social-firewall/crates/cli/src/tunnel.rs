//! CLI implementation for the tunnel-advertising subcommands: `offer-
//! tunnel`, `request-service`, the four `ingest-tunnel-*`/`request-
//! tunnel` handshake steps, and `set-tunnel-trust`. Kept in its own
//! module — `main.rs` stays focused on argument parsing/dispatch,
//! matching how a single flat file was fine for the smaller original
//! surface but stops being the right shape once a feature this size is
//! added on top.
//!
//! **Export format**: a `Public`-visibility item is written as one
//! plaintext signed JSON file — anyone who receives it can read it, the
//! same model `publish-opinion --out` already uses. A `Restricted` one
//! (or anything inherently pairwise — connection requests/accepts, which
//! are always sealed regardless of the advertisement's own visibility)
//! is wrapped in a small envelope: `{"sealed": true, "ciphertext_hex":
//! "..."}`, produced by `crypto::seal`-ing the plaintext JSON's bytes to
//! the recipient's messaging public key. One envelope file per approved
//! recipient for a restricted advertisement/service-request — no single
//! file two people could both read.

use crate::{now_unix, parse_hash32, parse_target, target_value_str};
use anyhow::{bail, Context, Result};
use domain_types::{
    MessagingPublicKeyBytes, PublicKeyBytes, StatementRef, TargetSelector, TunnelAdvertisement,
    TunnelConnectionAccept, TunnelConnectionRequest, TunnelServiceRequest, TunnelTrustRule, UserId,
    Visibility, WgPublicKeyBytes,
};
use p2p_transport::PeerTransport;
use state_store::StateStore;
use std::path::{Path, PathBuf};

// ── visibility ───────────────────────────────────────────────────────────

pub(crate) fn parse_visibility(s: &str) -> Result<Visibility> {
    match s.to_ascii_lowercase().as_str() {
        "public" => Ok(Visibility::Public),
        "restricted" => Ok(Visibility::Restricted),
        other => bail!("invalid visibility `{other}` — expected public|restricted"),
    }
}

// ── sealing envelope (shared by every export path below) ────────────────

pub(crate) fn own_messaging_keypair(store: &StateStore) -> Result<crypto::MessagingKeypair> {
    let seed = store.get_messaging_keypair_seed()?;
    match seed {
        Some(s) => Ok(crypto::MessagingKeypair::from_seed(&s)),
        None => {
            let kp = crypto::MessagingKeypair::generate();
            store.set_messaging_keypair_seed(&kp.seed_bytes())?;
            Ok(kp)
        }
    }
}

/// Writes `plaintext` (already-serialized JSON bytes) to `path` — sealed
/// to `recipient` if given, plain otherwise.
pub(crate) fn write_maybe_sealed(
    plaintext: &[u8],
    recipient: Option<&MessagingPublicKeyBytes>,
    path: &Path,
) -> Result<()> {
    std::fs::write(path, maybe_sealed_bytes(plaintext, recipient)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub(crate) fn maybe_sealed_bytes(
    plaintext: &[u8],
    recipient: Option<&MessagingPublicKeyBytes>,
) -> Result<Vec<u8>> {
    match recipient {
        None => Ok(plaintext.to_vec()),
        Some(pk) => {
            let sealed =
                crypto::seal(pk, plaintext).map_err(|e| anyhow::anyhow!("sealing failed: {e}"))?;
            let envelope =
                serde_json::json!({ "sealed": true, "ciphertext_hex": hex::encode(sealed) });
            Ok(serde_json::to_vec_pretty(&envelope)?)
        }
    }
}

pub(crate) fn parse_maybe_sealed_bytes(
    store: &StateStore,
    bytes: &[u8],
) -> Result<serde_json::Value> {
    let json: serde_json::Value = serde_json::from_slice(bytes)?;
    if json.get("sealed").and_then(|v| v.as_bool()) == Some(true) {
        let ciphertext_hex = json
            .get("ciphertext_hex")
            .and_then(|v| v.as_str())
            .context("missing `ciphertext_hex`")?;
        let ciphertext = hex::decode(ciphertext_hex)?;
        let kp = own_messaging_keypair(store)?;
        let plaintext = kp.unseal(&ciphertext).map_err(|_| {
            anyhow::anyhow!(
                "unsealing failed — not addressed to this router, or the file was tampered with"
            )
        })?;
        Ok(serde_json::from_slice(&plaintext)?)
    } else {
        Ok(json)
    }
}

/// Reads `path`, unsealing first if it's a sealed envelope (using this
/// router's own messaging keypair — generated on first use, same as
/// elsewhere). Thin wrapper around `parse_maybe_sealed_bytes` — the file
/// I/O is the only thing this layer adds, so `sf listen` (which receives
/// bytes directly over the network, never a file) can share the same
/// parsing/unsealing core.
pub(crate) fn read_maybe_sealed(store: &StateStore, path: &Path) -> Result<serde_json::Value> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    parse_maybe_sealed_bytes(store, &bytes)
}

pub(crate) enum DeliveryOutcome {
    Delivered,
    NoKnownAddress,
    Failed(String),
}

/// Attempts real delivery via Iroh, then the explicitly configured Reticulum
/// bridge when Iroh is unavailable. The caller is responsible for writing the
/// fallback file in every case except `Delivered` — this function never writes
/// to disk itself, keeping "how to fall back" a caller decision (each call
/// site already has its own `--out`/`--out-dir` convention to preserve).
/// One Iroh keypair/endpoint is generated per call — acceptable for this
/// phase's request/accept cadence (a handful of sends per reconciliation
/// run, not a hot path); reusing a single long-lived endpoint across
/// sends is a reasonable future optimization once this is proven, not
/// built now.
pub(crate) fn try_deliver(
    store: &StateStore,
    recipient: &UserId,
    kind: p2p_transport::StatementKind,
    payload: &[u8],
) -> DeliveryOutcome {
    let destinations = match delivery_destinations(store, recipient) {
        Ok(destinations) => destinations,
        Err(error) => return DeliveryOutcome::Failed(error.to_string()),
    };
    if destinations.is_empty() {
        return DeliveryOutcome::NoKnownAddress;
    }
    let envelope = p2p_transport::Envelope {
        kind,
        payload: payload.to_vec(),
    };
    let mut failures = Vec::new();
    for destination in destinations {
        match send_to_destination(store, &destination, &envelope) {
            Ok(()) => return DeliveryOutcome::Delivered,
            Err(error) => failures.push(format!("{destination}: {error}")),
        }
    }
    DeliveryOutcome::Failed(failures.join("; "))
}

fn send_to_destination(
    store: &StateStore,
    destination: &str,
    envelope: &p2p_transport::Envelope,
) -> Result<()> {
    if let Some(address) = destination.strip_prefix("reticulum:") {
        let socket = std::env::var_os("SF_RETICULUM_SOCKET")
            .unwrap_or_else(|| "/run/kestrel/reticulum.sock".into());
        let transport = p2p_transport::ReticulumTransport::new(socket)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        return transport
            .send(address, envelope)
            .map_err(|error| anyhow::anyhow!(error.to_string()));
    }

    let node_id = destination.strip_prefix("iroh:").unwrap_or(destination);
    let seed = store
        .get_iroh_keypair_seed()?
        .context("no local Iroh keypair yet — run `sf listen` once to generate one")?;
    let transport = p2p_transport::IrohTransport::new(seed, b"social-firewall/1")
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    transport
        .send(node_id, envelope)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

fn delivery_destinations(store: &StateStore, recipient: &UserId) -> Result<Vec<String>> {
    let Some(rule) = store.get_follow(recipient)? else {
        return Ok(Vec::new());
    };
    let iroh = rule.iroh_node_id;
    let reticulum = store
        .peer_transport_address(*recipient, "reticulum")?
        .filter(|address| address.enabled)
        .map(|address| address.address);
    Ok(ordered_destinations(iroh.as_deref(), reticulum.as_deref()))
}

fn ordered_destinations(iroh: Option<&str>, reticulum: Option<&str>) -> Vec<String> {
    let mut destinations = Vec::with_capacity(2);
    if let Some(node_id) = iroh {
        destinations.push(format!("iroh:{node_id}"));
    }
    if let Some(address) = reticulum {
        destinations.push(format!("reticulum:{address}"));
    }
    destinations
}

pub(crate) fn preferred_destination(
    store: &StateStore,
    recipient: &UserId,
) -> Result<Option<String>> {
    Ok(delivery_destinations(store, recipient)?.into_iter().next())
}

pub(crate) fn deliver_to_node(
    store: &StateStore,
    node_id: &str,
    kind: p2p_transport::StatementKind,
    payload: &[u8],
) -> Result<()> {
    let seed = store
        .get_iroh_keypair_seed()?
        .context("no local Iroh keypair yet — run `sf listen` once")?;
    let transport = p2p_transport::IrohTransport::new(seed, b"social-firewall/1")
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    transport
        .send(
            node_id,
            &p2p_transport::Envelope {
                kind,
                payload: payload.to_vec(),
            },
        )
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}

pub(crate) fn deliver_to_destination(
    store: &StateStore,
    destination: &str,
    kind: p2p_transport::StatementKind,
    payload: &[u8],
) -> Result<()> {
    let envelope = p2p_transport::Envelope {
        kind,
        payload: payload.to_vec(),
    };
    if let Some(address) = destination.strip_prefix("reticulum:") {
        let socket = std::env::var_os("SF_RETICULUM_SOCKET")
            .unwrap_or_else(|| "/run/kestrel/reticulum.sock".into());
        let transport = p2p_transport::ReticulumTransport::new(socket)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        return transport
            .send(address, &envelope)
            .map_err(|error| anyhow::anyhow!(error.to_string()));
    }
    let node_id = destination.strip_prefix("iroh:").unwrap_or(destination);
    deliver_to_node(store, node_id, kind, payload)
}

pub(crate) fn request_to_destination(
    store: &StateStore,
    destination: &str,
    envelope: &p2p_transport::Envelope,
) -> Result<p2p_transport::Envelope> {
    if let Some(address) = destination.strip_prefix("reticulum:") {
        let socket = std::env::var_os("SF_RETICULUM_SOCKET")
            .unwrap_or_else(|| "/run/kestrel/reticulum.sock".into());
        let transport = p2p_transport::ReticulumTransport::new(socket)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
        return transport
            .request(address, envelope)
            .map_err(|error| anyhow::anyhow!(error.to_string()));
    }
    let seed = store
        .get_iroh_keypair_seed()?
        .context("no local Iroh keypair yet — run `sf listen` once")?;
    let transport = p2p_transport::IrohTransport::new(seed, b"social-firewall/1")
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let node_id = destination.strip_prefix("iroh:").unwrap_or(destination);
    transport
        .request(node_id, envelope)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
}

/// Reports a `try_deliver` outcome to the operator and answers the one
/// question every call site then has: do I still need to write the
/// fallback file? Shared by all three call sites so they cannot drift
/// apart in how they describe a failure.
///
/// `Failed(msg)`'s message goes to stderr and is never discarded — a
/// delivery that failed because the peer's router refused, timed out, or
/// could not decode the envelope is a materially different situation
/// from a peer whose node id was simply never recorded, and only this
/// message distinguishes them.
///
/// Note the ceiling on what `Delivered` can mean: `PeerTransport::send`
/// returning `Ok(())` proves the peer's *transport* received and decoded
/// the statement, not that the peer's ingest logic accepted it (see
/// `p2p_transport`'s module docs). So "delivered" here means the bytes
/// arrived, and skipping the fallback file is safe only in that sense.
pub(crate) fn needs_file_fallback(outcome: DeliveryOutcome, peer: &UserId) -> bool {
    match outcome {
        DeliveryOutcome::Delivered => {
            println!("delivered to {}'s node", user_id_str(peer));
            false
        }
        DeliveryOutcome::NoKnownAddress => {
            println!(
                "no Iroh or Reticulum address on record for {} — falling back to file export",
                user_id_str(peer)
            );
            true
        }
        DeliveryOutcome::Failed(msg) => {
            eprintln!(
                "delivery to {}'s node failed: {msg} — falling back to file export",
                user_id_str(peer)
            );
            true
        }
    }
}

pub(crate) fn user_id_str(u: &UserId) -> String {
    format!("{}/{}", u.federation.0, u.local_id)
}

pub(crate) fn parse_user_ref(s: &str) -> Result<UserId> {
    let (fed, local) = s
        .split_once('/')
        .with_context(|| format!("expected <federation>/<local-id>, got `{s}`"))?;
    Ok(UserId {
        federation: domain_types::FederationId(parse_hash32(fed)?),
        local_id: parse_hash32(local)?,
    })
}

fn parse_statement_ref(s: &str) -> Result<StatementRef> {
    let parts: Vec<&str> = s.splitn(3, '/').collect();
    let [fed, local, seq] = parts.as_slice() else {
        bail!("expected <federation>/<local-id>/<sequence>, got `{s}`")
    };
    Ok(StatementRef {
        author: UserId {
            federation: domain_types::FederationId(parse_hash32(fed)?),
            local_id: parse_hash32(local)?,
        },
        sequence: seq
            .parse()
            .with_context(|| format!("`{seq}` is not a valid sequence number"))?,
    })
}

fn targets_to_json(targets: &[TargetSelector]) -> serde_json::Value {
    serde_json::Value::Array(
        targets
            .iter()
            .map(|t| serde_json::json!({ "kind": t.kind_str(), "value": target_value_str(t) }))
            .collect(),
    )
}

fn targets_from_json(json: &serde_json::Value) -> Result<Vec<TargetSelector>> {
    json.as_array()
        .context("expected an array of targets")?
        .iter()
        .map(|t| {
            let kind = t
                .get("kind")
                .and_then(|v| v.as_str())
                .context("missing target `kind`")?;
            let value = t
                .get("value")
                .and_then(|v| v.as_str())
                .context("missing target `value`")?;
            parse_target(kind, value)
        })
        .collect()
}

// ── TunnelAdvertisement ──────────────────────────────────────────────────

fn advertisement_to_json(
    ad: &TunnelAdvertisement,
    identity_pubkey: &PublicKeyBytes,
) -> serde_json::Value {
    serde_json::json!({
        "provider": user_id_str(&ad.provider),
        "sequence": ad.sequence,
        "description": ad.description,
        "limitations": ad.limitations,
        "visibility": if ad.visibility == Visibility::Public { "public" } else { "restricted" },
        "in_response_to": ad.in_response_to.map(|r| format!("{}/{}", user_id_str(&r.author), r.sequence)),
        "identity_pubkey": hex::encode(identity_pubkey.0),
        "messaging_pubkey": hex::encode(ad.messaging_pubkey.0),
        "wg_pubkey": hex::encode(ad.wg_pubkey.0),
        "endpoint_hint": ad.endpoint_hint,
        "route_scope": targets_to_json(&ad.route_scope),
        "tags": ad.tags,
        "max_connections": ad.max_connections,
        "max_bandwidth_kbps": ad.max_bandwidth_kbps,
        "issued_at": ad.issued_at,
        "expires_at": ad.expires_at,
        "supersedes": ad.supersedes,
        "signature": hex::encode(ad.signature.0),
    })
}

fn advertisement_from_json(
    json: &serde_json::Value,
) -> Result<(TunnelAdvertisement, PublicKeyBytes)> {
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let provider = parse_user_ref(get_str("provider")?)?;
    let in_response_to = match json.get("in_response_to").and_then(|v| v.as_str()) {
        Some(s) => Some(parse_statement_ref(s)?),
        None => None,
    };
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let ad = TunnelAdvertisement {
        provider,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        description: get_str("description")?.to_string(),
        limitations: json
            .get("limitations")
            .and_then(|v| v.as_str())
            .map(String::from),
        visibility: parse_visibility(get_str("visibility")?)?,
        in_response_to,
        messaging_pubkey: MessagingPublicKeyBytes(bytes32(get_str("messaging_pubkey")?)?),
        wg_pubkey: WgPublicKeyBytes(bytes32(get_str("wg_pubkey")?)?),
        endpoint_hint: get_str("endpoint_hint")?.to_string(),
        route_scope: targets_from_json(json.get("route_scope").context("missing `route_scope`")?)?,
        tags: json
            .get("tags")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        max_connections: json
            .get("max_connections")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32),
        max_bandwidth_kbps: json.get("max_bandwidth_kbps").and_then(|v| v.as_u64()),
        issued_at: json
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing `issued_at`")?,
        expires_at: json.get("expires_at").and_then(|v| v.as_i64()),
        supersedes: json.get("supersedes").and_then(|v| v.as_u64()),
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    ad.validate_tags().map_err(|e| anyhow::anyhow!(e))?;
    Ok((ad, identity_pubkey))
}

pub(crate) fn bytes32(hex_str: &str) -> Result<[u8; 32]> {
    hex::decode(hex_str)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}
pub(crate) fn bytes64(hex_str: &str) -> Result<[u8; 64]> {
    hex::decode(hex_str)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 64 bytes"))
}

// ── subcommands ──────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn offer_tunnel(
    store: &StateStore,
    description: &str,
    limitation: Option<String>,
    targets: &[(String, String)],
    tags: Vec<String>,
    max_connections: Option<u32>,
    max_bandwidth_kbps: Option<u64>,
    visibility: &str,
    recipients: &[String],
    in_response_to: Option<String>,
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

    let route_scope: Vec<TargetSelector> = targets
        .iter()
        .map(|(k, v)| parse_target(k, v))
        .collect::<Result<_>>()?;
    let in_response_to = in_response_to
        .map(|s| parse_statement_ref(&s))
        .transpose()?;
    let (ad, identity_pubkey) = build_and_store_own_advertisement(
        store,
        description,
        limitation,
        route_scope,
        tags,
        max_connections,
        max_bandwidth_kbps,
        visibility,
        in_response_to,
    )?;
    let sequence = ad.sequence;
    println!("published tunnel advertisement #{sequence}: {description}");

    let json = advertisement_to_json(&ad, &identity_pubkey);
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
                // The recipient's own messaging pubkey isn't known to us
                // yet unless we've already ingested something from them —
                // in practice this means offering a restricted tunnel to
                // someone whose advertisement/request we've already seen.
                bail_if_recipient_pubkey_unknown(store, &recipient_user)?;
                let recipient_pubkey = recipient_messaging_pubkey(store, &recipient_user)?;
                let path = dir.join(format!("{}.json", r.replace('/', "_")));
                let payload = maybe_sealed_bytes(&plaintext, Some(&recipient_pubkey))?;
                if needs_file_fallback(
                    try_deliver(
                        store,
                        &recipient_user,
                        p2p_transport::StatementKind::RestrictedTunnelAdvertisement,
                        &payload,
                    ),
                    &recipient_user,
                ) {
                    write_maybe_sealed(&plaintext, Some(&recipient_pubkey), &path)?;
                    println!("exported (sealed) to {}", path.display());
                }
            }
        }
    }
    Ok(())
}

/// Restricted exports need the intended recipient's messaging pubkey —
/// this local-only skeleton has no key registry (see `main.rs`'s own doc
/// on trust-on-first-ingest), so it can only be known if this router has
/// already ingested *something* signed by that user. Bailing with a clear
/// message here beats silently sealing to a garbage key.
fn bail_if_recipient_pubkey_unknown(store: &StateStore, recipient: &UserId) -> Result<()> {
    recipient_messaging_pubkey(store, recipient).map(|_| ())
}

pub(crate) fn recipient_messaging_pubkey(
    store: &StateStore,
    recipient: &UserId,
) -> Result<MessagingPublicKeyBytes> {
    for ad in store.list_tunnel_advertisements()? {
        if ad.provider == *recipient {
            return Ok(ad.messaging_pubkey);
        }
    }
    for req in store.list_tunnel_service_requests()? {
        if req.requester == *recipient {
            // Service requests don't carry a messaging pubkey (see
            // `TunnelServiceRequest`'s own doc — the requester isn't
            // offering anything yet at that stage), so this doesn't help;
            // kept as an explicit branch (rather than silently falling
            // through) so a future field addition here is obvious to wire up.
            continue;
        }
    }
    bail!(
        "no known messaging pubkey for {} — ingest something signed by them first",
        user_id_str(recipient)
    )
}

pub(crate) fn self_identity(store: &StateStore) -> Result<(UserId, [u8; 32])> {
    match (store.get_self_identity()?, store.get_self_seed()?) {
        (Some((user, _)), Some(seed)) => Ok((user, seed)),
        _ => bail!("no identity yet — run `sf init-identity` first"),
    }
}

/// Core "build, sign, store" logic for a self-authored advertisement —
/// shared by the manual `offer-tunnel` CLI command and Phase E's
/// auto-respond-to-service-request loop (`sync-tunnels`), so both go
/// through the exact same identity/keypair/signing path rather than
/// duplicating it. Callers own export (a manual `offer-tunnel` writes to
/// an admin-chosen path; auto-respond writes to a predictable location
/// for later pickup) and the `in_response_to` back-reference, if any.
#[allow(clippy::too_many_arguments)]
fn build_and_store_own_advertisement(
    store: &StateStore,
    description: &str,
    limitation: Option<String>,
    route_scope: Vec<TargetSelector>,
    tags: Vec<String>,
    max_connections: Option<u32>,
    max_bandwidth_kbps: Option<u64>,
    visibility: Visibility,
    in_response_to: Option<StatementRef>,
) -> Result<(TunnelAdvertisement, PublicKeyBytes)> {
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let messaging_kp = own_messaging_keypair(store)?;
    let wg_seed = store.get_wg_keypair_seed()?.unwrap_or_else(|| {
        let kp = wg_tunnel::WgKeypair::generate();
        let seed = kp.seed_bytes();
        let _ = store.set_wg_keypair_seed(&seed);
        seed
    });
    let wg_kp = wg_tunnel::WgKeypair::from_seed(&wg_seed);
    let sequence = store.next_tunnel_advertisement_sequence(&author)?;

    let mut ad = TunnelAdvertisement {
        provider: author,
        sequence,
        description: description.to_string(),
        limitations: limitation,
        visibility,
        in_response_to,
        messaging_pubkey: messaging_kp.public_key(),
        wg_pubkey: wg_kp.public_key(),
        endpoint_hint: String::new(),
        route_scope,
        tags,
        max_connections,
        max_bandwidth_kbps,
        issued_at: now_unix(),
        expires_at: None,
        supersedes: None,
        signature: domain_types::SignatureBytes([0; 64]),
    };
    ad.validate_tags().map_err(|e| anyhow::anyhow!(e))?;
    let signing_bytes = ad.signing_bytes();
    ad.signature = kp.sign(crypto::contexts::TUNNEL_ADVERTISEMENT, &signing_bytes);

    store.store_own_tunnel_advertisement(&ad)?;
    Ok((ad, kp.public_key()))
}

pub fn ingest_tunnel_advertisement(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_tunnel_advertisement_bytes(store, &bytes)
}

pub(crate) fn ingest_tunnel_advertisement_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = parse_maybe_sealed_bytes(store, bytes)?;
    let (ad, identity_pubkey) = advertisement_from_json(&json)?;
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::TUNNEL_ADVERTISEMENT,
        &ad.signing_bytes(),
        &ad.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store
        .ingest_tunnel_advertisement(&ad)
        .map_err(anyhow::Error::from)?;
    println!(
        "ingested tunnel advertisement #{} from {}: {}",
        ad.sequence,
        user_id_str(&ad.provider),
        ad.description
    );
    Ok(())
}

pub fn list_tunnels(store: &StateStore) -> Result<()> {
    let ads = store.list_tunnel_advertisements()?;
    if ads.is_empty() {
        println!("no known tunnel advertisements");
        return Ok(());
    }
    for ad in ads {
        println!("#{} from {}", ad.sequence, user_id_str(&ad.provider));
        println!("  description : {}", ad.description);
        if let Some(l) = &ad.limitations {
            println!("  limitations : {l}");
        }
        println!(
            "  route scope : {:?}",
            ad.route_scope
                .iter()
                .map(target_value_str)
                .collect::<Vec<_>>()
        );
        println!("  endpoint    : {}", ad.endpoint_hint);
    }
    Ok(())
}

pub fn request_service(
    store: &StateStore,
    description: &str,
    targets: &[(String, String)],
    visibility: &str,
    recipients: &[String],
    out: Option<PathBuf>,
    out_dir: Option<PathBuf>,
) -> Result<()> {
    let visibility = parse_visibility(visibility)?;
    if visibility == Visibility::Restricted && recipients.is_empty() {
        bail!("--visibility restricted requires at least one --recipient");
    }
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let desired_route_scope: Vec<TargetSelector> = targets
        .iter()
        .map(|(k, v)| parse_target(k, v))
        .collect::<Result<_>>()?;
    let sequence = store.next_tunnel_service_request_sequence(&author)?;

    let mut req = TunnelServiceRequest {
        requester: author,
        sequence,
        description: description.to_string(),
        desired_route_scope,
        visibility,
        issued_at: now_unix(),
        expires_at: None,
        supersedes: None,
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let signing_bytes = req.signing_bytes();
    req.signature = kp.sign(crypto::contexts::TUNNEL_SERVICE_REQUEST, &signing_bytes);

    store.store_own_tunnel_service_request(&req)?;
    println!("published tunnel service request #{sequence}: {description}");

    let json = serde_json::json!({
        "requester": user_id_str(&req.requester),
        "sequence": req.sequence,
        "description": req.description,
        "desired_route_scope": targets_to_json(&req.desired_route_scope),
        "visibility": if req.visibility == Visibility::Public { "public" } else { "restricted" },
        "identity_pubkey": hex::encode(kp.public_key().0),
        "issued_at": req.issued_at,
        "expires_at": req.expires_at,
        "supersedes": req.supersedes,
        "signature": hex::encode(req.signature.0),
    });
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
                let payload = maybe_sealed_bytes(&plaintext, Some(&recipient_pubkey))?;
                if needs_file_fallback(
                    try_deliver(
                        store,
                        &recipient_user,
                        p2p_transport::StatementKind::RestrictedTunnelServiceRequest,
                        &payload,
                    ),
                    &recipient_user,
                ) {
                    write_maybe_sealed(&plaintext, Some(&recipient_pubkey), &path)?;
                    println!("exported (sealed) to {}", path.display());
                }
            }
        }
    }
    Ok(())
}

pub fn ingest_tunnel_service_request(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_tunnel_service_request_bytes(store, &bytes)
}

pub(crate) fn ingest_tunnel_service_request_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = parse_maybe_sealed_bytes(store, bytes)?;
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let requester = parse_user_ref(get_str("requester")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let req = TunnelServiceRequest {
        requester,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        description: get_str("description")?.to_string(),
        desired_route_scope: targets_from_json(
            json.get("desired_route_scope")
                .context("missing `desired_route_scope`")?,
        )?,
        visibility: parse_visibility(get_str("visibility")?)?,
        issued_at: json
            .get("issued_at")
            .and_then(|v| v.as_i64())
            .context("missing `issued_at`")?,
        expires_at: json.get("expires_at").and_then(|v| v.as_i64()),
        supersedes: json.get("supersedes").and_then(|v| v.as_u64()),
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::TUNNEL_SERVICE_REQUEST,
        &req.signing_bytes(),
        &req.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.ingest_tunnel_service_request(&req)?;
    println!(
        "ingested tunnel service request #{} from {}: {}",
        req.sequence,
        user_id_str(&req.requester),
        req.description
    );
    Ok(())
}

pub fn list_pending_service_requests(store: &StateStore) -> Result<()> {
    let reqs = store.list_tunnel_service_requests()?;
    if reqs.is_empty() {
        println!("no known tunnel service requests");
        return Ok(());
    }
    for r in reqs {
        println!(
            "#{} from {}: {}",
            r.sequence,
            user_id_str(&r.requester),
            r.description
        );
    }
    Ok(())
}

fn connection_request_to_json(
    req: &TunnelConnectionRequest,
    identity_pubkey: &PublicKeyBytes,
) -> serde_json::Value {
    serde_json::json!({
        "requester": user_id_str(&req.requester),
        "sequence": req.sequence,
        "advertisement": format!("{}/{}", user_id_str(&req.advertisement.author), req.advertisement.sequence),
        "identity_pubkey": hex::encode(identity_pubkey.0),
        "requester_wg_pubkey": hex::encode(req.requester_wg_pubkey.0),
        "requester_messaging_pubkey": hex::encode(req.requester_messaging_pubkey.0),
        "requested_at": req.requested_at,
        "signature": hex::encode(req.signature.0),
    })
}

/// Core "build, sign, store" logic for a connection request against a
/// known advertisement — shared by the manual `request-tunnel` CLI
/// command and Phase E's auto-consume loop (`sync-tunnels`), the same
/// split `build_and_store_own_advertisement` uses for `offer-tunnel`.
fn build_and_store_connection_request(
    store: &StateStore,
    advertisement_ref: StatementRef,
) -> Result<(TunnelConnectionRequest, PublicKeyBytes)> {
    let (author, seed) = self_identity(store)?;
    let kp = crypto::Keypair::from_seed(&seed);
    let messaging_kp = own_messaging_keypair(store)?;
    let wg_seed = store.get_wg_keypair_seed()?.unwrap_or_else(|| {
        let kp = wg_tunnel::WgKeypair::generate();
        let seed = kp.seed_bytes();
        let _ = store.set_wg_keypair_seed(&seed);
        seed
    });
    let wg_kp = wg_tunnel::WgKeypair::from_seed(&wg_seed);
    let sequence = store.next_tunnel_connection_request_sequence(&author)?;

    let mut req = TunnelConnectionRequest {
        requester: author,
        sequence,
        advertisement: advertisement_ref,
        requester_wg_pubkey: wg_kp.public_key(),
        requester_messaging_pubkey: messaging_kp.public_key(),
        requested_at: now_unix(),
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let signing_bytes = req.signing_bytes();
    req.signature = kp.sign(crypto::contexts::TUNNEL_CONNECTION_REQUEST, &signing_bytes);

    store.store_tunnel_connection_request(&req)?;
    Ok((req, kp.public_key()))
}

pub fn request_tunnel(store: &StateStore, advertisement: &str, out: Option<PathBuf>) -> Result<()> {
    let advertisement_ref = parse_statement_ref(advertisement)?;
    let ad = store
        .get_tunnel_advertisement(advertisement_ref.author, advertisement_ref.sequence)?
        .context("unknown advertisement — ingest it first")?;

    let (req, identity_pubkey) = build_and_store_connection_request(store, advertisement_ref)?;
    println!(
        "requested tunnel #{} against {}/{}",
        req.sequence,
        user_id_str(&ad.provider),
        ad.sequence
    );

    let plaintext = serde_json::to_vec(&connection_request_to_json(&req, &identity_pubkey))?;
    // The arms are split rather than sharing one `NoKnownAddress |
    // Failed(_)` pattern because `Failed`'s message is the only place an
    // operator can learn *why* delivery failed — "unreachable right now"
    // and "we have no address for this peer at all" want very different
    // responses, and collapsing them discarded that distinction.
    if needs_file_fallback(
        try_deliver(
            store,
            &ad.provider,
            p2p_transport::StatementKind::TunnelConnectionRequest,
            &plaintext,
        ),
        &ad.provider,
    ) {
        match &out {
            Some(path) => {
                write_maybe_sealed(&plaintext, Some(&ad.messaging_pubkey), path)?;
                println!("exported to {} for manual delivery", path.display());
            }
            None => eprintln!(
                "no --out path given — this connection request has not reached {} by any route",
                user_id_str(&ad.provider)
            ),
        }
    }
    Ok(())
}

pub(crate) fn ingest_tunnel_request_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = parse_maybe_sealed_bytes(store, bytes)?;
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let requester = parse_user_ref(get_str("requester")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let req = TunnelConnectionRequest {
        requester,
        sequence: json
            .get("sequence")
            .and_then(|v| v.as_u64())
            .context("missing `sequence`")?,
        advertisement: parse_statement_ref(get_str("advertisement")?)?,
        requester_wg_pubkey: WgPublicKeyBytes(bytes32(get_str("requester_wg_pubkey")?)?),
        requester_messaging_pubkey: MessagingPublicKeyBytes(bytes32(get_str(
            "requester_messaging_pubkey",
        )?)?),
        requested_at: json
            .get("requested_at")
            .and_then(|v| v.as_i64())
            .context("missing `requested_at`")?,
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::TUNNEL_CONNECTION_REQUEST,
        &req.signing_bytes(),
        &req.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.store_tunnel_connection_request(&req)?;
    println!(
        "ingested tunnel connection request #{} from {} (pending review)",
        req.sequence,
        user_id_str(&req.requester)
    );
    Ok(())
}

pub fn ingest_tunnel_request(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_tunnel_request_bytes(store, &bytes)
}

pub fn list_pending_tunnel_requests(store: &StateStore) -> Result<()> {
    let reqs = store.list_pending_tunnel_connection_requests()?;
    if reqs.is_empty() {
        println!("no pending tunnel connection requests");
        return Ok(());
    }
    for r in reqs {
        println!(
            "#{} from {} (against advertisement {}/{})",
            r.sequence,
            user_id_str(&r.requester),
            user_id_str(&r.advertisement.author),
            r.advertisement.sequence
        );
    }
    Ok(())
}

/// The tunnel-reciprocity signal, visibility-first per this crate's usual
/// pattern — see `StateStore::list_tunnel_balances`'s own doc, including
/// its documented limitation for a peer this router both provides to and
/// consumes from at once.
pub fn tunnel_balance(store: &StateStore) -> Result<()> {
    let balances = store.list_tunnel_balances()?;
    if balances.is_empty() {
        println!("no tunnel transfer data recorded yet");
        return Ok(());
    }
    for b in balances {
        let ratio = if b.given_to > 0 {
            format!("{:.3}", b.taken_from as f64 / b.given_to as f64)
        } else {
            "n/a".to_string()
        };
        println!(
            "{}: given {}B, taken {}B (received/given ratio: {ratio})",
            user_id_str(&b.peer),
            b.given_to,
            b.taken_from
        );
    }
    Ok(())
}

/// Manually accepts a pending connection request — kept alongside
/// Phase E's auto-accept (`TunnelTrustRule.auto_accept_requests`) the
/// same way `LocalOverride` always exists alongside trust-weighted
/// aggregation: an explicit override path is worth having even once
/// automation exists.
/// Core accept logic, shared by the manual `accept-tunnel-request` CLI
/// command and `sync-tunnels`'s auto-accept loop (Phase E) — allocates
/// resources, records the provisioned tunnel, signs and stores the
/// accept. Callers own the "how did we decide to accept this" policy
/// (an explicit CLI invocation vs. a trusted `TunnelTrustRule`) and the
/// export step, since manual acceptance exports to an admin-chosen path
/// while auto-accept exports to a predictable location for later pickup.
fn do_accept_tunnel_request(
    store: &StateStore,
    provider: UserId,
    seed: &[u8; 32],
    req: &TunnelConnectionRequest,
) -> Result<(TunnelConnectionAccept, PublicKeyBytes)> {
    let kp = crypto::Keypair::from_seed(seed);
    let (fwmark, route_table) = store.allocate_fwmark_and_route_table()?;
    // Deterministic from the allocated route table, so each accepted
    // tunnel gets a distinct /24 out of a private range without needing
    // a separate IP allocator on top of the fwmark/route-table one.
    let tunnel_ip = format!("10.99.{}.1", route_table - 200);
    // Same deterministic-from-route_table scheme, one dimension over —
    // every social-firewall tunnel is dual-stack capable, so this is
    // always assigned alongside the IPv4 address, never left unset for a
    // newly accepted tunnel (see `TunnelConnectionAccept::assigned_tunnel_ip6`'s
    // own doc on why it's still `Option` at the type level).
    let tunnel_ip6 = format!("fd99::{route_table:x}:1");

    store.upsert_provisioned_tunnel(&state_store::ProvisionedTunnel {
        peer: req.requester,
        direction: state_store::TunnelDirection::Providing,
        peer_wg_pubkey: req.requester_wg_pubkey,
        interface_name: "sf_tun0".to_string(),
        fwmark,
        route_table,
        tunnel_ip: tunnel_ip.clone(),
        tunnel_ip6: Some(tunnel_ip6.clone()),
        status: "active".to_string(),
        created_at: now_unix(),
        // Not needed here — only the *consuming* side ever enforces
        // limits against its own traffic (see `wg_tunnel::provision_routing`'s own doc).
        advertisement_sequence: None,
    })?;

    let mut accept = TunnelConnectionAccept {
        provider,
        request_ref: StatementRef {
            author: req.requester,
            sequence: req.sequence,
        },
        assigned_tunnel_ip: tunnel_ip.clone(),
        assigned_tunnel_ip6: Some(tunnel_ip6.clone()),
        accepted_at: now_unix(),
        signature: domain_types::SignatureBytes([0; 64]),
    };
    let signing_bytes = accept.signing_bytes();
    accept.signature = kp.sign(crypto::contexts::TUNNEL_CONNECTION_ACCEPT, &signing_bytes);

    store.store_tunnel_connection_accept(&accept)?;
    store.set_tunnel_connection_request_status(&req.requester, req.sequence, "accepted")?;
    Ok((accept, kp.public_key()))
}

fn accept_to_json(
    accept: &TunnelConnectionAccept,
    identity_pubkey: &PublicKeyBytes,
) -> serde_json::Value {
    serde_json::json!({
        "provider": user_id_str(&accept.provider),
        "request_ref": format!("{}/{}", user_id_str(&accept.request_ref.author), accept.request_ref.sequence),
        "identity_pubkey": hex::encode(identity_pubkey.0),
        "assigned_tunnel_ip": accept.assigned_tunnel_ip,
        "assigned_tunnel_ip6": accept.assigned_tunnel_ip6,
        "accepted_at": accept.accepted_at,
        "signature": hex::encode(accept.signature.0),
    })
}

pub fn accept_tunnel_request(
    store: &StateStore,
    requester: &str,
    sequence: u64,
    out: Option<PathBuf>,
) -> Result<()> {
    let requester_user = parse_user_ref(requester)?;
    let (provider, seed) = self_identity(store)?;

    let req = store
        .list_pending_tunnel_connection_requests()?
        .into_iter()
        .find(|r| r.requester == requester_user && r.sequence == sequence)
        .context("no matching pending connection request — check `list-pending-tunnel-requests`")?;

    let (accept, identity_pubkey) = do_accept_tunnel_request(store, provider, &seed, &req)?;
    println!(
        "accepted tunnel connection request #{sequence} from {}: assigned {}{}",
        user_id_str(&requester_user),
        accept.assigned_tunnel_ip,
        accept
            .assigned_tunnel_ip6
            .as_deref()
            .map(|ip6| format!(" / {ip6}"))
            .unwrap_or_default()
    );

    let plaintext = serde_json::to_vec(&accept_to_json(&accept, &identity_pubkey))?;
    if needs_file_fallback(
        try_deliver(
            store,
            &requester_user,
            p2p_transport::StatementKind::TunnelConnectionAccept,
            &plaintext,
        ),
        &requester_user,
    ) {
        match out {
            Some(path) => {
                // Always sealed — a connection accept is inherently pairwise.
                write_maybe_sealed(&plaintext, Some(&req.requester_messaging_pubkey), &path)?;
                println!("exported (sealed to requester) to {}", path.display());
            }
            None => eprintln!(
                "no --out path given — this accept has not reached {} by any route",
                user_id_str(&requester_user)
            ),
        }
    }
    Ok(())
}

pub(crate) fn ingest_tunnel_accept_bytes(store: &StateStore, bytes: &[u8]) -> Result<()> {
    let json = parse_maybe_sealed_bytes(store, bytes)?;
    let get_str = |key: &str| -> Result<&str> {
        json.get(key)
            .and_then(|v| v.as_str())
            .with_context(|| format!("missing `{key}`"))
    };
    let provider = parse_user_ref(get_str("provider")?)?;
    let identity_pubkey = PublicKeyBytes(bytes32(get_str("identity_pubkey")?)?);
    let accept = TunnelConnectionAccept {
        provider,
        request_ref: parse_statement_ref(get_str("request_ref")?)?,
        assigned_tunnel_ip: get_str("assigned_tunnel_ip")?.to_string(),
        assigned_tunnel_ip6: json
            .get("assigned_tunnel_ip6")
            .and_then(|v| v.as_str())
            .map(String::from),
        accepted_at: json
            .get("accepted_at")
            .and_then(|v| v.as_i64())
            .context("missing `accepted_at`")?,
        signature: domain_types::SignatureBytes(bytes64(get_str("signature")?)?),
    };
    crypto::verify(
        &identity_pubkey,
        crypto::contexts::TUNNEL_CONNECTION_ACCEPT,
        &accept.signing_bytes(),
        &accept.signature,
    )
    .map_err(|_| anyhow::anyhow!("signature verification failed — refusing to ingest"))?;
    store.store_tunnel_connection_accept(&accept)?;

    // A `provisioned_tunnels` row is what `select-tunnel` (and later,
    // `wg-tunnel`'s own reconciliation) attaches to — without creating it
    // here, `select-tunnel` would fail its foreign-key check against a
    // row that was never created for the *consumer's* side (only the
    // provider's `accept-tunnel-request` created its own "Providing" row;
    // this is the missing "Consuming" counterpart). Caught via manual
    // end-to-end testing.
    let own_request = store
        .get_tunnel_connection_request(&accept.request_ref.author, accept.request_ref.sequence)?
        .context("missing our own connection request record — this accept doesn't match anything we sent")?;
    let ad = store
        .get_tunnel_advertisement(
            own_request.advertisement.author,
            own_request.advertisement.sequence,
        )?
        .context("missing the original advertisement this request was against")?;
    let (fwmark, route_table) = store.allocate_fwmark_and_route_table()?;
    store.upsert_provisioned_tunnel(&state_store::ProvisionedTunnel {
        peer: accept.provider,
        direction: state_store::TunnelDirection::Consuming,
        peer_wg_pubkey: ad.wg_pubkey,
        interface_name: "sf_tun0".to_string(),
        fwmark,
        route_table,
        tunnel_ip: accept.assigned_tunnel_ip.clone(),
        tunnel_ip6: accept.assigned_tunnel_ip6.clone(),
        status: "active".to_string(),
        created_at: now_unix(),
        // Lets `wg_tunnel::WgTunnelController::reconcile` look up this
        // advertisement's `max_connections`/`max_bandwidth_kbps` at
        // `provision_routing` time.
        advertisement_sequence: Some(ad.sequence),
    })?;

    println!(
        "ingested tunnel connection accept from {}: assigned IP {}{}",
        user_id_str(&accept.provider),
        accept.assigned_tunnel_ip,
        accept
            .assigned_tunnel_ip6
            .as_deref()
            .map(|ip6| format!(" / {ip6}"))
            .unwrap_or_default()
    );
    Ok(())
}

pub fn ingest_tunnel_accept(store: &StateStore, file: &Path) -> Result<()> {
    let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    ingest_tunnel_accept_bytes(store, &bytes)
}

/// The receive-side counterpart to Task 6's send-side wiring: dispatches
/// a decoded envelope's payload to the exact same `ingest_*_bytes`
/// function the file-based CLI path calls, so every signature check and
/// follow-gate runs completely unchanged regardless of how the bytes
/// arrived. A malformed or rejected payload returns `Err` — `sf listen`
/// (below) logs and continues rather than propagating a failure that
/// would kill the whole listener.
pub fn dispatch_envelope(
    store: &StateStore,
    kind: p2p_transport::StatementKind,
    payload: &[u8],
) -> Result<()> {
    match kind {
        p2p_transport::StatementKind::TunnelConnectionRequest => {
            ingest_tunnel_request_bytes(store, payload)
        }
        p2p_transport::StatementKind::TunnelConnectionAccept => {
            ingest_tunnel_accept_bytes(store, payload)
        }
        p2p_transport::StatementKind::GroupJoinRequest => {
            crate::group::ingest_group_join_request_bytes(store, payload)
        }
        p2p_transport::StatementKind::Group => crate::group::ingest_group_bytes(store, payload),
        p2p_transport::StatementKind::PartyLineMessage => {
            crate::group::ingest_party_line_bytes(store, payload)
        }
        p2p_transport::StatementKind::RestrictedTunnelAdvertisement => {
            ingest_tunnel_advertisement_bytes(store, payload)
        }
        p2p_transport::StatementKind::RestrictedTunnelServiceRequest => {
            ingest_tunnel_service_request_bytes(store, payload)
        }
        p2p_transport::StatementKind::RestrictedSharedRuleList => {
            crate::list::ingest_list_bytes(store, payload)
        }
        p2p_transport::StatementKind::SyncGroupRequest
        | p2p_transport::StatementKind::SyncGroupResponse => {
            bail!("group sync envelopes require the sync protocol handler")
        }
        p2p_transport::StatementKind::SharedPolicy => {
            crate::shared_policy::ingest_policy_bytes(store, payload)
        }
        p2p_transport::StatementKind::PolicyVote => {
            crate::shared_policy::ingest_policy_vote_bytes(store, payload)
        }
        p2p_transport::StatementKind::FingerprintObservation => {
            crate::fingerprint::ingest_observation_bytes(store, payload)
        }
        p2p_transport::StatementKind::FingerprintComment => {
            crate::fingerprint::ingest_comment_bytes(store, payload)
        }
    }
}

/// Decides whether an envelope arriving over the network from Iroh node
/// id `from` should be dispatched at all.
///
/// `from` is authenticated by Iroh as part of the QUIC/TLS handshake, so
/// it is a real identity claim rather than a self-reported one, and it
/// is safe to gate on. Everything the file-based ingest path could
/// assume about provenance came from a human choosing to copy a file
/// from someone they knew; on the network path there is no human in the
/// loop, and anyone who learns this router's node id can open a
/// connection to it. Requiring the sender's node id to match a follow
/// this router has explicitly recorded restores that same "someone
/// vetted this sender" property, automatically.
///
/// Fails **closed**: if the store cannot be read, the envelope is not
/// dispatched. A lookup failure is not evidence that the sender is
/// trusted.
///
/// Note that this is an additional gate, not a replacement for anything.
/// Signature verification and every other check inside `ingest_*_bytes`
/// still run afterwards, exactly as they do for a file.
pub(crate) fn known_follow_for_node_id(store: &StateStore, from: &str) -> Option<UserId> {
    match store.find_follow_by_iroh_node_id(from) {
        Ok(found) => found,
        Err(e) => {
            eprintln!(
                "could not check whether {from} is a known follow ({e}) — refusing the envelope"
            );
            None
        }
    }
}

pub(crate) fn known_follow_for_reticulum_address(store: &StateStore, from: &str) -> Option<UserId> {
    match store.find_follow_by_transport_address("reticulum", from) {
        Ok(found) => found,
        Err(e) => {
            eprintln!(
                "could not check whether {from} is a known Reticulum address ({e}) — refusing the envelope"
            );
            None
        }
    }
}

fn dispatch_received_envelope(
    store: &StateStore,
    from: &str,
    envelope: &p2p_transport::Envelope,
    peer: UserId,
) -> Result<Option<p2p_transport::Envelope>, String> {
    if envelope.kind == p2p_transport::StatementKind::SyncGroupRequest {
        let response =
            crate::group::handle_sync_group_request(store, peer, from, &envelope.payload)
                .map_err(|e| e.to_string())?;
        return Ok(Some(response));
    }
    dispatch_envelope(store, envelope.kind, &envelope.payload).map_err(|e| e.to_string())?;
    println!(
        "dispatched {:?} from {} ({from})",
        envelope.kind,
        user_id_str(&peer)
    );
    Ok(None)
}

/// The first genuinely persistent process in this codebase — accepts
/// inbound Iroh connections and dispatches each received envelope via
/// `dispatch_envelope`. A malformed envelope, a decode failure, an
/// unrecognized sender, or an `ingest_*` rejection is logged and the
/// loop continues; nothing here can crash the listener or affect
/// another connection (see the design spec's Error handling section).
pub fn listen(store: &StateStore) -> Result<()> {
    let seed = match store.get_iroh_keypair_seed()? {
        Some(seed) => seed,
        None => {
            let seed: [u8; 32] = {
                use rand::RngCore;
                let mut s = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut s);
                s
            };
            store.set_iroh_keypair_seed(&seed)?;
            seed
        }
    };
    let transport = p2p_transport::IrohTransport::new(seed, b"social-firewall/1")
        .map_err(|e| anyhow::anyhow!("failed to start Iroh transport: {e}"))?;
    println!("listening — this node's Iroh id: {}", transport.node_id());
    loop {
        match transport.recv_and_dispatch(&|from, envelope| {
            let peer = known_follow_for_node_id(store, from)
                .ok_or_else(|| format!("unrecognized node {from}"))?;
            dispatch_received_envelope(store, from, envelope, peer)
        }) {
            Ok(()) => {}
            Err(p2p_transport::TransportError::ApplicationRejected(reason)) => {
                eprintln!("rejected inbound envelope: {reason}");
            }
            Err(e) => {
                eprintln!("transport closed: {e}");
                return Ok(());
            }
        }
    }
}

/// Accepts inbound Reticulum connections through the optional bridge. This
/// runs as a separate service because the bridge's Unix socket receive stream
/// is blocking and must not prevent the Iroh listener from accepting peers.
pub fn reticulum_listen(store: &StateStore) -> Result<()> {
    let socket = std::env::var_os("SF_RETICULUM_SOCKET")
        .unwrap_or_else(|| "/run/kestrel/reticulum.sock".into());
    let transport = p2p_transport::ReticulumTransport::new(socket)
        .map_err(|e| anyhow::anyhow!("failed to start Reticulum transport: {e}"))?;
    println!("listening for Reticulum envelopes");
    loop {
        match transport.recv_and_dispatch(&|from, envelope| {
            let peer = known_follow_for_reticulum_address(store, from)
                .ok_or_else(|| format!("unrecognized Reticulum address {from}"))?;
            dispatch_received_envelope(store, from, envelope, peer)
        }) {
            Ok(()) => {}
            Err(p2p_transport::TransportError::ApplicationRejected(reason)) => {
                eprintln!("rejected inbound Reticulum envelope: {reason}");
            }
            Err(e) => {
                eprintln!("Reticulum transport closed: {e}");
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }
}

pub fn select_tunnel(
    store: &StateStore,
    advertisement: &str,
    targets: &[(String, String)],
) -> Result<()> {
    let advertisement_ref = parse_statement_ref(advertisement)?;
    let (requester, _) = self_identity(store)?;
    let accept = store
        .get_tunnel_connection_accept_for(&requester, advertisement_ref.sequence)?
        .context("no accepted connection for this advertisement yet — run request-tunnel and ingest-tunnel-accept first")?;
    let selected: Vec<TargetSelector> = targets
        .iter()
        .map(|(k, v)| parse_target(k, v))
        .collect::<Result<_>>()?;
    store.set_provisioned_tunnel_selected_targets(
        &accept.provider,
        state_store::TunnelDirection::Consuming,
        &selected,
    )?;
    println!(
        "selected {} target(s) to route through {}'s tunnel",
        selected.len(),
        user_id_str(&accept.provider)
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn set_tunnel_trust(
    store: &StateStore,
    target_user: UserId,
    auto_accept_requests: bool,
    auto_consume_advertisements: bool,
    auto_respond_to_service_requests: bool,
    exclude: bool,
    tag_filter: Option<String>,
    min_reciprocity_ratio: Option<f64>,
) -> Result<()> {
    store.upsert_tunnel_trust_rule(&TunnelTrustRule {
        user: target_user,
        auto_accept_requests,
        auto_consume_advertisements,
        auto_respond_to_service_requests,
        excluded: exclude,
        tag_filter,
        min_reciprocity_ratio,
        expires_at: None,
        created_at: now_unix(),
    })?;
    println!("tunnel trust set for {}", user_id_str(&target_user));
    Ok(())
}

// ── Phase E: reconciliation ──────────────────────────────────────────────

/// Below this much given to a peer, `TunnelTrustRule.min_reciprocity_ratio`
/// is never checked — a brand-new relationship shouldn't get flagged the
/// moment it starts, only once real volume is at stake.
const MIN_RECIPROCITY_VOLUME_FLOOR_BYTES: u64 = 100_000_000; // 100MB

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncTunnelsReport {
    pub auto_responses: usize,
    pub auto_accepts: usize,
    pub auto_consumes: usize,
    pub peers_added: usize,
    pub peers_removed: usize,
}

/// Cron-driven reconciliation, intended to run alongside `sf apply` (see
/// `social-firewall/install.sh`): auto-responds to pending service
/// requests, auto-accepts pending connection requests, and auto-requests
/// trusted providers' advertisements — each gated by the matching
/// `TunnelTrustRule` flag (never `excluded`) — then reconciles real
/// WireGuard peer state and, for every active *consuming* tunnel with
/// selected targets, the fwmark/nft/dnsmasq routing that gets its traffic
/// there. Every auto-generated artifact is exported to `out_dir` for a
/// human to physically carry to the other side — see this crate's own
/// module doc on why: there's no live transport in this pass, "auto"
/// only covers the decision and the signed artifact.
#[allow(clippy::too_many_arguments)]
pub fn sync_tunnels(
    store: &StateStore,
    wg_runner: &dyn wg_tunnel::CommandRunner,
    out_dir: &Path,
    wg_config: wg_tunnel::WgTunnelConfig,
    dry_run: bool,
) -> Result<SyncTunnelsReport> {
    let (self_user, _) = self_identity(store)?;
    let mut report = SyncTunnelsReport::default();

    if !dry_run {
        std::fs::create_dir_all(out_dir)
            .with_context(|| format!("creating {}", out_dir.display()))?;
    }

    // Auto-respond to pending service requests from trusted requesters.
    for req in store.list_tunnel_service_requests()? {
        if req.requester == self_user {
            continue; // never auto-respond to our own want-ad
        }
        let Some(trust) = store.get_tunnel_trust_rule(&req.requester)? else {
            continue;
        };
        if trust.excluded || !trust.auto_respond_to_service_requests {
            continue;
        }
        let already_responded = store.list_tunnel_advertisements()?.iter().any(|ad| {
            ad.provider == self_user
                && ad.in_response_to
                    == Some(StatementRef {
                        author: req.requester,
                        sequence: req.sequence,
                    })
        });
        if already_responded {
            continue;
        }
        let recipient_pubkey = match recipient_messaging_pubkey(store, &req.requester) {
            Ok(pk) => pk,
            Err(_) => {
                println!("skipping auto-response to service request #{} from {} — their messaging pubkey isn't known yet", req.sequence, user_id_str(&req.requester));
                continue;
            }
        };
        if dry_run {
            println!(
                "(dry-run) would auto-respond to service request #{} from {}",
                req.sequence,
                user_id_str(&req.requester)
            );
            report.auto_responses += 1;
            continue;
        }
        let (ad, identity_pubkey) = build_and_store_own_advertisement(
            store,
            &req.description,
            None,
            req.desired_route_scope.clone(),
            Vec::new(),
            None,
            None,
            Visibility::Restricted,
            Some(StatementRef {
                author: req.requester,
                sequence: req.sequence,
            }),
        )?;
        let plaintext = serde_json::to_vec(&advertisement_to_json(&ad, &identity_pubkey))?;
        let path = out_dir.join(format!("tunnel-advertisement-{}.json", ad.sequence));
        let payload = maybe_sealed_bytes(&plaintext, Some(&recipient_pubkey))?;
        if needs_file_fallback(
            try_deliver(
                store,
                &req.requester,
                p2p_transport::StatementKind::RestrictedTunnelAdvertisement,
                &payload,
            ),
            &req.requester,
        ) {
            write_maybe_sealed(&plaintext, Some(&recipient_pubkey), &path)?;
            println!(
                "auto-responded to service request #{} from {}: exported to {}",
                req.sequence,
                user_id_str(&req.requester),
                path.display()
            );
        }
        report.auto_responses += 1;
    }

    // Auto-accept pending connection requests against our own
    // advertisements from trusted requesters. `tunnel_connection_requests`
    // holds both directions (requests we sent and requests we received),
    // so this must filter to only ones against *our own* advertisement —
    // otherwise a node that's simultaneously a provider and a consumer
    // could "accept" its own outgoing request.
    let (provider, seed) = self_identity(store)?;
    let balances = store.list_tunnel_balances()?;
    for req in store.list_pending_tunnel_connection_requests()? {
        if req.advertisement.author != self_user {
            continue;
        }
        let Some(trust) = store.get_tunnel_trust_rule(&req.requester)? else {
            continue;
        };
        if trust.excluded || !trust.auto_accept_requests {
            continue;
        }
        // Reciprocity guard: only checked once this router has given the
        // peer a meaningful amount (the volume floor), so a brand-new
        // relationship is never flagged on noise — and it only downgrades
        // this one auto-accept to the same manual-review queue every
        // untrusted request already sits in, never revokes the tunnel
        // this router already granted them.
        if let Some(floor) = trust.min_reciprocity_ratio {
            let balance = balances.iter().find(|b| b.peer == req.requester);
            let given_to = balance.map(|b| b.given_to).unwrap_or(0);
            let taken_from = balance.map(|b| b.taken_from).unwrap_or(0);
            if given_to > MIN_RECIPROCITY_VOLUME_FLOOR_BYTES {
                let ratio = taken_from as f64 / given_to as f64;
                if ratio < floor {
                    let sequence = req.sequence;
                    let requester = user_id_str(&req.requester);
                    println!(
                        "skipping auto-accept of connection request #{sequence} from {requester} — reciprocity ratio {ratio:.3} (given {given_to}B, received back {taken_from}B) is below your configured floor {floor:.3}; falling back to manual review"
                    );
                    continue;
                }
            }
        }
        if dry_run {
            println!(
                "(dry-run) would auto-accept connection request #{} from {}",
                req.sequence,
                user_id_str(&req.requester)
            );
            report.auto_accepts += 1;
            continue;
        }
        let (accept, identity_pubkey) = do_accept_tunnel_request(store, provider, &seed, &req)?;
        let plaintext = serde_json::to_vec(&accept_to_json(&accept, &identity_pubkey))?;
        println!(
            "auto-accepted connection request #{} from {}",
            req.sequence,
            user_id_str(&req.requester)
        );
        if needs_file_fallback(
            try_deliver(
                store,
                &req.requester,
                p2p_transport::StatementKind::TunnelConnectionAccept,
                &plaintext,
            ),
            &req.requester,
        ) {
            let path = out_dir.join(format!(
                "tunnel-accept-{}-{}.json",
                user_id_str(&req.requester).replace('/', "_"),
                req.sequence
            ));
            write_maybe_sealed(&plaintext, Some(&req.requester_messaging_pubkey), &path)?;
            println!("exported to {} for manual delivery", path.display());
        }
        report.auto_accepts += 1;
    }

    // Auto-consume advertisements from trusted providers: automatically
    // request their tunnel, unless we've already requested this exact
    // advertisement before.
    for ad in store.list_tunnel_advertisements()? {
        if ad.provider == self_user {
            continue; // never auto-request our own advertisement
        }
        let Some(trust) = store.get_tunnel_trust_rule(&ad.provider)? else {
            continue;
        };
        if trust.excluded || !trust.auto_consume_advertisements {
            continue;
        }
        // Mirrors `LocalTrustRule.category_filter`: if set, only an
        // advertisement carrying this exact tag is eligible — `None`
        // means every advertisement from this trusted provider counts,
        // unchanged from before this filter existed.
        if let Some(filter) = &trust.tag_filter {
            if !ad.tags.iter().any(|t| t == filter) {
                continue;
            }
        }
        let ad_ref = StatementRef {
            author: ad.provider,
            sequence: ad.sequence,
        };
        if store.has_tunnel_connection_request_for(&self_user, &ad_ref)? {
            continue;
        }
        if dry_run {
            println!(
                "(dry-run) would auto-request tunnel against advertisement {}/{}",
                user_id_str(&ad.provider),
                ad.sequence
            );
            report.auto_consumes += 1;
            continue;
        }
        let (req, identity_pubkey) = build_and_store_connection_request(store, ad_ref)?;
        let plaintext = serde_json::to_vec(&connection_request_to_json(&req, &identity_pubkey))?;
        let path = out_dir.join(format!("tunnel-request-{}.json", req.sequence));
        let payload = maybe_sealed_bytes(&plaintext, Some(&ad.messaging_pubkey))?;
        if needs_file_fallback(
            try_deliver(
                store,
                &ad.provider,
                p2p_transport::StatementKind::TunnelConnectionRequest,
                &payload,
            ),
            &ad.provider,
        ) {
            write_maybe_sealed(&plaintext, Some(&ad.messaging_pubkey), &path)?;
            println!(
                "auto-requested tunnel against {}/{}: exported to {}",
                user_id_str(&ad.provider),
                ad.sequence,
                path.display()
            );
        }
        report.auto_consumes += 1;
    }

    if dry_run {
        println!("(dry-run) skipping WireGuard/routing reconciliation");
        return Ok(report);
    }

    let ctrl = wg_tunnel::WgTunnelController::new(wg_runner, store, wg_config);
    let result = ctrl.reconcile()?;
    report.peers_added = result.peers_added;
    report.peers_removed = result.peers_removed;
    println!(
        "wireguard reconcile: {} peer(s) added, {} peer(s) removed",
        result.peers_added, result.peers_removed
    );

    Ok(report)
}

#[cfg(test)]
mod sync_tunnels_tests {
    use super::*;
    use domain_types::FederationId;

    fn user(byte: u8) -> UserId {
        UserId {
            federation: FederationId(domain_types::Hash32([byte; 32])),
            local_id: domain_types::Hash32([byte.wrapping_add(100); 32]),
        }
    }

    fn store_with_self_identity() -> (StateStore, UserId) {
        let store = StateStore::open_in_memory().unwrap();
        let self_user = user(1);
        let kp = crypto::Keypair::generate();
        store
            .set_self_identity(self_user, kp.public_key(), &kp.seed_bytes(), None)
            .unwrap();
        (store, self_user)
    }

    fn seed_advertisement(
        provider: UserId,
        messaging_pubkey: MessagingPublicKeyBytes,
    ) -> TunnelAdvertisement {
        TunnelAdvertisement {
            provider,
            sequence: 0,
            description: "example ad".into(),
            limitations: None,
            visibility: Visibility::Public,
            in_response_to: None,
            messaging_pubkey,
            wg_pubkey: WgPublicKeyBytes([9; 32]),
            endpoint_hint: String::new(),
            route_scope: vec![TargetSelector::Domain("example.com".into())],
            tags: vec![],
            max_connections: None,
            max_bandwidth_kbps: None,
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: domain_types::SignatureBytes([0; 64]),
        }
    }

    fn seed_service_request(requester: UserId) -> TunnelServiceRequest {
        TunnelServiceRequest {
            requester,
            sequence: 0,
            description: "need an exit node".into(),
            desired_route_scope: vec![TargetSelector::Domain("example.com".into())],
            visibility: Visibility::Public,
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: domain_types::SignatureBytes([0; 64]),
        }
    }

    fn trust_rule(
        user: UserId,
        auto_accept_requests: bool,
        auto_consume_advertisements: bool,
        auto_respond_to_service_requests: bool,
    ) -> TunnelTrustRule {
        TunnelTrustRule {
            user,
            auto_accept_requests,
            auto_consume_advertisements,
            auto_respond_to_service_requests,
            excluded: false,
            tag_filter: None,
            min_reciprocity_ratio: None,
            expires_at: None,
            created_at: 0,
        }
    }

    fn wg_config(dir: &Path) -> wg_tunnel::WgTunnelConfig {
        wg_tunnel::WgTunnelConfig {
            scratch_dir: dir.to_path_buf(),
            dnsmasq_dir: dir.to_path_buf(),
            ..wg_tunnel::WgTunnelConfig::default()
        }
    }

    #[test]
    fn delivery_destinations_prefer_iroh_but_retain_reticulum_fallback() {
        assert_eq!(
            ordered_destinations(Some("node"), Some("address")),
            vec!["iroh:node", "reticulum:address"]
        );
    }

    #[test]
    fn delivery_destinations_use_reticulum_when_iroh_is_unconfigured() {
        assert_eq!(
            ordered_destinations(None, Some("address")),
            vec!["reticulum:address"]
        );
    }

    #[test]
    fn delivery_destinations_are_empty_without_configured_transports() {
        assert!(ordered_destinations(None, None).is_empty());
    }

    #[test]
    fn dispatch_envelope_routes_a_tunnel_connection_request_to_the_same_ingest_path() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pubkey) = build_and_store_own_advertisement(
            &store,
            "self's own ad",
            None,
            vec![TargetSelector::Domain("example.com".into())],
            Vec::new(),
            None,
            None,
            Visibility::Public,
            None,
        )
        .unwrap();
        let bob = user(2);
        let req = TunnelConnectionRequest {
            requester: bob,
            sequence: 0,
            advertisement: StatementRef {
                author: self_user,
                sequence: 0,
            },
            requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
            requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
            requested_at: 0,
            signature: domain_types::SignatureBytes([0; 64]),
        };
        // A real signature is required — dispatch_envelope must reject an
        // unsigned/garbage payload the same way ingest_tunnel_request does.
        let bob_kp = crypto::Keypair::generate();
        let mut signed_req = req.clone();
        signed_req.signature = bob_kp.sign(
            crypto::contexts::TUNNEL_CONNECTION_REQUEST,
            &req.signing_bytes(),
        );
        let json = connection_request_to_json(&signed_req, &bob_kp.public_key());
        let bytes = serde_json::to_vec(&json).unwrap();

        dispatch_envelope(
            &store,
            p2p_transport::StatementKind::TunnelConnectionRequest,
            &bytes,
        )
        .unwrap();

        assert_eq!(
            store
                .list_pending_tunnel_connection_requests()
                .unwrap()
                .len(),
            1,
            "the request must have been stored via the normal ingest path"
        );
    }

    #[test]
    fn dispatch_envelope_rejects_a_tampered_payload_without_panicking() {
        let (store, _self_user) = store_with_self_identity();
        let result = dispatch_envelope(
            &store,
            p2p_transport::StatementKind::TunnelConnectionRequest,
            b"not even json",
        );
        assert!(result.is_err());
    }

    fn follow_with_node_id(
        user: UserId,
        iroh_node_id: Option<String>,
    ) -> domain_types::LocalTrustRule {
        domain_types::LocalTrustRule {
            user,
            allow_weight: 1.0,
            deny_weight: 1.0,
            advisory_only: false,
            excluded: false,
            category_filter: None,
            display_name: None,
            iroh_node_id,
            expires_at: None,
            created_at: 0,
        }
    }

    #[test]
    fn known_follow_for_node_id_matches_only_a_node_id_a_follow_recorded() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bobs_node = "b0b".repeat(16);
        store
            .upsert_follow(&follow_with_node_id(bob, Some(bobs_node.clone())))
            .unwrap();
        // A follow with no node id recorded must never match anything.
        store
            .upsert_follow(&follow_with_node_id(user(3), None))
            .unwrap();

        assert_eq!(known_follow_for_node_id(&store, &bobs_node), Some(bob));
        assert!(
            known_follow_for_node_id(&store, &"dead".repeat(12)).is_none(),
            "a node id no follow claims must not resolve"
        );
        assert!(known_follow_for_node_id(&store, "").is_none());
    }

    /// The gate must stop an envelope that `dispatch_envelope` would
    /// otherwise have happily accepted — so this builds a genuinely
    /// valid, correctly-signed request, shows the gate refuses its
    /// sender, and then shows the very same bytes *do* dispatch once
    /// called directly. That second half is what proves the gate is the
    /// only thing that rejected it, rather than the payload being
    /// invalid for some unrelated reason.
    #[test]
    fn an_envelope_from_an_unrecognized_node_is_not_dispatched() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pubkey) = build_and_store_own_advertisement(
            &store,
            "self's own ad",
            None,
            vec![TargetSelector::Domain("example.com".into())],
            Vec::new(),
            None,
            None,
            Visibility::Public,
            None,
        )
        .unwrap();
        let bob = user(2);
        // Bob is followed, but with a *different* node id than the one
        // the connection arrives from.
        store
            .upsert_follow(&follow_with_node_id(bob, Some("b0b".repeat(16))))
            .unwrap();

        let bob_kp = crypto::Keypair::generate();
        let mut req = TunnelConnectionRequest {
            requester: bob,
            sequence: 0,
            advertisement: StatementRef {
                author: self_user,
                sequence: 0,
            },
            requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
            requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
            requested_at: 0,
            signature: domain_types::SignatureBytes([0; 64]),
        };
        req.signature = bob_kp.sign(
            crypto::contexts::TUNNEL_CONNECTION_REQUEST,
            &req.signing_bytes(),
        );
        let bytes =
            serde_json::to_vec(&connection_request_to_json(&req, &bob_kp.public_key())).unwrap();

        // What `listen` does: refuse before dispatching.
        let attacker_node = "acab".repeat(12);
        assert!(
            known_follow_for_node_id(&store, &attacker_node).is_none(),
            "an unrecognized sender must not resolve to a follow"
        );
        assert_eq!(
            store
                .list_pending_tunnel_connection_requests()
                .unwrap()
                .len(),
            0,
            "nothing may be ingested from an unrecognized sender"
        );

        // The payload itself was always fine — only the sender was not.
        dispatch_envelope(
            &store,
            p2p_transport::StatementKind::TunnelConnectionRequest,
            &bytes,
        )
        .unwrap();
        assert_eq!(
            store
                .list_pending_tunnel_connection_requests()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_recognized_follows_node_id_passes_the_gate_and_dispatches() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pubkey) = build_and_store_own_advertisement(
            &store,
            "self's own ad",
            None,
            vec![TargetSelector::Domain("example.com".into())],
            Vec::new(),
            None,
            None,
            Visibility::Public,
            None,
        )
        .unwrap();
        let bob = user(2);
        let bobs_node = "b0b".repeat(16);
        store
            .upsert_follow(&follow_with_node_id(bob, Some(bobs_node.clone())))
            .unwrap();

        let bob_kp = crypto::Keypair::generate();
        let mut req = TunnelConnectionRequest {
            requester: bob,
            sequence: 0,
            advertisement: StatementRef {
                author: self_user,
                sequence: 0,
            },
            requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
            requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
            requested_at: 0,
            signature: domain_types::SignatureBytes([0; 64]),
        };
        req.signature = bob_kp.sign(
            crypto::contexts::TUNNEL_CONNECTION_REQUEST,
            &req.signing_bytes(),
        );
        let bytes =
            serde_json::to_vec(&connection_request_to_json(&req, &bob_kp.public_key())).unwrap();

        // Exactly `listen`'s sequence: gate, then dispatch.
        let peer = known_follow_for_node_id(&store, &bobs_node)
            .expect("a follow that recorded this node id must be recognized");
        assert_eq!(peer, bob);
        dispatch_envelope(
            &store,
            p2p_transport::StatementKind::TunnelConnectionRequest,
            &bytes,
        )
        .unwrap();

        assert_eq!(
            store
                .list_pending_tunnel_connection_requests()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn auto_responds_to_a_service_request_from_a_trusted_requester() {
        let (store, self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        // Seeds bob's messaging pubkey into the store the only way this
        // trust-on-first-ingest model knows how — via something bob
        // published — since `sync_tunnels` needs it to seal the response.
        store
            .store_own_tunnel_advertisement(&seed_advertisement(bob, bob_messaging_kp.public_key()))
            .unwrap();
        store
            .store_own_tunnel_service_request(&seed_service_request(bob))
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(bob, false, false, true))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("out");

        let report = sync_tunnels(&store, &runner, &out_dir, wg_config(dir.path()), false).unwrap();

        assert_eq!(report.auto_responses, 1);
        let ads = store.list_tunnel_advertisements().unwrap();
        assert!(
            ads.iter().any(|ad| ad.provider == self_user
                && ad.in_response_to
                    == Some(StatementRef {
                        author: bob,
                        sequence: 0
                    })),
            "must have published a response advertisement referencing bob's want-ad"
        );
        assert!(
            std::fs::read_dir(&out_dir).unwrap().count() > 0,
            "the auto-response must be exported for pickup"
        );
    }

    #[test]
    fn does_not_auto_respond_twice_to_the_same_service_request() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement(bob, bob_messaging_kp.public_key()))
            .unwrap();
        store
            .store_own_tunnel_service_request(&seed_service_request(bob))
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(bob, false, false, true))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();
        let second = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            second.auto_responses, 0,
            "a service request already responded to must not be responded to again"
        );
    }

    #[test]
    fn auto_accepts_a_connection_request_against_our_own_advertisement_from_a_trusted_requester() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pubkey) = build_and_store_own_advertisement(
            &store,
            "self's own ad",
            None,
            vec![TargetSelector::Domain("example.com".into())],
            Vec::new(),
            None,
            None,
            Visibility::Public,
            None,
        )
        .unwrap();
        let bob = user(2);
        store
            .store_tunnel_connection_request(&TunnelConnectionRequest {
                requester: bob,
                sequence: 0,
                advertisement: StatementRef {
                    author: self_user,
                    sequence: 0,
                },
                requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
                requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
                requested_at: 0,
                signature: domain_types::SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(bob, true, false, false))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("out");

        let report = sync_tunnels(&store, &runner, &out_dir, wg_config(dir.path()), false).unwrap();

        assert_eq!(report.auto_accepts, 1);
        assert!(
            store
                .get_tunnel_connection_accept_for(&bob, 0)
                .unwrap()
                .is_some(),
            "an accept must have been stored"
        );
        assert!(
            std::fs::read_dir(&out_dir).unwrap().count() > 0,
            "the auto-accept must be exported for pickup"
        );
    }

    #[test]
    fn never_auto_accepts_a_request_this_router_itself_sent() {
        // `tunnel_connection_requests` holds both directions — requests we
        // sent and requests we received — so the auto-accept loop must
        // filter to only ones against *our own* advertisement. This is a
        // regression test for that filter: without it, a trust rule that
        // happens to match ourselves (or, more realistically, a node that
        // is simultaneously a provider and a consumer of a peer's tunnel)
        // could "accept" its own outgoing request.
        let (store, self_user) = store_with_self_identity();
        let bob = user(2);
        store
            .store_tunnel_connection_request(&TunnelConnectionRequest {
                requester: self_user,
                sequence: 0,
                advertisement: StatementRef {
                    author: bob,
                    sequence: 0,
                },
                requester_wg_pubkey: WgPublicKeyBytes([1; 32]),
                requester_messaging_pubkey: MessagingPublicKeyBytes([2; 32]),
                requested_at: 0,
                signature: domain_types::SignatureBytes([0; 64]),
            })
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(self_user, true, false, false))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_accepts, 0,
            "a request this router sent to someone else must never be auto-accepted"
        );
    }

    fn pending_request_against_own_ad(store: &StateStore, requester: UserId, provider: UserId) {
        store
            .store_tunnel_connection_request(&TunnelConnectionRequest {
                requester,
                sequence: 0,
                advertisement: StatementRef {
                    author: provider,
                    sequence: 0,
                },
                requester_wg_pubkey: WgPublicKeyBytes([3; 32]),
                requester_messaging_pubkey: MessagingPublicKeyBytes([4; 32]),
                requested_at: 0,
                signature: domain_types::SignatureBytes([0; 64]),
            })
            .unwrap();
    }

    #[test]
    fn reciprocity_floor_skips_auto_accept_when_a_taker_has_given_nothing_back() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pubkey) = build_and_store_own_advertisement(
            &store,
            "self's own ad",
            None,
            vec![TargetSelector::Domain("example.com".into())],
            Vec::new(),
            None,
            None,
            Visibility::Public,
            None,
        )
        .unwrap();
        let bob = user(2);
        pending_request_against_own_ad(&store, bob, self_user);
        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: bob,
                auto_accept_requests: true,
                auto_consume_advertisements: false,
                auto_respond_to_service_requests: false,
                excluded: false,
                tag_filter: None,
                min_reciprocity_ratio: Some(0.1),
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        // Past the volume floor (100MB), given entirely one-way — bob has
        // never reciprocated at all.
        store
            .record_transfer_sample(
                &bob,
                state_store::TunnelDirection::Providing,
                200_000_000,
                0,
                100,
            )
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_accepts, 0,
            "a peer below the configured reciprocity floor must fall back to manual review"
        );
        assert!(
            store
                .get_tunnel_connection_accept_for(&bob, 0)
                .unwrap()
                .is_none(),
            "no accept should have been stored"
        );
    }

    #[test]
    fn reciprocity_floor_is_not_checked_below_the_minimum_volume() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pubkey) = build_and_store_own_advertisement(
            &store,
            "self's own ad",
            None,
            vec![TargetSelector::Domain("example.com".into())],
            Vec::new(),
            None,
            None,
            Visibility::Public,
            None,
        )
        .unwrap();
        let bob = user(2);
        pending_request_against_own_ad(&store, bob, self_user);
        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: bob,
                auto_accept_requests: true,
                auto_consume_advertisements: false,
                auto_respond_to_service_requests: false,
                excluded: false,
                tag_filter: None,
                min_reciprocity_ratio: Some(0.1),
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        // Well under the 100MB volume floor, despite a terrible ratio — a
        // brand-new relationship must never be flagged on noise.
        store
            .record_transfer_sample(&bob, state_store::TunnelDirection::Providing, 1_000, 0, 100)
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_accepts, 1,
            "below the volume floor, the reciprocity ratio must not gate auto-accept at all"
        );
    }

    #[test]
    fn reciprocity_floor_allows_auto_accept_when_the_ratio_is_met() {
        let (store, self_user) = store_with_self_identity();
        let (_ad, _pubkey) = build_and_store_own_advertisement(
            &store,
            "self's own ad",
            None,
            vec![TargetSelector::Domain("example.com".into())],
            Vec::new(),
            None,
            None,
            Visibility::Public,
            None,
        )
        .unwrap();
        let bob = user(2);
        pending_request_against_own_ad(&store, bob, self_user);
        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: bob,
                auto_accept_requests: true,
                auto_consume_advertisements: false,
                auto_respond_to_service_requests: false,
                excluded: false,
                tag_filter: None,
                min_reciprocity_ratio: Some(0.1),
                expires_at: None,
                created_at: 0,
            })
            .unwrap();
        store
            .record_transfer_sample(
                &bob,
                state_store::TunnelDirection::Providing,
                200_000_000,
                0,
                100,
            )
            .unwrap();
        // Bob has reciprocated well above the 0.1 floor (0.5).
        store
            .record_transfer_sample(
                &bob,
                state_store::TunnelDirection::Consuming,
                100_000_000,
                0,
                100,
            )
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_accepts, 1,
            "a peer meeting the reciprocity floor must still be auto-accepted normally"
        );
    }

    #[test]
    fn auto_consumes_an_advertisement_from_a_trusted_provider() {
        let (store, self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement(bob, bob_messaging_kp.public_key()))
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(bob, false, true, false))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("out");

        let report = sync_tunnels(&store, &runner, &out_dir, wg_config(dir.path()), false).unwrap();

        assert_eq!(report.auto_consumes, 1);
        assert!(store
            .has_tunnel_connection_request_for(
                &self_user,
                &StatementRef {
                    author: bob,
                    sequence: 0
                }
            )
            .unwrap());
        assert!(
            std::fs::read_dir(&out_dir).unwrap().count() > 0,
            "the auto-request must be exported for pickup"
        );
    }

    #[test]
    fn does_not_auto_consume_the_same_advertisement_twice() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement(bob, bob_messaging_kp.public_key()))
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(bob, false, true, false))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();
        let second = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            second.auto_consumes, 0,
            "an advertisement already requested must not be requested again"
        );
    }

    #[test]
    fn excluded_overrides_every_auto_flag() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement(bob, bob_messaging_kp.public_key()))
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&TunnelTrustRule {
                user: bob,
                auto_accept_requests: true,
                auto_consume_advertisements: true,
                auto_respond_to_service_requests: true,
                excluded: true,
                tag_filter: None,
                min_reciprocity_ratio: None,
                expires_at: None,
                created_at: 0,
            })
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_consumes, 0,
            "`excluded` must override every auto-behavior flag on the same rule"
        );
    }

    fn seed_advertisement_with_tags(
        provider: UserId,
        messaging_pubkey: MessagingPublicKeyBytes,
        tags: Vec<String>,
    ) -> TunnelAdvertisement {
        let mut ad = seed_advertisement(provider, messaging_pubkey);
        ad.tags = tags;
        ad
    }

    #[test]
    fn tag_filter_excludes_an_advertisement_without_a_matching_tag() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement_with_tags(
                bob,
                bob_messaging_kp.public_key(),
                vec!["gaming".into()],
            ))
            .unwrap();
        let mut trust = trust_rule(bob, false, true, false);
        trust.tag_filter = Some("streaming".into());
        store.upsert_tunnel_trust_rule(&trust).unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_consumes, 0,
            "the advertisement's tags don't include the filter, so it must not be auto-consumed"
        );
    }

    #[test]
    fn tag_filter_includes_an_advertisement_with_a_matching_tag() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement_with_tags(
                bob,
                bob_messaging_kp.public_key(),
                vec!["streaming".into(), "gaming".into()],
            ))
            .unwrap();
        let mut trust = trust_rule(bob, false, true, false);
        trust.tag_filter = Some("streaming".into());
        store.upsert_tunnel_trust_rule(&trust).unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_consumes, 1,
            "the advertisement's tags include the filter, so it must be auto-consumed"
        );
    }

    #[test]
    fn no_tag_filter_auto_consumes_every_advertisement_unchanged() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement_with_tags(
                bob,
                bob_messaging_kp.public_key(),
                vec!["unrelated".into()],
            ))
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(bob, false, true, false))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let report = sync_tunnels(
            &store,
            &runner,
            &dir.path().join("out"),
            wg_config(dir.path()),
            false,
        )
        .unwrap();

        assert_eq!(
            report.auto_consumes, 1,
            "no tag_filter set means every advertisement from this trusted provider counts"
        );
    }

    #[test]
    fn dry_run_makes_no_persistent_changes() {
        let (store, _self_user) = store_with_self_identity();
        let bob = user(2);
        let bob_messaging_kp = crypto::MessagingKeypair::generate();
        store
            .store_own_tunnel_advertisement(&seed_advertisement(bob, bob_messaging_kp.public_key()))
            .unwrap();
        store
            .store_own_tunnel_service_request(&seed_service_request(bob))
            .unwrap();
        store
            .upsert_tunnel_trust_rule(&trust_rule(bob, false, false, true))
            .unwrap();

        let runner = wg_tunnel::FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let out_dir = dir.path().join("out");

        let report = sync_tunnels(&store, &runner, &out_dir, wg_config(dir.path()), true).unwrap();

        assert_eq!(
            report.auto_responses, 1,
            "dry-run must still report what it would have done"
        );
        assert!(
            !out_dir.exists(),
            "dry-run must not create the export directory or write any files"
        );
        assert_eq!(store.list_tunnel_advertisements().unwrap().len(), 1, "dry-run must not actually store a response advertisement — only bob's seeded one exists");
        assert_eq!(runner.call_count(), 0, "dry-run must never touch wg/ip/nft");
    }
}
