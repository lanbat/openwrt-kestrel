use anyhow::{bail, Context, Result};
use domain_types::{DirectMessage, PublicKeyBytes, SignatureBytes, UserId, MAX_DIRECT_MESSAGE_LEN};
use state_store::StateStore;
use std::path::Path;

use crate::tunnel::{
    bytes32, bytes64, maybe_sealed_bytes, parse_maybe_sealed_bytes, recipient_messaging_pubkey,
    self_identity, try_deliver, user_id_str, write_maybe_sealed,
};

pub(crate) fn send(
    store: &StateStore,
    recipient: UserId,
    body: &str,
    out_dir: &Path,
) -> Result<()> {
    if body.is_empty() || body.len() > MAX_DIRECT_MESSAGE_LEN {
        bail!("direct message body must be 1-{MAX_DIRECT_MESSAGE_LEN} bytes");
    }
    let (sender, seed) = self_identity(store)?;
    if sender == recipient {
        bail!("cannot send a direct message to the local identity");
    }
    let keypair = crypto::Keypair::from_seed(&seed);
    let message = DirectMessage {
        sender,
        recipient,
        sequence: store.next_direct_message_sequence(&sender)?,
        body: body.into(),
        issued_at: crate::now_unix(),
        signature: SignatureBytes([0; 64]),
    };
    let mut message = message;
    message.signature = keypair.sign(crypto::contexts::DIRECT_MESSAGE, &message.signing_bytes());
    let json = to_json(&message, &keypair.public_key());
    let plaintext = serde_json::to_vec(&json)?;
    let recipient_key = recipient_messaging_pubkey(store, &recipient)?;
    let payload = maybe_sealed_bytes(&plaintext, Some(&recipient_key))?;
    store.store_direct_message(&message)?;
    let path = out_dir.join(format!(
        "direct-{}.json",
        user_id_str(&recipient).replace('/', "_")
    ));
    if let Some(destination) = crate::tunnel::preferred_destination(store, &recipient)? {
        store.enqueue_outbox(
            &destination,
            i64::from(p2p_transport::StatementKind::DirectMessage.wire_tag()),
            &payload,
            crate::now_unix(),
        )?;
    } else if crate::tunnel::needs_file_fallback(
        try_deliver(
            store,
            &recipient,
            p2p_transport::StatementKind::DirectMessage,
            &payload,
        ),
        &recipient,
    ) {
        std::fs::create_dir_all(out_dir)?;
        write_maybe_sealed(&plaintext, Some(&recipient_key), &path)?;
    }
    Ok(())
}

pub fn ingest_bytes(store: &StateStore, payload: &[u8]) -> Result<()> {
    let json = parse_maybe_sealed_bytes(store, payload)?;
    let message = from_json(&json)?;
    message.validate().map_err(anyhow::Error::msg)?;
    let self_user = store.get_self_identity()?.context("no local identity")?.0;
    if message.recipient != self_user {
        bail!("direct message is addressed to another identity");
    }
    if message.sender != self_user && store.get_follow(&message.sender)?.is_none() {
        bail!("direct message sender is not followed");
    }
    let public_key = PublicKeyBytes(bytes32(
        json.get("identity_pubkey")
            .and_then(|value| value.as_str())
            .context("missing identity_pubkey")?,
    )?);
    crypto::verify(
        &public_key,
        crypto::contexts::DIRECT_MESSAGE,
        &message.signing_bytes(),
        &message.signature,
    )
    .map_err(|_| anyhow::anyhow!("direct message signature verification failed"))?;
    store.store_direct_message(&message)?;
    Ok(())
}

fn to_json(message: &DirectMessage, public_key: &PublicKeyBytes) -> serde_json::Value {
    serde_json::json!({
        "sender": user_id_str(&message.sender),
        "recipient": user_id_str(&message.recipient),
        "sequence": message.sequence,
        "body": message.body,
        "issued_at": message.issued_at,
        "identity_pubkey": hex::encode(public_key.0),
        "signature": hex::encode(message.signature.0),
    })
}

fn from_json(json: &serde_json::Value) -> Result<DirectMessage> {
    let text = |key: &str| {
        json.get(key)
            .and_then(|value| value.as_str())
            .with_context(|| format!("missing {key}"))
    };
    Ok(DirectMessage {
        sender: crate::tunnel::parse_user_ref(text("sender")?)?,
        recipient: crate::tunnel::parse_user_ref(text("recipient")?)?,
        sequence: json
            .get("sequence")
            .and_then(|value| value.as_u64())
            .context("missing sequence")?,
        body: text("body")?.into(),
        issued_at: json
            .get("issued_at")
            .and_then(|value| value.as_i64())
            .context("missing issued_at")?,
        signature: SignatureBytes(bytes64(text("signature")?)?),
    })
}
