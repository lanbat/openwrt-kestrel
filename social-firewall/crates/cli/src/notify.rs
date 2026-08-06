//! Scans pending decisions and surfaces each new item once on a party line.

use crate::group::{self, post_notification};
use crate::now_unix;
use crate::tunnel::user_id_str;
use anyhow::{Context, Result};
use state_store::StateStore;

fn maybe_push_ntfy(store: &StateStore, body: &str) {
    let Ok(Some(topic_url)) = store.get_ntfy_topic_url() else {
        return;
    };
    if let Err(error) = crate::ntfy::push(&topic_url, body) {
        eprintln!("ntfy push failed (party-line notification was still recorded): {error}");
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NotifyReport {
    pub notifications_posted: usize,
}

pub fn notify_pending_items(store: &StateStore) -> Result<NotifyReport> {
    let (self_user, self_pubkey) = store
        .get_self_identity()?
        .context("no identity yet - run init-identity first")?;
    let self_group = group::self_group_id(&self_pubkey);
    if store.get_group(self_group)?.is_none() {
        group::create_self_group(store, self_user, &self_pubkey)?;
    }
    let mut report = NotifyReport::default();

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
                "{} wants to join \"{}\" - /approve-group-join --group {} --requester {} --sequence {} --voting",
                user_id_str(&req.requester), g.name, group::group_id_str(g.group_id), user_id_str(&req.requester), req.sequence
            );
            post_notification(store, g.group_id, &body)?;
            store.mark_notified("group_join", &key, now_unix())?;
            maybe_push_ntfy(store, &body);
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
            "{} requested your tunnel - /accept-tunnel-request --requester {} --sequence {}",
            user_id_str(&req.requester),
            user_id_str(&req.requester),
            req.sequence
        );
        post_notification(store, self_group, &body)?;
        store.mark_notified("tunnel_request", &key, now_unix())?;
        maybe_push_ntfy(store, &body);
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
            "{} is looking for a tunnel: \"{}\" - respond with `offer-tunnel --in-response-to {}/{}`",
            user_id_str(&req.requester), req.description, user_id_str(&req.requester), req.sequence
        );
        post_notification(store, self_group, &body)?;
        store.mark_notified("tunnel_service_request", &key, now_unix())?;
        maybe_push_ntfy(store, &body);
        report.notifications_posted += 1;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::{
        FederationId, Hash32, MessagingPublicKeyBytes, StatementRef, TunnelConnectionRequest,
        UserId, WgPublicKeyBytes,
    };

    fn user(byte: u8) -> UserId {
        UserId {
            federation: FederationId(Hash32([byte; 32])),
            local_id: Hash32([byte.wrapping_add(100); 32]),
        }
    }

    #[test]
    fn notify_pending_items_posts_a_tunnel_notification_once() {
        let store = StateStore::open_in_memory().unwrap();
        let self_user = user(1);
        let kp = crypto::Keypair::generate();
        store
            .set_self_identity(self_user, kp.public_key(), &kp.seed_bytes(), None)
            .unwrap();
        group::create_self_group(&store, self_user, &kp.public_key()).unwrap();
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

        assert_eq!(
            notify_pending_items(&store).unwrap().notifications_posted,
            1
        );
        assert_eq!(
            notify_pending_items(&store).unwrap().notifications_posted,
            0
        );
        let messages = store
            .list_party_line_messages(group::self_group_id(&kp.public_key()))
            .unwrap();
        assert_eq!(messages.len(), 1);
        assert!(messages[0].body.contains("requested your tunnel"));
    }

    #[test]
    fn notify_pending_items_lazily_creates_self_group() {
        let store = StateStore::open_in_memory().unwrap();
        let self_user = user(1);
        let kp = crypto::Keypair::generate();
        store
            .set_self_identity(self_user, kp.public_key(), &kp.seed_bytes(), None)
            .unwrap();
        assert_eq!(
            notify_pending_items(&store).unwrap().notifications_posted,
            0
        );
        assert!(store
            .get_group(group::self_group_id(&kp.public_key()))
            .unwrap()
            .is_some());
    }

    #[test]
    fn failed_ntfy_push_does_not_block_notification() {
        let store = StateStore::open_in_memory().unwrap();
        let self_user = user(1);
        let kp = crypto::Keypair::generate();
        store
            .set_self_identity(self_user, kp.public_key(), &kp.seed_bytes(), None)
            .unwrap();
        group::create_self_group(&store, self_user, &kp.public_key()).unwrap();
        store
            .set_ntfy_topic_url(Some("http://127.0.0.1:1"))
            .unwrap();
        store
            .store_tunnel_connection_request(&TunnelConnectionRequest {
                requester: user(2),
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

        assert_eq!(
            notify_pending_items(&store).unwrap().notifications_posted,
            1
        );
    }
}
