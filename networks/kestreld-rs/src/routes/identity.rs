use askama::Template;
use axum::{
    extract::{Query, State},
    response::Html,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::routes::device::rel_time;
use crate::state::AppState;

// ── Template types ────────────────────────────────────────────────────────────

#[derive(Template)]
#[template(path = "identity.html")]
struct IdentityTmpl {
    net: String,
    id: String,
    label: String,
    first_seen: String,
    last_seen: String,
    dhcp_options: String,
    dhcp_vendor: String,
    wifi_caps: String,
    mdns_name: String,
    mdns_model: String,
    macs: Vec<String>,
    label_history: Vec<LabelHistoryRow>,
    similar: Vec<SimilarRow>,
}

struct LabelHistoryRow {
    label: String,
    until: String,
}

struct SimilarRow {
    id: String,
    label: String,
    score: u8,
}

// ── Route types ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct IdentityQuery {
    pub net: Option<String>,
    pub id: Option<String>,
}

fn valid_net(net: &str) -> bool {
    !net.is_empty() && net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

fn dash_if_empty(s: String) -> String {
    if s.is_empty() {
        "\u{2014}".into()
    } else {
        s
    }
}

// ── GET handler ───────────────────────────────────────────────────────────────

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<IdentityQuery>,
) -> Html<String> {
    let net = params.net.as_deref().unwrap_or("");
    let id = params.id.as_deref().unwrap_or("");

    if !valid_net(net) {
        return Html("<h1>Invalid network</h1>".into());
    }
    if !valid_id(id) {
        return Html("<h1>Invalid identity id</h1>".into());
    }

    let snap = state.snap().await;
    if !snap.net_confs.iter().any(|c| c.iface == net) {
        return Html(format!("<h1>Network not found: {net}</h1>"));
    }
    drop(snap);

    let records = crate::data::fingerprint::read_registry(&state.store, net).await;

    let record = match records.iter().find(|r| r.id == id) {
        Some(r) => r.clone(),
        None => return Html(format!("<h1>Identity not found: {id}</h1>")),
    };

    let similar = crate::data::fingerprint::similar_identities(&record, &records)
        .into_iter()
        .map(|(r, score)| SimilarRow {
            id: r.id,
            label: r.label,
            score,
        })
        .collect();

    let label_history = record
        .label_history
        .iter()
        .map(|(label, ts)| LabelHistoryRow {
            label: label.clone(),
            until: rel_time(*ts),
        })
        .collect();

    let tmpl = IdentityTmpl {
        net: net.to_string(),
        id: record.id,
        label: record.label,
        first_seen: rel_time(record.first_seen),
        last_seen: rel_time(record.last_seen),
        dhcp_options: dash_if_empty(record.dhcp_options),
        dhcp_vendor: dash_if_empty(record.dhcp_vendor),
        wifi_caps: dash_if_empty(record.wifi_caps),
        mdns_name: dash_if_empty(record.mdns_name),
        mdns_model: dash_if_empty(record.mdns_model),
        macs: record.macs,
        label_history,
        similar,
    };

    Html(
        tmpl.render()
            .unwrap_or_else(|e| format!("Template error: {e}")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_net_accepts_alphanumeric_underscore() {
        assert!(valid_net("guest_2"));
    }

    #[test]
    fn valid_net_rejects_empty() {
        assert!(!valid_net(""));
    }

    #[test]
    fn valid_net_rejects_special_chars() {
        assert!(!valid_net("guest;rm -rf"));
    }

    #[test]
    fn valid_id_accepts_hex() {
        assert!(valid_id("deadbeef"));
    }

    #[test]
    fn valid_id_rejects_empty() {
        assert!(!valid_id(""));
    }

    #[test]
    fn valid_id_rejects_non_hex() {
        assert!(!valid_id("not-hex!"));
    }

    #[test]
    fn valid_id_rejects_overlong() {
        assert!(!valid_id(&"a".repeat(33)));
    }

    #[test]
    fn dash_if_empty_substitutes_for_empty_string() {
        assert_eq!(dash_if_empty(String::new()), "\u{2014}");
    }

    #[test]
    fn dash_if_empty_passes_through_nonempty() {
        assert_eq!(dash_if_empty("Pixel 8".to_string()), "Pixel 8");
    }
}
