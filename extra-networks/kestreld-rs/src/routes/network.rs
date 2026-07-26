use axum::{extract::{Query, State}, response::Html};
use serde::Deserialize;
use std::sync::Arc;
use askama::Template;

use crate::state::{AppState, Snapshot};
use crate::routes::status::NetworkTmpl;

#[derive(Template)]
#[template(path = "network.html")]
struct NetworkPageTmpl {
    net: NetworkTmpl,
    show_ip6_col: bool,
    show_join_col: bool,
}

#[derive(Deserialize)]
pub struct NetworkQuery {
    pub net: Option<String>,
}

pub async fn render(snap: &Snapshot, iface: &str) -> Option<String> {
    let conf = snap.net_confs.iter().find(|c| c.iface == iface)?;
    let show_ip6_col = snap.ipv6_prefixes.get(iface).map(|v| !v.is_empty()).unwrap_or(false);
    let show_join_col = conf.join_approval;
    let net = crate::routes::status::build_one_network(snap, conf, show_ip6_col, show_join_col).await;
    let tmpl = NetworkPageTmpl { net, show_ip6_col, show_join_col };
    Some(tmpl.render().unwrap_or_else(|e| format!("Template error: {e}")))
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<NetworkQuery>,
) -> Html<String> {
    let iface = params.net.as_deref().unwrap_or("");
    if iface.is_empty() || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Html("<h1>Invalid network</h1>".to_string());
    }
    let snap = state.snap().await;
    match render(&snap, iface).await {
        Some(html) => Html(html),
        None => Html(format!("<h1>Network not found: {iface}</h1>")),
    }
}
