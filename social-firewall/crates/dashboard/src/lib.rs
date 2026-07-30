//! A minimal, read-only web dashboard for a social-firewall router:
//! tunnels (advertised + actually provisioned), subscribed shared rule
//! lists, groups, and device-approval opinions. Deliberately read-only —
//! no mutation endpoint exists here at all, so there's no CSRF/auth
//! surface to design: whoever can reach this page can already reach the
//! `sf` CLI on the same router, which is the actual privilege boundary.
//!
//! Kept intentionally small: one hand-built HTML page, no client-side
//! JS, no template engine, no async runtime. `render_index` is a pure
//! function (`&StateStore -> String`) so it's fully unit-testable
//! without ever binding a socket; `serve` is a thin, synchronous loop
//! around it.

use domain_types::{DeviceApprovalOpinion, Group, SharedRuleList, TargetSelector, UserId, Visibility};
use state_store::{StateStore, StoreError, TunnelDirection};
use std::fmt::Write as _;

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn user_ref(u: &UserId) -> String {
    format!("{}/{}", u.federation.0, u.local_id)
}

fn target_str(t: &TargetSelector) -> String {
    match t {
        TargetSelector::Domain(s) => format!("domain:{s}"),
        TargetSelector::DomainSuffix(s) => format!("domain_suffix:{s}"),
        TargetSelector::Ip(s) => format!("ip:{s}"),
        TargetSelector::Cidr(s) => format!("cidr:{s}"),
        TargetSelector::Service(s) => format!("service:{s}"),
        TargetSelector::ProtoPort { inner, proto, port } => format!("{}/{proto}:{port}", target_str(inner)),
    }
}

fn visibility_str(v: Visibility) -> &'static str {
    match v {
        Visibility::Public => "public",
        Visibility::Restricted => "restricted",
    }
}

fn render_tunnels_section(store: &StateStore) -> Result<String, StoreError> {
    let ads = store.list_tunnel_advertisements()?;
    let provisioned = store.list_provisioned_tunnels()?;
    let mut html = String::new();
    html.push_str("<h2>Tunnels</h2>");

    html.push_str("<h3>Advertisements</h3>");
    if ads.is_empty() {
        html.push_str("<p class=\"empty\">no known tunnel advertisements</p>");
    } else {
        html.push_str("<table><tr><th>Provider</th><th>#</th><th>Description</th><th>Visibility</th><th>Routes</th><th>Tags</th></tr>");
        for ad in &ads {
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&user_ref(&ad.provider)),
                ad.sequence,
                escape_html(&ad.description),
                visibility_str(ad.visibility),
                escape_html(&ad.route_scope.iter().map(target_str).collect::<Vec<_>>().join(", ")),
                escape_html(&ad.tags.join(", ")),
            );
        }
        html.push_str("</table>");
    }

    html.push_str("<h3>Provisioned</h3>");
    if provisioned.is_empty() {
        html.push_str("<p class=\"empty\">no locally-provisioned tunnels</p>");
    } else {
        html.push_str("<table><tr><th>Peer</th><th>Direction</th><th>Interface</th><th>Tunnel IP</th><th>Status</th></tr>");
        for t in &provisioned {
            let direction = match t.direction {
                TunnelDirection::Providing => "providing",
                TunnelDirection::Consuming => "consuming",
            };
            let _ = write!(
                html,
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&user_ref(&t.peer)),
                direction,
                escape_html(&t.interface_name),
                escape_html(&t.tunnel_ip),
                escape_html(&t.status),
            );
        }
        html.push_str("</table>");
    }
    Ok(html)
}

fn render_lists_section(store: &StateStore) -> Result<String, StoreError> {
    let lists = store.list_shared_rule_lists()?;
    let mut html = String::new();
    html.push_str("<h2>Shared Rule Lists</h2>");
    if lists.is_empty() {
        html.push_str("<p class=\"empty\">no known shared rule lists</p>");
        return Ok(html);
    }
    html.push_str("<table><tr><th>Author</th><th>Name</th><th>Categories</th><th>Entries</th><th>Visibility</th></tr>");
    for l in &lists {
        render_list_row(&mut html, l);
    }
    html.push_str("</table>");
    Ok(html)
}

fn render_list_row(html: &mut String, l: &SharedRuleList) {
    let _ = write!(
        html,
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        escape_html(&user_ref(&l.author)),
        escape_html(&l.name),
        escape_html(&l.categories.join(", ")),
        l.entries.len(),
        visibility_str(l.visibility),
    );
}

fn render_groups_section(store: &StateStore) -> Result<String, StoreError> {
    let groups = store.list_groups()?;
    let mut html = String::new();
    html.push_str("<h2>Groups</h2>");
    if groups.is_empty() {
        html.push_str("<p class=\"empty\">no known groups</p>");
        return Ok(html);
    }
    html.push_str("<table><tr><th>Name</th><th>Owners</th><th>Admins</th><th>Voting</th><th>Other members</th></tr>");
    for g in &groups {
        render_group_row(&mut html, g);
    }
    html.push_str("</table>");
    Ok(html)
}

fn render_group_row(html: &mut String, g: &Group) {
    let _ = write!(
        html,
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
        escape_html(&g.name),
        escape_html(&g.owners.iter().map(user_ref).collect::<Vec<_>>().join(", ")),
        escape_html(&g.admins.iter().map(user_ref).collect::<Vec<_>>().join(", ")),
        escape_html(&g.voting_members.iter().map(user_ref).collect::<Vec<_>>().join(", ")),
        escape_html(&g.non_voting_members.iter().map(user_ref).collect::<Vec<_>>().join(", ")),
    );
}

fn render_device_approvals_section(store: &StateStore) -> Result<String, StoreError> {
    let opinions = store.list_all_device_approval_opinions()?;
    let mut html = String::new();
    html.push_str("<h2>Device-Approval Opinions</h2>");
    html.push_str("<p class=\"note\">Advisory only — never written to any kestreld join-approval table.</p>");
    if opinions.is_empty() {
        html.push_str("<p class=\"empty\">no known device-approval opinions</p>");
        return Ok(html);
    }
    html.push_str("<table><tr><th>MAC</th><th>Author</th><th>Stance</th><th>Label</th></tr>");
    for o in &opinions {
        render_device_approval_row(&mut html, o);
    }
    html.push_str("</table>");
    Ok(html)
}

fn render_device_approval_row(html: &mut String, o: &DeviceApprovalOpinion) {
    let _ = write!(
        html,
        "<tr><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td></tr>",
        escape_html(&o.mac),
        escape_html(&user_ref(&o.author)),
        o.stance,
        escape_html(o.device_label.as_deref().unwrap_or("")),
    );
}

const STYLE: &str = "body{font-family:sans-serif;margin:2em;color:#222}h1{margin-bottom:0}table{border-collapse:collapse;margin:0.5em 0 1.5em}th,td{border:1px solid #ccc;padding:0.3em 0.6em;text-align:left}th{background:#eee}.empty{color:#777;font-style:italic}.note{color:#555;font-size:0.9em}";

/// Renders the full dashboard page — a pure function over the store's
/// current contents, safe to call from a test with no server involved.
pub fn render_index(store: &StateStore) -> Result<String, StoreError> {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\"><title>social-firewall dashboard</title>");
    let _ = write!(html, "<style>{STYLE}</style>");
    html.push_str("</head><body>");
    html.push_str("<h1>social-firewall</h1><p class=\"note\">read-only local dashboard</p>");
    html.push_str(&render_tunnels_section(store)?);
    html.push_str(&render_lists_section(store)?);
    html.push_str(&render_groups_section(store)?);
    html.push_str(&render_device_approvals_section(store)?);
    html.push_str("</body></html>");
    Ok(html)
}

/// Runs the dashboard's HTTP server, blocking forever. One request at a
/// time is enough for a router-local admin page — no thread pool, no
/// async runtime.
pub fn serve(store: StateStore, addr: &str) -> std::io::Result<()> {
    let server = tiny_http::Server::http(addr).map_err(std::io::Error::other)?;
    println!("dashboard listening on http://{addr}/");
    for request in server.incoming_requests() {
        let response = match render_index(&store) {
            Ok(html) => {
                let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).expect("valid header");
                tiny_http::Response::from_string(html).with_header(header)
            }
            Err(e) => tiny_http::Response::from_string(format!("internal error: {e}")).with_status_code(500),
        };
        let _ = request.respond(response);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::{FederationId, Hash32, LocalOverride, OverrideKind, Reason, ReasonCode, SignatureBytes, Stance};

    fn user(fed_n: u8, local_n: u8) -> UserId {
        UserId { federation: FederationId(Hash32([fed_n; 32])), local_id: Hash32([local_n; 32]) }
    }

    #[test]
    fn escape_html_neutralizes_script_tags() {
        let escaped = escape_html("<script>alert(1)</script>");
        assert!(!escaped.contains("<script>"));
        assert!(escaped.contains("&lt;script&gt;"));
    }

    #[test]
    fn render_index_on_an_empty_store_shows_every_section_as_empty() {
        let store = StateStore::open_in_memory().unwrap();
        let html = render_index(&store).unwrap();
        assert!(html.contains("no known tunnel advertisements"));
        assert!(html.contains("no locally-provisioned tunnels"));
        assert!(html.contains("no known shared rule lists"));
        assert!(html.contains("no known groups"));
        assert!(html.contains("no known device-approval opinions"));
    }

    #[test]
    fn render_index_lists_a_stored_group() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let group = Group {
            group_id: domain_types::GroupId(Hash32([2; 32])),
            published_by: owner,
            sequence: 0,
            name: "neighborhood watch".into(),
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
            signature: SignatureBytes([0; 64]),
        };
        store.ingest_group(&group).unwrap();

        let html = render_index(&store).unwrap();
        assert!(html.contains("neighborhood watch"));
    }

    #[test]
    fn render_index_escapes_a_maliciously_named_group() {
        let store = StateStore::open_in_memory().unwrap();
        let owner = user(1, 1);
        let group = Group {
            group_id: domain_types::GroupId(Hash32([2; 32])),
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
            signature: SignatureBytes([0; 64]),
        };
        store.ingest_group(&group).unwrap();

        let html = render_index(&store).unwrap();
        assert!(!html.contains("<script>alert(1)</script>"), "a peer-controlled group name must never be emitted unescaped");
        assert!(html.contains("&lt;script&gt;"));
    }

    #[test]
    fn render_index_lists_a_device_approval_opinion() {
        let store = StateStore::open_in_memory().unwrap();
        let author = user(1, 1);
        store.store_own_device_approval_opinion(&DeviceApprovalOpinion {
            author,
            sequence: 0,
            mac: "aa:bb:cc:dd:ee:ff".into(),
            stance: Stance::Deny,
            reason: Reason { code: ReasonCode::Malware, note: None, evidence: vec![] },
            device_label: Some("shady-cam".into()),
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }).unwrap();

        let html = render_index(&store).unwrap();
        assert!(html.contains("aa:bb:cc:dd:ee:ff"));
        assert!(html.contains("shady-cam"));
        assert!(html.contains("Advisory only"));
    }

    #[test]
    fn render_index_ignores_local_overrides_entirely() {
        // Local overrides are explicitly private/never-synced data — the
        // dashboard's job here is to show *shared* state, so this is a
        // smoke check that adding one doesn't crash rendering, not that
        // it appears anywhere.
        let store = StateStore::open_in_memory().unwrap();
        store
            .set_local_override(&LocalOverride {
                target: TargetSelector::Domain("example.com".into()),
                stance: Stance::Deny,
                kind: OverrideKind::Normal,
                note: None,
                created_at: 0,
                expires_at: None,
            })
            .unwrap();
        assert!(render_index(&store).is_ok());
    }
}
