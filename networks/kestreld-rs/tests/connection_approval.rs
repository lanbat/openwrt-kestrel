//! BDD coverage for `/cgi-bin/device`'s `approve_domain` action, focused on
//! the WAN/VPN split-routing "route" option — connection approvals and
//! plain (WAN) domain rules already had coverage elsewhere; this suite is
//! specifically about the route dimension. Exercises
//! `kestreld::routes::device::post` directly (no HTTP server) against a
//! temp `base_dir`, same pattern as `tests/join_approval.rs`.
//!
//! Note: `approve_domain` also writes a live dnsmasq conf under the real
//! `/etc/dnsmasq.d/` (not `base_dir`-relative) — that write is a no-op
//! here (permission denied, silently ignored same as the `nft`/`curl`
//! calls other tests already document) since this suite doesn't run as
//! root. Assertions are scoped to what's actually base_dir-relative: the
//! device-rules file's route field.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Form;
use cucumber::{given, then, when, World};
use std::path::PathBuf;

use kestreld::routes::device::{self, DeviceForm, DeviceQuery};
use kestreld::state::AppState;

const GUEST_CONF: &str = "\
SUBNET=192.168.3
NOTIFY_URL=
IFACE_NAME=guest
DEFAULT_DURATION=24h
MAX_DURATION=30d
REASON_REQUIRED=no
BANDWIDTH_THRESHOLD_MB=0
RATE_LIMIT=10mbit
RATE_LIMIT_PER_DEVICE=5mbit
DNS_SERVER=1.1.1.1
DNS_SERVER_V6=
ISOLATE=yes
LAN_ACCESS=no
DOT=no
SHOW_QR=yes
NOTIFY_JOIN=yes
JOIN_APPROVAL=no
JOIN_HISTORY_RETENTION=90d
REJOIN_NOTIFY_AFTER=
ROTATE_PASSWORD=yes
DEVICE_CONTROL=yes
DESCRIPTION='Guest WiFi hwsim test'
";

#[derive(Debug, cucumber::World)]
struct ConnectionApprovalWorld {
    // Held for its Drop impl (cleans up the directory); never read directly.
    _dir: tempfile::TempDir,
    base_dir: PathBuf,
    split_routing_dir: PathBuf,
    current_mac: String,
    last_ok: bool,
    last_error: Option<String>,
}

impl Default for ConnectionApprovalWorld {
    fn default() -> Self {
        let dir = tempfile::tempdir().expect("create tempdir for base_dir");
        let base_dir = dir.path().to_path_buf();
        let split_routing_dir = dir.path().join("split-routing");
        Self {
            _dir: dir,
            base_dir,
            split_routing_dir,
            current_mac: String::new(),
            last_ok: false,
            last_error: None,
        }
    }
}

async fn approve_domain(world: &mut ConnectionApprovalWorld, net: &str, domain: &str, route: &str) {
    let state = AppState::new_once(world.base_dir.clone(), world.split_routing_dir.clone()).await;
    let form = DeviceForm {
        net: Some(net.to_string()),
        mac: Some(world.current_mac.clone()),
        action: Some("approve_domain".to_string()),
        label: None,
        limit: None,
        domain: Some(domain.to_string()),
        route: if route.is_empty() {
            None
        } else {
            Some(route.to_string())
        },
        duration: None,
        dst_ip: None,
        dst_port: None,
        dst_proto: None,
        dst: None,
        port: None,
        proto: None,
    };
    let result = device::post(
        State(state),
        HeaderMap::new(),
        Query(DeviceQuery {
            net: None,
            mac: None,
        }),
        Form(form),
    )
    .await
    .0;
    world.last_ok = result.ok;
    world.last_error = result.error;
}

#[given(expr = "the {string} network is installed")]
async fn network_installed(world: &mut ConnectionApprovalWorld, net: String) {
    let conf = match net.as_str() {
        "guest" => GUEST_CONF,
        other => panic!("no fixture notify.conf for network {other:?}"),
    };
    let path = world.base_dir.join(format!("{net}-notify.conf"));
    tokio::fs::write(&path, conf)
        .await
        .expect("write notify.conf");
}

#[given(expr = "a VPN tier {string} is configured with fwmark {string}")]
async fn vpn_tier_configured(world: &mut ConnectionApprovalWorld, name: String, fwmark: String) {
    tokio::fs::create_dir_all(&world.split_routing_dir)
        .await
        .expect("create split-routing dir");
    let conf = format!("VPN_IFACE=mv_{name}\nROUTE_TABLE=100\nFWMARK={fwmark}\n");
    let path = world.split_routing_dir.join(format!("vpn-{name}.conf"));
    tokio::fs::write(&path, conf).await.expect("write vpn conf");
}

#[given(expr = "a device {string}")]
async fn a_device(world: &mut ConnectionApprovalWorld, mac: String) {
    world.current_mac = mac;
}

#[when(expr = "the device approves domain {string} on {string} with no route")]
async fn approve_domain_no_route(world: &mut ConnectionApprovalWorld, domain: String, net: String) {
    approve_domain(world, &net, &domain, "").await;
}

#[when(expr = "the device approves domain {string} on {string} routed via {string}")]
async fn approve_domain_with_route(
    world: &mut ConnectionApprovalWorld,
    domain: String,
    net: String,
    route: String,
) {
    approve_domain(world, &net, &domain, &route).await;
}

#[then("the request succeeds")]
async fn request_succeeds(world: &mut ConnectionApprovalWorld) {
    assert!(
        world.last_ok,
        "expected success, got error: {:?}",
        world.last_error
    );
}

#[then(expr = "the request is rejected with error {string}")]
async fn request_rejected(world: &mut ConnectionApprovalWorld, expected: String) {
    assert!(
        !world.last_ok,
        "expected the request to be rejected but it succeeded"
    );
    assert_eq!(world.last_error.as_deref(), Some(expected.as_str()));
}

#[then(expr = "the {string} rules file has a rule for domain {string} routed via {string}")]
async fn rules_file_has_route(
    world: &mut ConnectionApprovalWorld,
    net: String,
    domain: String,
    route: String,
) {
    let store = kestreld::db::Store::open(&world.base_dir)
        .await
        .expect("open store");
    let rules = store
        .list_device_rules(&net)
        .await
        .expect("read device_rules");
    let expected_route = if route == "WAN" { "" } else { route.as_str() };
    let found = rules
        .iter()
        .find(|r| r.mac == world.current_mac && r.dst == domain);
    assert!(
        found.is_some(),
        "no rule found for domain {domain:?}; rules: {rules:?}"
    );
    assert_eq!(found.unwrap().route, expected_route);
}

#[then(expr = "the {string} rules file has exactly one rule for domain {string}")]
async fn rules_file_has_exactly_one(
    world: &mut ConnectionApprovalWorld,
    net: String,
    domain: String,
) {
    let store = kestreld::db::Store::open(&world.base_dir)
        .await
        .expect("open store");
    let rules = store
        .list_device_rules(&net)
        .await
        .expect("read device_rules");
    let count = rules
        .iter()
        .filter(|r| r.mac == world.current_mac && r.dst == domain)
        .count();
    assert_eq!(
        count, 1,
        "expected exactly one rule for domain {domain:?}, found {count}; rules: {rules:?}"
    );
}

#[tokio::main]
async fn main() {
    ConnectionApprovalWorld::run("tests/features/connection_approval.feature").await;
}
