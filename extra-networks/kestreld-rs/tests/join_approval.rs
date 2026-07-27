//! BDD coverage for the /cgi-bin/approve-join handler (the join approval
//! process for JOIN_APPROVAL=yes networks), run against real `guest` and
//! `untrusted` fixture configs. Exercises `kestreld::routes::approve_join`
//! directly (no HTTP server) against a temp `base_dir`, so the only real
//! dependency is the filesystem — `nft`/`curl`/`uci` calls the handler makes
//! along the way fail silently (their errors are already discarded in
//! production code) when those binaries aren't present.

use axum::extract::State;
use axum::http::{header::ORIGIN, HeaderMap, HeaderValue};
use axum::Form;
use cucumber::{given, then, when, World};
use std::path::PathBuf;

use kestreld::data::files;
use kestreld::routes::approve_join::{self, JoinForm};
use kestreld::state::AppState;

// Captured verbatim from a real `install.sh` run against
// test/qemu/configs/guest.conf and untrusted.conf.
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
JOIN_APPROVAL=yes
JOIN_HISTORY_RETENTION=90d
REJOIN_NOTIFY_AFTER=
ROTATE_PASSWORD=yes
DEVICE_CONTROL=no
DESCRIPTION='Guest WiFi hwsim test'
";

const UNTRUSTED_CONF: &str = "\
SUBNET=192.168.4
NOTIFY_URL=
IFACE_NAME=untrusted
DEFAULT_DURATION=24h
MAX_DURATION=30d
REASON_REQUIRED=no
BANDWIDTH_THRESHOLD_MB=0
RATE_LIMIT=500kbit
RATE_LIMIT_PER_DEVICE=0
DNS_SERVER=1.1.1.1
DNS_SERVER_V6=
ISOLATE=yes
LAN_ACCESS=yes
DOT=no
SHOW_QR=no
NOTIFY_JOIN=no
JOIN_APPROVAL=yes
JOIN_HISTORY_RETENTION=90d
REJOIN_NOTIFY_AFTER=
ROTATE_PASSWORD=no
DEVICE_CONTROL=yes
DESCRIPTION='IoT / untrusted hwsim test'
";

#[derive(Debug, cucumber::World)]
struct JoinApprovalWorld {
    // Held for its Drop impl (cleans up the directory); never read directly.
    _dir: tempfile::TempDir,
    base_dir: PathBuf,
    current_mac: String,
    current_ip: String,
    last_ok: bool,
    last_error: Option<String>,
}

impl Default for JoinApprovalWorld {
    fn default() -> Self {
        let dir = tempfile::tempdir().expect("create tempdir for base_dir");
        let base_dir = dir.path().to_path_buf();
        Self {
            _dir: dir,
            base_dir,
            current_mac: String::new(),
            current_ip: String::new(),
            last_ok: false,
            last_error: None,
        }
    }
}

async fn submit(world: &mut JoinApprovalWorld, net: &str, action: &str, label: &str, origin: &str) {
    let state = AppState::new_once(world.base_dir.clone()).await;
    let mut headers = HeaderMap::new();
    if !origin.is_empty() {
        headers.insert(ORIGIN, HeaderValue::from_str(origin).expect("valid origin header"));
    }
    let form = JoinForm {
        net: Some(net.to_string()),
        ip: Some(world.current_ip.clone()),
        mac: Some(world.current_mac.clone()),
        host: Some(String::new()),
        action: Some(action.to_string()),
        label: if label.is_empty() { None } else { Some(label.to_string()) },
        redirect: None,
        dhcp_options: None,
        dhcp_vendor: None,
        wifi_caps: None,
        identity_id: None,
        mdns_name: None,
        mdns_model: None,
    };
    let result = approve_join::post(State(state), headers, Form(form)).await.0;
    world.last_ok = result.ok;
    world.last_error = result.error;
}

async fn submit_with_mdns(world: &mut JoinApprovalWorld, net: &str, label: &str, mdns_name: &str, mdns_model: &str) {
    let state = AppState::new_once(world.base_dir.clone()).await;
    let form = JoinForm {
        net: Some(net.to_string()),
        ip: Some(world.current_ip.clone()),
        mac: Some(world.current_mac.clone()),
        host: Some(String::new()),
        action: Some("approve".to_string()),
        label: Some(label.to_string()),
        redirect: None,
        dhcp_options: None,
        dhcp_vendor: None,
        wifi_caps: None,
        identity_id: None,
        mdns_name: Some(mdns_name.to_string()),
        mdns_model: Some(mdns_model.to_string()),
    };
    let result = approve_join::post(State(state), HeaderMap::new(), Form(form)).await.0;
    world.last_ok = result.ok;
    world.last_error = result.error;
}

async fn submit_set_label(world: &mut JoinApprovalWorld, net: &str, new_label: &str) {
    let state = AppState::new_once(world.base_dir.clone()).await;
    let form = JoinForm {
        net: Some(net.to_string()),
        ip: None,
        mac: Some(world.current_mac.clone()),
        host: None,
        action: Some("set_label".to_string()),
        label: Some(new_label.to_string()),
        redirect: None,
        dhcp_options: None,
        dhcp_vendor: None,
        wifi_caps: None,
        identity_id: None,
        mdns_name: None,
        mdns_model: None,
    };
    let result = approve_join::post(State(state), HeaderMap::new(), Form(form)).await.0;
    world.last_ok = result.ok;
    world.last_error = result.error;
}

#[when(expr = "the device's label on {string} is changed to {string}")]
async fn change_label(world: &mut JoinApprovalWorld, net: String, new_label: String) {
    submit_set_label(world, &net, &new_label).await;
}

#[given(expr = "the {string} network is installed with join approval enabled")]
async fn network_installed(world: &mut JoinApprovalWorld, net: String) {
    let conf = match net.as_str() {
        "guest" => GUEST_CONF,
        "untrusted" => UNTRUSTED_CONF,
        other => panic!("no fixture notify.conf for network {other:?}"),
    };
    let path = world.base_dir.join(format!("{net}-notify.conf"));
    tokio::fs::write(&path, conf).await.expect("write notify.conf");
}

#[given(expr = "a device {string} at {string} is pending join on {string}")]
async fn device_pending(world: &mut JoinApprovalWorld, mac: String, ip: String, net: String) {
    let path = world.base_dir.join(format!("{net}-join-pending"));
    files::file_append(&path, &format!("{mac} {ip}")).await.expect("seed pending entry");
    world.current_mac = mac;
    world.current_ip = ip;
}

#[given(expr = "{string} was already labeled {string} on {string}")]
async fn device_prelabeled(world: &mut JoinApprovalWorld, mac: String, label: String, net: String) {
    let path = world.base_dir.join(format!("{net}-device-labels"));
    files::file_upsert_by_mac(&path, &mac, &format!("{mac}\t{label}"))
        .await
        .expect("seed existing label");
}

#[when(expr = "the device is approved on {string} with label {string}")]
async fn approve(world: &mut JoinApprovalWorld, net: String, label: String) {
    submit(world, &net, "approve", &label, "").await;
}

#[when(expr = "the device is approved on {string} with label {string} from origin {string}")]
async fn approve_from_origin(world: &mut JoinApprovalWorld, net: String, label: String, origin: String) {
    submit(world, &net, "approve", &label, &origin).await;
}

#[when(expr = "the device is denied on {string}")]
async fn deny(world: &mut JoinApprovalWorld, net: String) {
    submit(world, &net, "deny", "", "").await;
}

#[given(expr = "the device is approved on {string} with label {string} and mDNS name {string} model {string}")]
#[when(expr = "the device is approved on {string} with label {string} and mDNS name {string} model {string}")]
async fn approve_with_mdns(world: &mut JoinApprovalWorld, net: String, label: String, mdns_name: String, mdns_model: String) {
    submit_with_mdns(world, &net, &label, &mdns_name, &mdns_model).await;
}

#[when(regex = r"^the (\w+) network's labeled pending devices are bulk-approved$")]
async fn bulk_approve(world: &mut JoinApprovalWorld, net: String) {
    let state = AppState::new_once(world.base_dir.clone()).await;
    let form = JoinForm {
        net: Some(net),
        ip: None,
        mac: None,
        host: None,
        action: Some("bulk_approve_labeled".into()),
        label: None,
        redirect: None,
        dhcp_options: None,
        dhcp_vendor: None,
        wifi_caps: None,
        identity_id: None,
        mdns_name: None,
        mdns_model: None,
    };
    let result = approve_join::post(State(state), HeaderMap::new(), Form(form)).await.0;
    world.last_ok = result.ok;
    world.last_error = result.error;
}

#[then("the request succeeds")]
async fn request_succeeds(world: &mut JoinApprovalWorld) {
    assert!(world.last_ok, "expected success, got error: {:?}", world.last_error);
}

#[then(expr = "the request is rejected with error {string}")]
async fn request_rejected(world: &mut JoinApprovalWorld, expected: String) {
    assert!(!world.last_ok, "expected the request to be rejected but it succeeded");
    assert_eq!(world.last_error.as_deref(), Some(expected.as_str()));
}

#[then(expr = "{string} is approved on {string}")]
async fn mac_is_approved(world: &mut JoinApprovalWorld, mac: String, net: String) {
    let path = world.base_dir.join(format!("{net}-join-approved"));
    let lines = files::read_lines(&path).await;
    assert!(
        lines.iter().any(|l| l.eq_ignore_ascii_case(&mac)),
        "{mac} not found in {path:?}: {lines:?}"
    );
}

#[then(expr = "{string} is denied on {string}")]
async fn mac_is_denied(world: &mut JoinApprovalWorld, mac: String, net: String) {
    let path = world.base_dir.join(format!("{net}-join-denied"));
    let lines = files::read_lines(&path).await;
    assert!(
        lines.iter().any(|l| l.eq_ignore_ascii_case(&mac)),
        "{mac} not found in {path:?}: {lines:?}"
    );
}

#[then(expr = "{string} is no longer pending on {string}")]
async fn mac_not_pending(world: &mut JoinApprovalWorld, mac: String, net: String) {
    let path = world.base_dir.join(format!("{net}-join-pending"));
    let pending = files::read_pending(&path).await;
    assert!(!pending.contains_key(&mac.to_lowercase()), "{mac} is still pending in {path:?}");
}

#[then(expr = "{string} is still pending on {string}")]
async fn mac_still_pending(world: &mut JoinApprovalWorld, mac: String, net: String) {
    let path = world.base_dir.join(format!("{net}-join-pending"));
    let pending = files::read_pending(&path).await;
    assert!(pending.contains_key(&mac.to_lowercase()), "{mac} missing from {path:?}");
}

#[then(expr = "{string} is labeled {string} on {string}")]
async fn mac_labeled(world: &mut JoinApprovalWorld, mac: String, label: String, net: String) {
    let path = world.base_dir.join(format!("{net}-device-labels"));
    let labels = files::read_labels(&path).await;
    assert_eq!(labels.get(&mac.to_lowercase()).map(String::as_str), Some(label.as_str()));
}

// `kestreld::cmd::append_join_history` writes the same 11-field row layout
// as the shell tooling (`_lib.sh:_join_history_add`): ts, human-readable
// "when", action, mac, ip4, ip6, hostname, actor, actor_ip4, actor_ip6,
// actor_mac. `action` is column 2 and `mac` is column 3.
#[then(expr = "a join history entry {string} exists for {string} on {string}")]
async fn history_entry_exists(world: &mut JoinApprovalWorld, action: String, mac: String, net: String) {
    let path = world.base_dir.join(format!("{net}-join-history"));
    let rows = files::read_join_history(&path).await;
    assert!(
        rows.iter().any(|r| r.get(2).map(String::as_str) == Some(action.as_str())
            && r.get(3).map(|m| m.eq_ignore_ascii_case(&mac)).unwrap_or(false)),
        "no {action:?} history row for {mac} in {rows:?}"
    );
}

#[then(expr = "{string} has its IP tracked for device control on {string}")]
async fn ip_tracked(world: &mut JoinApprovalWorld, mac: String, net: String) {
    let path = world.base_dir.join(format!("{net}-device-ips"));
    let map = files::read_mac_ip_map(&path).await;
    assert!(map.contains_key(&mac.to_lowercase()), "{mac} not tracked in {path:?}");
}

#[then(expr = "{string} has no IP tracked for device control on {string}")]
async fn ip_not_tracked(world: &mut JoinApprovalWorld, mac: String, net: String) {
    let path = world.base_dir.join(format!("{net}-device-ips"));
    let map = files::read_mac_ip_map(&path).await;
    assert!(!map.contains_key(&mac.to_lowercase()), "{mac} unexpectedly tracked in {path:?}");
}

#[then(expr = "the {string} fingerprint registry has an entry for {string} with mDNS name {string}")]
async fn fingerprint_entry_has_mdns_name(world: &mut JoinApprovalWorld, net: String, label: String, mdns_name: String) {
    let path = world.base_dir.join(format!("{net}-device-fingerprints"));
    let records = kestreld::data::fingerprint::read_registry(&path).await;
    let record = records.iter().find(|r| r.label == label)
        .unwrap_or_else(|| panic!("no fingerprint entry for {label:?} in {records:?}"));
    assert_eq!(record.mdns_name, mdns_name);
    assert!(record.macs.contains(&world.current_mac));
}

#[then(expr = "the {string} fingerprint registry has no entry for {string}")]
async fn fingerprint_entry_absent(world: &mut JoinApprovalWorld, net: String, label: String) {
    let path = world.base_dir.join(format!("{net}-device-fingerprints"));
    let records = kestreld::data::fingerprint::read_registry(&path).await;
    assert!(!records.iter().any(|r| r.label == label), "unexpected fingerprint entry for {label:?} in {records:?}");
}

#[tokio::main]
async fn main() {
    JoinApprovalWorld::run("tests/features/join_approval.feature").await;
}
