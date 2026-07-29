//! Browser-driven counterpart to `join_approval.rs`. That suite calls the
//! `approve_join::post()` handler directly and never renders a page or
//! runs a line of JS; this one starts a real `kestreld` daemon instance on
//! an ephemeral port, points a real (headless) Firefox at it via
//! `fantoccini`/WebDriver, and clicks the actual Approve button — the only
//! way to exercise `_jsonpost.html`'s fetch-then-reload logic at all.
//!
//! Requires `geckodriver` on `PATH`; `main()` below starts and stops it
//! for the whole run (geckodriver only supports one session at a time, so
//! scenarios are also forced to run one-at-a-time).

use std::path::PathBuf;
use std::time::Duration;

use cucumber::{given, then, when, World};
use fantoccini::{ClientBuilder, Locator};

use kestreld::data::files;
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
JOIN_APPROVAL=yes
JOIN_HISTORY_RETENTION=90d
REJOIN_NOTIFY_AFTER=
ROTATE_PASSWORD=yes
DEVICE_CONTROL=yes
DESCRIPTION='Guest WiFi hwsim test'
";

#[derive(cucumber::World)]
#[world(init = Self::init)]
struct BrowserWorld {
    // Held only for its Drop impl (cleans up the directory on disk).
    _dir: tempfile::TempDir,
    base_dir: PathBuf,
    split_routing_dir: PathBuf,
    // Started lazily (see `ensure_server_started`) — not in `init()` —
    // because `AppState::new` takes one snapshot immediately and only
    // refreshes every 5s after that. Starting the server before the Given
    // steps have written their fixture files would race that first
    // snapshot against an empty `base_dir` every time.
    base_url: Option<String>,
    client: fantoccini::Client,
    current_mac: String,
}

impl std::fmt::Debug for BrowserWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserWorld").field("base_url", &self.base_url).finish()
    }
}

impl BrowserWorld {
    async fn init() -> Self {
        let dir = tempfile::tempdir().expect("create tempdir for base_dir");
        let base_dir = dir.path().to_path_buf();
        let split_routing_dir = dir.path().join("split-routing");

        // Plain HTTP connector — geckodriver and kestreld are both plain
        // localhost HTTP here, no TLS involved anywhere in this test.
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client = ClientBuilder::new(connector)
            .connect("http://127.0.0.1:4444")
            .await
            .expect("connect to geckodriver on :4444 — is it running? (see tests/browser_workflow.rs main())");

        Self {
            _dir: dir,
            base_dir,
            split_routing_dir,
            base_url: None,
            client,
            current_mac: String::new(),
        }
    }

    /// A real, long-running kestreld instance (not CGI mode) on a free
    /// port — the same server code the real router runs, just started
    /// fresh per scenario against an isolated fixture directory, and not
    /// until the fixtures are actually in place.
    async fn ensure_server_started(&mut self) -> &str {
        if self.base_url.is_none() {
            let state = AppState::new(self.base_dir.clone(), self.split_routing_dir.clone()).await;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("bind ephemeral port");
            let port = listener.local_addr().expect("local_addr").port();
            tokio::spawn(async move {
                let _ = axum::serve(listener, kestreld::routes::build(state)).await;
            });
            self.base_url = Some(format!("http://127.0.0.1:{port}"));
        }
        self.base_url.as_deref().unwrap()
    }
}

#[given(expr = "the {string} network is installed with join approval enabled")]
async fn network_installed(world: &mut BrowserWorld, net: String) {
    assert_eq!(net, "guest", "this suite only ships a guest.conf fixture");
    let path = world.base_dir.join(format!("{net}-notify.conf"));
    tokio::fs::write(&path, GUEST_CONF).await.expect("write notify.conf");
}

#[given(expr = "a device {string} at {string} is pending join on {string}")]
async fn device_pending(world: &mut BrowserWorld, mac: String, ip: String, net: String) {
    let path = world.base_dir.join(format!("{net}-join-pending"));
    files::file_append(&path, &format!("{mac} {ip}")).await.expect("seed pending entry");

    // The device table only ever renders rows that have a DHCP lease (see
    // `data::dhcp::fetch`, hardcoded to `/tmp/dhcp.leases` — there's no
    // base_dir-relative override, so unlike everything else in this test
    // this one fixture has to go through a real, fixed, global system
    // path rather than our isolated tempdir).
    let expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 86400;
    files::file_append(
        std::path::Path::new("/tmp/dhcp.leases"),
        &format!("{expiry} {mac} {ip} browser-test-device *"),
    ).await.expect("seed dhcp lease");

    world.current_mac = mac;
}

#[given(expr = "a VPN tier {string} is configured with fwmark {string}")]
async fn vpn_tier_configured(world: &mut BrowserWorld, name: String, fwmark: String) {
    tokio::fs::create_dir_all(&world.split_routing_dir).await.expect("create split-routing dir");
    let conf = format!("VPN_IFACE=mv_{name}\nROUTE_TABLE=100\nFWMARK={fwmark}\n");
    let path = world.split_routing_dir.join(format!("vpn-{name}.conf"));
    tokio::fs::write(&path, conf).await.expect("write vpn conf");
}

#[when("I open the dashboard in a browser")]
async fn open_dashboard(world: &mut BrowserWorld) {
    let url = format!("{}/cgi-bin/status", world.ensure_server_started().await);
    world.client.goto(&url).await.expect("navigate to dashboard");
}

#[when(expr = "I open the device page for {string} on {string} in a browser")]
async fn open_device_page(world: &mut BrowserWorld, mac: String, net: String) {
    let url = format!("{}/cgi-bin/device?net={net}&mac={mac}", world.ensure_server_started().await);
    world.client.goto(&url).await.expect("navigate to device page");
    world.current_mac = mac;
}

#[when(expr = "I approve domain {string} routed via {string}")]
async fn approve_domain_via_browser(world: &mut BrowserWorld, domain: String, route: String) {
    let domain_input = world.client
        .wait().for_element(Locator::Css("form#domain-form input[name=domain]"))
        .await
        .expect("find the domain input");
    domain_input.send_keys(&domain).await.expect("type domain");

    let route_option = world.client
        .find(Locator::XPath(&format!("//form[@id='domain-form']//select[@name='route']/option[@value='{route}']")))
        .await
        .expect("find the route option");
    route_option.click().await.expect("select route option");

    let allow_button = world.client
        .find(Locator::Css("form#domain-form button"))
        .await
        .expect("find the Allow button");
    allow_button.click().await.expect("click Allow");

    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[when(expr = "I approve that device with label {string}")]
async fn approve_via_browser(world: &mut BrowserWorld, label: String) {
    // Exactly one pending device exists on this page, so an unscoped
    // selector for the approve-form is unambiguous.
    let label_input = world.client
        .wait().for_element(Locator::Css("form.approve-form input[name=label]"))
        .await
        .expect("find the approve form's label field");
    label_input.send_keys(&label).await.expect("type label");

    let approve_button = world.client
        .find(Locator::Css("form.approve-form button.btn-ok"))
        .await
        .expect("find the Approve button");
    approve_button.click().await.expect("click Approve");

    // _jsonpost.html's success path is `location.reload()` — give the
    // fetch + reload a moment to actually complete before we look again.
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// Re-fetches the dashboard until the device's badge matches `want` or
/// `tries` are exhausted. Needed only because this test runs kestreld in
/// its long-running daemon mode (`AppState::new`, 5s background refresh)
/// so a real browser session survives across requests — production only
/// ever runs in CGI mode (`AppState::new_once`, a fresh snapshot per
/// request), where an approve is visible on the very next load. This
/// polling loop compensates for a test-harness artifact, not something
/// being asserted about production behavior.
async fn wait_for_badge(world: &mut BrowserWorld, want: &str, tries: u32) -> String {
    let mut last = String::new();
    for _ in 0..tries {
        let url = format!("{}/cgi-bin/status", world.ensure_server_started().await);
        world.client.goto(&url).await.expect("reload dashboard");
        let badge = world.client
            .wait().for_element(Locator::Css(".badge-approved, .badge-pending, .badge-denied"))
            .await
            .expect("find a join-state badge");
        last = badge.text().await.expect("badge text");
        if last == want {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    last
}

#[then(expr = "the dashboard shows that device as {string}")]
async fn shows_state(world: &mut BrowserWorld, state: String) {
    let text = wait_for_badge(world, &state, 8).await;
    assert_eq!(text, state, "device {} is not shown as {state:?}", world.current_mac);
}

#[then(expr = "the rules table shows domain {string} routed via {string}")]
async fn rules_table_shows_route(world: &mut BrowserWorld, domain: String, route: String) {
    // Same daemon-mode 5s background-refresh artifact `wait_for_badge`
    // documents: the file write from the approval POST is already on
    // disk, but the in-memory snapshot this page renders from may not
    // have picked it up yet on the very next reload. Poll instead of a
    // one-shot reload.
    let xpath = format!("//table//tr[td[1][text()='{domain}']]");
    let mut row_text = None;
    for _ in 0..8 {
        let base_url = world.ensure_server_started().await.to_string();
        let url = format!("{base_url}/cgi-bin/device?net=guest&mac={}", world.current_mac);
        world.client.goto(&url).await.expect("reload device page");
        if let Ok(el) = world.client.find(Locator::XPath(&xpath)).await {
            row_text = Some(el.text().await.expect("row text"));
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let row_text = row_text.unwrap_or_else(|| panic!("no rules row for domain {domain:?} appeared after polling"));
    assert!(
        row_text.contains(&route),
        "expected the rules row for {domain:?} to show route {route:?}, got: {row_text:?}"
    );
}

#[tokio::main]
async fn main() {
    let mut gecko = tokio::process::Command::new("geckodriver")
        .arg("--port").arg("4444")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start geckodriver (must be on PATH — see tests/browser_workflow.rs)");

    // Poll until geckodriver's HTTP endpoint actually accepts connections
    // instead of guessing a fixed startup delay.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect("127.0.0.1:4444").await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    BrowserWorld::cucumber()
        .max_concurrent_scenarios(1) // geckodriver only supports one session at a time
        .run("tests/features/browser_workflow.feature")
        .await;

    let _ = gecko.kill().await;
}
