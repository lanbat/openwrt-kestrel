use std::path::PathBuf;
use std::time::Duration;

use cucumber::{given, then, when, World};
use domain_types::{FederationId, Group, GroupId, Hash32, PublicKeyBytes, SignatureBytes, UserId};
use fantoccini::{ClientBuilder, Locator};
use state_store::StateStore;

#[derive(cucumber::World)]
#[world(init = Self::init)]
struct DashboardWorld {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    client: Option<fantoccini::Client>,
    base_url: Option<String>,
    server: Option<tokio::process::Child>,
}

impl std::fmt::Debug for DashboardWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DashboardWorld")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl Drop for DashboardWorld {
    fn drop(&mut self) {
        if let Some(server) = &mut self.server {
            let _ = server.start_kill();
        }
    }
}

impl DashboardWorld {
    fn browser(&self) -> &fantoccini::Client {
        self.client.as_ref().expect("browser session is available")
    }

    async fn init() -> Self {
        let dir = tempfile::tempdir().expect("create dashboard fixture directory");
        let db_path = dir.path().join("social-firewall.sqlite");
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client = ClientBuilder::new(connector)
            .connect("http://127.0.0.1:4444")
            .await
            .expect("connect to geckodriver on :4444; is it installed and running?");
        Self {
            _dir: dir,
            db_path,
            client: Some(client),
            base_url: None,
            server: None,
        }
    }

    async fn start_server(&mut self) {
        if self.server.is_some() {
            return;
        }
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("reserve dashboard port");
        let port = listener
            .local_addr()
            .expect("dashboard local address")
            .port();
        drop(listener);

        let executable = std::env::var("CARGO_BIN_EXE_sf")
            .expect("Cargo must provide CARGO_BIN_EXE_sf for the browser test");
        let server = tokio::process::Command::new(executable)
            .arg("--db")
            .arg(&self.db_path)
            .arg("serve-dashboard")
            .arg("--addr")
            .arg(format!("127.0.0.1:{port}"))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("start sf serve-dashboard");
        self.server = Some(server);
        self.base_url = Some(format!("http://127.0.0.1:{port}"));

        for _ in 0..50 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("sf dashboard did not listen on port {port}");
    }
}

fn fixture_user() -> UserId {
    UserId {
        federation: FederationId(Hash32([1; 32])),
        local_id: Hash32([2; 32]),
    }
}

fn seed_group(path: &PathBuf, name: &str) {
    let store = StateStore::open(path).expect("open dashboard fixture database");
    let owner = fixture_user();
    store
        .set_self_identity(owner, PublicKeyBytes([1; 32]), &[4; 32], None)
        .expect("seed self identity");
    store
        .ingest_group(&Group {
            group_id: GroupId(Hash32([5; 32])),
            published_by: owner,
            sequence: 0,
            name: name.to_string(),
            description: "browser test group".into(),
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
        })
        .expect("seed group");
}

#[given("an empty social-firewall database")]
async fn empty_database(_world: &mut DashboardWorld) {}

#[given(expr = "a social-firewall database containing a group named {string}")]
async fn database_with_group(world: &mut DashboardWorld, name: String) {
    seed_group(&world.db_path, &name);
}

#[when("I open the social-firewall dashboard")]
async fn open_dashboard(world: &mut DashboardWorld) {
    world.start_server().await;
    let url = format!("{}/", world.base_url.as_deref().unwrap());
    world.browser().goto(&url).await.expect("open dashboard");
}

#[then(expr = "the page title is {string}")]
async fn page_title(world: &mut DashboardWorld, expected: String) {
    assert_eq!(
        world.browser().title().await.expect("read page title"),
        expected
    );
}

#[then(expr = "the dashboard contains {string}")]
async fn dashboard_contains(world: &mut DashboardWorld, expected: String) {
    let body = world
        .browser()
        .find(Locator::Css("body"))
        .await
        .expect("find dashboard body")
        .text()
        .await
        .expect("read dashboard body");
    assert!(
        body.contains(&expected),
        "dashboard did not contain {expected:?}: {body}"
    );
}

#[then(expr = "the dashboard does not contain {string}")]
async fn dashboard_does_not_contain(world: &mut DashboardWorld, unexpected: String) {
    let source = world.browser().source().await.expect("read dashboard HTML");
    assert!(
        !source.contains(&unexpected),
        "dashboard contained {unexpected:?}: {source}"
    );
}

#[then(expr = "the dashboard source contains {string}")]
async fn dashboard_source_contains(world: &mut DashboardWorld, expected: String) {
    let source = world.browser().source().await.expect("read dashboard HTML");
    assert!(
        source.contains(&expected),
        "dashboard source did not contain {expected:?}: {source}"
    );
}

#[tokio::main]
async fn main() {
    let mut gecko = tokio::process::Command::new("geckodriver")
        .arg("--port")
        .arg("4444")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start geckodriver; install it or see the browser-test prerequisites");
    for _ in 0..50 {
        if tokio::net::TcpStream::connect("127.0.0.1:4444")
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    DashboardWorld::cucumber()
        .after(|_, _, _, _, world| {
            Box::pin(async move {
                if let Some(world) = world {
                    if let Some(client) = world.client.take() {
                        let _ = client.close().await;
                    }
                }
            })
        })
        .max_concurrent_scenarios(1)
        .run("tests/features/dashboard.feature")
        .await;
    let _ = gecko.kill().await;
    let _ = gecko.wait().await;
}
