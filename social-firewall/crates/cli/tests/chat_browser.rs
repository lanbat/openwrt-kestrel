use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use cucumber::{given, then, when, World};
use domain_types::{FederationId, Group, GroupId, Hash32, PublicKeyBytes, SignatureBytes, UserId};
use fantoccini::{ClientBuilder, Locator};
use state_store::StateStore;
use tiny_http::{Header, Response, Server};

#[derive(cucumber::World)]
#[world(init = Self::init)]
struct ChatWorld {
    _dir: tempfile::TempDir,
    db_path: PathBuf,
    client: Option<fantoccini::Client>,
    base_url: String,
    stop: Arc<AtomicBool>,
}

impl std::fmt::Debug for ChatWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatWorld")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl Drop for ChatWorld {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ChatWorld {
    fn browser(&self) -> &fantoccini::Client {
        self.client.as_ref().expect("browser session is available")
    }

    async fn init() -> Self {
        let dir = tempfile::tempdir().expect("create chat fixture directory");
        let db_path = dir.path().join("social-firewall.sqlite");
        let out_dir = dir.path().join("chat-out");
        let connector = hyper_util::client::legacy::connect::HttpConnector::new();
        let client = ClientBuilder::new(connector)
            .connect("http://127.0.0.1:4445")
            .await
            .expect("connect to geckodriver on :4445; is it installed and running?");

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("reserve chat port");
        let port = listener.local_addr().expect("chat local address").port();
        drop(listener);
        let server = Server::http(format!("127.0.0.1:{port}")).expect("start CGI test server");
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let db_for_thread = db_path.clone();
        let out_for_thread = out_dir.clone();
        let executable =
            std::env::var("CARGO_BIN_EXE_sf").expect("Cargo must provide CARGO_BIN_EXE_sf");
        thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok(Some(mut request)) = server.recv_timeout(Duration::from_millis(100)) else {
                    continue;
                };
                let url = request.url().to_string();
                let (path, query) = url.split_once('?').unwrap_or((&url, ""));
                if path != "/cgi-bin/sf-chat" && path != "/cgi-bin/sf-partyline" && path != "/cgi-bin/sf-chat-font" {
                    let _ = request.respond(Response::empty(404));
                    continue;
                }
                let method = request.method().as_str().to_string();
                let mut body = String::new();
                if method == "POST" {
                    let _ = request.as_reader().read_to_string(&mut body);
                }
                let mut command = std::process::Command::new(&executable);
                command
                    .env("REQUEST_METHOD", &method)
                    .env("SCRIPT_NAME", path)
                    .env("QUERY_STRING", query)
                    .env("SF_DB_PATH", &db_for_thread)
                    .env("SF_CHAT_OUT_DIR", &out_for_thread)
                    .env("SF_EXECUTABLE", &executable)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped());
                let Ok(mut child) = command.spawn() else {
                    let _ = request.respond(Response::empty(500));
                    continue;
                };
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(body.as_bytes());
                }
                let Ok(output) = child.wait_with_output() else {
                    let _ = request.respond(Response::empty(500));
                    continue;
                };
                let separator = b"\r\n\r\n";
                let separator_at = output
                    .stdout
                    .windows(separator.len())
                    .position(|window| window == separator)
                    .unwrap_or(output.stdout.len());
                let cgi_headers = String::from_utf8_lossy(&output.stdout[..separator_at]);
                let body_start = separator_at.saturating_add(separator.len());
                let response_body = output.stdout[body_start..].to_vec();
                let status = cgi_headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Status: "))
                    .and_then(|value| value.split_whitespace().next())
                    .and_then(|value| value.parse::<u16>().ok())
                    .unwrap_or(200);
                let content_type = if path == "/cgi-bin/sf-chat-font" {
                    "font/ttf"
                } else {
                    "text/html; charset=utf-8"
                };
                let header = Header::from_bytes(&b"Content-Type"[..], content_type.as_bytes())
                    .expect("valid header");
                let mut response = Response::from_data(response_body).with_header(header);
                if let Some(location) = cgi_headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Location: "))
                {
                    let location = Header::from_bytes(&b"Location"[..], location.as_bytes())
                        .expect("valid location header");
                    response = response.with_header(location);
                }
                let _ = request.respond(response.with_status_code(status));
            }
        });

        Self {
            _dir: dir,
            db_path,
            client: Some(client),
            base_url: format!("http://127.0.0.1:{port}"),
            stop,
        }
    }
}

fn seed_self_group(path: &Path) {
    let store = StateStore::open(path).expect("open chat fixture database");
    let owner = UserId {
        federation: FederationId(Hash32([1; 32])),
        local_id: Hash32([2; 32]),
    };
    store
        .set_self_identity(owner, PublicKeyBytes([1; 32]), &[4; 32], None)
        .expect("seed self identity");
    store
        .ingest_group(&Group {
            group_id: GroupId(crypto::hash(
                &[b"sf-self-group-v1".as_slice(), &[1; 32]].concat(),
            )),
            published_by: owner,
            sequence: 0,
            name: "self".into(),
            description: "browser test self group".into(),
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
        .expect("seed self group");
}

#[given("a social-firewall chat database with a self group")]
async fn chat_database(world: &mut ChatWorld) {
    seed_self_group(&world.db_path);
}

#[when("I open the social-firewall chat")]
async fn open_chat(world: &mut ChatWorld) {
    let url = format!("{}/cgi-bin/sf-partyline", world.base_url);
    world
        .browser()
        .goto(&url)
        .await
        .expect("open social-firewall chat");
}

#[when(expr = "I send the party-line message {string}")]
async fn send_message(world: &mut ChatWorld, message: String) {
    let input = world
        .browser()
        .find(Locator::Css("input[name=input]"))
        .await
        .expect("find chat input");
    input.send_keys(&message).await.expect("type chat message");
    world
        .browser()
        .find(Locator::Css("form button"))
        .await
        .expect("find chat send button")
        .click()
        .await
        .expect("submit chat message");
}

#[when(expr = "I type the command prefix {string}")]
async fn type_command_prefix(world: &mut ChatWorld, prefix: String) {
    world
        .browser()
        .find(Locator::Css("input[name=input]"))
        .await
        .expect("find chat input")
        .send_keys(&prefix)
        .await
        .expect("type command prefix");
}

#[then(expr = "the command suggestions include {string}")]
async fn command_suggestions_include(world: &mut ChatWorld, expected: String) {
    let value = world
        .browser()
        .execute(
            "return document.getElementById('command-assist-matches').textContent",
            vec![],
        )
        .await
        .expect("read command suggestions");
    assert!(value.as_str().unwrap_or_default().contains(&expected));
}

#[then(expr = "the command documentation includes {string}")]
async fn command_documentation_includes(world: &mut ChatWorld, expected: String) {
    let value = world
        .browser()
        .execute(
            "return {hidden: document.getElementById('command-assist').hidden, text: document.getElementById('command-assist-detail').textContent}",
            vec![],
        )
        .await
        .expect("read command documentation");
    assert_eq!(value.get("hidden").and_then(|v| v.as_bool()), Some(false));
    assert!(value
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .contains(&expected));
}

#[then(expr = "the chat title is {string}")]
async fn chat_title(world: &mut ChatWorld, expected: String) {
    assert_eq!(
        world.browser().title().await.expect("read chat title"),
        expected
    );
}

#[then(expr = "the chat contains {string}")]
async fn chat_contains(world: &mut ChatWorld, expected: String) {
    let body = world
        .browser()
        .find(Locator::Css("body"))
        .await
        .expect("find chat body")
        .text()
        .await
        .expect("read chat body");
    assert!(
        body.contains(&expected),
        "chat did not contain {expected:?}: {body}"
    );
}

#[then("the chat uses the bundled Fixedsys font")]
async fn chat_uses_fixedsys(world: &mut ChatWorld) {
    let result = world
        .browser()
        .execute(
            "return document.fonts.check('14px \\\"Fixedsys Excelsior 3.01\\\"');",
            vec![],
        )
        .await
        .expect("check the loaded chat font");
    assert_eq!(
        result.as_bool(),
        Some(true),
        "the bundled Fixedsys font was not loaded"
    );
}

#[tokio::main]
async fn main() {
    let mut gecko = tokio::process::Command::new("geckodriver")
        .arg("--port")
        .arg("4445")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start geckodriver; install it or see the browser-test prerequisites");
    for _ in 0..50 {
        if tokio::net::TcpStream::connect("127.0.0.1:4445")
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    ChatWorld::cucumber()
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
        .run("tests/features/chat_browser.feature")
        .await;
    let _ = gecko.kill().await;
    let _ = gecko.wait().await;
}
