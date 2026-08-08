use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use domain_types::{FederationId, Hash32, UserId};
use state_store::StateStore;

pub const SHARED_FEDERATION: FederationId = FederationId(Hash32([0x42; 32]));

pub struct Node {
    pub name: &'static str,
    pub dir: tempfile::TempDir,
    pub db: String,
    pub federation: FederationId,
    pub user: UserId,
}

pub struct TwoNode {
    pub alice: Node,
    pub bob: Node,
}

impl TwoNode {
    pub fn new() -> Self {
        Self {
            alice: Node::new("alice", [1; 32]),
            bob: Node::new("bob", [2; 32]),
        }
    }
}

impl Node {
    fn new(name: &'static str, seed: [u8; 32]) -> Self {
        let dir = tempfile::tempdir().expect("create node directory");
        let db = format!("{name}.sqlite");
        let keypair = crypto::Keypair::from_seed(&seed);
        let user = UserId {
            federation: SHARED_FEDERATION,
            local_id: crypto::hash(
                &[b"sf-local-id-v1".as_slice(), &keypair.public_key().0].concat(),
            ),
        };
        let store = StateStore::open(&dir.path().join(&db)).expect("open node database");
        store
            .set_self_identity(user, keypair.public_key(), &seed, Some(name))
            .expect("seed node identity");
        Self {
            name,
            dir,
            db,
            federation: SHARED_FEDERATION,
            user,
        }
    }

    pub fn path(&self, file: &str) -> PathBuf {
        self.dir.path().join(file)
    }

    pub fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sf"))
            .arg("--db")
            .arg(self.dir.path().join(&self.db))
            .args(args)
            .output()
            .expect("spawn sf binary")
    }

    pub fn run_ok(&self, args: &[&str]) -> Output {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{} command failed: {}",
            self.name,
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    pub fn copy_to(&self, source: &Path, target_name: &str) -> PathBuf {
        let target = self.path(target_name);
        std::fs::copy(source, &target).expect("copy statement between nodes");
        target
    }
}

pub fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[allow(dead_code)]
pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn group_id(output: &Output) -> String {
    stdout(output)
        .lines()
        .find(|line| line.starts_with("created group"))
        .and_then(|line| line.split_whitespace().nth(2))
        .expect("create-group output contains a group ID")
        .to_string()
}

pub fn setup_group(nodes: &TwoNode) -> String {
    let group_path = nodes.alice.path("group.json");
    let created = nodes.alice.run_ok(&[
        "create-group",
        "--name",
        "Neighborhood Watch",
        "--description",
        "two-node test group",
        "--join-prompt",
        "why are you joining?",
        "--out",
        group_path.to_str().unwrap(),
    ]);
    let id = group_id(&created);
    let bob_group = nodes.bob.copy_to(&group_path, "group.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group.to_str().unwrap()]);
    id
}
