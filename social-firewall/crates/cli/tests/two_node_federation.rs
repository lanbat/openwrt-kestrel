mod support;

use std::path::PathBuf;

use cucumber::{given, then, when, World};
use serde_json::json;
use support::two_node::{setup_group, stdout, TwoNode};

#[derive(cucumber::World)]
#[world(init = Self::init)]
struct TwoNodeWorld {
    nodes: TwoNode,
    group_id: Option<String>,
    join_path: Option<PathBuf>,
    group_v2_path: Option<PathBuf>,
    alice_vote_path: Option<PathBuf>,
    last_output: Option<std::process::Output>,
}

impl std::fmt::Debug for TwoNodeWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TwoNodeWorld")
            .field("group_id", &self.group_id)
            .finish()
    }
}

impl TwoNodeWorld {
    async fn init() -> Self {
        Self {
            nodes: TwoNode::new(),
            group_id: None,
            join_path: None,
            group_v2_path: None,
            alice_vote_path: None,
            last_output: None,
        }
    }

    fn group(&self) -> &str {
        self.group_id.as_deref().expect("group exists")
    }

    fn approve_bob(&mut self) {
        let group_id = self.group_id.clone().expect("group exists");
        let join_path = self.nodes.bob.path("join.json");
        self.nodes.bob.run_ok(&[
            "request-group-join",
            "--group",
            &group_id,
            "--answer",
            "vote",
            "--out",
            join_path.to_str().unwrap(),
        ]);
        let alice_join = self.nodes.alice.copy_to(&join_path, "join.json");
        self.nodes.alice.run_ok(&[
            "ingest-group-join-request",
            "--file",
            alice_join.to_str().unwrap(),
        ]);
        let bob_ref = format!(
            "{}/{}",
            self.nodes.bob.user.federation.0, self.nodes.bob.user.local_id
        );
        let group_v2_path = self.nodes.alice.path("group-v2.json");
        self.nodes.alice.run_ok(&[
            "approve-group-join",
            "--group",
            &group_id,
            "--requester",
            &bob_ref,
            "--sequence",
            "0",
            "--voting",
            "--out",
            group_v2_path.to_str().unwrap(),
        ]);
        self.join_path = Some(join_path);
        self.group_v2_path = Some(group_v2_path);
    }
}

#[given("Alice and Bob are separate functioning nodes")]
async fn separate_nodes(world: &mut TwoNodeWorld) {
    assert_ne!(world.nodes.alice.user, world.nodes.bob.user);
}

#[given("Alice and Bob belong to the same federation")]
async fn same_federation(world: &mut TwoNodeWorld) {
    assert_eq!(world.nodes.alice.federation, world.nodes.bob.federation);
}

#[given(expr = "Alice creates the {string} group")]
async fn create_group(world: &mut TwoNodeWorld, _name: String) {
    world.group_id = Some(setup_group(&world.nodes));
}

#[given("Bob has ingested the group snapshot")]
async fn bob_has_group(world: &mut TwoNodeWorld) {
    assert!(stdout(&world.nodes.bob.run_ok(&["list-groups"])).contains(world.group()));
}

#[when(expr = "Bob requests to join {string}")]
async fn bob_requests_join(world: &mut TwoNodeWorld, _name: String) {
    let path = world.nodes.bob.path("join.json");
    world.nodes.bob.run_ok(&[
        "request-group-join",
        "--group",
        world.group(),
        "--answer",
        "I contribute reliable network information",
        "--out",
        path.to_str().unwrap(),
    ]);
    world.join_path = Some(path);
}

#[when("Alice ingests Bob's join request")]
async fn alice_ingests_join(world: &mut TwoNodeWorld) {
    let source = world.join_path.as_ref().expect("join request exists");
    let path = world.nodes.alice.copy_to(source, "alice-join.json");
    world.nodes.alice.run_ok(&[
        "ingest-group-join-request",
        "--file",
        path.to_str().unwrap(),
    ]);
}

#[then("Alice sees Bob as a pending member")]
async fn alice_sees_pending(world: &mut TwoNodeWorld) {
    let output = world
        .nodes
        .alice
        .run_ok(&["list-pending-group-joins", "--group", world.group()]);
    assert!(stdout(&output).contains(&world.nodes.bob.user.local_id.to_string()));
}

#[then("Bob is not yet a member")]
async fn bob_not_member(world: &mut TwoNodeWorld) {
    let output = world.nodes.bob.run_ok(&["list-groups"]);
    assert!(!stdout(&output).contains(&world.nodes.bob.user.local_id.to_string()));
}

#[when("Alice approves Bob as a voting member")]
async fn alice_approves(world: &mut TwoNodeWorld) {
    world.approve_bob();
}

#[when("Bob ingests the updated group snapshot")]
async fn bob_ingests_update(world: &mut TwoNodeWorld) {
    let source = world.group_v2_path.as_ref().expect("updated group exists");
    let path = world.nodes.bob.copy_to(source, "bob-group-v2.json");
    world
        .nodes
        .bob
        .run_ok(&["ingest-group", "--file", path.to_str().unwrap()]);
}

#[then("Alice and Bob both list Bob as a voting member")]
async fn both_list_member(world: &mut TwoNodeWorld) {
    let bob_id = world.nodes.bob.user.local_id.to_string();
    assert!(stdout(&world.nodes.alice.run_ok(&["list-groups"])).contains(&bob_id));
    assert!(stdout(&world.nodes.bob.run_ok(&["list-groups"])).contains(&bob_id));
}

#[when("Bob submits a forged update making himself the sole owner")]
async fn bob_submits_forged_update(world: &mut TwoNodeWorld) {
    let group_path = world.nodes.alice.path("group.json");
    let mut forged: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(group_path).unwrap()).unwrap();
    forged["sequence"] = json!(1);
    forged["supersedes"] = json!(0);
    forged["owners"] = json!([format!(
        "{}/{}",
        world.nodes.bob.user.federation.0, world.nodes.bob.user.local_id
    )]);
    let path = world.nodes.bob.path("forged.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();
    let copied = world.nodes.alice.copy_to(&path, "forged.json");
    world.last_output =
        Some(
            world
                .nodes
                .alice
                .run(&["ingest-group", "--file", copied.to_str().unwrap()]),
        );
}

#[then("Alice rejects the group update")]
async fn alice_rejects(world: &mut TwoNodeWorld) {
    assert!(!world
        .last_output
        .as_ref()
        .expect("rejection output")
        .status
        .success());
}

#[then("Alice's group membership is unchanged")]
async fn membership_unchanged(world: &mut TwoNodeWorld) {
    let output = world.nodes.alice.run_ok(&["list-groups"]);
    assert!(!stdout(&output).contains(&world.nodes.bob.user.local_id.to_string()));
}

#[given(expr = "Bob is an approved voting member of {string}")]
async fn bob_is_approved(world: &mut TwoNodeWorld, _name: String) {
    world.approve_bob();
    let source = world.group_v2_path.as_ref().unwrap();
    let path = world.nodes.bob.copy_to(source, "bob-group-v2.json");
    world
        .nodes
        .bob
        .run_ok(&["ingest-group", "--file", path.to_str().unwrap()]);
    world.nodes.bob.run_ok(&[
        "set-group-trust",
        "--group",
        world.group(),
        "--allow-weight",
        "1.0",
        "--deny-weight",
        "1.0",
    ]);
}

#[when(expr = "Alice votes to deny {string}")]
async fn alice_votes(world: &mut TwoNodeWorld, target: String) {
    let path = world.nodes.alice.path("alice-vote.json");
    world.nodes.alice.run_ok(&[
        "cast-group-vote",
        "--group",
        world.group(),
        "--target-kind",
        "ip",
        "--target-value",
        &target,
        "--stance",
        "deny",
        "--reason-code",
        "malware",
        "--out",
        path.to_str().unwrap(),
    ]);
    world.alice_vote_path = Some(path);
}

#[when(expr = "Bob votes to deny {string}")]
async fn bob_votes(world: &mut TwoNodeWorld, target: String) {
    world.nodes.bob.run_ok(&[
        "cast-group-vote",
        "--group",
        world.group(),
        "--target-kind",
        "ip",
        "--target-value",
        &target,
        "--stance",
        "deny",
        "--reason-code",
        "malware",
    ]);
}

#[when("Bob ingests Alice's vote")]
async fn bob_ingests_vote(world: &mut TwoNodeWorld) {
    let source = world.alice_vote_path.as_ref().expect("Alice vote exists");
    let path = world.nodes.bob.copy_to(source, "alice-vote.json");
    world
        .nodes
        .bob
        .run_ok(&["ingest-group-vote", "--file", path.to_str().unwrap()]);
}

#[then("Bob's group explanation shows both votes")]
async fn bob_explanation_shows_votes(world: &mut TwoNodeWorld) {
    let output = world.nodes.bob.run_ok(&[
        "explain-group-vote",
        "--group",
        world.group(),
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.9",
    ]);
    assert!(stdout(&output).matches("Deny (counts)").count() >= 2);
}

#[then(expr = "the group decision for {string} is {string}")]
async fn decision_is(world: &mut TwoNodeWorld, target: String, expected: String) {
    let output = world.nodes.bob.run_ok(&[
        "evaluate-target",
        "--target-kind",
        "ip",
        "--target-value",
        &target,
    ]);
    assert!(stdout(&output).contains(&format!("decision   : {expected}")));
}

#[tokio::main]
async fn main() {
    TwoNodeWorld::cucumber()
        .max_concurrent_scenarios(1)
        .run("tests/features/two_node_federation.feature")
        .await;
}
