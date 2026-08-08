mod support;

use domain_types::{FederationId, Group, GroupId, Hash32, SignatureBytes, UserId};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use support::two_node::{group_id, setup_group, stderr, stdout, TwoNode};

struct Listener {
    child: Child,
    node_id: String,
    _stdout_drain: std::thread::JoinHandle<()>,
}

impl Listener {
    fn start(node: &support::two_node::Node) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_sf"))
            .arg("--db")
            .arg(node.dir.path().join(&node.db))
            .arg("listen")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("start sf listener");
        let stdout = child.stdout.take().expect("listener stdout");
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).expect("read listener node ID");
        let node_id = line
            .split_whitespace()
            .last()
            .expect("listener prints an Iroh node ID")
            .to_string();
        let stdout_drain = std::thread::spawn(move || {
            let mut line = String::new();
            while reader.read_line(&mut line).unwrap_or(0) > 0 {
                line.clear();
            }
        });
        Self {
            child,
            node_id,
            _stdout_drain: stdout_drain,
        }
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for(label: &str, mut condition: impl FnMut() -> bool) {
    for _ in 0..100 {
        if condition() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("timed out waiting for {label}");
}

#[test]
fn two_nodes_in_one_federation_replicate_a_group_snapshot() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);

    let alice_groups = nodes.alice.run_ok(&["list-groups"]);
    let bob_groups = nodes.bob.run_ok(&["list-groups"]);

    assert!(stdout(&alice_groups).contains(&group_id));
    assert!(stdout(&bob_groups).contains(&group_id));
    assert_eq!(nodes.alice.federation, nodes.bob.federation);
    assert_ne!(nodes.alice.user, nodes.bob.user);
}

#[test]
fn join_request_and_approval_converge_on_both_nodes() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);

    let join_path = nodes.bob.path("join.json");
    nodes.bob.run_ok(&[
        "request-group-join",
        "--group",
        &group_id,
        "--answer",
        "I maintain the neighborhood network",
        "--out",
        join_path.to_str().unwrap(),
    ]);
    let alice_join = nodes.alice.copy_to(&join_path, "join.json");
    nodes.alice.run_ok(&[
        "ingest-group-join-request",
        "--file",
        alice_join.to_str().unwrap(),
    ]);

    let pending = nodes
        .alice
        .run_ok(&["list-pending-group-joins", "--group", &group_id]);
    assert!(stdout(&pending).contains(&nodes.bob.user.local_id.to_string()));

    let bob_ref = format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    );
    let group_v2 = nodes.alice.path("group-v2.json");
    nodes.alice.run_ok(&[
        "approve-group-join",
        "--group",
        &group_id,
        "--requester",
        &bob_ref,
        "--sequence",
        "0",
        "--voting",
        "--out",
        group_v2.to_str().unwrap(),
    ]);
    let bob_group_v2 = nodes.bob.copy_to(&group_v2, "group-v2.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v2.to_str().unwrap()]);

    let bob_groups = nodes.bob.run_ok(&["list-groups"]);
    assert!(stdout(&bob_groups).contains(&nodes.bob.user.local_id.to_string()));
}

#[test]
fn replaying_a_group_snapshot_is_idempotent() {
    let nodes = TwoNode::new();
    let group_path = nodes.alice.path("group.json");
    let created = nodes.alice.run_ok(&[
        "create-group",
        "--name",
        "Replay Test",
        "--description",
        "idempotence",
        "--out",
        group_path.to_str().unwrap(),
    ]);
    let group_id = group_id(&created);
    let bob_group = nodes.bob.copy_to(&group_path, "group.json");

    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group.to_str().unwrap()]);
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group.to_str().unwrap()]);

    let groups = nodes.bob.run_ok(&["list-groups"]);
    let occurrences = stdout(&groups).matches(&group_id).count();
    assert_eq!(
        occurrences, 1,
        "replayed group should have one current listing"
    );
}

#[test]
fn a_forged_group_update_from_the_non_owner_is_rejected() {
    let nodes = TwoNode::new();
    let group_path = nodes.alice.path("group.json");
    nodes.alice.run_ok(&[
        "create-group",
        "--name",
        "Protected",
        "--description",
        "owner authorization",
        "--out",
        group_path.to_str().unwrap(),
    ]);
    let bob_group = nodes.bob.copy_to(&group_path, "group.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group.to_str().unwrap()]);

    let mut forged: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&group_path).unwrap()).unwrap();
    forged["sequence"] = serde_json::json!(1);
    forged["supersedes"] = serde_json::json!(0);
    forged["owners"] = serde_json::json!([format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    )]);
    let forged_path = nodes.bob.path("forged.json");
    std::fs::write(&forged_path, serde_json::to_vec_pretty(&forged).unwrap()).unwrap();

    let rejected = nodes
        .alice
        .run(&["ingest-group", "--file", forged_path.to_str().unwrap()]);
    assert!(!rejected.status.success());
    assert!(!stderr(&rejected).is_empty());
}

#[test]
fn group_votes_from_two_members_converge_on_the_same_decision() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);

    let join_path = nodes.bob.path("join.json");
    nodes.bob.run_ok(&[
        "request-group-join",
        "--group",
        &group_id,
        "--answer",
        "vote",
        "--out",
        join_path.to_str().unwrap(),
    ]);
    let alice_join = nodes.alice.copy_to(&join_path, "join.json");
    nodes.alice.run_ok(&[
        "ingest-group-join-request",
        "--file",
        alice_join.to_str().unwrap(),
    ]);
    let bob_ref = format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    );
    let group_v2 = nodes.alice.path("group-v2.json");
    nodes.alice.run_ok(&[
        "approve-group-join",
        "--group",
        &group_id,
        "--requester",
        &bob_ref,
        "--sequence",
        "0",
        "--voting",
        "--out",
        group_v2.to_str().unwrap(),
    ]);
    let bob_group_v2 = nodes.bob.copy_to(&group_v2, "group-v2.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v2.to_str().unwrap()]);

    let alice_vote = nodes.alice.path("alice-vote.json");
    nodes.alice.run_ok(&[
        "cast-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.9",
        "--stance",
        "deny",
        "--reason-code",
        "malware",
        "--out",
        alice_vote.to_str().unwrap(),
    ]);
    nodes.bob.run_ok(&[
        "cast-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.9",
        "--stance",
        "deny",
        "--reason-code",
        "malware",
    ]);
    let bob_vote = nodes.bob.copy_to(&alice_vote, "alice-vote.json");
    nodes
        .bob
        .run_ok(&["ingest-group-vote", "--file", bob_vote.to_str().unwrap()]);

    let explanation = nodes.bob.run_ok(&[
        "explain-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.9",
    ]);
    let text = stdout(&explanation);
    assert!(text.contains("Deny (counts)"));
    assert!(text.matches("Deny (counts)").count() >= 2);
}

#[test]
fn a_non_member_cannot_publish_to_the_group_partyline() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);

    let rejected = nodes.bob.run(&[
        "publish-party-line",
        "--group",
        &group_id,
        "--body",
        "unauthorized message",
    ]);
    assert!(!rejected.status.success());
    assert!(stderr(&rejected).contains("not a member"));
}

#[test]
fn removing_a_voter_stops_their_existing_vote_from_counting() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);

    let join_path = nodes.bob.path("join.json");
    nodes.bob.run_ok(&[
        "request-group-join",
        "--group",
        &group_id,
        "--answer",
        "voting",
        "--out",
        join_path.to_str().unwrap(),
    ]);
    let alice_join = nodes.alice.copy_to(&join_path, "join.json");
    nodes.alice.run_ok(&[
        "ingest-group-join-request",
        "--file",
        alice_join.to_str().unwrap(),
    ]);
    let bob_ref = format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    );
    let group_v2 = nodes.alice.path("group-v2.json");
    nodes.alice.run_ok(&[
        "approve-group-join",
        "--group",
        &group_id,
        "--requester",
        &bob_ref,
        "--sequence",
        "0",
        "--voting",
        "--out",
        group_v2.to_str().unwrap(),
    ]);
    let bob_group_v2 = nodes.bob.copy_to(&group_v2, "group-v2.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v2.to_str().unwrap()]);

    let alice_vote = nodes.alice.path("alice-vote.json");
    nodes.alice.run_ok(&[
        "cast-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.10",
        "--stance",
        "allow",
        "--reason-code",
        "tracker",
        "--out",
        alice_vote.to_str().unwrap(),
    ]);
    let bob_vote = nodes.bob.run_ok(&[
        "cast-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.10",
        "--stance",
        "deny",
        "--reason-code",
        "malware",
    ]);
    assert!(bob_vote.status.success());
    let bob_alice_vote = nodes.bob.copy_to(&alice_vote, "alice-vote.json");
    nodes.bob.run_ok(&[
        "ingest-group-vote",
        "--file",
        bob_alice_vote.to_str().unwrap(),
    ]);
    nodes.bob.run_ok(&[
        "set-group-trust",
        "--group",
        &group_id,
        "--allow-weight",
        "1.0",
        "--deny-weight",
        "1.0",
    ]);

    let before = nodes.bob.run_ok(&[
        "explain-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.10",
    ]);
    assert!(stdout(&before).contains("Allow (counts)"));
    assert!(stdout(&before).contains("Deny (counts)"));

    let group_v3 = nodes.alice.path("group-v3.json");
    nodes.alice.run_ok(&[
        "set-group-voting-right",
        "--group",
        &group_id,
        "--user",
        &bob_ref,
        "--out",
        group_v3.to_str().unwrap(),
    ]);
    let bob_group_v3 = nodes.bob.copy_to(&group_v3, "group-v3.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v3.to_str().unwrap()]);

    let after = nodes.bob.run_ok(&[
        "explain-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.10",
    ]);
    assert!(stdout(&after).contains("Allow (counts)"));
    assert!(!stdout(&after).contains(&nodes.bob.user.local_id.to_string()));
}

#[test]
fn moderation_and_voice_state_replicate_between_group_nodes() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);

    let join_path = nodes.bob.path("join.json");
    nodes.bob.run_ok(&[
        "request-group-join",
        "--group",
        &group_id,
        "--answer",
        "partyline",
        "--out",
        join_path.to_str().unwrap(),
    ]);
    let alice_join = nodes.alice.copy_to(&join_path, "join.json");
    nodes.alice.run_ok(&[
        "ingest-group-join-request",
        "--file",
        alice_join.to_str().unwrap(),
    ]);
    let bob_ref = format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    );
    let group_v2 = nodes.alice.path("group-v2.json");
    nodes.alice.run_ok(&[
        "approve-group-join",
        "--group",
        &group_id,
        "--requester",
        &bob_ref,
        "--sequence",
        "0",
        "--voting",
        "--out",
        group_v2.to_str().unwrap(),
    ]);
    let bob_group_v2 = nodes.bob.copy_to(&group_v2, "group-v2.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v2.to_str().unwrap()]);

    let open_message = nodes.bob.run_ok(&[
        "publish-party-line",
        "--group",
        &group_id,
        "--body",
        "open message",
    ]);
    assert!(stdout(&open_message).contains("published party-line message"));

    let group_v3 = nodes.alice.path("group-v3.json");
    nodes.alice.run_ok(&[
        "set-group-party-line-moderation",
        "--group",
        &group_id,
        "--moderated",
        "--out",
        group_v3.to_str().unwrap(),
    ]);
    let bob_group_v3 = nodes.bob.copy_to(&group_v3, "group-v3.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v3.to_str().unwrap()]);

    let blocked = nodes.bob.run(&[
        "publish-party-line",
        "--group",
        &group_id,
        "--body",
        "blocked message",
    ]);
    assert!(!blocked.status.success());
    assert!(
        stderr(&blocked).contains("not a member") || stderr(&blocked).contains("posting rights")
    );

    let group_v4 = nodes.alice.path("group-v4.json");
    nodes.alice.run_ok(&[
        "set-group-voice",
        "--group",
        &group_id,
        "--user",
        &bob_ref,
        "--voiced",
        "--out",
        group_v4.to_str().unwrap(),
    ]);
    let bob_group_v4 = nodes.bob.copy_to(&group_v4, "group-v4.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v4.to_str().unwrap()]);

    let voiced = nodes.bob.run_ok(&[
        "publish-party-line",
        "--group",
        &group_id,
        "--body",
        "voiced message",
    ]);
    assert!(stdout(&voiced).contains("published party-line message"));
}

#[test]
fn an_expired_vote_is_visible_but_does_not_count_on_the_other_node() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);
    let vote_path = nodes.alice.path("expiring-vote.json");
    nodes.alice.run_ok(&[
        "cast-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.11",
        "--stance",
        "deny",
        "--reason-code",
        "malware",
        "--ttl-seconds",
        "1",
        "--out",
        vote_path.to_str().unwrap(),
    ]);
    std::thread::sleep(std::time::Duration::from_secs(2));
    let bob_vote = nodes.bob.copy_to(&vote_path, "expiring-vote.json");
    nodes
        .bob
        .run_ok(&["ingest-group-vote", "--file", bob_vote.to_str().unwrap()]);

    let explanation = nodes.bob.run_ok(&[
        "explain-group-vote",
        "--group",
        &group_id,
        "--target-kind",
        "ip",
        "--target-value",
        "203.0.113.11",
    ]);
    assert!(stdout(&explanation).contains("Deny (expired, does not count)"));
}

#[test]
fn a_validly_signed_group_update_from_another_federation_is_rejected() {
    let nodes = TwoNode::new();
    let group = setup_group(&nodes);
    let group_id = GroupId(Hash32(
        hex::decode(&group)
            .unwrap()
            .try_into()
            .expect("group ID is 32 bytes"),
    ));
    let foreign_key = crypto::Keypair::from_seed(&[3; 32]);
    let foreign_user = UserId {
        federation: FederationId(Hash32([0x99; 32])),
        local_id: crypto::hash(
            &[b"sf-local-id-v1".as_slice(), &foreign_key.public_key().0].concat(),
        ),
    };
    let mut foreign_group = Group {
        group_id,
        published_by: foreign_user,
        sequence: 1,
        name: "Foreign update".into(),
        description: "must not be accepted".into(),
        join_prompt: None,
        owners: vec![foreign_user],
        admins: vec![],
        voting_members: vec![foreign_user],
        non_voting_members: vec![],
        party_line_moderated: false,
        voiced_members: vec![],
        issued_at: 1,
        expires_at: None,
        supersedes: Some(0),
        signature: SignatureBytes([0; 64]),
    };
    foreign_group.signature =
        foreign_key.sign(crypto::contexts::GROUP, &foreign_group.signing_bytes());
    let json = serde_json::json!({
        "group_id": group,
        "published_by": format!("{}/{}", foreign_user.federation.0, foreign_user.local_id),
        "identity_pubkey": hex::encode(foreign_key.public_key().0),
        "sequence": foreign_group.sequence,
        "name": foreign_group.name,
        "description": foreign_group.description,
        "join_prompt": null,
        "owners": [format!("{}/{}", foreign_user.federation.0, foreign_user.local_id)],
        "admins": [],
        "voting_members": [format!("{}/{}", foreign_user.federation.0, foreign_user.local_id)],
        "non_voting_members": [],
        "party_line_moderated": false,
        "voiced_members": [],
        "issued_at": foreign_group.issued_at,
        "expires_at": null,
        "supersedes": 0,
        "signature": hex::encode(foreign_group.signature.0),
    });
    let path = nodes.bob.path("foreign-group.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
    let copied = nodes.alice.copy_to(&path, "foreign-group.json");
    let rejected = nodes
        .alice
        .run(&["ingest-group", "--file", copied.to_str().unwrap()]);
    assert!(!rejected.status.success());
    assert!(stderr(&rejected).contains("owner or admin"));
}

#[test]
#[ignore = "requires working two-node Iroh connectivity; run explicitly in a network-capable environment"]
fn two_sf_listeners_deliver_group_join_and_approval_over_iroh() {
    let nodes = TwoNode::new();
    let mut alice_listener = Listener::start(&nodes.alice);
    let mut bob_listener = Listener::start(&nodes.bob);

    nodes.alice.run_ok(&[
        "add-follow",
        "--federation",
        &nodes.bob.user.federation.0.to_string(),
        "--user",
        &nodes.bob.user.local_id.to_string(),
        "--iroh-node-id",
        &bob_listener.node_id,
    ]);
    nodes.bob.run_ok(&[
        "add-follow",
        "--federation",
        &nodes.alice.user.federation.0.to_string(),
        "--user",
        &nodes.alice.user.local_id.to_string(),
        "--iroh-node-id",
        &alice_listener.node_id,
    ]);
    assert!(
        alice_listener
            .child
            .try_wait()
            .expect("check Alice listener")
            .is_none(),
        "Alice listener exited before delivery"
    );
    assert!(
        bob_listener
            .child
            .try_wait()
            .expect("check Bob listener")
            .is_none(),
        "Bob listener exited before delivery"
    );

    let group_path = nodes.alice.path("group.json");
    let created = nodes.alice.run_ok(&[
        "create-group",
        "--name",
        "Live Iroh Group",
        "--description",
        "two listener integration",
        "--join-prompt",
        "why join?",
        "--out",
        group_path.to_str().unwrap(),
    ]);
    let group = group_id(&created);
    let bob_group = nodes.bob.copy_to(&group_path, "group.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group.to_str().unwrap()]);

    let request = nodes.bob.run(&[
        "request-group-join",
        "--group",
        &group,
        "--answer",
        "live transport",
    ]);
    assert!(
        request.status.success(),
        "request-group-join failed: {}",
        stderr(&request)
    );
    assert!(
        stdout(&request).contains("delivered to"),
        "request did not use live delivery: stdout={} stderr={}",
        stdout(&request),
        stderr(&request)
    );
    wait_for("Alice to receive Bob's join request", || {
        stdout(
            &nodes
                .alice
                .run(&["list-pending-group-joins", "--group", &group]),
        )
        .contains(&nodes.bob.user.local_id.to_string())
    });

    let bob_ref = format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    );
    let approval = nodes.alice.run(&[
        "approve-group-join",
        "--group",
        &group,
        "--requester",
        &bob_ref,
        "--sequence",
        "0",
        "--voting",
    ]);
    assert!(
        approval.status.success(),
        "approval failed: {}",
        stderr(&approval)
    );
    assert!(stdout(&approval).contains("queued group delivery"));
    let sync = nodes.alice.run_ok(&["sync"]);
    assert!(stdout(&sync).contains("delivered"));
    wait_for("Bob to receive Alice's approved group", || {
        stdout(&nodes.bob.run(&["list-groups"])).contains(&nodes.bob.user.local_id.to_string())
    });
}

#[test]
fn a_group_block_report_crosses_nodes_without_creating_local_enforcement() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);
    let alice_ref = format!(
        "{}/{}",
        nodes.alice.user.federation.0, nodes.alice.user.local_id
    );
    let report_path = nodes.bob.path("block-report.json");

    nodes.bob.run_ok(&[
        "block-group-user",
        "--group",
        &group_id,
        "--user",
        &alice_ref,
        "--reason-code",
        "abuse_report",
        "--note",
        "reported by the second node",
        "--out",
        report_path.to_str().unwrap(),
    ]);
    let alice_report = nodes.alice.copy_to(&report_path, "block-report.json");
    nodes.alice.run_ok(&[
        "ingest-group-block-report",
        "--file",
        alice_report.to_str().unwrap(),
    ]);

    let reports = nodes.alice.run_ok(&[
        "list-group-block-reports",
        "--group",
        &group_id,
        "--user",
        &alice_ref,
    ]);
    assert!(stdout(&reports).contains("abuse_report"));
    let local_blocks = nodes
        .alice
        .run_ok(&["list-blocked-group-users", "--group", &group_id]);
    assert!(stdout(&local_blocks).contains("no blocked users"));
}

#[test]
fn an_approved_member_can_deliver_an_encrypted_partyline_message() {
    let nodes = TwoNode::new();
    let group_id = setup_group(&nodes);
    let join_path = nodes.bob.path("join.json");
    nodes.bob.run_ok(&[
        "request-group-join",
        "--group",
        &group_id,
        "--answer",
        "encrypted partyline",
        "--out",
        join_path.to_str().unwrap(),
    ]);
    let alice_join = nodes.alice.copy_to(&join_path, "join.json");
    nodes.alice.run_ok(&[
        "ingest-group-join-request",
        "--file",
        alice_join.to_str().unwrap(),
    ]);
    let bob_ref = format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    );
    let group_v2 = nodes.alice.path("group-v2.json");
    nodes.alice.run_ok(&[
        "approve-group-join",
        "--group",
        &group_id,
        "--requester",
        &bob_ref,
        "--sequence",
        "0",
        "--voting",
        "--out",
        group_v2.to_str().unwrap(),
    ]);
    let bob_group_v2 = nodes.bob.copy_to(&group_v2, "group-v2.json");
    nodes
        .bob
        .run_ok(&["ingest-group", "--file", bob_group_v2.to_str().unwrap()]);

    nodes.bob.run_ok(&[
        "add-follow",
        "--federation",
        &nodes.alice.user.federation.0.to_string(),
        "--user",
        &nodes.alice.user.local_id.to_string(),
    ]);
    nodes.alice.run_ok(&[
        "add-follow",
        "--federation",
        &nodes.bob.user.federation.0.to_string(),
        "--user",
        &nodes.bob.user.local_id.to_string(),
    ]);

    // Tunnel advertisements carry each node's messaging public key. They
    // are used here only to bootstrap the existing sealed Partyline path.
    let alice_ad = nodes.alice.path("alice-ad.json");
    nodes.alice.run_ok(&[
        "offer-tunnel",
        "--description",
        "message-key bootstrap",
        "--target",
        "domain:example.com",
        "--out",
        alice_ad.to_str().unwrap(),
    ]);
    let bob_alice_ad = nodes.bob.copy_to(&alice_ad, "alice-ad.json");
    nodes.bob.run_ok(&[
        "ingest-tunnel-advertisement",
        "--file",
        bob_alice_ad.to_str().unwrap(),
    ]);
    let bob_ad = nodes.bob.path("bob-ad.json");
    nodes.bob.run_ok(&[
        "offer-tunnel",
        "--description",
        "message-key bootstrap",
        "--target",
        "domain:example.com",
        "--out",
        bob_ad.to_str().unwrap(),
    ]);
    let alice_bob_ad = nodes.alice.copy_to(&bob_ad, "bob-ad.json");
    nodes.alice.run_ok(&[
        "ingest-tunnel-advertisement",
        "--file",
        alice_bob_ad.to_str().unwrap(),
    ]);

    let out_dir = nodes.bob.path("partyline-out");
    nodes.bob.run_ok(&[
        "publish-party-line",
        "--group",
        &group_id,
        "--body",
        "encrypted hello from Bob",
        "--out-dir",
        out_dir.to_str().unwrap(),
    ]);
    let sealed = std::fs::read_dir(&out_dir)
        .expect("partyline output directory")
        .next()
        .expect("sealed Partyline export")
        .expect("read sealed Partyline export")
        .path();
    let alice_message = nodes.alice.copy_to(&sealed, "sealed-partyline.json");
    nodes.alice.run_ok(&[
        "ingest-party-line",
        "--file",
        alice_message.to_str().unwrap(),
    ]);
    let timeline = nodes
        .alice
        .run_ok(&["list-party-line", "--group", &group_id]);
    assert!(stdout(&timeline).contains("encrypted hello from Bob"));
}

#[test]
fn same_federation_nodes_complete_a_tunnel_handshake() {
    let nodes = TwoNode::new();
    nodes.bob.run_ok(&[
        "add-follow",
        "--federation",
        &nodes.alice.user.federation.0.to_string(),
        "--user",
        &nodes.alice.user.local_id.to_string(),
    ]);

    let advertisement = nodes.alice.path("advertisement.json");
    nodes.alice.run_ok(&[
        "offer-tunnel",
        "--description",
        "same federation test tunnel",
        "--target",
        "domain:example.com",
        "--out",
        advertisement.to_str().unwrap(),
    ]);
    let bob_advertisement = nodes.bob.copy_to(&advertisement, "advertisement.json");
    nodes.bob.run_ok(&[
        "ingest-tunnel-advertisement",
        "--file",
        bob_advertisement.to_str().unwrap(),
    ]);

    let advertisement_ref = format!(
        "{}/{}/0",
        nodes.alice.user.federation.0, nodes.alice.user.local_id
    );
    let request = nodes.bob.path("tunnel-request.json");
    nodes.bob.run_ok(&[
        "request-tunnel",
        "--advertisement",
        &advertisement_ref,
        "--out",
        request.to_str().unwrap(),
    ]);
    let alice_request = nodes.alice.copy_to(&request, "tunnel-request.json");
    nodes.alice.run_ok(&[
        "ingest-tunnel-request",
        "--file",
        alice_request.to_str().unwrap(),
    ]);

    let requester = format!(
        "{}/{}",
        nodes.bob.user.federation.0, nodes.bob.user.local_id
    );
    let accept = nodes.alice.path("tunnel-accept.json");
    nodes.alice.run_ok(&[
        "accept-tunnel-request",
        "--requester",
        &requester,
        "--sequence",
        "0",
        "--out",
        accept.to_str().unwrap(),
    ]);
    let bob_accept = nodes.bob.copy_to(&accept, "tunnel-accept.json");
    let ingested = nodes.bob.run_ok(&[
        "ingest-tunnel-accept",
        "--file",
        bob_accept.to_str().unwrap(),
    ]);
    assert!(stdout(&ingested).contains("10.99.0.1"));
    assert!(stdout(&ingested).contains("fd99::c8:1"));
}

#[test]
fn same_federation_nodes_replicate_and_evaluate_a_shared_policy() {
    let nodes = TwoNode::new();
    nodes.bob.run_ok(&[
        "add-follow",
        "--federation",
        &nodes.alice.user.federation.0.to_string(),
        "--user",
        &nodes.alice.user.local_id.to_string(),
    ]);
    let entries = nodes.alice.path("policy-entries.json");
    std::fs::write(
        &entries,
        r#"[{"target_kind":"domain","target_value":"tracker.example","stance":"deny","reason_code":"tracker","reason_note":"shared test"}]"#,
    )
    .unwrap();
    let policy = nodes.alice.path("policy.json");
    nodes.alice.run_ok(&[
        "publish-list",
        "--name",
        "Shared tracker policy",
        "--description",
        "same federation policy",
        "--category",
        "privacy",
        "--entries-file",
        entries.to_str().unwrap(),
        "--visibility",
        "public",
        "--out",
        policy.to_str().unwrap(),
    ]);
    let bob_policy = nodes.bob.copy_to(&policy, "policy.json");
    nodes
        .bob
        .run_ok(&["ingest-list", "--file", bob_policy.to_str().unwrap()]);

    let decision = nodes.bob.run_ok(&[
        "evaluate-target",
        "--target-kind",
        "domain",
        "--target-value",
        "tracker.example",
    ]);
    assert!(stdout(&decision).contains("decision   : Deny"));
}
