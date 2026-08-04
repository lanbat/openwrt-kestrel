//! End-to-end tests against the actual built `sf` binary — each test gets
//! its own temp directory so separate "nodes" (alice/bob/carol) never share
//! a database. These exercise the same scenarios verified manually during
//! development: no-signal, unfollowed-opinion, threshold-crossing,
//! local-override precedence, and signature tampering.

use std::path::Path;
use std::process::{Command, Output};

fn sf(dir: &Path, db: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sf"))
        .arg("--db")
        .arg(dir.join(db))
        .args(args)
        .output()
        .expect("failed to spawn sf binary")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Pulls `federation`, `local_id`, `public_key` hex values out of
/// `init-identity`'s stdout so a test can pass them to `add-follow`.
struct Identity {
    federation: String,
    local_id: String,
}

fn init_identity(dir: &Path, db: &str, display_name: &str) -> Identity {
    let out = sf(dir, db, &["init-identity", "--display-name", display_name]);
    assert!(out.status.success(), "init-identity failed: {}", stderr(&out));
    let text = stdout(&out);
    let field = |label: &str| -> String {
        text.lines()
            .find(|l| l.trim_start().starts_with(label))
            .and_then(|l| l.split(':').nth(1))
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| panic!("missing `{label}` in init-identity output:\n{text}"))
    };
    Identity { federation: field("federation"), local_id: field("local_id") }
}

#[test]
fn init_identity_then_evaluate_with_no_signal_is_no_decision() {
    let dir = tempfile::tempdir().unwrap();
    init_identity(dir.path(), "node.sqlite", "solo");

    let out = sf(dir.path(), "node.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("decision   : NoDecision"), "expected NoDecision, got:\n{text}");
}

#[test]
fn init_identity_twice_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    init_identity(dir.path(), "node.sqlite", "first");

    let out = sf(dir.path(), "node.sqlite", &["init-identity"]);
    assert!(!out.status.success(), "second init-identity should have failed");
    assert!(stderr(&out).contains("already exists"), "unexpected error: {}", stderr(&out));
}

#[test]
fn full_publish_export_ingest_flow_reaches_deny_once_followed() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let export_path = alice_dir.path().join("opinion.json");

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let publish = sf(
        alice_dir.path(),
        "alice.sqlite",
        &[
            "publish-opinion",
            "--target-kind", "domain",
            "--target-value", "ads.example",
            "--stance", "deny",
            "--reason-code", "tracker",
            "--note", "phones home constantly",
            "--out", export_path.to_str().unwrap(),
        ],
    );
    assert!(publish.status.success(), "publish-opinion failed: {}", stderr(&publish));
    assert!(export_path.exists(), "expected exported opinion file to exist");

    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    // Copy the exported file into bob's directory so bob's ingest-opinion
    // reads it from his own working set (simulating a sync transport
    // having delivered it).
    let bob_copy = bob_dir.path().join("from-alice.json");
    std::fs::copy(&export_path, &bob_copy).unwrap();

    let ingest = sf(bob_dir.path(), "bob.sqlite", &["ingest-opinion", "--file", bob_copy.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-opinion failed: {}", stderr(&ingest));

    // Before following alice: the opinion is stored but carries no trust
    // weight, so it must not affect the decision.
    let before = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example"]);
    let before_text = stdout(&before);
    assert!(before_text.contains("decision   : NoDecision"), "expected NoDecision before following, got:\n{before_text}");
    assert!(before_text.contains("NoTrustWeight"), "expected the unfollowed opinion to be listed as ignored:\n{before_text}");

    let follow = sf(
        bob_dir.path(),
        "bob.sqlite",
        &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id, "--allow-weight", "0.3", "--deny-weight", "1.0"],
    );
    assert!(follow.status.success(), "add-follow failed: {}", stderr(&follow));

    let after = sf(
        bob_dir.path(),
        "bob.sqlite",
        &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example", "--threshold", "0.5"],
    );
    let after_text = stdout(&after);
    assert!(after_text.contains("decision   : Deny"), "expected Deny after following with enough weight, got:\n{after_text}");
    assert!(after_text.contains("tier       : TrustWeighted"));
}

#[test]
fn local_override_beats_trust_weighted_aggregation() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let export_path = alice_dir.path().join("opinion.json");

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    sf(
        alice_dir.path(),
        "alice.sqlite",
        &[
            "publish-opinion", "--target-kind", "domain", "--target-value", "ads.example",
            "--stance", "deny", "--reason-code", "tracker", "--out", export_path.to_str().unwrap(),
        ],
    );

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    sf(bob_dir.path(), "bob.sqlite", &["ingest-opinion", "--file", export_path.to_str().unwrap()]);
    sf(
        bob_dir.path(),
        "bob.sqlite",
        &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id, "--allow-weight", "1.0", "--deny-weight", "5.0"],
    );

    // Unanimous, well-above-threshold deny signal from a followed user...
    let before = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example", "--threshold", "0.5"]);
    assert!(stdout(&before).contains("decision   : Deny"));

    // ...but the owner's own local override must still win outright.
    sf(bob_dir.path(), "bob.sqlite", &["set-override", "--target-kind", "domain", "--target-value", "ads.example", "--stance", "allow", "--note", "trust the household"]);
    let after = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example", "--threshold", "0.5"]);
    let text = stdout(&after);
    assert!(text.contains("decision   : Allow"), "expected local override to win, got:\n{text}");
    assert!(text.contains("tier       : LocalOverride"));
}

#[test]
fn conflicting_opinions_below_threshold_fall_to_ask_not_a_coin_flip() {
    let alice_dir = tempfile::tempdir().unwrap();
    let dave_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let alice_export = alice_dir.path().join("opinion.json");
    sf(
        alice_dir.path(), "alice.sqlite",
        &["publish-opinion", "--target-kind", "domain", "--target-value", "cdn.example", "--stance", "deny", "--reason-code", "tracker", "--out", alice_export.to_str().unwrap()],
    );

    let dave = init_identity(dave_dir.path(), "dave.sqlite", "dave");
    let dave_export = dave_dir.path().join("opinion.json");
    sf(
        dave_dir.path(), "dave.sqlite",
        &["publish-opinion", "--target-kind", "domain", "--target-value", "cdn.example", "--stance", "allow", "--reason-code", "known_good_cdn", "--out", dave_export.to_str().unwrap()],
    );

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    sf(bob_dir.path(), "bob.sqlite", &["ingest-opinion", "--file", alice_export.to_str().unwrap()]);
    sf(bob_dir.path(), "bob.sqlite", &["ingest-opinion", "--file", dave_export.to_str().unwrap()]);
    sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id, "--allow-weight", "0.6", "--deny-weight", "0.6"]);
    sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &dave.federation, "--user", &dave.local_id, "--allow-weight", "0.4", "--deny-weight", "0.4"]);

    let out = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "cdn.example", "--threshold", "1.0"]);
    let text = stdout(&out);
    assert!(text.contains("decision   : Ask"), "neither side crosses threshold — must not silently pick a winner, got:\n{text}");
}

#[test]
fn tampered_opinion_signature_is_rejected_on_ingest() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let export_path = alice_dir.path().join("opinion.json");

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    sf(
        alice_dir.path(), "alice.sqlite",
        &["publish-opinion", "--target-kind", "domain", "--target-value", "ads.example", "--stance", "deny", "--reason-code", "tracker", "--out", export_path.to_str().unwrap()],
    );

    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
    json["stance"] = serde_json::Value::String("allow".into());
    let tampered_path = bob_dir.path().join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-opinion", "--file", tampered_path.to_str().unwrap()]);
    assert!(!out.status.success(), "ingesting a tampered opinion must fail");
    assert!(stderr(&out).contains("signature verification failed"), "unexpected error: {}", stderr(&out));
}

#[test]
fn tampered_tunnel_advertisement_signature_is_rejected_on_ingest() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let export_path = alice_dir.path().join("advert.json");

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let offer = sf(
        alice_dir.path(), "alice.sqlite",
        &["offer-tunnel", "--description", "EU exit", "--target", "domain:example.com", "--visibility", "public", "--out", export_path.to_str().unwrap()],
    );
    assert!(offer.status.success(), "offer-tunnel failed: {}", stderr(&offer));

    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
    json["description"] = serde_json::Value::String("free unlimited VPN, definitely not a trap".into());
    let tampered_path = bob_dir.path().join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-advertisement", "--file", tampered_path.to_str().unwrap()]);
    assert!(!out.status.success(), "ingesting a tampered tunnel advertisement must fail");
    assert!(stderr(&out).contains("signature verification failed"), "unexpected error: {}", stderr(&out));
}

#[test]
fn offer_tunnel_rejects_more_than_five_tags() {
    let dir = tempfile::tempdir().unwrap();
    init_identity(dir.path(), "node.sqlite", "solo");

    let mut args = vec!["offer-tunnel", "--description", "EU exit", "--target", "domain:example.com", "--visibility", "public"];
    for tag in ["a", "b", "c", "d", "e", "f"] {
        args.push("--tag");
        args.push(tag);
    }
    let out = sf(dir.path(), "node.sqlite", &args);
    assert!(!out.status.success(), "publishing an advertisement with 6 tags must be rejected, not truncated to 5");
}

#[test]
fn tunnel_advertisement_tags_round_trip_and_a_tampered_extra_tag_is_rejected_on_ingest() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let export_path = alice_dir.path().join("advert.json");

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let offer = sf(
        alice_dir.path(), "alice.sqlite",
        &["offer-tunnel", "--description", "EU exit", "--target", "domain:example.com", "--tag", "streaming", "--tag", "gaming", "--visibility", "public", "--out", export_path.to_str().unwrap()],
    );
    assert!(offer.status.success(), "offer-tunnel failed: {}", stderr(&offer));

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    let follow = sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id]);
    assert!(follow.status.success(), "add-follow failed: {}", stderr(&follow));
    let bob_copy = bob_dir.path().join("advert.json");
    std::fs::copy(&export_path, &bob_copy).unwrap();
    let ingest = sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-advertisement", "--file", bob_copy.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-tunnel-advertisement failed: {}", stderr(&ingest));
    assert!(stdout(&sf(bob_dir.path(), "bob.sqlite", &["list-tunnels"])).contains("EU exit"));

    // A peer's own client can't be trusted to have applied the cap —
    // tamper the exported file to smuggle in a 6th tag and confirm
    // ingest still rejects it, not just the publish-time check.
    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
    json["tags"] = serde_json::json!(["streaming", "gaming", "c", "d", "e", "f"]);
    let tampered_path = bob_dir.path().join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();
    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-advertisement", "--file", tampered_path.to_str().unwrap()]);
    assert!(!out.status.success(), "an advertisement with more than 5 tags must be rejected at ingest too, since it's now a different signed payload and would fail signature verification regardless — but the tag-count check must never be bypassed either way");
}

#[test]
fn tunnel_advertisement_connection_and_bandwidth_limits_round_trip_through_export_and_ingest() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let export_path = alice_dir.path().join("advert.json");

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let offer = sf(
        alice_dir.path(), "alice.sqlite",
        &["offer-tunnel", "--description", "EU exit", "--target", "domain:example.com", "--max-connections", "50", "--max-bandwidth-kbps", "8000", "--visibility", "public", "--out", export_path.to_str().unwrap()],
    );
    assert!(offer.status.success(), "offer-tunnel failed: {}", stderr(&offer));

    let exported: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
    assert_eq!(exported["max_connections"], 50);
    assert_eq!(exported["max_bandwidth_kbps"], 8000);

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    let follow = sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id]);
    assert!(follow.status.success(), "add-follow failed: {}", stderr(&follow));
    let bob_copy = bob_dir.path().join("advert.json");
    std::fs::copy(&export_path, &bob_copy).unwrap();
    let ingest = sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-advertisement", "--file", bob_copy.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-tunnel-advertisement failed: {}", stderr(&ingest));
}

#[test]
fn full_tunnel_handshake_flow_reaches_a_selected_route() {
    // Regression coverage for three real bugs manual end-to-end testing
    // caught that no unit test had: (1) `offer-tunnel` originally called
    // the follow-gated `ingest_tunnel_advertisement`, so publishing your
    // own advertisement failed with "not a followed user" — about
    // yourself; (2) `ingest-tunnel-accept` never created the consumer's
    // own `provisioned_tunnels` row, so `select-tunnel` failed a foreign-
    // key check; (3) `tunnel_connection_accepts` was missing a
    // `provider_local_id` column, so the reconstructed provider UserId
    // silently borrowed the requester's own local_id instead.
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let bob = init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let follow = sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id]);
    assert!(follow.status.success(), "add-follow failed: {}", stderr(&follow));

    let advert_path = alice_dir.path().join("advert.json");
    let offer = sf(
        alice_dir.path(), "alice.sqlite",
        &["offer-tunnel", "--description", "EU exit", "--target", "domain:example.com", "--visibility", "public", "--out", advert_path.to_str().unwrap()],
    );
    assert!(offer.status.success(), "offer-tunnel failed: {}", stderr(&offer));

    let bob_advert = bob_dir.path().join("advert.json");
    std::fs::copy(&advert_path, &bob_advert).unwrap();
    let ingest_ad = sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-advertisement", "--file", bob_advert.to_str().unwrap()]);
    assert!(ingest_ad.status.success(), "ingest-tunnel-advertisement failed: {}", stderr(&ingest_ad));

    let advertisement_ref = format!("{}/{}/0", alice.federation, alice.local_id);
    let request_path = bob_dir.path().join("request.json");
    let request = sf(bob_dir.path(), "bob.sqlite", &["request-tunnel", "--advertisement", &advertisement_ref, "--out", request_path.to_str().unwrap()]);
    assert!(request.status.success(), "request-tunnel failed: {}", stderr(&request));

    let alice_request = alice_dir.path().join("request.json");
    std::fs::copy(&request_path, &alice_request).unwrap();
    let ingest_req = sf(alice_dir.path(), "alice.sqlite", &["ingest-tunnel-request", "--file", alice_request.to_str().unwrap()]);
    assert!(ingest_req.status.success(), "ingest-tunnel-request failed: {}", stderr(&ingest_req));

    let pending = sf(alice_dir.path(), "alice.sqlite", &["list-pending-tunnel-requests"]);
    assert!(stdout(&pending).contains(&bob.federation), "expected bob's request to be listed as pending:\n{}", stdout(&pending));

    let requester_ref = format!("{}/{}", bob.federation, bob.local_id);
    let accept_path = alice_dir.path().join("accept.json");
    let accept = sf(
        alice_dir.path(), "alice.sqlite",
        &["accept-tunnel-request", "--requester", &requester_ref, "--sequence", "0", "--out", accept_path.to_str().unwrap()],
    );
    assert!(accept.status.success(), "accept-tunnel-request failed: {}", stderr(&accept));

    let bob_accept = bob_dir.path().join("accept.json");
    std::fs::copy(&accept_path, &bob_accept).unwrap();
    let ingest_accept = sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-accept", "--file", bob_accept.to_str().unwrap()]);
    assert!(ingest_accept.status.success(), "ingest-tunnel-accept failed: {}", stderr(&ingest_accept));
    assert!(stdout(&ingest_accept).contains("10.99.0.1"), "expected the assigned tunnel IP in output:\n{}", stdout(&ingest_accept));
    assert!(stdout(&ingest_accept).contains("fd99::c8:1"), "every social-firewall tunnel is dual-stack — expected an assigned IPv6 address too, got:\n{}", stdout(&ingest_accept));

    // This is the step that failed with a foreign-key error before bug #2
    // was fixed — the real proof this whole flow is wired correctly end
    // to end, not just that each step individually returns success.
    let select = sf(bob_dir.path(), "bob.sqlite", &["select-tunnel", "--advertisement", &advertisement_ref, "--target", "domain:example.com"]);
    assert!(select.status.success(), "select-tunnel failed: {}", stderr(&select));
    assert!(stdout(&select).contains(&alice.federation), "expected the selection to reference alice (the provider), got:\n{}", stdout(&select));
}

#[test]
fn request_tunnel_falls_back_to_file_export_when_no_iroh_node_id_is_known() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    // `ingest-tunnel-advertisement` is follow-gated (see
    // `StateStore::ingest_tunnel_advertisement`), so bob must follow
    // alice before ingesting her advertisement — the brief's Step 6 draft
    // had this the other way around, which doesn't work against the
    // actual current code; reordered here the same way the existing
    // `full_tunnel_handshake_flow_reaches_a_selected_route` test above
    // already does it.
    assert!(sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id, "--allow-weight", "1.0", "--deny-weight", "1.0"]).status.success());

    let ad_path = alice_dir.path().join("ad.json");
    let offer = sf(alice_dir.path(), "alice.sqlite", &["offer-tunnel", "--description", "d", "--target", "domain:example.com", "--visibility", "public", "--out", ad_path.to_str().unwrap()]);
    assert!(offer.status.success(), "offer-tunnel failed: {}", stderr(&offer));

    let bob_ad = bob_dir.path().join("ad.json");
    std::fs::copy(&ad_path, &bob_ad).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-tunnel-advertisement", "--file", bob_ad.to_str().unwrap()]).status.success());

    // No `set-follow-node-id` was ever run — bob has no known Iroh
    // address for alice, so delivery must fall back to the file.
    let out_path = bob_dir.path().join("request.json");
    let request = sf(bob_dir.path(), "bob.sqlite", &["request-tunnel", "--advertisement", &format!("{}/{}/0", alice.federation, alice.local_id), "--out", out_path.to_str().unwrap()]);
    assert!(request.status.success(), "request-tunnel failed: {}", stderr(&request));
    assert!(stdout(&request).contains("not known or unreachable") || stdout(&request).contains("exported"), "expected a fallback-to-file message, got:\n{}", stdout(&request));
    assert!(out_path.exists(), "the fallback file export must still happen when no Iroh address is known");
}

#[test]
fn full_shared_rule_list_flow_reaches_trust_weighted_deny() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let follow = sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id]);
    assert!(follow.status.success(), "add-follow failed: {}", stderr(&follow));

    let entries_path = alice_dir.path().join("entries.json");
    std::fs::write(
        &entries_path,
        r#"[
            {"target_kind": "domain", "target_value": "ads.example", "stance": "deny", "reason_code": "tracker", "reason_note": "known ad tracker"},
            {"target_kind": "domain", "target_value": "cdn.example", "stance": "allow", "reason_code": "known_good_cdn", "reason_note": null}
        ]"#,
    )
    .unwrap();

    let list_path = alice_dir.path().join("list.json");
    let publish = sf(
        alice_dir.path(), "alice.sqlite",
        &["publish-list", "--name", "known trackers", "--description", "confirmed trackers", "--category", "privacy", "--category", "ads", "--entries-file", entries_path.to_str().unwrap(), "--visibility", "public", "--out", list_path.to_str().unwrap()],
    );
    assert!(publish.status.success(), "publish-list failed: {}", stderr(&publish));

    let bob_list = bob_dir.path().join("list.json");
    std::fs::copy(&list_path, &bob_list).unwrap();
    let ingest = sf(bob_dir.path(), "bob.sqlite", &["ingest-list", "--file", bob_list.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-list failed: {}", stderr(&ingest));

    let deny = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example"]);
    assert!(stdout(&deny).contains("decision   : Deny"), "expected the list's Deny entry to reach trust-weighted aggregation, got:\n{}", stdout(&deny));

    let allow = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "cdn.example"]);
    assert!(stdout(&allow).contains("decision   : Allow"), "expected the list's Allow entry to reach trust-weighted aggregation, got:\n{}", stdout(&allow));

    // A non-matching category filter must exclude this list's entries...
    let filter_out = sf(bob_dir.path(), "bob.sqlite", &["set-follow-category-filter", "--federation", &alice.federation, "--user", &alice.local_id, "--category", "security"]);
    assert!(filter_out.status.success(), "set-follow-category-filter failed: {}", stderr(&filter_out));
    let no_decision = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example"]);
    assert!(stdout(&no_decision).contains("decision   : NoDecision"), "a non-matching category_filter must exclude this list's entries, got:\n{}", stdout(&no_decision));

    // ...but a matching one must let it count again.
    let filter_in = sf(bob_dir.path(), "bob.sqlite", &["set-follow-category-filter", "--federation", &alice.federation, "--user", &alice.local_id, "--category", "privacy"]);
    assert!(filter_in.status.success(), "set-follow-category-filter failed: {}", stderr(&filter_in));
    let deny_again = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "domain", "--target-value", "ads.example"]);
    assert!(stdout(&deny_again).contains("decision   : Deny"), "a matching category_filter must let the list's entries count, got:\n{}", stdout(&deny_again));
}

#[test]
fn tampered_shared_rule_list_signature_is_rejected_on_ingest() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let entries_path = alice_dir.path().join("entries.json");
    std::fs::write(&entries_path, r#"[{"target_kind": "domain", "target_value": "ads.example", "stance": "deny", "reason_code": "tracker", "reason_note": null}]"#).unwrap();

    let list_path = alice_dir.path().join("list.json");
    let publish = sf(
        alice_dir.path(), "alice.sqlite",
        &["publish-list", "--name", "known trackers", "--description", "d", "--entries-file", entries_path.to_str().unwrap(), "--visibility", "public", "--out", list_path.to_str().unwrap()],
    );
    assert!(publish.status.success(), "publish-list failed: {}", stderr(&publish));

    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&list_path).unwrap()).unwrap();
    json["name"] = serde_json::Value::String("totally legit list, please subscribe".into());
    let tampered_path = bob_dir.path().join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-list", "--file", tampered_path.to_str().unwrap()]);
    assert!(!out.status.success(), "ingesting a tampered shared rule list must fail");
    assert!(stderr(&out).contains("signature verification failed"), "unexpected error: {}", stderr(&out));
}

fn extract_group_id(create_output: &Output) -> String {
    let text = stdout(create_output);
    let line = text.lines().find(|l| l.starts_with("created group")).expect("expected a \"created group <id>\" line");
    line.split_whitespace().nth(2).expect("expected a group id in the output").to_string()
}

#[test]
fn full_group_flow_join_approve_vote_reaches_trust_weighted_deny() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let _alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let bob = init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "neighborhood watch", "--description", "trusted local ops", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    let bob_group = bob_dir.path().join("group.json");
    std::fs::copy(&group_path, &bob_group).unwrap();
    let ingest_group = sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group.to_str().unwrap()]);
    assert!(ingest_group.status.success(), "ingest-group failed: {}", stderr(&ingest_group));

    let join_path = bob_dir.path().join("join.json");
    let request_join = sf(bob_dir.path(), "bob.sqlite", &["request-group-join", "--group", &group_id, "--out", join_path.to_str().unwrap()]);
    assert!(request_join.status.success(), "request-group-join failed: {}", stderr(&request_join));

    let alice_join = alice_dir.path().join("join.json");
    std::fs::copy(&join_path, &alice_join).unwrap();
    let ingest_join = sf(alice_dir.path(), "alice.sqlite", &["ingest-group-join-request", "--file", alice_join.to_str().unwrap()]);
    assert!(ingest_join.status.success(), "ingest-group-join-request failed: {}", stderr(&ingest_join));

    let bob_ref = format!("{}/{}", bob.federation, bob.local_id);
    let group_v2_path = alice_dir.path().join("group_v2.json");
    let approve = sf(alice_dir.path(), "alice.sqlite", &["approve-group-join", "--group", &group_id, "--requester", &bob_ref, "--sequence", "0", "--voting", "--out", group_v2_path.to_str().unwrap()]);
    assert!(approve.status.success(), "approve-group-join failed: {}", stderr(&approve));

    let bob_group_v2 = bob_dir.path().join("group_v2.json");
    std::fs::copy(&group_v2_path, &bob_group_v2).unwrap();
    let ingest_v2 = sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group_v2.to_str().unwrap()]);
    assert!(ingest_v2.status.success(), "ingest-group (v2) failed: {}", stderr(&ingest_v2));
    assert!(stdout(&sf(bob_dir.path(), "bob.sqlite", &["list-groups"])).contains(&bob.federation), "bob must now appear in the group's membership");

    // Alice and bob both vote Deny on behalf of the group.
    let alice_vote_path = alice_dir.path().join("alice_vote.json");
    let alice_vote = sf(alice_dir.path(), "alice.sqlite", &["cast-group-vote", "--group", &group_id, "--target-kind", "ip", "--target-value", "203.0.113.9", "--stance", "deny", "--reason-code", "malware", "--out", alice_vote_path.to_str().unwrap()]);
    assert!(alice_vote.status.success(), "cast-group-vote (alice) failed: {}", stderr(&alice_vote));
    let bob_vote = sf(bob_dir.path(), "bob.sqlite", &["cast-group-vote", "--group", &group_id, "--target-kind", "ip", "--target-value", "203.0.113.9", "--stance", "deny", "--reason-code", "malware"]);
    assert!(bob_vote.status.success(), "cast-group-vote (bob) failed: {}", stderr(&bob_vote));

    let bob_alice_vote = bob_dir.path().join("alice_vote.json");
    std::fs::copy(&alice_vote_path, &bob_alice_vote).unwrap();
    let ingest_vote = sf(bob_dir.path(), "bob.sqlite", &["ingest-group-vote", "--file", bob_alice_vote.to_str().unwrap()]);
    assert!(ingest_vote.status.success(), "ingest-group-vote failed: {}", stderr(&ingest_vote));

    let trust = sf(bob_dir.path(), "bob.sqlite", &["set-group-trust", "--group", &group_id, "--allow-weight", "1.0", "--deny-weight", "1.0"]);
    assert!(trust.status.success(), "set-group-trust failed: {}", stderr(&trust));

    let eval = sf(bob_dir.path(), "bob.sqlite", &["evaluate-target", "--target-kind", "ip", "--target-value", "203.0.113.9"]);
    assert!(stdout(&eval).contains("decision   : Deny"), "expected the group's 2-0 majority to drive a Deny decision, got:\n{}", stdout(&eval));
    assert!(stdout(&eval).contains(&format!("group {group_id}")), "expected the explanation to attribute the group as the source, got:\n{}", stdout(&eval));

    // The per-voter breakdown behind that 2-0 majority must be visible
    // on bob's node too, not just the collapsed tally.
    let explain = sf(bob_dir.path(), "bob.sqlite", &["explain-group-vote", "--group", &group_id, "--target-kind", "ip", "--target-value", "203.0.113.9"]);
    assert!(explain.status.success(), "explain-group-vote failed: {}", stderr(&explain));
    let explain_out = stdout(&explain);
    assert!(explain_out.contains(&bob.federation), "expected bob's own vote to show up in the breakdown, got:\n{explain_out}");
    assert!(explain_out.contains("Deny (counts)"), "expected a Deny vote marked as counting, got:\n{explain_out}");
}

#[test]
fn ingest_group_rejects_zero_owners() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let group_path = alice_dir.path().join("group.json");

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "x", "--description", "y", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));

    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&group_path).unwrap()).unwrap();
    json["owners"] = serde_json::json!([]);
    let tampered_path = bob_dir.path().join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", tampered_path.to_str().unwrap()]);
    assert!(!out.status.success(), "a group with zero owners must be rejected, not accepted");
}

#[test]
fn ingest_group_rejects_a_forged_update_from_a_non_owner() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();
    let group_path = alice_dir.path().join("group.json");

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "x", "--description", "y", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));

    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    let bob_group = bob_dir.path().join("group.json");
    std::fs::copy(&group_path, &bob_group).unwrap();
    let ingest = sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-group failed: {}", stderr(&ingest));

    // Bob is not an owner/admin — his own signed "update" naming himself
    // owner must be rejected, whether by signature mismatch (the group_id/
    // sequence were tampered to look like a supersede) or by the
    // authorization check — either way, never silently accepted.
    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&group_path).unwrap()).unwrap();
    json["sequence"] = serde_json::json!(1);
    json["supersedes"] = serde_json::json!(0);
    let forged_path = bob_dir.path().join("forged.json");
    std::fs::write(&forged_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", forged_path.to_str().unwrap()]);
    assert!(!out.status.success(), "a group update from a non-owner must be rejected");
}

#[test]
fn full_device_approval_flow_reaches_a_trust_weighted_deny() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let follow = sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id, "--allow-weight", "1.0", "--deny-weight", "1.0"]);
    assert!(follow.status.success(), "add-follow failed: {}", stderr(&follow));

    let approval_path = alice_dir.path().join("approval.json");
    let publish = sf(
        alice_dir.path(),
        "alice.sqlite",
        &["publish-device-approval", "--mac", "AA:BB:CC:DD:EE:FF", "--stance", "deny", "--reason-code", "malware", "--note", "botnet C2 beacon", "--label", "shady-iot-cam", "--out", approval_path.to_str().unwrap()],
    );
    assert!(publish.status.success(), "publish-device-approval failed: {}", stderr(&publish));

    let bob_approval = bob_dir.path().join("approval.json");
    std::fs::copy(&approval_path, &bob_approval).unwrap();
    let ingest = sf(bob_dir.path(), "bob.sqlite", &["ingest-device-approval", "--file", bob_approval.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-device-approval failed: {}", stderr(&ingest));

    let list = sf(bob_dir.path(), "bob.sqlite", &["list-device-approvals", "--mac", "aa:bb:cc:dd:ee:ff"]);
    assert!(stdout(&list).contains("shady-iot-cam"), "expected the device label to show up, got:\n{}", stdout(&list));

    let eval = sf(bob_dir.path(), "bob.sqlite", &["evaluate-device", "--mac", "AA:BB:CC:DD:EE:FF"]);
    assert!(stdout(&eval).contains("decision   : Deny"), "expected a trusted Deny opinion to drive the aggregate decision, got:\n{}", stdout(&eval));
}

#[test]
fn list_party_line_shows_an_irc_style_join_line_when_a_member_is_approved() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let _alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let bob = init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "neighborhood watch", "--description", "trusted local ops", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    // Alice's own party line is empty before bob ever joins.
    let empty = sf(alice_dir.path(), "alice.sqlite", &["list-party-line", "--group", &group_id]);
    assert!(stdout(&empty).contains("no party-line activity"), "expected no activity yet, got:\n{}", stdout(&empty));

    let bob_group = bob_dir.path().join("group.json");
    std::fs::copy(&group_path, &bob_group).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group.to_str().unwrap()]).status.success());

    let join_path = bob_dir.path().join("join.json");
    assert!(sf(bob_dir.path(), "bob.sqlite", &["request-group-join", "--group", &group_id, "--out", join_path.to_str().unwrap()]).status.success());

    let alice_join = alice_dir.path().join("join.json");
    std::fs::copy(&join_path, &alice_join).unwrap();
    assert!(sf(alice_dir.path(), "alice.sqlite", &["ingest-group-join-request", "--file", alice_join.to_str().unwrap()]).status.success());

    let bob_ref = format!("{}/{}", bob.federation, bob.local_id);
    let approve = sf(alice_dir.path(), "alice.sqlite", &["approve-group-join", "--group", &group_id, "--requester", &bob_ref, "--sequence", "0", "--voting"]);
    assert!(approve.status.success(), "approve-group-join failed: {}", stderr(&approve));

    // Alice republished the group locally as part of approving — her own
    // party line should already show bob's join, with no export/ingest
    // round-trip needed (the event is derived purely from her own
    // ingest_group diff).
    let party_line = sf(alice_dir.path(), "alice.sqlite", &["list-party-line", "--group", &group_id]);
    assert!(party_line.status.success(), "list-party-line failed: {}", stderr(&party_line));
    let out = stdout(&party_line);
    assert!(out.contains("*** ") && out.contains("has joined the group"), "expected an IRC-style join line, got:\n{out}");
    // No display name was ever set for bob on alice's node, so nick and
    // ident both fall back to bob's truncated local_id (first 8 hex
    // chars) and host falls back to bob's federation's truncated hex —
    // alice has no `federations` row for a federation that isn't her own.
    let ident = &bob.local_id[..8];
    assert!(out.contains(ident), "expected the fallback truncated local_id `{ident}` in the join line, got:\n{out}");
    assert!(out.contains(".fed"), "expected the fallback `.fed` host suffix for bob's unknown-to-alice federation, got:\n{out}");
}

#[test]
fn list_party_line_shows_a_cast_group_vote() {
    let alice_dir = tempfile::tempdir().unwrap();
    let _alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "neighborhood watch", "--description", "trusted local ops", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    let vote = sf(alice_dir.path(), "alice.sqlite", &["cast-group-vote", "--group", &group_id, "--target-kind", "domain", "--target-value", "ads.example", "--stance", "deny", "--reason-code", "malware"]);
    assert!(vote.status.success(), "cast-group-vote failed: {}", stderr(&vote));

    let party_line = sf(alice_dir.path(), "alice.sqlite", &["list-party-line", "--group", &group_id]);
    assert!(party_line.status.success(), "list-party-line failed: {}", stderr(&party_line));
    let out = stdout(&party_line);
    assert!(out.contains("voted") && out.contains("domain:ads.example") && out.contains("deny"), "expected the cast vote to show up in the party line, got:\n{out}");
    assert!(out.contains("poll: deny 1"), "expected an inline poll tally after the vote, got:\n{out}");
}

#[test]
fn list_party_line_shows_a_structured_reply_comment_on_a_vote() {
    let alice_dir = tempfile::tempdir().unwrap();
    let _alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "neighborhood watch", "--description", "trusted local ops", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    let vote = sf(alice_dir.path(), "alice.sqlite", &["cast-group-vote", "--group", &group_id, "--target-kind", "domain", "--target-value", "ads.example", "--stance", "deny", "--reason-code", "malware"]);
    assert!(vote.status.success(), "cast-group-vote failed: {}", stderr(&vote));

    let out_dir = alice_dir.path().join("out");
    let comment = sf(
        alice_dir.path(),
        "alice.sqlite",
        &["publish-party-line", "--group", &group_id, "--body", "actually this is our CDN, not malware", "--re-target-kind", "domain", "--re-target-value", "ads.example", "--out-dir", out_dir.to_str().unwrap()],
    );
    assert!(comment.status.success(), "publish-party-line with a reply target failed: {}", stderr(&comment));

    let party_line = sf(alice_dir.path(), "alice.sqlite", &["list-party-line", "--group", &group_id]);
    assert!(party_line.status.success(), "list-party-line failed: {}", stderr(&party_line));
    let out = stdout(&party_line);
    assert!(out.contains("(re: domain:ads.example)"), "expected the comment to show its structured reply target, got:\n{out}");
    assert!(out.contains("actually this is our CDN, not malware"), "expected the comment body to show up, got:\n{out}");
}

#[test]
fn ingest_device_approval_rejects_an_unfollowed_author() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let approval_path = alice_dir.path().join("approval.json");
    let publish = sf(alice_dir.path(), "alice.sqlite", &["publish-device-approval", "--mac", "aa:bb:cc:dd:ee:ff", "--stance", "allow", "--reason-code", "known_good_service", "--out", approval_path.to_str().unwrap()]);
    assert!(publish.status.success(), "publish-device-approval failed: {}", stderr(&publish));

    // Bob never followed alice — her opinion must be rejected outright,
    // not silently stored at zero weight.
    let bob_approval = bob_dir.path().join("approval.json");
    std::fs::copy(&approval_path, &bob_approval).unwrap();
    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-device-approval", "--file", bob_approval.to_str().unwrap()]);
    assert!(!out.status.success(), "a device-approval opinion from an unfollowed author must be rejected");
    assert!(stderr(&out).contains("not a followed user"), "unexpected error: {}", stderr(&out));
}

#[test]
fn tampered_device_approval_signature_is_rejected_on_ingest() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");
    let follow = sf(bob_dir.path(), "bob.sqlite", &["add-follow", "--federation", &alice.federation, "--user", &alice.local_id, "--allow-weight", "1.0", "--deny-weight", "1.0"]);
    assert!(follow.status.success(), "add-follow failed: {}", stderr(&follow));

    let approval_path = alice_dir.path().join("approval.json");
    let publish = sf(alice_dir.path(), "alice.sqlite", &["publish-device-approval", "--mac", "aa:bb:cc:dd:ee:ff", "--stance", "deny", "--reason-code", "malware", "--out", approval_path.to_str().unwrap()]);
    assert!(publish.status.success(), "publish-device-approval failed: {}", stderr(&publish));

    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&approval_path).unwrap()).unwrap();
    json["mac"] = serde_json::json!("00:00:00:00:00:00");
    let tampered_path = bob_dir.path().join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    let out = sf(bob_dir.path(), "bob.sqlite", &["ingest-device-approval", "--file", tampered_path.to_str().unwrap()]);
    assert!(!out.status.success(), "ingesting a tampered device-approval opinion must fail");
    assert!(stderr(&out).contains("signature verification failed"), "unexpected error: {}", stderr(&out));
}

#[test]
fn request_group_join_requires_an_answer_when_the_group_has_a_join_prompt() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(
        alice_dir.path(),
        "alice.sqlite",
        &["create-group", "--name", "watch", "--description", "d", "--join-prompt", "please share a contact email", "--out", group_path.to_str().unwrap()],
    );
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    let bob_group = bob_dir.path().join("group.json");
    std::fs::copy(&group_path, &bob_group).unwrap();
    let ingest = sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-group failed: {}", stderr(&ingest));

    let no_answer = sf(bob_dir.path(), "bob.sqlite", &["request-group-join", "--group", &group_id]);
    assert!(!no_answer.status.success(), "requesting to join a group with a join_prompt must fail without --answer");
    assert!(stderr(&no_answer).contains("please share a contact email"), "expected the prompt to be echoed back, got: {}", stderr(&no_answer));

    let with_answer = sf(bob_dir.path(), "bob.sqlite", &["request-group-join", "--group", &group_id, "--answer", "bob@example.com"]);
    assert!(with_answer.status.success(), "request-group-join with --answer should succeed: {}", stderr(&with_answer));
}

#[test]
fn full_group_block_report_flow_surfaces_without_triggering_foreign_enforcement() {
    let alice_dir = tempfile::tempdir().unwrap(); // the group's owner
    let bob_dir = tempfile::tempdir().unwrap(); // the blocked user
    let carol_dir = tempfile::tempdir().unwrap(); // an independent reporter

    let _alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let bob = init_identity(bob_dir.path(), "bob.sqlite", "bob");
    init_identity(carol_dir.path(), "carol.sqlite", "carol");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "watch", "--description", "d", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    // Carol blocks bob from the group — she doesn't even need to be a
    // member herself; blocking is ungated the same way join requests are.
    let report_path = carol_dir.path().join("report.json");
    let bob_ref = format!("{}/{}", bob.federation, bob.local_id);
    let block = sf(
        carol_dir.path(),
        "carol.sqlite",
        &["block-group-user", "--group", &group_id, "--user", &bob_ref, "--reason-code", "abuse_report", "--note", "spammed the party line", "--out", report_path.to_str().unwrap()],
    );
    assert!(block.status.success(), "block-group-user failed: {}", stderr(&block));

    // Carol's own local block list reflects the reason.
    let carol_blocked = stdout(&sf(carol_dir.path(), "carol.sqlite", &["list-blocked-group-users", "--group", &group_id]));
    assert!(carol_blocked.contains("abuse_report"), "expected the reason on carol's own block list, got:\n{carol_blocked}");

    // Alice (the owner) ingests carol's report.
    let alice_report = alice_dir.path().join("report.json");
    std::fs::copy(&report_path, &alice_report).unwrap();
    let ingest = sf(alice_dir.path(), "alice.sqlite", &["ingest-group-block-report", "--file", alice_report.to_str().unwrap()]);
    assert!(ingest.status.success(), "ingest-group-block-report failed: {}", stderr(&ingest));

    // Ingesting carol's report must NEVER cause alice's own router to
    // locally block bob — no automatic global ban.
    let alice_blocked = stdout(&sf(alice_dir.path(), "alice.sqlite", &["list-blocked-group-users", "--group", &group_id]));
    assert!(alice_blocked.contains("no blocked users"), "ingesting a foreign report must not cause local enforcement, got:\n{alice_blocked}");

    // But alice can see the report when reviewing bob specifically.
    let reports = stdout(&sf(alice_dir.path(), "alice.sqlite", &["list-group-block-reports", "--group", &group_id, "--user", &bob_ref]));
    assert!(reports.contains("abuse_report"), "expected alice to see carol's report against bob, got:\n{reports}");
}

#[test]
fn tampered_group_block_report_signature_is_rejected_on_ingest() {
    let carol_dir = tempfile::tempdir().unwrap();
    let alice_dir = tempfile::tempdir().unwrap();

    init_identity(carol_dir.path(), "carol.sqlite", "carol");
    let bob = init_identity(alice_dir.path(), "alice.sqlite", "alice"); // reuse as a stand-in user id
    let bob_ref = format!("{}/{}", bob.federation, bob.local_id);

    let group_id = "00".repeat(32);
    let report_path = carol_dir.path().join("report.json");
    let block = sf(
        carol_dir.path(),
        "carol.sqlite",
        &["block-group-user", "--group", &group_id, "--user", &bob_ref, "--reason-code", "abuse_report", "--out", report_path.to_str().unwrap()],
    );
    assert!(block.status.success(), "block-group-user failed: {}", stderr(&block));

    let mut json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&report_path).unwrap()).unwrap();
    json["reason_code"] = serde_json::json!("malware");
    let tampered_path = alice_dir.path().join("tampered.json");
    std::fs::write(&tampered_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

    let out = sf(alice_dir.path(), "alice.sqlite", &["ingest-group-block-report", "--file", tampered_path.to_str().unwrap()]);
    assert!(!out.status.success(), "ingesting a tampered block report must fail");
    assert!(stderr(&out).contains("signature verification failed"), "unexpected error: {}", stderr(&out));
}

#[test]
fn party_line_moderation_and_voice_gate_posting_correctly() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    let _alice = init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let bob = init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "watch", "--description", "d", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    let bob_group = bob_dir.path().join("group.json");
    std::fs::copy(&group_path, &bob_group).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group.to_str().unwrap()]).status.success());

    let join_path = bob_dir.path().join("join.json");
    assert!(sf(bob_dir.path(), "bob.sqlite", &["request-group-join", "--group", &group_id, "--out", join_path.to_str().unwrap()]).status.success());
    let alice_join = alice_dir.path().join("join.json");
    std::fs::copy(&join_path, &alice_join).unwrap();
    assert!(sf(alice_dir.path(), "alice.sqlite", &["ingest-group-join-request", "--file", alice_join.to_str().unwrap()]).status.success());

    let bob_ref = format!("{}/{}", bob.federation, bob.local_id);
    let group_v2 = alice_dir.path().join("group_v2.json");
    let approve = sf(alice_dir.path(), "alice.sqlite", &["approve-group-join", "--group", &group_id, "--requester", &bob_ref, "--sequence", "0", "--out", group_v2.to_str().unwrap()]);
    assert!(approve.status.success(), "approve-group-join failed: {}", stderr(&approve));
    let bob_group_v2 = bob_dir.path().join("group_v2.json");
    std::fs::copy(&group_v2, &bob_group_v2).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group_v2.to_str().unwrap()]).status.success());

    // Unmoderated: a plain (non-voting) member can post.
    let out_dir1 = bob_dir.path().join("out1");
    let post1 = sf(bob_dir.path(), "bob.sqlite", &["publish-party-line", "--group", &group_id, "--body", "hi everyone", "--out-dir", out_dir1.to_str().unwrap()]);
    assert!(post1.status.success(), "publish-party-line should succeed while unmoderated: {}", stderr(&post1));
    assert!(stdout(&sf(bob_dir.path(), "bob.sqlite", &["list-party-line", "--group", &group_id])).contains("hi everyone"));

    // Alice moderates the channel.
    let group_v3 = alice_dir.path().join("group_v3.json");
    let moderate = sf(alice_dir.path(), "alice.sqlite", &["set-group-party-line-moderation", "--group", &group_id, "--moderated", "--out", group_v3.to_str().unwrap()]);
    assert!(moderate.status.success(), "set-group-party-line-moderation failed: {}", stderr(&moderate));
    let bob_group_v3 = bob_dir.path().join("group_v3.json");
    std::fs::copy(&group_v3, &bob_group_v3).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group_v3.to_str().unwrap()]).status.success());

    // Bob's own prior message must now be hidden — current permission
    // wins, the same principle already applied to group votes. His
    // earlier join notice must still show, though: moderation gates who
    // can *speak*, not membership visibility, the same way real IRC's
    // `+m` mutes without hiding join/part notices.
    let after_moderation = stdout(&sf(bob_dir.path(), "bob.sqlite", &["list-party-line", "--group", &group_id]));
    assert!(!after_moderation.contains("hi everyone"), "bob's un-voiced message must be hidden once moderated, got:\n{after_moderation}");
    assert!(after_moderation.contains("has joined the group"), "bob's join notice must still show even though his message is hidden, got:\n{after_moderation}");

    // Bob, un-voiced, can no longer post.
    let out_dir2 = bob_dir.path().join("out2");
    let post2 = sf(bob_dir.path(), "bob.sqlite", &["publish-party-line", "--group", &group_id, "--body", "still here?", "--out-dir", out_dir2.to_str().unwrap()]);
    assert!(!post2.status.success(), "an un-voiced member must not be able to post on a moderated party line");

    // Alice grants bob voice.
    let group_v4 = alice_dir.path().join("group_v4.json");
    let voice = sf(alice_dir.path(), "alice.sqlite", &["set-group-voice", "--group", &group_id, "--user", &bob_ref, "--voiced", "--out", group_v4.to_str().unwrap()]);
    assert!(voice.status.success(), "set-group-voice failed: {}", stderr(&voice));
    let bob_group_v4 = bob_dir.path().join("group_v4.json");
    std::fs::copy(&group_v4, &bob_group_v4).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group_v4.to_str().unwrap()]).status.success());

    let out_dir3 = bob_dir.path().join("out3");
    let post3 = sf(bob_dir.path(), "bob.sqlite", &["publish-party-line", "--group", &group_id, "--body", "voiced now!", "--out-dir", out_dir3.to_str().unwrap()]);
    assert!(post3.status.success(), "a voiced member must be able to post on a moderated party line: {}", stderr(&post3));
    assert!(stdout(&sf(bob_dir.path(), "bob.sqlite", &["list-party-line", "--group", &group_id])).contains("voiced now!"));
}

#[test]
fn group_vote_ttl_stops_counting_once_expired() {
    let dir = tempfile::tempdir().unwrap();
    init_identity(dir.path(), "alice.sqlite", "alice");

    let group_path = dir.path().join("group.json");
    let create = sf(dir.path(), "alice.sqlite", &["create-group", "--name", "watch", "--description", "d", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    // A negative TTL puts `expires_at` in the past immediately — a fast,
    // deterministic way to test the expired path without sleeping.
    let vote = sf(dir.path(), "alice.sqlite", &["cast-group-vote", "--group", &group_id, "--target-kind", "ip", "--target-value", "203.0.113.9", "--stance", "deny", "--reason-code", "malware", "--ttl-seconds=-10"]);
    assert!(vote.status.success(), "cast-group-vote failed: {}", stderr(&vote));

    let explain = stdout(&sf(dir.path(), "alice.sqlite", &["explain-group-vote", "--group", &group_id, "--target-kind", "ip", "--target-value", "203.0.113.9"]));
    assert!(explain.contains("expired, does not count"), "a vote with a negative TTL must show as expired, got:\n{explain}");

    let eval = stdout(&sf(dir.path(), "alice.sqlite", &["evaluate-target", "--target-kind", "ip", "--target-value", "203.0.113.9"]));
    assert!(!eval.contains("decision   : Deny"), "an expired vote must not drive the aggregate decision, got:\n{eval}");
}

#[test]
fn group_join_track_record_reflects_a_rejection() {
    let alice_dir = tempfile::tempdir().unwrap();
    let bob_dir = tempfile::tempdir().unwrap();

    init_identity(alice_dir.path(), "alice.sqlite", "alice");
    let bob = init_identity(bob_dir.path(), "bob.sqlite", "bob");

    let group_path = alice_dir.path().join("group.json");
    let create = sf(alice_dir.path(), "alice.sqlite", &["create-group", "--name", "watch", "--description", "d", "--out", group_path.to_str().unwrap()]);
    assert!(create.status.success(), "create-group failed: {}", stderr(&create));
    let group_id = extract_group_id(&create);

    let before = stdout(&sf(alice_dir.path(), "alice.sqlite", &["group-join-track-record", "--group", &group_id]));
    assert!(before.contains("rejected : 0"));

    let bob_group = bob_dir.path().join("group.json");
    std::fs::copy(&group_path, &bob_group).unwrap();
    assert!(sf(bob_dir.path(), "bob.sqlite", &["ingest-group", "--file", bob_group.to_str().unwrap()]).status.success());
    let join_path = bob_dir.path().join("join.json");
    assert!(sf(bob_dir.path(), "bob.sqlite", &["request-group-join", "--group", &group_id, "--out", join_path.to_str().unwrap()]).status.success());
    let alice_join = alice_dir.path().join("join.json");
    std::fs::copy(&join_path, &alice_join).unwrap();
    assert!(sf(alice_dir.path(), "alice.sqlite", &["ingest-group-join-request", "--file", alice_join.to_str().unwrap()]).status.success());

    let bob_ref = format!("{}/{}", bob.federation, bob.local_id);
    let reject = sf(alice_dir.path(), "alice.sqlite", &["reject-group-join", "--requester", &bob_ref, "--sequence", "0"]);
    assert!(reject.status.success(), "reject-group-join failed: {}", stderr(&reject));

    let after = stdout(&sf(alice_dir.path(), "alice.sqlite", &["group-join-track-record", "--group", &group_id]));
    assert!(after.contains("rejected : 1"), "expected the rejection to be tallied, got:\n{after}");
}
