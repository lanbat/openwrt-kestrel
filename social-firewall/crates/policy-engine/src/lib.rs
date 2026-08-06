//! The deterministic policy algorithm. Pure functions only — no I/O, no
//! SQLite, no network — so it's fully testable without any of that, and
//! so replaying the same inputs always produces exactly the same
//! decision and explanation, on any machine, forever.
//!
//! Precedence order, highest wins, evaluation stops immediately (no
//! blending across tiers):
//!   1. An active `LocalOverride` for this exact target.
//!   2. The owner's own latest non-expired `PolicyOpinion` for this
//!      target — beats even the crowd's unanimous opposite opinion, but
//!      *not* the owner's own more recent local override (tier 1 always
//!      wins on the owner's own router, even against their own past
//!      published opinion).
//!   3. Trust-weighted aggregation of followed users' opinions and
//!      followed federations' statements.
//!   4. Otherwise: `NoDecision` — the caller is responsible for applying
//!      whatever local safety default it wants; this crate never invents
//!      one silently.
//!
//! **Scope note**: target matching (e.g. whether a `DomainSuffix` rule
//! covers a specific subdomain query, or a `Cidr` rule contains a
//! specific IP) is deliberately the *caller's* job — the inputs here are
//! already filtered to "candidates relevant to this exact target." That
//! matching algorithm is real and non-trivial, but it's a separate
//! concern from precedence/weighting, which is what this crate is for.

use domain_types::{
    Contribution, Decision, DecisionTier, EffectivePolicyDecision, Explanation,
    FederationStatement, FederationTrustRule, GroupId, GroupTrustRule, IgnoredInput, IgnoredReason,
    LocalOverride, LocalTrustRule, PolicyOpinion, Reason, ReasonCode, SharedRuleEntry, Stance,
    StatementAuthor, TargetSelector, Timestamp, UserId,
};

pub struct PolicyInputs<'a> {
    pub target: TargetSelector,
    pub local_overrides: &'a [LocalOverride],
    /// The router owner's own published log — already filtered to this
    /// target by the caller.
    pub own_opinions: &'a [PolicyOpinion],
    /// Opinions from other users for this target, each paired with the
    /// trust rule that applies to its author — `None` if the author
    /// isn't followed at all (still shown as ignored in the explanation,
    /// never silently dropped without a trace).
    pub followed_opinions: &'a [(PolicyOpinion, Option<LocalTrustRule>)],
    /// Entries from subscribed shared rule lists that target this exact
    /// target — each paired with the list's author, that list's own
    /// categories (so `LocalTrustRule.category_filter` can be applied),
    /// and that author's current follow/trust rule. Contributes to the
    /// exact same trust-weighted tally `followed_opinions` does — a list
    /// subscription is not a second, more-authoritative decision path.
    pub list_entries: &'a [(SharedRuleEntry, UserId, Vec<String>, Option<LocalTrustRule>)],
    /// Each trusted group's majority-aggregated stance for this target
    /// (see `StateStore::group_stance_for`'s own doc on how that's
    /// computed) — `(group_id, stance, allow_votes, deny_votes,
    /// trust_rule)`. Contributes to the same trust-weighted tally
    /// everything else here does; a group's collective decision is not a
    /// second, more-authoritative path, structurally close to how a
    /// `FederationStatement` is treated.
    pub group_contributions: &'a [(GroupId, Stance, usize, usize, GroupTrustRule)],
    pub federation_statements: &'a [(FederationStatement, Option<FederationTrustRule>)],
    /// Combined weight required on one side, with nothing on the other,
    /// to auto-decide. Both sides crossing it is a real conflict → `Ask`.
    pub threshold: f64,
    pub now: Timestamp,
}

pub fn evaluate(inputs: &PolicyInputs) -> EffectivePolicyDecision {
    if let Some(decision) = evaluate_local_override(inputs) {
        return decision;
    }
    if let Some(decision) = evaluate_own_opinion(inputs) {
        return decision;
    }
    evaluate_trust_weighted(inputs)
}

fn evaluate_local_override(inputs: &PolicyInputs) -> Option<EffectivePolicyDecision> {
    let active = inputs
        .local_overrides
        .iter()
        .filter(|o| !o.is_expired(inputs.now))
        .max_by_key(|o| o.created_at)?;

    let decision = match active.stance {
        Stance::Allow => Decision::Allow,
        Stance::Deny => Decision::Deny,
        Stance::Ask => Decision::Ask,
    };

    Some(EffectivePolicyDecision {
        target: inputs.target.clone(),
        decision,
        explanation: Explanation {
            tier: DecisionTier::LocalOverride,
            decisive_override: Some(active.clone()),
            decisive_own_opinion: None,
            contributing: vec![],
            ignored: vec![],
            allow_weight_total: 0.0,
            deny_weight_total: 0.0,
            threshold: inputs.threshold,
        },
        computed_at: inputs.now,
    })
}

fn evaluate_own_opinion(inputs: &PolicyInputs) -> Option<EffectivePolicyDecision> {
    let latest = inputs
        .own_opinions
        .iter()
        .filter(|o| !o.is_expired(inputs.now))
        .max_by_key(|o| o.sequence)?;

    let decision = match latest.stance {
        Stance::Allow => Decision::Allow,
        Stance::Deny => Decision::Deny,
        Stance::Ask => Decision::Ask,
    };

    Some(EffectivePolicyDecision {
        target: inputs.target.clone(),
        decision,
        explanation: Explanation {
            tier: DecisionTier::OwnOpinion,
            decisive_override: None,
            decisive_own_opinion: Some(latest.clone()),
            contributing: vec![],
            ignored: vec![],
            allow_weight_total: 0.0,
            deny_weight_total: 0.0,
            threshold: inputs.threshold,
        },
        computed_at: inputs.now,
    })
}

fn evaluate_trust_weighted(inputs: &PolicyInputs) -> EffectivePolicyDecision {
    let mut contributing = Vec::new();
    let mut ignored = Vec::new();
    let mut allow_weight_total = 0.0f64;
    let mut deny_weight_total = 0.0f64;

    for (opinion, rule) in inputs.followed_opinions {
        if opinion.is_expired(inputs.now) {
            ignored.push(IgnoredInput {
                source: StatementAuthor::User(opinion.author),
                stance: opinion.stance,
                why: IgnoredReason::Expired,
            });
            continue;
        }
        let Some(rule) = rule else {
            ignored.push(IgnoredInput {
                source: StatementAuthor::User(opinion.author),
                stance: opinion.stance,
                why: IgnoredReason::NoTrustWeight,
            });
            continue;
        };
        if rule.excluded || rule.is_expired(inputs.now) {
            ignored.push(IgnoredInput {
                source: StatementAuthor::User(opinion.author),
                stance: opinion.stance,
                why: IgnoredReason::Excluded,
            });
            continue;
        }
        if rule.advisory_only {
            ignored.push(IgnoredInput {
                source: StatementAuthor::User(opinion.author),
                stance: opinion.stance,
                why: IgnoredReason::AdvisoryOnly,
            });
            continue;
        }

        let weight = match opinion.stance {
            Stance::Allow => rule.allow_weight,
            Stance::Deny => rule.deny_weight,
            Stance::Ask => 0.0,
        };
        match opinion.stance {
            Stance::Allow => allow_weight_total += weight,
            Stance::Deny => deny_weight_total += weight,
            Stance::Ask => {}
        }
        contributing.push(Contribution {
            source: StatementAuthor::User(opinion.author),
            stance: opinion.stance,
            weight,
            reason: opinion.reason.clone(),
        });
    }

    for (entry, author, categories, rule) in inputs.list_entries {
        // No `is_expired` check here — unlike `PolicyOpinion`,
        // `SharedRuleEntry` carries no expiry of its own; an expired
        // list's entries are already filtered out before they ever reach
        // this crate (see `StateStore::list_entries_for`'s own doc).
        let Some(rule) = rule else {
            ignored.push(IgnoredInput {
                source: StatementAuthor::User(*author),
                stance: entry.stance,
                why: IgnoredReason::NoTrustWeight,
            });
            continue;
        };
        if rule.excluded || rule.is_expired(inputs.now) {
            ignored.push(IgnoredInput {
                source: StatementAuthor::User(*author),
                stance: entry.stance,
                why: IgnoredReason::Excluded,
            });
            continue;
        }
        if rule.advisory_only {
            ignored.push(IgnoredInput {
                source: StatementAuthor::User(*author),
                stance: entry.stance,
                why: IgnoredReason::AdvisoryOnly,
            });
            continue;
        }
        // The one dimension standalone opinions never have: if this
        // follow has a `category_filter` set, only a list whose
        // categories include it counts — `None` (the default, and the
        // only behavior that existed before this filter had any effect)
        // means every subscribed list from this person counts, unchanged.
        if let Some(filter) = &rule.category_filter {
            if !categories.iter().any(|c| c == filter) {
                ignored.push(IgnoredInput {
                    source: StatementAuthor::User(*author),
                    stance: entry.stance,
                    why: IgnoredReason::CategoryFiltered,
                });
                continue;
            }
        }

        let weight = match entry.stance {
            Stance::Allow => rule.allow_weight,
            Stance::Deny => rule.deny_weight,
            Stance::Ask => 0.0,
        };
        match entry.stance {
            Stance::Allow => allow_weight_total += weight,
            Stance::Deny => deny_weight_total += weight,
            Stance::Ask => {}
        }
        contributing.push(Contribution {
            source: StatementAuthor::User(*author),
            stance: entry.stance,
            weight,
            reason: entry.reason.clone(),
        });
    }

    // Groups are pre-filtered by the caller (`excluded`/expiry already
    // applied when building `group_contributions`, mirroring
    // `StateStore::list_group_contributions_for`'s own doc) — every entry
    // here is a real, current majority stance to weigh in.
    for (group_id, stance, allow_votes, deny_votes, rule) in inputs.group_contributions {
        let weight = match stance {
            Stance::Allow => rule.allow_weight,
            Stance::Deny => rule.deny_weight,
            Stance::Ask => 0.0,
        };
        match stance {
            Stance::Allow => allow_weight_total += weight,
            Stance::Deny => deny_weight_total += weight,
            Stance::Ask => {}
        }
        contributing.push(Contribution {
            source: StatementAuthor::Group(*group_id),
            stance: *stance,
            weight,
            reason: Reason {
                code: ReasonCode::Other,
                note: Some(format!(
                    "{allow_votes} allow vote(s), {deny_votes} deny vote(s)"
                )),
                evidence: vec![],
            },
        });
    }

    for (statement, rule) in inputs.federation_statements {
        if statement.is_expired(inputs.now) {
            ignored.push(IgnoredInput {
                source: StatementAuthor::Federation(statement.federation),
                stance: statement.stance,
                why: IgnoredReason::Expired,
            });
            continue;
        }
        let Some(rule) = rule else {
            ignored.push(IgnoredInput {
                source: StatementAuthor::Federation(statement.federation),
                stance: statement.stance,
                why: IgnoredReason::NoTrustWeight,
            });
            continue;
        };
        if rule.is_expired(inputs.now) {
            ignored.push(IgnoredInput {
                source: StatementAuthor::Federation(statement.federation),
                stance: statement.stance,
                why: IgnoredReason::Excluded,
            });
            continue;
        }

        let weight = match statement.stance {
            Stance::Allow => rule.allow_weight,
            Stance::Deny => rule.deny_weight,
            Stance::Ask => 0.0,
        };
        match statement.stance {
            Stance::Allow => allow_weight_total += weight,
            Stance::Deny => deny_weight_total += weight,
            Stance::Ask => {}
        }
        contributing.push(Contribution {
            source: StatementAuthor::Federation(statement.federation),
            stance: statement.stance,
            weight,
            reason: statement.reason.clone(),
        });
    }

    let allow_crosses = allow_weight_total >= inputs.threshold;
    let deny_crosses = deny_weight_total >= inputs.threshold;

    let decision = match (allow_crosses, deny_crosses) {
        (true, false) => Decision::Allow,
        (false, true) => Decision::Deny,
        (true, true) => Decision::Ask, // genuine conflict, both sides have enough weight
        (false, false) => {
            if allow_weight_total == 0.0 && deny_weight_total == 0.0 {
                Decision::NoDecision // no signal at all, not even a weak one
            } else {
                Decision::Ask // some signal, just not enough to auto-decide either way
            }
        }
    };

    EffectivePolicyDecision {
        target: inputs.target.clone(),
        decision,
        explanation: Explanation {
            tier: DecisionTier::TrustWeighted,
            decisive_override: None,
            decisive_own_opinion: None,
            contributing,
            ignored,
            allow_weight_total,
            deny_weight_total,
            threshold: inputs.threshold,
        },
        computed_at: inputs.now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::{
        FederationId, Hash32, OverrideKind, Reason, ReasonCode, SignatureBytes, UserId,
    };

    fn fed(n: u8) -> FederationId {
        FederationId(Hash32([n; 32]))
    }
    fn user(fed_n: u8, local_n: u8) -> UserId {
        UserId {
            federation: fed(fed_n),
            local_id: Hash32([local_n; 32]),
        }
    }
    fn reason(code: ReasonCode) -> Reason {
        Reason {
            code,
            note: None,
            evidence: vec![],
        }
    }
    fn opinion(author: UserId, seq: u64, target: &TargetSelector, stance: Stance) -> PolicyOpinion {
        PolicyOpinion {
            author,
            sequence: seq,
            target: target.clone(),
            stance,
            reason: reason(ReasonCode::PersonalPreference),
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: SignatureBytes([0; 64]),
        }
    }
    fn trust(user: UserId, allow_w: f64, deny_w: f64) -> LocalTrustRule {
        LocalTrustRule {
            user,
            allow_weight: allow_w,
            deny_weight: deny_w,
            advisory_only: false,
            excluded: false,
            category_filter: None,
            display_name: None,
            iroh_node_id: None,
            expires_at: None,
            created_at: 0,
        }
    }
    fn target() -> TargetSelector {
        TargetSelector::Domain("ads.example".into())
    }

    // ── Scenario B: conflicting opinions, threshold logic ──────────────────

    #[test]
    fn threshold_met_on_deny_side_auto_denies() {
        let alice = user(1, 1);
        let dave = user(1, 2);
        let opinions = vec![
            (
                opinion(alice, 1, &target(), Stance::Deny),
                Some(trust(alice, 0.6, 1.0)),
            ),
            (
                opinion(dave, 1, &target(), Stance::Allow),
                Some(trust(dave, 0.4, 0.4)),
            ),
        ];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.explanation.tier, DecisionTier::TrustWeighted);
    }

    #[test]
    fn threshold_unmet_on_both_sides_falls_to_ask_not_a_coin_flip() {
        let alice = user(1, 1);
        let dave = user(1, 2);
        let opinions = vec![
            (
                opinion(alice, 1, &target(), Stance::Deny),
                Some(trust(alice, 0.6, 0.6)),
            ),
            (
                opinion(dave, 1, &target(), Stance::Allow),
                Some(trust(dave, 0.4, 0.4)),
            ),
        ];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(
            result.decision,
            Decision::Ask,
            "neither side crossed threshold — must not silently pick the larger one"
        );
    }

    #[test]
    fn no_contributing_opinions_at_all_is_no_decision_not_ask() {
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &[],
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::NoDecision);
    }

    #[test]
    fn both_sides_crossing_threshold_is_a_genuine_conflict_ask() {
        let alice = user(1, 1);
        let dave = user(1, 2);
        let opinions = vec![
            (
                opinion(alice, 1, &target(), Stance::Deny),
                Some(trust(alice, 1.0, 1.0)),
            ),
            (
                opinion(dave, 1, &target(), Stance::Allow),
                Some(trust(dave, 1.0, 1.0)),
            ),
        ];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Ask);
    }

    // ── Scenario C: owner precedence ────────────────────────────────────────

    #[test]
    fn owner_local_override_beats_unanimous_followed_deny() {
        let alice = user(1, 1);
        let opinions = vec![(
            opinion(alice, 1, &target(), Stance::Deny),
            Some(trust(alice, 1.0, 5.0)),
        )];
        let overrides = vec![LocalOverride {
            target: target(),
            stance: Stance::Allow,
            kind: OverrideKind::Normal,
            note: None,
            created_at: 500,
            expires_at: None,
        }];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &overrides,
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.explanation.tier, DecisionTier::LocalOverride);
    }

    #[test]
    fn expired_override_does_not_apply_falls_through_to_next_tier() {
        let alice = user(1, 1);
        let opinions = vec![(
            opinion(alice, 1, &target(), Stance::Deny),
            Some(trust(alice, 0.0, 5.0)),
        )];
        let overrides = vec![LocalOverride {
            target: target(),
            stance: Stance::Allow,
            kind: OverrideKind::Normal,
            note: None,
            created_at: 0,
            expires_at: Some(500),
        }];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &overrides,
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000, // past the override's expiry
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.explanation.tier, DecisionTier::TrustWeighted);
    }

    /// The subtle precedence point from the design conversation: a local
    /// override beats *even the owner's own* previously-published opinion.
    #[test]
    fn local_override_beats_owners_own_stale_published_opinion() {
        let owner_opinions = vec![opinion(user(1, 9), 1, &target(), Stance::Allow)];
        let overrides = vec![LocalOverride {
            target: target(),
            stance: Stance::Deny,
            kind: OverrideKind::Normal,
            note: None,
            created_at: 999,
            expires_at: None,
        }];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &overrides,
            own_opinions: &owner_opinions,
            followed_opinions: &[],
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.explanation.tier, DecisionTier::LocalOverride);
    }

    #[test]
    fn owner_opinion_beats_trust_weighted_aggregation() {
        let alice = user(1, 1);
        let followed = vec![(
            opinion(alice, 1, &target(), Stance::Deny),
            Some(trust(alice, 0.0, 5.0)),
        )];
        let own = vec![opinion(user(1, 9), 1, &target(), Stance::Allow)];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &own,
            followed_opinions: &followed,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Allow);
        assert_eq!(result.explanation.tier, DecisionTier::OwnOpinion);
    }

    // ── Excluded / advisory-only / unfollowed authors are visible, not silent ─

    #[test]
    fn excluded_author_is_ignored_but_recorded_in_explanation() {
        let bob = user(1, 3);
        let mut rule = trust(bob, 1.0, 1.0);
        rule.excluded = true;
        let opinions = vec![(opinion(bob, 1, &target(), Stance::Deny), Some(rule))];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::NoDecision);
        assert_eq!(result.explanation.ignored.len(), 1);
        assert_eq!(result.explanation.ignored[0].why, IgnoredReason::Excluded);
    }

    #[test]
    fn advisory_only_author_never_contributes_to_the_tally() {
        let bob = user(1, 3);
        let mut rule = trust(bob, 1.0, 1.0);
        rule.advisory_only = true;
        let opinions = vec![(opinion(bob, 1, &target(), Stance::Deny), Some(rule))];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.explanation.deny_weight_total, 0.0);
        assert_eq!(result.decision, Decision::NoDecision);
    }

    #[test]
    fn unfollowed_author_opinion_is_ignored_with_a_specific_reason() {
        let stranger = user(1, 99);
        let opinions = vec![(opinion(stranger, 1, &target(), Stance::Deny), None)];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(
            result.explanation.ignored[0].why,
            IgnoredReason::NoTrustWeight
        );
    }

    // ── Replaying the same inputs must produce the exact same result ────────

    #[test]
    fn evaluation_is_deterministic_given_identical_inputs() {
        let alice = user(1, 1);
        let opinions = vec![(
            opinion(alice, 1, &target(), Stance::Deny),
            Some(trust(alice, 0.6, 0.6)),
        )];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let a = evaluate(&inputs);
        let b = evaluate(&inputs);
        assert_eq!(a, b);
    }

    // ── Shared rule list entries ─────────────────────────────────────────

    fn list_entry(stance: Stance) -> SharedRuleEntry {
        SharedRuleEntry {
            target: target(),
            stance,
            reason: reason(ReasonCode::Tracker),
        }
    }

    #[test]
    fn a_list_entry_from_a_followed_author_contributes_like_an_opinion_would() {
        let alice = user(1, 1);
        let entries = vec![(
            list_entry(Stance::Deny),
            alice,
            vec!["privacy".to_string()],
            Some(trust(alice, 0.5, 1.0)),
        )];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &[],
            list_entries: &entries,
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.explanation.tier, DecisionTier::TrustWeighted);
        assert_eq!(result.explanation.contributing.len(), 1);
    }

    #[test]
    fn an_unset_category_filter_counts_every_subscribed_lists_entries_unchanged() {
        // The default, and the only behavior that existed before this
        // filter had any effect at all — a regression guard, not just a
        // feature test.
        let alice = user(1, 1);
        let mut rule = trust(alice, 1.0, 1.0);
        rule.category_filter = None;
        let entries = vec![(
            list_entry(Stance::Deny),
            alice,
            vec!["unrelated-category".to_string()],
            Some(rule),
        )];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &[],
            list_entries: &entries,
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "no category_filter set means every list from this person counts"
        );
    }

    #[test]
    fn a_category_filter_excludes_a_non_matching_lists_entries() {
        let alice = user(1, 1);
        let mut rule = trust(alice, 1.0, 1.0);
        rule.category_filter = Some("security".to_string());
        let entries = vec![(
            list_entry(Stance::Deny),
            alice,
            vec!["privacy".to_string(), "ads".to_string()],
            Some(rule),
        )];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &[],
            list_entries: &entries,
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(
            result.decision,
            Decision::NoDecision,
            "the list's categories don't include the filter, so it must not count"
        );
        assert_eq!(
            result.explanation.ignored[0].why,
            IgnoredReason::CategoryFiltered
        );
    }

    #[test]
    fn a_category_filter_includes_a_matching_lists_entries() {
        let alice = user(1, 1);
        let mut rule = trust(alice, 1.0, 1.0);
        rule.category_filter = Some("privacy".to_string());
        let entries = vec![(
            list_entry(Stance::Deny),
            alice,
            vec!["privacy".to_string(), "ads".to_string()],
            Some(rule),
        )];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &[],
            list_entries: &entries,
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "the list's categories do include the filter, so it must count"
        );
    }

    #[test]
    fn category_filter_never_affects_a_standalone_opinion_from_the_same_author() {
        // The deliberate scope boundary: `category_filter` only restricts
        // *list-derived* entries, never a person's individually-published
        // opinions — those were never categorized in the first place.
        let alice = user(1, 1);
        let mut rule = trust(alice, 1.0, 1.0);
        rule.category_filter = Some("security".to_string()); // matches nothing below
        let opinions = vec![(opinion(alice, 1, &target(), Stance::Deny), Some(rule))];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &opinions,
            list_entries: &[],
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(
            result.decision,
            Decision::Deny,
            "a category_filter must never gate a standalone opinion"
        );
    }

    #[test]
    fn excluded_author_is_ignored_even_for_list_entries() {
        let alice = user(1, 1);
        let mut rule = trust(alice, 1.0, 1.0);
        rule.excluded = true;
        let entries = vec![(
            list_entry(Stance::Deny),
            alice,
            vec!["privacy".to_string()],
            Some(rule),
        )];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &[],
            list_entries: &entries,
            group_contributions: &[],
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::NoDecision);
        assert_eq!(result.explanation.ignored[0].why, IgnoredReason::Excluded);
    }

    // ── Group contributions ──────────────────────────────────────────────

    #[test]
    fn a_trusted_groups_aggregate_stance_contributes_like_a_federation_statement_would() {
        let group_id = domain_types::GroupId(domain_types::Hash32([7; 32]));
        let rule = domain_types::GroupTrustRule {
            group_id,
            allow_weight: 1.0,
            deny_weight: 1.0,
            excluded: false,
            expires_at: None,
            created_at: 0,
        };
        let contributions = vec![(group_id, Stance::Deny, 3usize, 1usize, rule)];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &[],
            followed_opinions: &[],
            list_entries: &[],
            group_contributions: &contributions,
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(result.decision, Decision::Deny);
        assert_eq!(result.explanation.tier, DecisionTier::TrustWeighted);
        assert_eq!(result.explanation.contributing.len(), 1);
        assert_eq!(
            result.explanation.contributing[0].source,
            StatementAuthor::Group(group_id)
        );
    }

    #[test]
    fn a_group_contribution_never_beats_the_owners_own_opinion() {
        let alice = user(1, 1);
        let opinions = vec![opinion(alice, 0, &target(), Stance::Allow)];
        let group_id = domain_types::GroupId(domain_types::Hash32([7; 32]));
        let rule = domain_types::GroupTrustRule {
            group_id,
            allow_weight: 1.0,
            deny_weight: 1.0,
            excluded: false,
            expires_at: None,
            created_at: 0,
        };
        let contributions = vec![(group_id, Stance::Deny, 3usize, 0usize, rule)];
        let inputs = PolicyInputs {
            target: target(),
            local_overrides: &[],
            own_opinions: &opinions,
            followed_opinions: &[],
            list_entries: &[],
            group_contributions: &contributions,
            federation_statements: &[],
            threshold: 1.0,
            now: 1000,
        };
        let result = evaluate(&inputs);
        assert_eq!(
            result.decision,
            Decision::Allow,
            "the owner's own opinion beats even a unanimous group vote"
        );
        assert_eq!(result.explanation.tier, DecisionTier::OwnOpinion);
    }
}
