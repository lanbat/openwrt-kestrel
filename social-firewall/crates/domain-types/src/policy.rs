//! The output of the deterministic policy algorithm (implemented in the
//! `policy-engine` crate) — a decision plus a full explanation of how it
//! was reached. The explanation is not a debugging nicety; the original
//! design requirement is that the router must be able to explain which
//! opinions contributed, which were ignored, and why, for every decision.

use crate::opinion::StatementAuthor;
use crate::opinion::{LocalOverride, PolicyOpinion, Reason, Stance, Timestamp};
use crate::target::TargetSelector;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
    Ask,
    /// No local override, no owner opinion, and trust-weighted
    /// aggregation didn't cross the threshold on either side — this is a
    /// real, distinct outcome, not the same as `Ask`. `Ask` means
    /// "conflicting signal strong enough that a human should look at it";
    /// `NoDecision` means "not enough signal to say anything at all,"
    /// which should fall through to whatever local safety default the
    /// owner has configured (not silently become Allow or Deny).
    NoDecision,
}

/// Which precedence tier actually produced the decision — see the
/// ordering agreed in the design conversation: local override beats the
/// owner's own published opinion beats trust-weighted aggregation beats
/// the local safety default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionTier {
    LocalOverride,
    OwnOpinion,
    TrustWeighted,
    SafetyDefault,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Contribution {
    pub source: StatementAuthor,
    pub stance: Stance,
    pub weight: f64,
    pub reason: Reason,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IgnoredReason {
    Excluded,
    Expired,
    AdvisoryOnly,
    NoTrustWeight,
    /// The author is followed, but their `LocalTrustRule.category_filter`
    /// doesn't match any of this entry's list's categories — the entry
    /// simply isn't one this router opted into, distinct from every other
    /// reason (which are all about the *author*, not which of their
    /// content counts). Never applies to a standalone `PolicyOpinion` —
    /// only to list-derived entries, which is the entire point of the
    /// filter existing on a per-follow basis.
    CategoryFiltered,
}

#[derive(Debug, Clone, PartialEq)]
pub struct IgnoredInput {
    pub source: StatementAuthor,
    pub stance: Stance,
    pub why: IgnoredReason,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Explanation {
    pub tier: DecisionTier,
    /// Set iff `tier == LocalOverride` — the exact record that decided it.
    pub decisive_override: Option<LocalOverride>,
    /// Set iff `tier == OwnOpinion`.
    pub decisive_own_opinion: Option<PolicyOpinion>,
    /// Populated only for `tier == TrustWeighted`.
    pub contributing: Vec<Contribution>,
    pub ignored: Vec<IgnoredInput>,
    pub allow_weight_total: f64,
    pub deny_weight_total: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EffectivePolicyDecision {
    pub target: TargetSelector,
    pub decision: Decision,
    pub explanation: Explanation,
    pub computed_at: Timestamp,
}
