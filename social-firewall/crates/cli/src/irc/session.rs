use super::auth::AuthenticatedIdentity;
use domain_types::GroupId;
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(crate) struct SessionState {
    pub(crate) nick: Option<String>,
    pub(crate) username: Option<String>,
    pub(crate) registered: bool,
    pub(crate) channels: HashMap<GroupId, String>,
    pub(crate) capabilities: HashSet<String>,
    pub(crate) sasl_pending: bool,
    pub(crate) authenticated: Option<AuthenticatedIdentity>,
    pub(crate) auth_groups: Vec<String>,
    pub(crate) auth_entitlements: Vec<String>,
}
