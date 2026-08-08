use super::auth::AuthenticatedIdentity;
use domain_types::GroupId;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

#[derive(Default)]
pub(crate) struct SessionState {
    // Retained for the local kestreld device-fingerprint lookup.
    #[allow(dead_code)]
    pub(crate) remote_addr: Option<SocketAddr>,
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
