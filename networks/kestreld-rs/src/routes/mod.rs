pub mod approve_access;
pub mod approve_join;
pub mod device;
pub mod identity;
pub mod network;
pub mod qr;
pub mod rotate_password;
pub mod status;

use axum::{routing::{get, post}, Router};
use std::sync::Arc;

use crate::state::AppState;

pub fn build(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/cgi-bin/status", get(status::get))
        .route("/cgi-bin/network", get(network::get))
        .route("/cgi-bin/device", get(device::get).post(device::post))
        .route("/cgi-bin/identity", get(identity::get))
        .route("/cgi-bin/qr", get(qr::get))
        .route("/cgi-bin/approve-access", get(approve_access::get).post(approve_access::post))
        .route("/cgi-bin/approve-join", get(approve_join::get).post(approve_join::post))
        .route("/cgi-bin/rotate-password", post(rotate_password::post))
        .with_state(state)
}

/// Only honor same-origin, same-app redirect targets requested by the caller
/// (used by POST handlers that let the client suggest where to send the
/// browser after a successful action).
pub(crate) fn safe_redirect(redirect: Option<&str>) -> Option<String> {
    redirect
        .map(str::trim)
        .filter(|s| s.starts_with("/cgi-bin/"))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_redirect_accepts_cgi_bin_path() {
        assert_eq!(safe_redirect(Some("/cgi-bin/network?net=guest")), Some("/cgi-bin/network?net=guest".to_string()));
    }

    #[test]
    fn safe_redirect_rejects_absolute_url() {
        assert_eq!(safe_redirect(Some("http://evil.example.com")), None);
    }

    #[test]
    fn safe_redirect_rejects_non_cgi_bin_path() {
        assert_eq!(safe_redirect(Some("/etc/passwd")), None);
    }

    #[test]
    fn safe_redirect_none_when_absent() {
        assert_eq!(safe_redirect(None), None);
    }
}
