pub mod approve_access;
pub mod approve_join;
pub mod device;
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
        .route("/cgi-bin/qr", get(qr::get))
        .route("/cgi-bin/approve-access", get(approve_access::get).post(approve_access::post))
        .route("/cgi-bin/approve-join", get(approve_join::get).post(approve_join::post))
        .route("/cgi-bin/rotate-password", post(rotate_password::post))
        .with_state(state)
}
