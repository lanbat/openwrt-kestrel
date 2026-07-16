pub mod device;
pub mod status;

use axum::{routing::get, Router};
use std::sync::Arc;

use crate::state::AppState;

pub fn build(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/cgi-bin/status", get(status::get))
        .route("/cgi-bin/device", get(device::get).post(device::post))
        .with_state(state)
}
