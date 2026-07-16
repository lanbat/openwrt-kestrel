use std::path::PathBuf;

mod data;
mod routes;
mod state;

#[tokio::main]
async fn main() {
    let base_dir = PathBuf::from("/etc/extra-networks");
    let app_state = state::AppState::new(base_dir).await;

    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|e| panic!("bind 0.0.0.0:{port} failed: {e}"));

    axum::serve(listener, routes::build(app_state)).await.unwrap();
}
