use std::path::PathBuf;

use kestreld::{cgi, routes, routes::rotate_password, state};

fn main() {
    // Detached re-exec target for rotate-password's delayed hostapd
    // reload (see routes::rotate_password) — not a CGI request, must be
    // checked first.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(rotate_password::ROTATE_APPLY_ARG) {
        if let (Some(iface), Some(pwfile)) = (args.get(2), args.get(3)) {
            current_thread_rt().block_on(rotate_password::run_delayed_apply(iface, pwfile));
        }
        return;
    }

    // CGI mode: uhttpd forks this process fresh for every single HTTP
    // request and it exits immediately after responding. Spawning a full
    // multi-threaded runtime's worker pool for what's essentially
    // sequential file/DNS I/O is pure overhead — worst on exactly the
    // low-end single-core routers this project targets. A current-thread
    // runtime drives the same async I/O without that cost.
    if cgi::is_cgi() {
        current_thread_rt().block_on(cgi::run());
        return;
    }

    // Daemon mode: long-lived, serves concurrent connections — the one
    // path that actually benefits from a multi-threaded runtime.
    multi_thread_rt().block_on(async {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let split_routing_dir = PathBuf::from("/etc/kestrel/split-routing");
        let app_state = state::AppState::new(base_dir, split_routing_dir).await;

        let port: u16 = std::env::args()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(8080);

        let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
            .await
            .unwrap_or_else(|e| panic!("bind 0.0.0.0:{port} failed: {e}"));

        axum::serve(listener, routes::build(app_state)).await.unwrap();
    });
}

fn current_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build current-thread tokio runtime")
}

fn multi_thread_rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build multi-thread tokio runtime")
}
