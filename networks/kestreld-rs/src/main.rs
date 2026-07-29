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

    // Cron-invoked subcommand — same one-shot shape as --rotate-apply
    // above, just no detached re-exec involved. Replaces the old
    // `sh tools/oui-update.sh` cron entry (see networks/install.sh).
    if args.get(1).map(String::as_str) == Some("--update-oui") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let code = current_thread_rt().block_on(kestreld::oui_update::run(&base_dir));
        std::process::exit(code);
    }

    // Cron-invoked subcommand, same shape as --update-oui above — refreshes
    // the domain threat-intel feed `data::threat_domains` checks DNS
    // queries/resolved domains against on the device page.
    if args.get(1).map(String::as_str) == Some("--update-threat-intel") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let code = current_thread_rt().block_on(kestreld::threat_intel_update::run(&base_dir));
        std::process::exit(code);
    }

    // Cron-invoked subcommand, replacing the old `sh tools/check-wan.sh`
    // cron entry (see networks/install.sh).
    if args.get(1).map(String::as_str) == Some("--check-wan") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let code = current_thread_rt().block_on(kestreld::check_wan::run(&base_dir));
        std::process::exit(code);
    }

    // Cron-invoked subcommand, replacing the old `sh tools/check-vpn.sh`
    // cron entry (see networks/install.sh).
    if args.get(1).map(String::as_str) == Some("--check-vpn") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let split_routing_dir = PathBuf::from("/etc/kestrel/split-routing");
        let code = current_thread_rt().block_on(kestreld::check_vpn::run(&base_dir, &split_routing_dir));
        std::process::exit(code);
    }

    // Cron-invoked subcommand, replacing the old
    // `sh tools/bandwidth-check.sh` cron entry (see networks/install.sh).
    if args.get(1).map(String::as_str) == Some("--check-bandwidth") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let code = current_thread_rt().block_on(kestreld::bandwidth_check::run(&base_dir));
        std::process::exit(code);
    }

    // Cron-invoked subcommand, replacing the old
    // `sh tools/check-access-log.sh` cron entry (see networks/install.sh).
    if args.get(1).map(String::as_str) == Some("--check-access-log") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let code = current_thread_rt().block_on(kestreld::check_access_log::run(&base_dir));
        std::process::exit(code);
    }

    // Cron-invoked subcommand, replacing the old `sh tools/digest.sh`
    // cron entry (see networks/install.sh).
    if args.get(1).map(String::as_str) == Some("--digest") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let split_routing_dir = PathBuf::from("/etc/kestrel/split-routing");
        let code = current_thread_rt().block_on(kestreld::digest::run(&base_dir, &split_routing_dir));
        std::process::exit(code);
    }

    // Called directly by install.sh at setup time (device-control networks
    // only). Everyday callers — approve/revoke/label routes — call
    // kestreld::regen_inspect::run() in-process instead (see routes/device.rs,
    // routes/approve_join.rs); this subcommand exists for the shell side.
    if args.get(1).map(String::as_str) == Some("--regen-inspect") {
        let Some(iface) = args.get(2) else {
            eprintln!("Usage: kestreld --regen-inspect IFACE");
            std::process::exit(1);
        };
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let split_routing_dir = PathBuf::from("/etc/kestrel/split-routing");
        let code = current_thread_rt()
            .block_on(kestreld::regen_inspect::run(&base_dir, &split_routing_dir, iface));
        std::process::exit(code);
    }

    // The persistent monitor daemon: procd-supervised (respawn) via the
    // init.d service install.sh sets up, replacing the check-wan/
    // check-vpn/check-bandwidth cron entries and the check-access-log
    // one — see daemon.rs's module doc for why this is a genuinely
    // long-running, multi-task process rather than another one-shot
    // subcommand, and thus uses multi_thread_rt() below.
    if args.get(1).map(String::as_str) == Some("--daemon") {
        let base_dir = PathBuf::from("/etc/kestrel/networks");
        let split_routing_dir = PathBuf::from("/etc/kestrel/split-routing");
        let code = multi_thread_rt().block_on(kestreld::daemon::run(base_dir, split_routing_dir));
        std::process::exit(code);
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
