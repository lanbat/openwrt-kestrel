//! Port of `tools/check-wan.sh`: alerts when WAN connectivity is restored
//! after an outage. Can't alert on the way down (no internet to send the
//! alert), so it just records the outage start time and reports the
//! duration once connectivity returns. Invoked as `kestreld --check-wan`
//! every 5 minutes via cron (see `install.sh`).

use std::path::Path;

use crate::cmd;
use crate::data::files;

/// What to do about a WAN-state observation, decided independently of any
/// I/O so it's directly testable.
#[derive(Debug, PartialEq)]
enum Transition {
    /// Steady state (up→up or down→down) — the state file still gets
    /// (re)written, but nothing else happens.
    None,
    /// Outage just started — no notification (no internet to send one).
    WentDown,
    /// Outage just ended.
    CameUp { duration_secs: u64 },
}

fn decide(state: &str, last: &str, down_since: u64, now: u64) -> Transition {
    if state == "down" && last != "down" {
        Transition::WentDown
    } else if state == "up" && last == "down" {
        Transition::CameUp { duration_secs: now.saturating_sub(down_since) }
    } else {
        Transition::None
    }
}

fn format_duration(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}m", secs / 60)
    }
}

async fn ping_ok(host: &str) -> bool {
    let (ok, _) = cmd::run("ping", &["-c", "1", "-W", "3", host]).await;
    ok
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub async fn run(base_dir: &Path) -> i32 {
    let confs = files::read_all_network_confs(base_dir).await;
    let Some(notify_url) = confs.into_iter().map(|c| c.notify_url).find(|u| !u.is_empty()) else {
        return 0;
    };

    let state_file = base_dir.join("wan-state");
    let down_since_file = base_dir.join("wan-down-since");

    let state = if ping_ok("1.1.1.1").await || ping_ok("8.8.8.8").await { "up" } else { "down" };
    let last = tokio::fs::read_to_string(&state_file).await
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "up".to_string());
    let down_since: u64 = tokio::fs::read_to_string(&down_since_file).await
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);

    match decide(state, &last, down_since, now_secs()) {
        Transition::WentDown => {
            let _ = tokio::fs::write(&down_since_file, format!("{}\n", now_secs())).await;
            let _ = tokio::fs::write(&state_file, "down\n").await;
        }
        Transition::CameUp { duration_secs } => {
            let _ = tokio::fs::write(&state_file, "up\n").await;
            let _ = tokio::fs::remove_file(&down_since_file).await;

            let dash = cmd::dashboard_url().await;
            let dur_str = format_duration(duration_secs);
            cmd::ntfy_with_action(
                &notify_url,
                "WAN restored",
                "default",
                "white_check_mark",
                "Dashboard",
                &dash,
                &format!("WAN connectivity restored after {dur_str} outage.\nDashboard: {dash}"),
            ).await;
        }
        Transition::None => {
            let _ = tokio::fs::write(&state_file, format!("{state}\n")).await;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn went_down_when_state_down_and_last_was_not_down() {
        assert_eq!(decide("down", "up", 0, 0), Transition::WentDown);
    }

    #[test]
    fn came_up_computes_duration_from_down_since() {
        assert_eq!(decide("up", "down", 1_000, 1_130), Transition::CameUp { duration_secs: 130 });
    }

    #[test]
    fn steady_state_up_up_is_none() {
        assert_eq!(decide("up", "up", 0, 100), Transition::None);
    }

    #[test]
    fn steady_state_down_down_is_none() {
        assert_eq!(decide("down", "down", 0, 100), Transition::None);
    }

    #[test]
    fn duration_under_an_hour_formats_as_minutes() {
        assert_eq!(format_duration(125), "2m");
    }

    #[test]
    fn duration_of_an_hour_or_more_formats_as_hours_and_minutes() {
        assert_eq!(format_duration(3_725), "1h 2m");
    }
}
