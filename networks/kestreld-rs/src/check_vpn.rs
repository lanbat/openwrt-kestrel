//! Port of `tools/check-vpn.sh`: pushes an alert when any VPN tier
//! (split-routing) changes state (up ↔ down). Invoked as
//! `kestreld --check-vpn` every 5 minutes via cron (see `install.sh`).
//! Reuses `data::vpn::fetch_tiers` for the actual up/down detection — the
//! same live `ip link`/`ip rule`/`ip route` checks the dashboard's VPN
//! panel already uses, rather than re-implementing them. The shell
//! version only ever alerted on a binary up/down, so `VpnState::RoutingFault`
//! (interface up but routing broken) counts as "down" here, same as the
//! dashboard's `css_class()` treats it as a warning state rather than "ok".

use std::path::Path;

use crate::cmd;
use crate::data::{files, vpn};
use crate::db::Store;

/// Whether a state-change notification needs to go out — kept separate
/// from the real `ip`/file I/O in `run()` so it's directly testable.
#[derive(Debug, PartialEq)]
enum Transition {
    None,
    Changed { now_up: bool },
}

fn decide(current_up: bool, last_state: &str) -> Transition {
    let state = if current_up { "up" } else { "down" };
    if state == last_state {
        Transition::None
    } else {
        Transition::Changed { now_up: current_up }
    }
}

pub async fn run(base_dir: &Path, split_routing_dir: &Path) -> i32 {
    let store = match Store::open(base_dir).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("check-vpn: failed to open kestrel.sqlite: {e}");
            return 1;
        }
    };
    run_and_report(base_dir, split_routing_dir, &store).await.0
}

/// Same as `run`, but also reports every tier that actually changed state
/// this call (`(iface, now_up)`) so `daemon.rs` can broadcast a
/// `plugins::Event::VpnStateChanged` per tier — `run` stays the CLI-facing
/// entry point (`kestreld --check-vpn`, exit code only).
pub async fn run_and_report(
    base_dir: &Path,
    split_routing_dir: &Path,
    store: &Store,
) -> (i32, Vec<(String, bool)>) {
    if tokio::fs::metadata(split_routing_dir).await.is_err() {
        return (0, Vec::new());
    }

    let confs = files::read_all_network_confs(base_dir).await;
    let Some(notify_url) = confs
        .into_iter()
        .map(|c| c.notify_url)
        .find(|u| !u.is_empty())
    else {
        return (0, Vec::new());
    };

    let tiers = vpn::fetch_tiers(split_routing_dir).await;
    let dash = cmd::dashboard_url().await;
    let mut changed = Vec::new();

    for tier in tiers {
        let current_up = tier.state == vpn::VpnState::Up;
        let last = store
            .get_vpn_state(&tier.iface)
            .await
            .unwrap_or(None)
            .unwrap_or_default();

        let Transition::Changed { now_up } = decide(current_up, &last) else {
            continue;
        };

        let _ = store
            .set_vpn_state(&tier.iface, if now_up { "up" } else { "down" })
            .await;
        changed.push((tier.iface.clone(), now_up));

        if now_up {
            cmd::ntfy_with_action(
                &notify_url,
                &format!("VPN up — {}", tier.iface),
                "default",
                "white_check_mark",
                "Dashboard",
                &dash,
                &format!("VPN ({}) came back up.\nDashboard: {dash}", tier.iface),
            )
            .await;
        } else {
            cmd::ntfy_with_action(
                &notify_url,
                &format!("VPN down — {}", tier.iface),
                "high",
                "warning",
                "Dashboard",
                &dash,
                &format!(
                    "VPN ({}) went down. Check the connection.\nDashboard: {dash}",
                    tier.iface
                ),
            )
            .await;
        }
    }

    (0, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_change_when_state_matches_last() {
        assert_eq!(decide(true, "up"), Transition::None);
        assert_eq!(decide(false, "down"), Transition::None);
    }

    #[test]
    fn reports_change_when_state_differs_from_last() {
        assert_eq!(decide(true, "down"), Transition::Changed { now_up: true });
        assert_eq!(decide(false, "up"), Transition::Changed { now_up: false });
    }

    #[test]
    fn reports_change_on_first_ever_check_empty_last_state() {
        // No state file yet reads as "" — a fresh tier starting down
        // shouldn't notify (matches the shell version silently writing
        // the initial state without alerting), but starting up should
        // notify. Handled by the caller comparing "" != "up"/"down": both
        // count as a transition here — see the shell's own behavior,
        // which has the identical property (`_last` defaults to "" too).
        assert_eq!(decide(true, ""), Transition::Changed { now_up: true });
        assert_eq!(decide(false, ""), Transition::Changed { now_up: false });
    }
}
