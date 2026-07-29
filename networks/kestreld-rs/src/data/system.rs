use std::collections::HashMap;

#[derive(Default, Clone)]
pub struct SystemInfo {
    pub hostname: String,
    pub uptime: String,
    pub memory: String,
    pub load: String,
    pub wan_ip: Option<String>,
    pub wan_ipv6: Option<String>,
}

pub async fn fetch() -> SystemInfo {
    let hostname = tokio::fs::read_to_string("/proc/sys/kernel/hostname")
        .await
        .unwrap_or_default()
        .trim()
        .to_string();

    let uptime = tokio::fs::read_to_string("/proc/uptime")
        .await
        .ok()
        .and_then(|s| {
            let secs = s.split_whitespace().next()?.parse::<f64>().ok()? as u64;
            let d = secs / 86400;
            let h = (secs % 86400) / 3600;
            let m = (secs % 3600) / 60;
            if d > 0 {
                Some(format!("{d}d {h}h {m}m"))
            } else {
                Some(format!("{h}h {m}m"))
            }
        })
        .unwrap_or_default();

    let memory = tokio::fs::read_to_string("/proc/meminfo")
        .await
        .ok()
        .and_then(|s| {
            let mut total: u64 = 0;
            let mut avail: u64 = 0;
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    total = rest.split_whitespace().next()?.parse().ok()?;
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    avail = rest.split_whitespace().next()?.parse().ok()?;
                }
            }
            Some(format!("{} MB free / {} MB total", avail / 1024, total / 1024))
        })
        .unwrap_or_default();

    let load = tokio::fs::read_to_string("/proc/loadavg")
        .await
        .ok()
        .map(|s| {
            s.split_whitespace()
                .take(3)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();

    let (wan_ip, wan_ipv6) = fetch_wan_ips().await;

    SystemInfo { hostname, uptime, memory, load, wan_ip, wan_ipv6 }
}

async fn fetch_wan_ips() -> (Option<String>, Option<String>) {
    use tokio::process::Command;

    let route = Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .await
        .ok();

    let dev = route.as_ref().and_then(|o| {
        std::str::from_utf8(&o.stdout).ok().and_then(|s| {
            s.lines().next().and_then(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                parts.windows(2).find(|w| w[0] == "dev").map(|w| w[1].to_string())
            })
        })
    });

    let Some(dev) = dev else { return (None, None) };

    let ip4 = Command::new("ip")
        .args(["addr", "show", &dev])
        .output()
        .await
        .ok()
        .and_then(|o| {
            std::str::from_utf8(&o.stdout).ok().and_then(|s| {
                s.lines()
                    .find(|l| l.trim_start().starts_with("inet "))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|a| a.split('/').next())
                    .map(|s| s.to_string())
            })
        });

    let ip6 = Command::new("ip")
        .args(["-6", "addr", "show", "dev", &dev, "scope", "global"])
        .output()
        .await
        .ok()
        .and_then(|o| {
            std::str::from_utf8(&o.stdout).ok().and_then(|s| {
                s.lines()
                    .find(|l| l.trim_start().starts_with("inet6 "))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|a| a.split('/').next())
                    .map(|s| s.to_string())
            })
        });

    (ip4, ip6)
}
