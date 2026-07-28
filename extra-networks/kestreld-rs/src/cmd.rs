use std::process::Stdio;
use tokio::process::Command;

/// In CGI mode this process's stdout/stderr *is* the HTTP response stream
/// uhttpd reads (headers + body). `Command::status`/`spawn` inherit the
/// parent's stdio by default, so any unrelated output a helper binary
/// writes (e.g. `uci get` printing a section type, a script's own logging)
/// gets spliced into the response and breaks uhttpd's CGI framing —
/// observed as a plain 502 Bad Gateway with no error on kestreld's side.
/// Every fire-and-forget `Command` here must have its stdio silenced.
pub fn silent(cmd: &mut Command) -> &mut Command {
    cmd.stdout(Stdio::null()).stderr(Stdio::null())
}

pub async fn run(prog: &str, args: &[&str]) -> (bool, String) {
    match Command::new(prog).args(args).output().await {
        Ok(o) => {
            let ok = o.status.success();
            let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            (ok, if ok { out } else { err })
        }
        Err(e) => (false, e.to_string()),
    }
}

pub async fn nft_add_element(set: &str, ip: &str, timeout: &str) {
    let expr = if timeout.is_empty() {
        format!("{{ {ip} }}")
    } else {
        format!("{{ {ip} timeout {timeout} }}")
    };
    let _ = silent(Command::new("nft")
        .args(["add", "element", "inet", "fw4", set, &expr]))
        .status()
        .await;
}

pub async fn nft_del_element(set: &str, ip: &str) {
    let _ = silent(Command::new("nft")
        .args(["delete", "element", "inet", "fw4", set, &format!("{{ {ip} }}")]))
        .status()
        .await;
}

pub async fn nft_add_set(set: &str, family: &str) {
    let type_str = if family == "4" { "ipv4_addr" } else { "ipv6_addr" };
    let _ = silent(Command::new("nft")
        .args(["add", "set", "inet", "fw4", set,
            &format!("{{ type {type_str}; flags dynamic,timeout; timeout 24h; }}")]))
        .status()
        .await;
}

pub async fn reload_dnsmasq() {
    let _ = silent(Command::new("/etc/init.d/dnsmasq")
        .arg("reload"))
        .status()
        .await;
}

pub async fn regen_inspect(iface: &str) {
    let _ = silent(Command::new("/etc/kestrel/networks/_regen-inspect.sh")
        .arg(iface))
        .status()
        .await;
}

/// Run a hotplug-style macfilter for an interface in the background.
pub fn spawn_macfilter(iface: &str) {
    let script = format!("/etc/hotplug.d/iface/51-{iface}-macfilter");
    let _ = silent(Command::new("sh")
        .env("ACTION", "ifup")
        .env("INTERFACE", iface)
        .arg(&script))
        .spawn();
}

pub async fn allow_service(iface: &str, dst: &str, proto: &str, port: &str, duration: &str, dest_zone: &str) -> bool {
    let mut args = vec![iface, dst, proto, port, duration];
    if !dest_zone.is_empty() { args.push(dest_zone); }
    let (ok, _) = run("/etc/kestrel/networks/allow-service.sh", &args).await;
    ok
}

pub async fn ntfy(url: &str, title: &str, priority: &str, icon: &str, body: &str) {
    if url.is_empty() { return; }
    let _ = silent(Command::new("curl")
        .args([
            "-s", "-o", "/dev/null",
            "-H", &format!("Title: {title}"),
            "-H", &format!("Priority: {priority}"),
            "-H", &format!("Tags: {icon}"),
            "-d", body,
            url,
        ]))
        .status()
        .await;
}

pub async fn write_device_dns(base_dir: &std::path::Path, iface: &str, mac: &str, label: &str, domain: &str) {
    if label.is_empty() && domain.is_empty() { return; }
    let mac_n = mac.replace(':', "");
    let path = format!("/etc/dnsmasq.d/{iface}-dns-{mac_n}.conf");
    let hostname = if !label.is_empty() {
        label.to_lowercase().replace(' ', "-")
    } else {
        mac_n.clone()
    };
    let local_domain = tokio::process::Command::new("uci")
        .args(["-q", "get", "dhcp.@dnsmasq[0].domain"])
        .output().await
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "lan".to_string());
    let _ = tokio::fs::write(&path,
        format!("address=/{hostname}.{local_domain}/\n")).await;
    let _ = base_dir; // suppress warning
}

pub async fn append_join_history(base_dir: &std::path::Path, iface: &str, action: &str,
    mac: &str, ip4: &str, ip6: &str, hostname: &str,
    actor: &str, actor_ip4: &str, actor_ip6: &str, actor_mac: &str)
{
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // 11 tab-separated fields — matches the shell tooling's
    // `_lib.sh:_join_history_add` layout (ts, human-readable "when", then the
    // rest), which `routes::status::build_history_rows` and
    // `routes::device`'s history section both parse by fixed column index.
    let (_, when) = run("date", &["+%d %b %H:%M"]).await;
    let line = format!("{ts}\t{when}\t{action}\t{mac}\t{ip4}\t{ip6}\t{hostname}\t{actor}\t{actor_ip4}\t{actor_ip6}\t{actor_mac}");
    let path = base_dir.join(format!("{iface}-join-history"));
    let _ = crate::data::files::file_append(&path, &line).await;
}
