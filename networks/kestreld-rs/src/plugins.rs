//! Event-driven plugin framework for `kestreld --daemon`, in two flavors:
//!
//! - **External process** (`RustPlugin` is *not* this — see below): any
//!   executable file dropped in `/etc/kestrel/plugins/` — shell, Python,
//!   a compiled binary, anything — is spawned and kept running for the
//!   daemon's lifetime; as events happen, one JSON line per event is
//!   written to that process's stdin, and whatever JSON lines it writes
//!   back to its stdout are interpreted as a small, explicit action
//!   vocabulary. This is the mechanism for user-authored, untrusted-by-
//!   default plugins — arbitrary scripts, not compiled into kestreld.
//! - **In-process Rust** (the `RustPlugin` trait): compiled directly into
//!   the `kestreld` binary, called as a plain async function with no
//!   serialization or IPC — for first-party functionality that ships
//!   *with* kestreld (see `DeviceApprovedNotifier` below) rather than
//!   something a user drops in later. Trusted the same as any other
//!   first-party module, since it's part of the binary the admin already
//!   installed.
//!
//! Both kinds share the same `Event` enum and the same enable/disable
//! mechanism (`{plugins_dir}/disabled`, matched by name) — "is this
//! reacting to daemon events" is one concept; "is it trusted compiled
//! code or a dropped-in script" is a separate, orthogonal choice.
//!
//! **Why external processes aren't a dynamically loaded `.so`.** This
//! project runs as root on a home router and already targets 7+ CPU
//! architectures — a `dlopen`ed plugin would share the daemon's address
//! space and crash domain (a bad plugin takes down connection monitoring
//! entirely) and would need Rust ABI stability across separately-compiled
//! artifacts, which is fragile across architectures/toolchain versions. A
//! subprocess has its own crash domain, can be run as a less-privileged
//! user, and needs no ABI at all — closer to how OpenWrt itself treats
//! extensibility (separate init.d services, hotplug scripts). A `RustPlugin`
//! doesn't have this problem in the first place: it's compiled into the
//! same binary, not a separately-built artifact loaded at runtime.
//!
//! An external-process plugin gets **no shell/root access by default** —
//! only the actions below, on purpose: this is a security product, and an
//! event subscriber shouldn't need to be trusted with arbitrary command
//! execution just to react to "a new connection happened". A `RustPlugin`
//! has no such restriction (it's given a `PluginContext` with real,
//! typed methods) since it's first-party code, not external input.
//!
//! **Event coverage**: every `Event` variant fires from somewhere in
//! `daemon.rs` — `NewConnection`/`DnsQuery`/`DnsAnswer` from the log-follow
//! loop, `DeviceApproved` from `observation.rs`'s automatic rule
//! materialization, and `WanStateChanged`/`VpnStateChanged`/
//! `BandwidthThresholdCrossed` from the WAN/VPN/bandwidth interval tasks
//! (via each checker's `run_and_report`). All daemon-only: CGI-mode
//! request handlers are one-shot processes with no persistent plugin
//! manager to fire into, so approving a rule from the device page directly
//! doesn't emit `DeviceApproved` — only the daemon's own automatic
//! observation-window materialization does. The WAN/VPN/bandwidth events
//! also inherit those checkers' existing gate: they only run at all when
//! some network has a `NOTIFY_URL` configured.
//!
//! **Selective subscriptions**: by default a plugin receives every event.
//! Writing `{"subscribe":["NewConnection","DnsAnswer"]}` on its stdout at
//! any point narrows that to just the named events (a later `subscribe`
//! line replaces the filter, doesn't add to it) — worth doing once
//! `WanStateChanged`/`VpnStateChanged`/`BandwidthThresholdCrossed` are in
//! the mix too, since a plugin that only cares about connections
//! shouldn't have to filter out everything else itself.
//!
//! **Hot-reload**: `rescan()` is called both at daemon startup and on a
//! periodic timer (`daemon.rs`), so dropping a new executable into
//! `/etc/kestrel/plugins/` doesn't require restarting the whole daemon.
//! Already-running plugins are left alone; a plugin file removed from disk
//! isn't killed (this only ever adds, never removes, keeping the
//! lifecycle simple).
//!
//! A plugin process that exits or crashes is just logged and left dead
//! until the next daemon start — not respawned mid-run, so a crash-looping
//! plugin can't consume resources indefinitely.

use std::collections::HashSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, Mutex, RwLock};

#[derive(Serialize, Clone, Debug)]
#[serde(tag = "event")]
pub enum Event {
    NewConnection {
        mac: String,
        dst: String,
        port: String,
        proto: String,
    },
    DnsQuery {
        mac: String,
        domain: String,
        qtype: String,
    },
    DnsAnswer {
        mac: String,
        domain: String,
        ip: String,
    },
    DeviceApproved {
        iface: String,
        mac: String,
        dst: String,
        route: String,
    },
    WanStateChanged {
        iface: String,
        up: bool,
    },
    VpnStateChanged {
        tier: String,
        up: bool,
    },
    BandwidthThresholdCrossed {
        mac: String,
        bytes: u64,
    },
    /// A message received by the social-firewall chat bridge. The bridge is
    /// deliberately transport-neutral; it only needs to call
    /// `PluginManager::broadcast_chat_message`.
    ChatMessage {
        group: String,
        sender: String,
        body: String,
    },
}

impl Event {
    /// The `event` tag's value, i.e. the variant name — used for
    /// subscription filtering without re-parsing the serialized line.
    fn tag(&self) -> &'static str {
        match self {
            Event::NewConnection { .. } => "NewConnection",
            Event::DnsQuery { .. } => "DnsQuery",
            Event::DnsAnswer { .. } => "DnsAnswer",
            Event::DeviceApproved { .. } => "DeviceApproved",
            Event::WanStateChanged { .. } => "WanStateChanged",
            Event::VpnStateChanged { .. } => "VpnStateChanged",
            Event::BandwidthThresholdCrossed { .. } => "BandwidthThresholdCrossed",
            Event::ChatMessage { .. } => "ChatMessage",
        }
    }
}

/// Where external plugins live, and where each plugin's `.info` file
/// (see `PluginInfo`) and the `disabled` enable/disable list are kept
/// alongside them. A `pub` constant rather than a private one repeated in
/// both `daemon.rs` (which spawns plugins here) and `routes::plugin_info`
/// (which reads `.info` files from here in CGI mode, a separate process
/// with no access to the daemon's live `PluginManager`).
pub const PLUGINS_DIR: &str = "/etc/kestrel/plugins";

/// A plugin narrowing which events it wants to receive — see the module
/// doc's "Selective subscriptions" section. Not an `Action`: this changes
/// what the plugin is sent, not something the daemon does in response to
/// one event.
#[derive(Deserialize)]
struct Subscribe {
    subscribe: Vec<String>,
}

/// A plugin self-describing what it does, for the "ⓘ" link the device
/// page shows next to a plugin's name (in a `plugin_note`'s badge, or in
/// a future plugin-listing page) — external plugins send this as a JSON
/// line like `{"info":"Flags domains against my private threat feed.","version":"1.2.0"}`,
/// at any point, same as `Subscribe`. `version` is optional and purely
/// informational (freeform, not semver-checked) — an external plugin has
/// no natural version of its own the framework could infer, unlike a
/// `RustPlugin`, which is versioned in lockstep with kestreld itself (see
/// `RustPlugin::version`'s default). Not an `Action`: this describes the
/// plugin itself, not something the daemon does in response to one event.
#[derive(Deserialize)]
struct Info {
    info: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    maintainer: String,
    #[serde(default)]
    website: String,
}

/// Persisted to `{PLUGINS_DIR}/{name}.info` so `routes::plugin_info` (a
/// CGI-mode, one-shot process with no access to the daemon's live
/// `PluginManager`) can read it back. `kind` distinguishes an external
/// script from a compiled-in `RustPlugin` on the detail page — cosmetic,
/// not a security boundary. `version`/`maintainer`/`website` are all
/// freeform and may be empty — none of them are validated as a real
/// semver/contact/URL, they're just shown as-is on the detail page.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct PluginInfo {
    pub kind: String,
    pub description: String,
    pub version: String,
    pub maintainer: String,
    pub website: String,
}

#[allow(clippy::too_many_arguments)]
async fn write_plugin_info(
    plugins_dir: &Path,
    name: &str,
    kind: &str,
    description: &str,
    version: &str,
    maintainer: &str,
    website: &str,
) {
    if !crate::data::files::is_valid_plugin_name(name) {
        return;
    }
    let info = PluginInfo {
        kind: kind.to_string(),
        description: description.to_string(),
        version: version.to_string(),
        maintainer: maintainer.to_string(),
        website: website.to_string(),
    };
    if let Ok(json) = serde_json::to_string(&info) {
        let _ = tokio::fs::write(plugins_dir.join(format!("{name}.info")), json).await;
    }
}

/// Reads back what `write_plugin_info` wrote — used by `routes::plugin_info`
/// (CGI mode) to render a plugin's detail page. `None` for a plugin that
/// hasn't self-reported an `info` line yet (external) or hasn't been
/// discovered by a daemon run since it started shipping a description
/// (`RustPlugin`) — the caller shows a "no description yet" fallback.
pub async fn read_plugin_info(plugins_dir: &Path, name: &str) -> Option<PluginInfo> {
    if !crate::data::files::is_valid_plugin_name(name) {
        return None;
    }
    let content = tokio::fs::read_to_string(plugins_dir.join(format!("{name}.info")))
        .await
        .ok()?;
    serde_json::from_str(&content).ok()
}

/// The whitelisted set of things a plugin can ask the daemon to do,
/// written back as one JSON line per action on the plugin's stdout.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Action {
    /// Sends an ntfy push through the named network's own `NOTIFY_URL` —
    /// a plugin can't specify an arbitrary notification endpoint, only
    /// pick which already-configured network to notify through.
    /// `icon`/`priority` default to ntfy's own defaults when empty; a
    /// clickable action button (ntfy's `Actions:` header) is added only
    /// when both `action_label` and `action_url` are set.
    Notify {
        iface: String,
        title: String,
        body: String,
        #[serde(default)]
        icon: String,
        #[serde(default)]
        priority: String,
        #[serde(default)]
        action_label: String,
        #[serde(default)]
        action_url: String,
    },
    Log {
        message: String,
    },
    /// Approves a destination for a device — the same effect as the
    /// device page's "Approve domain"/pending-connection approval, minus
    /// the ability to choose a VPN route (always plain WAN), letting a
    /// plugin implement custom auto-approval logic (e.g. an always-safe
    /// domain allowlist) without giving it any broader access. Exactly
    /// one of `domain` or `ip` must be set; `port`/`proto` are required
    /// (and ignored) for the two forms respectively.
    AddRule {
        iface: String,
        mac: String,
        #[serde(default)]
        domain: String,
        #[serde(default)]
        ip: String,
        #[serde(default)]
        port: String,
        #[serde(default)]
        proto: String,
    },
    /// Attaches a short note to a specific device+destination, shown next
    /// to it in the device page's pending-connections table — e.g. a
    /// plugin doing its own reputation lookup can explain *why* it thinks
    /// a destination is worth a second look, right where the approve/deny
    /// decision actually gets made, not just as a separate log line.
    /// Replaces any previous note for the same `(mac, dst)` pair; a plugin
    /// can clear one by sending an empty `note`.
    Annotate {
        iface: String,
        mac: String,
        dst: String,
        note: String,
    },
    /// Fetches a small HTTP(S) response through kestreld and sends the result
    /// back to the plugin as `http_response`. This keeps request limits in one
    /// place and avoids giving bot authors a shell command vocabulary.
    HttpGet {
        request_id: String,
        url: String,
    },
    /// Publishes a signed message through the installed social-firewall CLI.
    ChatSend {
        group: String,
        body: String,
    },
}

/// What a compiled-in `RustPlugin` gets instead of the JSON `Action`
/// vocabulary external plugins are limited to — plain, typed, in-process
/// calls to the same functions those actions ultimately invoke anyway
/// (`observation::write_domain_rule`/`write_ip_rule`, `cmd::ntfy`). No
/// validation gate here the way `handle_plugin_line` has for `AddRule`:
/// a `RustPlugin` is first-party code, not untrusted external input, and
/// `write_domain_rule`/`write_ip_rule` still validate their own inputs
/// regardless (see their doc comments) as a second line of defense.
pub struct PluginContext {
    base_dir: PathBuf,
    split_routing_dir: PathBuf,
    store: std::sync::Arc<crate::db::Store>,
    /// Whichever plugin this context was built for — used to attribute
    /// `annotate()` calls without letting the plugin self-report a
    /// different name (see `db::PluginNote::plugin_name`).
    plugin_name: String,
}

/// Longest note `annotate`/`Annotate` accepts — a plugin flagging
/// something should be a short pointer, not a place to dump arbitrary
/// text into a file that grows without bound.
const MAX_NOTE_LEN: usize = 200;

impl PluginContext {
    pub async fn notify(&self, iface: &str, title: &str, body: &str) {
        self.notify_full(iface, title, body, "", "", "", "").await;
    }

    /// Same as `notify`, but lets the plugin also choose an ntfy icon/tag
    /// and priority (falling back to `electric_plug`/`default` when
    /// empty) and add a clickable action button (ntfy's `Actions:`
    /// header) when both `action_label` and `action_url` are set.
    pub async fn notify_full(
        &self,
        iface: &str,
        title: &str,
        body: &str,
        icon: &str,
        priority: &str,
        action_label: &str,
        action_url: &str,
    ) {
        let confs = crate::data::files::read_all_network_confs(&self.base_dir).await;
        let Some(conf) = confs.iter().find(|c| c.iface == iface) else {
            return;
        };
        if conf.notify_url.is_empty() {
            return;
        }
        let icon = if icon.is_empty() {
            "electric_plug"
        } else {
            icon
        };
        let priority = if priority.is_empty() {
            "default"
        } else {
            priority
        };
        if action_label.is_empty() || action_url.is_empty() {
            crate::cmd::ntfy(&conf.notify_url, title, priority, icon, body).await;
        } else {
            crate::cmd::ntfy_with_action(
                &conf.notify_url,
                title,
                priority,
                icon,
                action_label,
                action_url,
                body,
            )
            .await;
        }
    }

    pub async fn add_rule_domain(&self, iface: &str, mac: &str, domain: &str) {
        crate::observation::write_domain_rule(
            &self.store,
            &self.base_dir,
            &self.split_routing_dir,
            iface,
            mac,
            domain,
            "",
        )
        .await;
    }

    pub async fn add_rule_ip(&self, iface: &str, mac: &str, ip: &str, port: &str, proto: &str) {
        crate::observation::write_ip_rule(&self.store, iface, mac, ip, port, proto).await;
    }

    /// See `Action::Annotate` — same effect, for a `RustPlugin`, attributed
    /// to whichever plugin this context was built for.
    pub async fn annotate(&self, iface: &str, mac: &str, dst: &str, note: &str) {
        annotate(&self.store, iface, mac, dst, &self.plugin_name, note).await;
    }

    pub fn log(&self, message: &str) {
        println!("plugin: {message}");
    }
}

/// Shared by `Action::Annotate` (untrusted external plugin input) and
/// `PluginContext::annotate` (first-party `RustPlugin`s) — validates
/// `iface`/`mac` itself for the same reason `observation::write_domain_rule`
/// does, since the external-plugin path isn't a validated HTTP form.
/// `plugin_name` is supplied by the framework (the caller), never taken
/// from the note's own payload — see `PluginNote::plugin_name`.
async fn annotate(
    store: &crate::db::Store,
    iface: &str,
    mac: &str,
    dst: &str,
    plugin_name: &str,
    note: &str,
) {
    if !crate::data::files::is_valid_iface(iface)
        || !crate::data::files::is_valid_mac(mac)
        || dst.is_empty()
    {
        return;
    }
    let note: String = note.chars().take(MAX_NOTE_LEN).collect();
    let _ = store
        .upsert_plugin_note(iface, mac, dst, plugin_name, &note)
        .await;
}

/// A first-party, compiled-in plugin — see the module doc's "in-process
/// Rust" section for how this differs from an external-process plugin.
/// Object-safe on purpose (`Vec<Box<dyn RustPlugin>>` in `PluginManager`)
/// so registering one is just adding it to the list `daemon.rs` passes to
/// `PluginManager::discover`; `handle` returns a boxed future rather than
/// being an `async fn` directly since native `async fn`-in-traits isn't
/// object-safe on stable Rust yet.
pub trait RustPlugin: Send + Sync {
    /// Used for the same `{plugins_dir}/disabled` enable/disable list
    /// external plugins use — must be stable and not collide with an
    /// external plugin's filename.
    fn name(&self) -> &'static str;
    /// Shown on this plugin's `/cgi-bin/plugin_info` detail page.
    fn description(&self) -> &'static str;
    /// Defaults to kestreld's own crate version, since a `RustPlugin` is
    /// compiled directly into the binary and released in lockstep with
    /// it — there's no separate version for it to have unless it wants
    /// one (e.g. a plugin ported from an external script that wants to
    /// keep its own version numbering visible).
    fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    /// Defaults to empty (shown as "kestreld" by the detail page's
    /// fallback) — override for a `RustPlugin` maintained separately from
    /// the rest of kestreld.
    fn maintainer(&self) -> &'static str {
        ""
    }
    /// Defaults to empty — most first-party plugins don't need their own
    /// page beyond `description()`.
    fn website(&self) -> &'static str {
        ""
    }
    fn handle<'a>(
        &'a self,
        event: &'a Event,
        ctx: &'a PluginContext,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Ships with kestreld: sends an ntfy notification when an observation
/// window (`observation.rs`) automatically approves a destination —
/// closing a real gap, since that automatic materialization otherwise
/// happens silently. Doesn't duplicate `check_wan`/`check_vpn`/
/// `bandwidth_check`'s own notifications (those already send one
/// directly and aren't routed through the plugin framework), only adds
/// one for the daemon behavior that had none at all.
pub struct DeviceApprovedNotifier;

impl RustPlugin for DeviceApprovedNotifier {
    fn name(&self) -> &'static str {
        "device-approved-notifier"
    }

    fn description(&self) -> &'static str {
        "Ships with kestreld. Sends an ntfy push whenever a device observation window (see Per-device control) automatically approves a destination — without this, that automatic approval would otherwise happen silently."
    }

    fn handle<'a>(
        &'a self,
        event: &'a Event,
        ctx: &'a PluginContext,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let Event::DeviceApproved {
                iface,
                mac,
                dst,
                route,
            } = event
            else {
                return;
            };
            let route_suffix = if route.is_empty() {
                String::new()
            } else {
                format!(" via {route} VPN")
            };
            let body = format!(
                "Observation window on {iface} auto-approved {dst}{route_suffix} for {mac}."
            );
            ctx.notify(iface, &format!("Rule added — {iface}"), &body)
                .await;
        })
    }
}

struct Plugin {
    path: PathBuf,
    name: String,
    sender: mpsc::UnboundedSender<(&'static str, String)>,
    child: tokio::process::Child,
}

pub struct PluginManager {
    plugins_dir: PathBuf,
    base_dir: PathBuf,
    split_routing_dir: PathBuf,
    store: std::sync::Arc<crate::db::Store>,
    plugins: Mutex<Vec<Plugin>>,
    /// `Arc`, not `Box`: `broadcast` hands each call to `tokio::spawn` (see
    /// there for why) rather than awaiting it in place, and a spawned
    /// task needs an owned, `'static` handle to call through — a `&self`
    /// borrow doesn't outlive the call to `broadcast`.
    rust_plugins: Vec<std::sync::Arc<dyn RustPlugin>>,
    disabled: RwLock<HashSet<String>>,
}

/// Filenames (not full paths — matches what shows up in a `ls
/// /etc/kestrel/plugins/` listing) listed one per line in
/// `{plugins_dir}/disabled`. Absence means "nothing disabled" — the same
/// missing-file-is-fine handling every other list file in this project
/// gets. This one file lives *inside* `plugins_dir` rather than under
/// `base_dir`: it's read fresh on every `rescan()` right alongside the
/// directory listing it's filtering, and — since it's not executable —
/// harmlessly ignored as a plugin candidate itself.
async fn read_disabled(plugins_dir: &Path) -> HashSet<String> {
    crate::data::files::read_lines(&plugins_dir.join("disabled"))
        .await
        .into_iter()
        .collect()
}

impl PluginManager {
    /// Spawns every executable already present in `plugins_dir` (except
    /// ones listed in `disabled`), and registers `rust_plugins` (checked
    /// against the same `disabled` list by name, but never spawned —
    /// they're plain function calls, not processes). Absence of
    /// `plugins_dir` (or an unreadable directory) just means no external
    /// plugins — same "absence is fine" handling every other optional
    /// data source in this project uses.
    pub async fn discover(
        plugins_dir: &Path,
        base_dir: PathBuf,
        split_routing_dir: PathBuf,
        store: std::sync::Arc<crate::db::Store>,
        rust_plugins: Vec<std::sync::Arc<dyn RustPlugin>>,
    ) -> Self {
        for plugin in &rust_plugins {
            write_plugin_info(
                plugins_dir,
                plugin.name(),
                "rust",
                plugin.description(),
                plugin.version(),
                plugin.maintainer(),
                plugin.website(),
            )
            .await;
        }
        let mgr = Self {
            plugins_dir: plugins_dir.to_path_buf(),
            base_dir,
            split_routing_dir,
            store,
            plugins: Mutex::new(Vec::new()),
            rust_plugins,
            disabled: RwLock::new(HashSet::new()),
        };
        mgr.rescan().await;
        mgr
    }

    /// Re-reads `{plugins_dir}/disabled` and the directory listing: stops
    /// (kills) any tracked plugin that's now disabled, and spawns any
    /// executable that's new and not disabled. Safe to call repeatedly —
    /// `daemon.rs` polls it on a timer, which is what makes both
    /// hot-reloading a newly dropped-in plugin and toggling one off
    /// without restarting the daemon possible. Already-running,
    /// still-enabled plugins are left alone; a plugin file removed from
    /// disk (as opposed to disabled) isn't stopped — only the `disabled`
    /// list does that, keeping "delete the file" and "turn it off"
    /// distinct actions.
    pub async fn rescan(&self) {
        let disabled = read_disabled(&self.plugins_dir).await;
        *self.disabled.write().await = disabled.clone();
        let mut plugins = self.plugins.lock().await;

        // Stop anything now disabled, and reap anything that already
        // exited on its own (the reader task doesn't own `child`, so
        // this periodic sweep is what prevents a crashed plugin from
        // lingering as a zombie process).
        let mut i = 0;
        while i < plugins.len() {
            if disabled.contains(&plugins[i].name) {
                let mut stopped = plugins.remove(i);
                println!("plugin disabled, stopping: {}", stopped.name);
                let _ = stopped.child.kill().await;
                continue;
            }
            match plugins[i].child.try_wait() {
                Ok(Some(_)) => {
                    println!("plugin exited: {}", plugins[i].name);
                    plugins.remove(i);
                }
                _ => i += 1,
            }
        }

        let Ok(mut dir) = tokio::fs::read_dir(&self.plugins_dir).await else {
            return;
        };
        while let Ok(Some(entry)) = dir.next_entry().await {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if disabled.contains(&name) || plugins.iter().any(|p| p.path == path) {
                continue;
            }
            let Ok(meta) = entry.metadata().await else {
                continue;
            };
            if !meta.is_file() || !is_executable(&meta) {
                continue;
            }
            match spawn_plugin(
                &path,
                self.base_dir.clone(),
                self.split_routing_dir.clone(),
                self.store.clone(),
                self.plugins_dir.clone(),
                name.clone(),
            )
            .await
            {
                Some((sender, child)) => {
                    println!("plugin loaded: {name}");
                    plugins.push(Plugin {
                        path,
                        name,
                        sender,
                        child,
                    });
                }
                None => eprintln!("failed to spawn plugin: {name}"),
            }
        }
    }

    /// Calls every enabled `RustPlugin` in-process (no serialization),
    /// then serializes `event` once and hands it to every external
    /// plugin's writer task, which applies that plugin's own subscription
    /// filter (if any).
    ///
    /// A crashed or slow external plugin can't affect the daemon at all —
    /// it's a separate OS process. A `RustPlugin` doesn't get that for
    /// free (it's an in-process function call), so each call is run
    /// inside its own `tokio::spawn` and awaited via the resulting
    /// `JoinHandle` rather than called directly: a panic inside a spawned
    /// task is caught by tokio at that task's boundary and surfaces here
    /// as an `Err`, instead of unwinding into `broadcast`'s caller — which
    /// matters a lot for this specific caller, since `daemon.rs` treats
    /// any of its own tasks (the ones that call `broadcast`) ending for
    /// any reason, panic included, as fatal to the whole daemon process.
    /// Without this, a bug in one first-party plugin could take the
    /// entire monitor down. A slow (not panicking) `RustPlugin` still
    /// delays the next event, same as before — this isolates crashes, not
    /// latency.
    pub async fn broadcast(&self, event: &Event) {
        {
            let disabled = self.disabled.read().await;
            for plugin in &self.rust_plugins {
                let name = plugin.name();
                if disabled.contains(name) {
                    continue;
                }
                let plugin = plugin.clone();
                let event = event.clone();
                let ctx = PluginContext {
                    base_dir: self.base_dir.clone(),
                    split_routing_dir: self.split_routing_dir.clone(),
                    store: self.store.clone(),
                    plugin_name: name.to_string(),
                };
                if let Err(e) = tokio::spawn(async move { plugin.handle(&event, &ctx).await }).await
                {
                    eprintln!("plugin '{name}' panicked while handling an event: {e}");
                }
            }
        }

        let Ok(line) = serde_json::to_string(event) else {
            return;
        };
        let tag = event.tag();
        for plugin in self.plugins.lock().await.iter() {
            let _ = plugin.sender.send((tag, line.clone()));
        }
    }

    /// Entry point for the social-firewall transport bridge. Keeping this
    /// method on the existing manager means chat bots use the same lifecycle,
    /// subscriptions, and crash isolation as every other plugin.
    pub async fn broadcast_chat_message(&self, group: &str, sender: &str, body: &str) {
        self.broadcast(&Event::ChatMessage {
            group: group.to_string(),
            sender: sender.to_string(),
            body: body.to_string(),
        })
        .await;
    }

    #[cfg(test)]
    async fn active_names(&self) -> Vec<String> {
        self.plugins
            .lock()
            .await
            .iter()
            .map(|p| p.name.clone())
            .collect()
    }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

async fn spawn_plugin(
    path: &Path,
    base_dir: PathBuf,
    split_routing_dir: PathBuf,
    store: std::sync::Arc<crate::db::Store>,
    plugins_dir: PathBuf,
    name: String,
) -> Option<(
    mpsc::UnboundedSender<(&'static str, String)>,
    tokio::process::Child,
)> {
    let mut child = Command::new(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut stdin = child.stdin.take()?;
    let stdout = child.stdout.take()?;

    // `None` = no filter (receive everything); `Some(set)` = only the
    // named event tags. Shared between the writer task (reads it before
    // forwarding each event) and the reader task (writes it when the
    // plugin sends a `subscribe` line) — updated live, not just once at
    // startup.
    let subscription: std::sync::Arc<RwLock<Option<HashSet<String>>>> =
        std::sync::Arc::new(RwLock::new(None));

    let (tx, mut rx) = mpsc::unbounded_channel::<(&'static str, String)>();

    let writer_subscription = subscription.clone();
    let response_tx = tx.clone();
    tokio::spawn(async move {
        while let Some((tag, line)) = rx.recv().await {
            let allowed = match &*writer_subscription.read().await {
                None => true,
                // Request responses must not be hidden by an event-only
                // subscription such as `ChatMessage`.
                Some(subscribed) => {
                    matches!(tag, "HttpResponse" | "ChatResponse") || subscribed.contains(tag)
                }
            };
            if !allowed {
                continue;
            }
            if stdin.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            if stdin.write_all(b"\n").await.is_err() {
                break;
            }
        }
    });

    // Reader: acts on whatever this plugin writes back, independently of
    // the writer side above — a plugin doesn't have to reply to every
    // event, or reply in lockstep with them. Doesn't own `child` (that's
    // returned to the caller, for `rescan()` to kill on disable) — a
    // plugin that exits on its own is reaped by `rescan()`'s periodic
    // `try_wait()` sweep instead, not here.
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    handle_plugin_line(
                        &base_dir,
                        &split_routing_dir,
                        &store,
                        &plugins_dir,
                        &name,
                        &line,
                        &subscription,
                        &response_tx,
                    )
                    .await
                }
                _ => break,
            }
        }
    });

    Some((tx, child))
}

async fn handle_plugin_line(
    base_dir: &Path,
    split_routing_dir: &Path,
    store: &std::sync::Arc<crate::db::Store>,
    plugins_dir: &Path,
    name: &str,
    line: &str,
    subscription: &std::sync::Arc<RwLock<Option<HashSet<String>>>>,
    response_tx: &mpsc::UnboundedSender<(&'static str, String)>,
) {
    if let Ok(sub) = serde_json::from_str::<Subscribe>(line) {
        *subscription.write().await = Some(sub.subscribe.into_iter().collect());
        return;
    }

    if let Ok(info) = serde_json::from_str::<Info>(line) {
        write_plugin_info(
            plugins_dir,
            name,
            "external",
            &info.info,
            &info.version,
            &info.maintainer,
            &info.website,
        )
        .await;
        return;
    }

    let Ok(action) = serde_json::from_str::<Action>(line) else {
        return;
    };
    let ctx = PluginContext {
        base_dir: base_dir.to_path_buf(),
        split_routing_dir: split_routing_dir.to_path_buf(),
        store: store.clone(),
        plugin_name: name.to_string(),
    };
    match action {
        Action::Log { message } => ctx.log(&message),
        Action::Notify {
            iface,
            title,
            body,
            icon,
            priority,
            action_label,
            action_url,
        } => {
            ctx.notify_full(
                &iface,
                &title,
                &body,
                &icon,
                &priority,
                &action_label,
                &action_url,
            )
            .await;
        }
        Action::AddRule {
            iface,
            mac,
            domain,
            ip,
            port,
            proto,
        } => {
            if !crate::data::files::is_valid_mac(&mac) {
                return;
            }
            if !domain.is_empty() && ip.is_empty() {
                ctx.add_rule_domain(&iface, &mac, &domain).await;
            } else if !ip.is_empty() && domain.is_empty() {
                ctx.add_rule_ip(&iface, &mac, &ip, &port, &proto).await;
            }
            // Both or neither set: ambiguous, ignored rather than guessing.
        }
        Action::Annotate {
            iface,
            mac,
            dst,
            note,
        } => {
            ctx.annotate(&iface, &mac, &dst, &note).await;
        }
        Action::HttpGet { request_id, url } => {
            let response = http_get(&url).await;
            let line = serde_json::json!({
                "response": "http_response",
                "request_id": request_id,
                "ok": response.is_ok(),
                "body": response.unwrap_or_else(|e| e),
            })
            .to_string();
            let _ = response_tx.send(("HttpResponse", line));
        }
        Action::ChatSend { group, body } => {
            let response = chat_send(&group, &body).await;
            let line = serde_json::json!({
                "response": "chat_response",
                "ok": response.is_ok(),
                "detail": response.unwrap_or_else(|e| e),
            })
            .to_string();
            let _ = response_tx.send(("ChatResponse", line));
        }
    }
}

const MAX_HTTP_RESPONSE_BYTES: usize = 64 * 1024;

async fn http_get(url: &str) -> Result<String, String> {
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("URL must use http:// or https://".into());
    }
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-time",
            "10",
            "--max-filesize",
            "65536",
            url,
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    if output.stdout.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err("response exceeds 64 KiB".into());
    }
    String::from_utf8(output.stdout).map_err(|_| "response was not UTF-8".into())
}

async fn chat_send(group: &str, body: &str) -> Result<String, String> {
    if group.is_empty() || body.is_empty() || body.len() > 4096 {
        return Err("group and body are required; body is limited to 4096 bytes".into());
    }
    let output = Command::new("/usr/bin/sf")
        .args([
            "--db",
            "/etc/kestrel/social-firewall/social-firewall.sqlite",
            "publish-party-line",
            "--group",
            group,
            "--body",
            body,
        ])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(if output.status.success() {
        &output.stdout
    } else {
        &output.stderr
    })
    .trim()
    .to_string();
    if output.status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_serializes_with_internal_tag() {
        let event = Event::NewConnection {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            dst: "1.2.3.4".into(),
            port: "443".into(),
            proto: "tcp".into(),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"event\":\"NewConnection\""));
        assert!(json.contains("\"dst\":\"1.2.3.4\""));
    }

    #[test]
    fn event_tag_matches_serialized_variant_name() {
        assert_eq!(
            Event::NewConnection {
                mac: "".into(),
                dst: "".into(),
                port: "".into(),
                proto: "".into()
            }
            .tag(),
            "NewConnection"
        );
        assert_eq!(
            Event::WanStateChanged {
                iface: "".into(),
                up: true
            }
            .tag(),
            "WanStateChanged"
        );
        assert_eq!(
            Event::BandwidthThresholdCrossed {
                mac: "".into(),
                bytes: 0
            }
            .tag(),
            "BandwidthThresholdCrossed"
        );
        assert_eq!(
            Event::ChatMessage {
                group: "g".into(),
                sender: "s".into(),
                body: "b".into()
            }
            .tag(),
            "ChatMessage"
        );
    }

    #[test]
    fn subscribe_parses_event_name_list() {
        let line = r#"{"subscribe":["NewConnection","DnsAnswer"]}"#;
        let sub: Subscribe = serde_json::from_str(line).unwrap();
        assert_eq!(
            sub.subscribe,
            vec!["NewConnection".to_string(), "DnsAnswer".to_string()]
        );
    }

    #[test]
    fn action_parses_notify() {
        let line = r#"{"action":"notify","iface":"guest","title":"t","body":"b"}"#;
        let action: Action = serde_json::from_str(line).unwrap();
        assert_eq!(
            action,
            Action::Notify {
                iface: "guest".into(),
                title: "t".into(),
                body: "b".into(),
                icon: "".into(),
                priority: "".into(),
                action_label: "".into(),
                action_url: "".into(),
            }
        );
    }

    #[test]
    fn action_parses_notify_with_icon_priority_and_action() {
        let line = r#"{"action":"notify","iface":"guest","title":"t","body":"b","icon":"warning","priority":"high","action_label":"View","action_url":"http://x"}"#;
        let action: Action = serde_json::from_str(line).unwrap();
        assert_eq!(
            action,
            Action::Notify {
                iface: "guest".into(),
                title: "t".into(),
                body: "b".into(),
                icon: "warning".into(),
                priority: "high".into(),
                action_label: "View".into(),
                action_url: "http://x".into(),
            }
        );
    }

    #[test]
    fn action_parses_annotate() {
        let line = r#"{"action":"annotate","iface":"guest","mac":"aa:bb:cc:dd:ee:ff","dst":"1.2.3.4","note":"looks like a CDN"}"#;
        let action: Action = serde_json::from_str(line).unwrap();
        assert_eq!(
            action,
            Action::Annotate {
                iface: "guest".into(),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                dst: "1.2.3.4".into(),
                note: "looks like a CDN".into(),
            }
        );
    }

    // ── plugin info (description/version/maintainer/website) ─────────────────

    #[test]
    fn info_parses_description_only() {
        let line = r#"{"info":"Flags domains against my private threat feed."}"#;
        let info: Info = serde_json::from_str(line).unwrap();
        assert_eq!(info.info, "Flags domains against my private threat feed.");
        assert_eq!(info.version, "");
        assert_eq!(info.maintainer, "");
        assert_eq!(info.website, "");
    }

    #[test]
    fn info_parses_all_fields() {
        let line = r#"{"info":"desc","version":"1.2.0","maintainer":"someone","website":"https://example.com"}"#;
        let info: Info = serde_json::from_str(line).unwrap();
        assert_eq!(info.version, "1.2.0");
        assert_eq!(info.maintainer, "someone");
        assert_eq!(info.website, "https://example.com");
    }

    #[tokio::test]
    async fn write_and_read_plugin_info_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        write_plugin_info(
            dir.path(),
            "my-plugin",
            "external",
            "desc",
            "1.0",
            "me",
            "https://x",
        )
        .await;
        let info = read_plugin_info(dir.path(), "my-plugin").await.unwrap();
        assert_eq!(info.kind, "external");
        assert_eq!(info.description, "desc");
        assert_eq!(info.version, "1.0");
        assert_eq!(info.maintainer, "me");
        assert_eq!(info.website, "https://x");
    }

    #[tokio::test]
    async fn read_plugin_info_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(read_plugin_info(dir.path(), "never-ran").await.is_none());
    }

    #[tokio::test]
    async fn write_plugin_info_rejects_invalid_name() {
        let dir = tempfile::tempdir().unwrap();
        write_plugin_info(dir.path(), "../evil", "external", "desc", "", "", "").await;
        let mut entries = tokio::fs::read_dir(dir.path()).await.unwrap();
        assert!(entries.next_entry().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn discover_writes_info_for_rust_plugins() {
        let dir = tempfile::tempdir().unwrap();
        let plugin: std::sync::Arc<dyn RustPlugin> = std::sync::Arc::new(DeviceApprovedNotifier);
        let _mgr = PluginManager::discover(
            dir.path(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            vec![plugin],
        )
        .await;

        let info = read_plugin_info(dir.path(), "device-approved-notifier")
            .await
            .unwrap();
        assert_eq!(info.kind, "rust");
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
        // Empty by default at the trait level — routes::plugin_info is
        // what falls back to displaying "kestreld" for an empty maintainer.
        assert_eq!(info.maintainer, "");
        assert!(!info.description.is_empty());
    }

    #[test]
    fn action_parses_log() {
        let line = r#"{"action":"log","message":"hello"}"#;
        let action: Action = serde_json::from_str(line).unwrap();
        assert_eq!(
            action,
            Action::Log {
                message: "hello".into()
            }
        );
    }

    #[test]
    fn action_parses_http_get() {
        let action = serde_json::from_str::<Action>(
            r#"{"action":"http_get","request_id":"weather","url":"https://example.com"}"#,
        )
        .unwrap();
        assert_eq!(
            action,
            Action::HttpGet {
                request_id: "weather".into(),
                url: "https://example.com".into()
            }
        );
    }

    #[test]
    fn action_parses_chat_send() {
        let action = serde_json::from_str::<Action>(
            r#"{"action":"chat_send","group":"alerts","body":"WAN is down"}"#,
        )
        .unwrap();
        assert_eq!(
            action,
            Action::ChatSend {
                group: "alerts".into(),
                body: "WAN is down".into()
            }
        );
    }

    #[test]
    fn action_parses_add_rule_with_domain() {
        let line = r#"{"action":"add_rule","iface":"guest","mac":"aa:bb:cc:dd:ee:ff","domain":"example.com"}"#;
        let action: Action = serde_json::from_str(line).unwrap();
        assert_eq!(
            action,
            Action::AddRule {
                iface: "guest".into(),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                domain: "example.com".into(),
                ip: "".into(),
                port: "".into(),
                proto: "".into(),
            }
        );
    }

    #[test]
    fn action_parses_add_rule_with_ip_port_proto() {
        let line = r#"{"action":"add_rule","iface":"guest","mac":"aa:bb:cc:dd:ee:ff","ip":"1.2.3.4","port":"443","proto":"tcp"}"#;
        let action: Action = serde_json::from_str(line).unwrap();
        assert_eq!(
            action,
            Action::AddRule {
                iface: "guest".into(),
                mac: "aa:bb:cc:dd:ee:ff".into(),
                domain: "".into(),
                ip: "1.2.3.4".into(),
                port: "443".into(),
                proto: "tcp".into(),
            }
        );
    }

    #[test]
    fn action_rejects_unknown_action_name() {
        let line = r#"{"action":"exec","command":"rm -rf /"}"#;
        assert!(serde_json::from_str::<Action>(line).is_err());
    }

    #[test]
    fn action_rejects_malformed_json() {
        assert!(serde_json::from_str::<Action>("not json").is_err());
    }

    fn no_rust_plugins() -> Vec<std::sync::Arc<dyn RustPlugin>> {
        Vec::new()
    }

    #[tokio::test]
    async fn discover_with_missing_directory_returns_no_plugins() {
        let mgr = PluginManager::discover(
            Path::new("/nonexistent/plugins"),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            no_rust_plugins(),
        )
        .await;
        assert!(mgr.plugins.lock().await.is_empty());
    }

    #[tokio::test]
    async fn discover_skips_non_executable_files() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("not-a-plugin.txt"), "hello")
            .await
            .unwrap();
        let mgr = PluginManager::discover(
            dir.path(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            no_rust_plugins(),
        )
        .await;
        assert!(mgr.plugins.lock().await.is_empty());
    }

    async fn write_executable_script(dir: &Path, name: &str) -> PathBuf {
        let script_path = dir.join(name);
        tokio::fs::write(&script_path, "#!/bin/sh\ncat\n")
            .await
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&script_path)
                .await
                .unwrap()
                .permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&script_path, perms)
                .await
                .unwrap();
        }
        script_path
    }

    #[tokio::test]
    async fn discover_spawns_executable_scripts() {
        let dir = tempfile::tempdir().unwrap();
        write_executable_script(dir.path(), "echo-plugin.sh").await;
        let mgr = PluginManager::discover(
            dir.path(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            no_rust_plugins(),
        )
        .await;
        assert_eq!(mgr.plugins.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn rescan_picks_up_a_newly_added_plugin_without_duplicating_existing_ones() {
        let dir = tempfile::tempdir().unwrap();
        write_executable_script(dir.path(), "first.sh").await;
        let mgr = PluginManager::discover(
            dir.path(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            no_rust_plugins(),
        )
        .await;
        assert_eq!(mgr.plugins.lock().await.len(), 1);

        write_executable_script(dir.path(), "second.sh").await;
        mgr.rescan().await;
        assert_eq!(mgr.plugins.lock().await.len(), 2);

        // Rescanning again with nothing new added doesn't duplicate.
        mgr.rescan().await;
        assert_eq!(mgr.plugins.lock().await.len(), 2);
    }

    // ── enable/disable (both plugin kinds) ───────────────────────────────────

    #[tokio::test]
    async fn discover_skips_a_plugin_listed_as_disabled() {
        let dir = tempfile::tempdir().unwrap();
        write_executable_script(dir.path(), "quiet.sh").await;
        tokio::fs::write(dir.path().join("disabled"), "quiet.sh\n")
            .await
            .unwrap();
        let mgr = PluginManager::discover(
            dir.path(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            no_rust_plugins(),
        )
        .await;
        assert!(mgr.active_names().await.is_empty());
    }

    #[tokio::test]
    async fn rescan_stops_a_running_plugin_once_disabled_and_restarts_it_when_re_enabled() {
        let dir = tempfile::tempdir().unwrap();
        write_executable_script(dir.path(), "toggle.sh").await;
        let mgr = PluginManager::discover(
            dir.path(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            no_rust_plugins(),
        )
        .await;
        assert_eq!(mgr.active_names().await, vec!["toggle.sh".to_string()]);

        tokio::fs::write(dir.path().join("disabled"), "toggle.sh\n")
            .await
            .unwrap();
        mgr.rescan().await;
        assert!(mgr.active_names().await.is_empty());

        tokio::fs::remove_file(dir.path().join("disabled"))
            .await
            .unwrap();
        mgr.rescan().await;
        assert_eq!(mgr.active_names().await, vec!["toggle.sh".to_string()]);
    }

    // ── RustPlugin (in-process) dispatch ─────────────────────────────────────

    struct RecordingPlugin {
        calls: std::sync::Arc<Mutex<Vec<Event>>>,
    }

    impl RustPlugin for RecordingPlugin {
        fn name(&self) -> &'static str {
            "recording-plugin"
        }
        fn description(&self) -> &'static str {
            "Test-only plugin that records received events."
        }
        fn handle<'a>(
            &'a self,
            event: &'a Event,
            _ctx: &'a PluginContext,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().await.push(event.clone());
            })
        }
    }

    struct PanickingPlugin;

    impl RustPlugin for PanickingPlugin {
        fn name(&self) -> &'static str {
            "panicking-plugin"
        }
        fn description(&self) -> &'static str {
            "Test-only plugin that always panics."
        }
        fn handle<'a>(
            &'a self,
            _event: &'a Event,
            _ctx: &'a PluginContext,
        ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
            Box::pin(async move { panic!("boom") })
        }
    }

    fn new_connection_event() -> Event {
        Event::NewConnection {
            mac: "aa:bb:cc:dd:ee:ff".into(),
            dst: "1.2.3.4".into(),
            port: "443".into(),
            proto: "tcp".into(),
        }
    }

    #[tokio::test]
    async fn broadcast_invokes_a_registered_rust_plugin() {
        let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
        let plugin: std::sync::Arc<dyn RustPlugin> = std::sync::Arc::new(RecordingPlugin {
            calls: calls.clone(),
        });
        let mgr = PluginManager::discover(
            Path::new("/nonexistent"),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            vec![plugin],
        )
        .await;

        mgr.broadcast(&new_connection_event()).await;

        assert_eq!(calls.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn broadcast_skips_a_disabled_rust_plugin() {
        let dir = tempfile::tempdir().unwrap();
        tokio::fs::write(dir.path().join("disabled"), "recording-plugin\n")
            .await
            .unwrap();
        let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
        let plugin: std::sync::Arc<dyn RustPlugin> = std::sync::Arc::new(RecordingPlugin {
            calls: calls.clone(),
        });
        let mgr = PluginManager::discover(
            dir.path(),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            vec![plugin],
        )
        .await;

        mgr.broadcast(&new_connection_event()).await;

        assert!(calls.lock().await.is_empty());
    }

    #[tokio::test]
    async fn broadcast_survives_a_panicking_rust_plugin() {
        let plugin: std::sync::Arc<dyn RustPlugin> = std::sync::Arc::new(PanickingPlugin);
        let mgr = PluginManager::discover(
            Path::new("/nonexistent"),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            vec![plugin],
        )
        .await;

        // If the panic escaped `broadcast` instead of being caught at the
        // spawned task boundary, this call itself would panic and fail
        // the test — the real assertion is that it returns normally.
        mgr.broadcast(&new_connection_event()).await;
    }

    #[tokio::test]
    async fn broadcast_still_runs_other_rust_plugins_after_one_panics() {
        let calls = std::sync::Arc::new(Mutex::new(Vec::new()));
        let panicking: std::sync::Arc<dyn RustPlugin> = std::sync::Arc::new(PanickingPlugin);
        let recording: std::sync::Arc<dyn RustPlugin> = std::sync::Arc::new(RecordingPlugin {
            calls: calls.clone(),
        });
        let mgr = PluginManager::discover(
            Path::new("/nonexistent"),
            PathBuf::from("/tmp"),
            PathBuf::from("/tmp"),
            std::sync::Arc::new(crate::db::Store::open_in_memory().unwrap()),
            vec![panicking, recording],
        )
        .await;

        mgr.broadcast(&new_connection_event()).await;

        assert_eq!(calls.lock().await.len(), 1);
    }

    #[test]
    fn device_approved_notifier_name_is_stable() {
        assert_eq!(DeviceApprovedNotifier.name(), "device-approved-notifier");
    }

    // ── annotate ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn annotate_writes_a_plugin_note() {
        let store = crate::db::Store::open_in_memory().unwrap();
        annotate(
            &store,
            "guest",
            "aa:bb:cc:dd:ee:ff",
            "1.2.3.4",
            "my-plugin",
            "looks like a CDN",
        )
        .await;
        let notes = store.list_plugin_notes("guest").await.unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note, "looks like a CDN");
    }

    #[tokio::test]
    async fn annotate_rejects_invalid_iface_and_mac() {
        let store = crate::db::Store::open_in_memory().unwrap();
        annotate(
            &store,
            "../evil",
            "aa:bb:cc:dd:ee:ff",
            "1.2.3.4",
            "my-plugin",
            "note",
        )
        .await;
        annotate(&store, "guest", "not-a-mac", "1.2.3.4", "my-plugin", "note").await;
        // Neither call should have written anything at all, anywhere.
        assert!(store.list_plugin_notes("guest").await.unwrap().is_empty());
        assert!(store.list_plugin_notes("../evil").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn annotate_truncates_overly_long_notes() {
        let store = crate::db::Store::open_in_memory().unwrap();
        let long_note = "x".repeat(MAX_NOTE_LEN + 50);
        annotate(
            &store,
            "guest",
            "aa:bb:cc:dd:ee:ff",
            "1.2.3.4",
            "my-plugin",
            &long_note,
        )
        .await;
        let notes = store.list_plugin_notes("guest").await.unwrap();
        assert_eq!(notes[0].note.chars().count(), MAX_NOTE_LEN);
    }
}
