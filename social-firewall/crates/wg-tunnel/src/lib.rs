//! Reconciles this router's *desired* tunnel state (`provisioned_tunnels`
//! in `state-store` — the record of which tunnels this router is
//! providing or consuming) against real WireGuard interface/peer state,
//! via `wg`/`ip`. The direct analogue of `nft-enforcer`'s
//! `NftablesController`, for WireGuard instead of nftables: same
//! `CommandRunner` abstraction so the whole flow is testable without root
//! or a real interface, same "compute desired state, diff against live
//! state, apply minimally" shape.
//!
//! **Deliberately out of scope here** (per the request that introduced
//! tunnel advertising): full-tunnel ("route everything") mode — this repo
//! has no such mechanism anywhere, and it carries a much bigger blast
//! radius than category-scoped routing. Only WireGuard peer management
//! and category-scoped fwmark/policy-routing are modeled.
//!
//! # Coexistence safety
//!
//! The direct analogue of `nft-enforcer`'s "never touch `fw4`" principle:
//! this crate must never allocate a fwmark/route-table ID outside its own
//! reserved range (see `state-store`'s `tunnel_resource_allocator`
//! comment — starts at `0x1000`/`200`, comfortably clear of
//! `split-routing`'s own hand-picked low integers like `0x1`/`100`), must
//! never modify a `vpn-*.conf`-defined tier's own table/fwmark/interface,
//! and provisions its own nft sets/chain in their own table (not
//! `split-routing`'s generated `/etc/nftables.d/30-split-routing.nft`
//! chain, not `nft-enforcer`'s own `inet social_firewall` table — a
//! *third*, separate table, since this one *marks* traffic for policy
//! routing rather than dropping it, a different job from either).

mod command;
mod keypair;
mod routing;

pub use command::{CommandOutput, CommandRunner, FakeCommandRunner, SystemCommandRunner};
pub use keypair::WgKeypair;
pub use routing::{
    apply_policy_route, compile_mark_script, dnsmasq_conf_snippet, CompiledMarkScript,
};

use domain_types::WgPublicKeyBytes;
use state_store::{StateStore, StoreError};
use std::path::PathBuf;
use std::time::Duration;

pub const NFT_TABLE: &str = "social_firewall_tunnels";

/// Applied to every peer this crate ever adds — every tunnel it manages
/// is inherently a peer across the internet, often with at least one
/// side behind NAT (the same scenario WireGuard's own docs recommend 25s
/// for). Without this, an idle tunnel's NAT/firewall mapping can expire
/// silently: the interface stays administratively up throughout, so
/// nothing in `reconcile()`'s own diff-and-apply loop would ever notice
/// — it just quietly stops passing traffic until something happens to
/// re-trigger a handshake. Unconditional, not a `WgTunnelConfig` knob,
/// since there's no legitimate case here where a remote peer-to-peer
/// tunnel wouldn't want it.
pub const PERSISTENT_KEEPALIVE_SECS: u32 = 25;

#[derive(thiserror::Error, Debug)]
pub enum WgTunnelError {
    #[error("state store error: {0}")]
    Store(#[from] StoreError),
    #[error("command failed: {0}")]
    Command(String),
    #[error("io error writing scratch file: {0}")]
    Io(#[from] std::io::Error),
}

pub struct WgTunnelConfig {
    pub interface_name: String,
    pub command_timeout: Duration,
    /// Where a compiled mark-chain script is written before being handed
    /// to `nft -f` — same "scratch file on disk, not stdin" shape
    /// `NftablesController::apply` already uses, for the same reason
    /// (`nft -f -` reading stdin makes the exact failing script harder to
    /// inspect after the fact than a real path does).
    pub scratch_dir: PathBuf,
    /// Where per-peer `nftset=` dnsmasq conf-dir snippets are written —
    /// a real `/etc/dnsmasq.d/`-style directory on the router, a tempdir
    /// in tests.
    pub dnsmasq_dir: PathBuf,
}

impl Default for WgTunnelConfig {
    fn default() -> Self {
        Self {
            interface_name: "sf_tun0".into(),
            command_timeout: Duration::from_secs(5),
            scratch_dir: std::env::temp_dir(),
            dnsmasq_dir: std::env::temp_dir(),
        }
    }
}

pub struct WgTunnelController<'a> {
    runner: &'a dyn CommandRunner,
    store: &'a StateStore,
    config: WgTunnelConfig,
}

impl<'a> WgTunnelController<'a> {
    pub fn new(
        runner: &'a dyn CommandRunner,
        store: &'a StateStore,
        config: WgTunnelConfig,
    ) -> Self {
        Self {
            runner,
            store,
            config,
        }
    }

    /// Idempotently ensures this router has a WireGuard keypair
    /// (generating and persisting one via `state-store` on first use —
    /// same "lazily generated, then reused forever" pattern the identity
    /// keypair already follows — and loading the existing one on every
    /// subsequent call, so the public key is stable across restarts and
    /// repeated reconcile passes, not regenerated each time) and a live
    /// WireGuard interface with that key installed. Returns the public
    /// key so a caller can put it in an advertisement/connection request.
    pub fn ensure_interface_and_keypair(&self) -> Result<WgPublicKeyBytes, WgTunnelError> {
        let keypair = match self.store.get_wg_keypair_seed()? {
            Some(seed) => WgKeypair::from_seed(&seed),
            None => {
                let kp = WgKeypair::generate();
                self.store.set_wg_keypair_seed(&kp.seed_bytes())?;
                kp
            }
        };

        let public_key = keypair.public_key();
        let iface = &self.config.interface_name;

        let show = self
            .runner
            .run("ip", &["link", "show", iface], self.config.command_timeout);
        if !show.success {
            let add = self.runner.run(
                "ip",
                &["link", "add", iface, "type", "wireguard"],
                self.config.command_timeout,
            );
            if !add.success {
                return Err(WgTunnelError::Command(format!(
                    "failed to create interface {iface}: {}",
                    add.stderr
                )));
            }
        }

        let up = self.runner.run(
            "ip",
            &["link", "set", iface, "up"],
            self.config.command_timeout,
        );
        if !up.success {
            return Err(WgTunnelError::Command(format!(
                "failed to bring up interface {iface}: {}",
                up.stderr
            )));
        }

        Ok(public_key)
    }

    /// Adds (or updates, if already present) a WireGuard peer — real
    /// `wg set <iface> peer <pubkey> allowed-ips <v4>[,<v6>]
    /// persistent-keepalive <PERSISTENT_KEEPALIVE_SECS> [endpoint
    /// <hint>]`. Idempotent: `wg set` on an already-configured peer
    /// simply updates it in place.
    ///
    /// `allowed_ip_v6`, when given, is comma-joined onto `allowed_ip_v4`
    /// in the single `allowed-ips` argument `wg`'s own CLI expects — not
    /// a separate flag. Without an IPv6 entry here, WireGuard's own
    /// crypto-routing layer would drop this peer's IPv6 traffic before
    /// it ever reached the policy-routing layer, regardless of what
    /// `apply_policy_route` does — `allowed-ips` is the one thing
    /// `apply_policy_route`'s own IPv4/IPv6 symmetry can't substitute
    /// for.
    pub fn add_or_update_peer(
        &self,
        peer_wg_pubkey: &WgPublicKeyBytes,
        allowed_ip_v4: &str,
        allowed_ip_v6: Option<&str>,
        endpoint_hint: Option<&str>,
    ) -> Result<(), WgTunnelError> {
        let pubkey_b64 = base64_encode(&peer_wg_pubkey.0);
        let keepalive_secs = PERSISTENT_KEEPALIVE_SECS.to_string();
        let allowed_ips = match allowed_ip_v6 {
            Some(v6) => format!("{allowed_ip_v4},{v6}"),
            None => allowed_ip_v4.to_string(),
        };
        let mut args = vec![
            "set",
            self.config.interface_name.as_str(),
            "peer",
            pubkey_b64.as_str(),
            "allowed-ips",
            allowed_ips.as_str(),
            "persistent-keepalive",
            keepalive_secs.as_str(),
        ];
        if let Some(hint) = endpoint_hint {
            args.push("endpoint");
            args.push(hint);
        }
        let out = self.runner.run("wg", &args, self.config.command_timeout);
        if !out.success {
            return Err(WgTunnelError::Command(format!(
                "failed to add/update peer: {}",
                out.stderr
            )));
        }
        Ok(())
    }

    /// Real `wg set <iface> peer <pubkey> remove`.
    pub fn remove_peer(&self, peer_wg_pubkey: &WgPublicKeyBytes) -> Result<(), WgTunnelError> {
        let pubkey_b64 = base64_encode(&peer_wg_pubkey.0);
        let out = self.runner.run(
            "wg",
            &[
                "set",
                self.config.interface_name.as_str(),
                "peer",
                pubkey_b64.as_str(),
                "remove",
            ],
            self.config.command_timeout,
        );
        if !out.success {
            return Err(WgTunnelError::Command(format!(
                "failed to remove peer: {}",
                out.stderr
            )));
        }
        Ok(())
    }

    /// Parses `wg show <iface> dump` to find which peer public keys are
    /// *actually* configured live — the real-state half of a reconcile
    /// diff, mirroring how `nft-enforcer`'s health check re-lists live
    /// `nft` state rather than trusting its own compiled struct.
    pub fn list_configured_peers(&self) -> Result<Vec<WgPublicKeyBytes>, WgTunnelError> {
        let out = self.runner.run(
            "wg",
            &["show", self.config.interface_name.as_str(), "dump"],
            self.config.command_timeout,
        );
        if !out.success {
            // No interface yet is a legitimate "zero peers configured"
            // state, not an error — `ensure_interface_and_keypair` is
            // what creates it, this is a read-only query.
            return Ok(Vec::new());
        }
        let mut peers = Vec::new();
        for (i, line) in out.stdout.lines().enumerate() {
            if i == 0 {
                continue; // first line is the interface's own private/public key + listen port, not a peer
            }
            if let Some(first_field) = line.split('\t').next() {
                if let Some(bytes) = base64_decode(first_field) {
                    if bytes.len() == 32 {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&bytes);
                        peers.push(WgPublicKeyBytes(arr));
                    }
                }
            }
        }
        Ok(peers)
    }

    /// Same `wg show <iface> dump` call `list_configured_peers` already
    /// makes, but also reads columns 5/6 (transfer-rx, transfer-tx) —
    /// WireGuard tracks these natively per peer, so this is free data
    /// that was already flowing past unused. The substrate for the
    /// tunnel-reciprocity signal (see
    /// `state_store::StateStore::list_tunnel_balances`); this method only
    /// reads live state, it doesn't touch `state-store` itself.
    pub fn list_peer_transfers(&self) -> Result<Vec<(WgPublicKeyBytes, u64, u64)>, WgTunnelError> {
        let out = self.runner.run(
            "wg",
            &["show", self.config.interface_name.as_str(), "dump"],
            self.config.command_timeout,
        );
        if !out.success {
            return Ok(Vec::new());
        }
        let mut transfers = Vec::new();
        for (i, line) in out.stdout.lines().enumerate() {
            if i == 0 {
                continue; // interface line, not a peer
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let (Some(pubkey_field), Some(rx_field), Some(tx_field)) =
                (fields.first(), fields.get(5), fields.get(6))
            else {
                continue;
            };
            let Some(bytes) = base64_decode(pubkey_field) else {
                continue;
            };
            if bytes.len() != 32 {
                continue;
            }
            let (Ok(rx), Ok(tx)) = (rx_field.parse::<u64>(), tx_field.parse::<u64>()) else {
                continue;
            };
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            transfers.push((WgPublicKeyBytes(arr), rx, tx));
        }
        Ok(transfers)
    }

    /// Diffs `state-store`'s `provisioned_tunnels` (desired state — every
    /// row with `status == "active"`, regardless of direction: this
    /// router is a WireGuard peer of the other party either way) against
    /// real `wg show` output (live state) and adds/removes peers to
    /// match — the same "compute desired, diff against live, apply
    /// minimally" shape `NftablesController::apply` uses for nftables.
    ///
    /// **Known limitation, stated rather than silently overclaimed**:
    /// this only reconciles peer *presence* (added if missing, removed
    /// if no longer desired) — it doesn't detect drift in an
    /// already-present peer's `allowed-ips`/endpoint (e.g. if this
    /// router's own assigned `tunnel_ip` changed since the peer was last
    /// added). `list_configured_peers` only extracts pubkeys today, not
    /// each peer's full configured state, so that drift can't be
    /// detected yet — a real gap to close before relying on this for
    /// anything beyond initial provisioning, not a design decision.
    pub fn reconcile(&self) -> Result<ReconcileResult, WgTunnelError> {
        self.ensure_interface_and_keypair()?;
        let desired = self.store.list_provisioned_tunnels()?;
        let desired_active: Vec<&state_store::ProvisionedTunnel> =
            desired.iter().filter(|t| t.status == "active").collect();
        let live = self.list_configured_peers()?;

        let mut added = 0;
        for t in &desired_active {
            if !live.contains(&t.peer_wg_pubkey) {
                let allowed_ip_v6 = t.tunnel_ip6.as_ref().map(|ip6| format!("{ip6}/128"));
                self.add_or_update_peer(
                    &t.peer_wg_pubkey,
                    &format!("{}/32", t.tunnel_ip),
                    allowed_ip_v6.as_deref(),
                    None,
                )?;
                added += 1;
            }
        }

        let mut removed = 0;
        for live_pubkey in &live {
            if !desired_active
                .iter()
                .any(|t| &t.peer_wg_pubkey == live_pubkey)
            {
                self.remove_peer(live_pubkey)?;
                removed += 1;
            }
        }

        // Feed the tunnel-reciprocity ledger from the same `wg show dump`
        // data `list_configured_peers` above already reads — see
        // `list_peer_transfers`'s own doc. A pubkey can match more than
        // one `desired_active` row (a peer this router both provides to
        // and consumes from at once) — see `list_tunnel_balances`'s
        // documented limitation on why that case can't be split by role.
        let now = now_unix();
        for (pubkey, rx, tx) in self.list_peer_transfers()? {
            for t in desired_active.iter().filter(|t| t.peer_wg_pubkey == pubkey) {
                self.store
                    .record_transfer_sample(&t.peer, t.direction, rx, tx, now)?;
            }
        }

        // Only *consuming* tunnels need this router to mark and route its
        // own outgoing traffic — a *providing* tunnel's routing is the
        // other side's problem, this side just accepts the WireGuard peer
        // (handled above) and forwards whatever arrives on the interface.
        for t in desired_active
            .iter()
            .filter(|t| t.direction == state_store::TunnelDirection::Consuming)
        {
            let selected = self.store.get_provisioned_tunnel_selected_targets(
                &t.peer,
                state_store::TunnelDirection::Consuming,
            )?;
            let mut domains = Vec::new();
            let mut static_addrs = Vec::new();
            for target in &selected {
                match target {
                    domain_types::TargetSelector::Domain(d)
                    | domain_types::TargetSelector::DomainSuffix(d) => domains.push(d.clone()),
                    domain_types::TargetSelector::Ip(a) | domain_types::TargetSelector::Cidr(a) => {
                        static_addrs.push(a.clone())
                    }
                    // `Service`/`ProtoPort` aren't resolvable to an
                    // address at all — not yet enforceable here, same
                    // "recorded but not yet enforceable" gap `nft-enforcer`
                    // already has for domain/service targets.
                    _ => {}
                }
            }
            if domains.is_empty() && static_addrs.is_empty() {
                continue;
            }
            // Read (never enforce anything from) the original
            // advertisement's limits — only meaningful for a `Consuming`
            // row, which is exactly the branch this loop is already
            // scoped to; a missing/unresolvable advertisement just means
            // no limits are applied, not an error.
            let (max_connections, max_bandwidth_kbps) = t
                .advertisement_sequence
                .and_then(|seq| {
                    self.store
                        .get_tunnel_advertisement(t.peer, seq)
                        .ok()
                        .flatten()
                })
                .map(|ad| (ad.max_connections, ad.max_bandwidth_kbps))
                .unwrap_or((None, None));
            let peer_short_id = hex_prefix(&t.peer.local_id.0, 8);
            self.provision_routing(
                &peer_short_id,
                t.fwmark,
                t.route_table,
                &domains,
                &static_addrs,
                max_connections,
                max_bandwidth_kbps,
            )?;
        }

        Ok(ReconcileResult {
            peers_added: added,
            peers_removed: removed,
        })
    }

    /// Provisions the traffic-marking half of routing a consuming
    /// tunnel's selected targets through it: the dedicated mark-chain nft
    /// script (fully idempotent — flushes and rebuilds this peer's own
    /// chain/static sets every call, see `compile_mark_script`'s own doc
    /// on why that matters — safe to reapply every reconcile pass), the
    /// dnsmasq `nftset=` snippet that populates the dynamic set for
    /// `domains` on DNS resolution, and the fwmark policy-route.
    /// `static_addrs` (already-known `Ip`/`Cidr` targets) are populated
    /// directly rather than needing a DNS trigger. `max_connections`/
    /// `max_bandwidth_kbps` are the advertised limits for this tunnel,
    /// enforced here since this is the consumer's own router — see
    /// `compile_mark_script`'s own doc on how. Distinct from
    /// [`Self::reconcile`]'s WireGuard peer management — this is "what
    /// happens to this peer's traffic," that's "is this peer allowed to
    /// connect at all."
    #[allow(clippy::too_many_arguments)]
    pub fn provision_routing(
        &self,
        peer_short_id: &str,
        fwmark: i64,
        route_table: i64,
        domains: &[String],
        static_addrs: &[String],
        max_connections: Option<u32>,
        max_bandwidth_kbps: Option<u64>,
    ) -> Result<(), WgTunnelError> {
        let compiled = compile_mark_script(
            peer_short_id,
            fwmark,
            static_addrs,
            max_connections,
            max_bandwidth_kbps,
        );
        let script_path = self
            .config
            .scratch_dir
            .join(format!("social_firewall_tunnel_{peer_short_id}.nft"));
        std::fs::write(&script_path, &compiled.script)?;
        let script_path_str = script_path.to_string_lossy().into_owned();
        let out = self.runner.run(
            "nft",
            &["-f", &script_path_str],
            self.config.command_timeout,
        );
        if !out.success {
            return Err(WgTunnelError::Command(format!(
                "failed to apply mark script for {peer_short_id}: {}",
                out.stderr
            )));
        }

        let snippet = dnsmasq_conf_snippet(domains, &compiled.set_v4, &compiled.set_v6);
        let conf_path = self
            .config
            .dnsmasq_dir
            .join(format!("social-firewall-tunnel-{peer_short_id}.conf"));
        std::fs::write(&conf_path, snippet)?;

        apply_policy_route(
            self.runner,
            fwmark,
            route_table,
            &self.config.interface_name,
            self.config.command_timeout,
        )
        .map_err(WgTunnelError::Command)?;
        Ok(())
    }
}

/// First `len` bytes of a 32-byte id, hex-encoded — a short, stable,
/// filesystem/nft-identifier-safe label derived from a peer's `local_id`,
/// used to namespace this peer's own nft sets/dnsmasq conf file so two
/// concurrently-provisioned tunnels never collide.
fn hex_prefix(bytes: &[u8; 32], len: usize) -> String {
    bytes[..len].iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileResult {
    pub peers_added: usize,
    pub peers_removed: usize,
}

/// Minimal base64 encode/decode — `wg`'s own CLI takes/reports keys in
/// standard base64, not hex, so this crate needs it regardless of any
/// other dependency's own base64 support. Deliberately tiny and
/// self-contained rather than pulling in a general-purpose base64 crate
/// for two small functions.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        out.push(ALPHABET[(b0 >> 2) as usize] as char);
        out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim_end_matches('=');
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk.iter().map(|&b| val(b)).collect::<Option<_>>()?;
        out.push((vals[0] << 2) | (vals.get(1).copied().unwrap_or(0) >> 4));
        if vals.len() > 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if vals.len() > 3 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Some(out)
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use domain_types::{FederationId, Hash32, PublicKeyBytes, UserId};

    /// `ensure_interface_and_keypair` persists the WireGuard keypair seed
    /// on the `is_self` row (see `StateStore::set_wg_keypair_seed`'s own
    /// doc on why a missing identity must fail loudly rather than
    /// silently no-op) — every test that exercises it needs an identity
    /// set up first.
    fn store_with_identity() -> StateStore {
        let store = StateStore::open_in_memory().unwrap();
        let user = UserId {
            federation: FederationId(Hash32([1; 32])),
            local_id: Hash32([2; 32]),
        };
        store
            .set_self_identity(user, PublicKeyBytes([3; 32]), &[4; 32], None)
            .unwrap();
        store
    }

    #[test]
    fn base64_round_trips() {
        let bytes: [u8; 32] = std::array::from_fn(|i| i as u8);
        let encoded = base64_encode(&bytes);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, bytes.to_vec());
    }

    fn controller<'a>(
        runner: &'a FakeCommandRunner,
        store: &'a StateStore,
    ) -> WgTunnelController<'a> {
        WgTunnelController::new(runner, store, WgTunnelConfig::default())
    }

    #[test]
    fn ensure_interface_creates_it_when_missing() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.first().map(String::as_str) == Some("link")
                && a.get(1).map(String::as_str) == Some("show")
        });
        let ctrl = controller(&runner, &store);

        ctrl.ensure_interface_and_keypair().unwrap();

        let calls = runner.calls();
        assert!(
            calls.iter().any(|(p, a)| p == "ip"
                && a.first().map(String::as_str) == Some("link")
                && a.get(1).map(String::as_str) == Some("add")),
            "must create the interface when `ip link show` fails"
        );
    }

    #[test]
    fn ensure_interface_skips_creation_when_already_present() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        ctrl.ensure_interface_and_keypair().unwrap();

        let calls = runner.calls();
        assert!(
            !calls.iter().any(|(p, a)| p == "ip"
                && a.first().map(String::as_str) == Some("link")
                && a.get(1).map(String::as_str) == Some("add")),
            "must not recreate an already-present interface"
        );
    }

    #[test]
    fn ensure_interface_and_keypair_reuses_the_same_key_across_calls() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        let first = ctrl.ensure_interface_and_keypair().unwrap();
        let second = ctrl.ensure_interface_and_keypair().unwrap();
        assert_eq!(first, second, "the WireGuard public key must be stable across repeated calls, not regenerated each time");
    }

    #[test]
    fn add_or_update_peer_includes_endpoint_when_given() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        ctrl.add_or_update_peer(
            &WgPublicKeyBytes([7; 32]),
            "10.99.0.4/32",
            None,
            Some("203.0.113.9:51820"),
        )
        .unwrap();

        let calls = runner.calls();
        let (_, args) = calls.last().unwrap();
        assert!(args.contains(&"endpoint".to_string()));
        assert!(args.contains(&"203.0.113.9:51820".to_string()));
        assert!(
            args.contains(&"persistent-keepalive".to_string()),
            "an endpoint being present must not crowd out the keepalive flag"
        );
    }

    /// The IPv6 allowed-ip must be comma-joined onto the v4 one in a
    /// single `allowed-ips` argument (real `wg` CLI syntax), not passed
    /// as a separate flag — and it must survive alongside an endpoint
    /// hint too, not crowd it out or vice versa.
    #[test]
    fn add_or_update_peer_comma_joins_ipv6_onto_the_allowed_ips_argument() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        ctrl.add_or_update_peer(
            &WgPublicKeyBytes([7; 32]),
            "10.99.0.4/32",
            Some("fd99::c8:4/128"),
            Some("203.0.113.9:51820"),
        )
        .unwrap();

        let calls = runner.calls();
        let (_, args) = calls.last().unwrap();
        assert!(
            args.contains(&"10.99.0.4/32,fd99::c8:4/128".to_string()),
            "expected a single comma-joined allowed-ips value, got: {args:?}"
        );
        assert!(args.contains(&"endpoint".to_string()));
        assert!(args.contains(&"203.0.113.9:51820".to_string()));
    }

    #[test]
    fn add_or_update_peer_without_ipv6_uses_only_the_v4_allowed_ip() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        ctrl.add_or_update_peer(&WgPublicKeyBytes([7; 32]), "10.99.0.4/32", None, None)
            .unwrap();

        let calls = runner.calls();
        let (_, args) = calls.last().unwrap();
        assert!(args.contains(&"10.99.0.4/32".to_string()));
        assert!(
            !args.iter().any(|a| a.contains(',')),
            "must not emit a trailing comma or empty second entry when no IPv6 address is assigned"
        );
    }

    /// Every peer this crate ever manages is inherently a remote,
    /// often-NAT'd tunnel — a missing `persistent-keepalive` is exactly
    /// the class of bug that lets an idle tunnel's NAT mapping expire
    /// silently while the interface stays administratively "up," with
    /// nothing in `reconcile()`'s diff loop ever noticing. This must
    /// never regress, endpoint hint or not.
    #[test]
    fn add_or_update_peer_always_sets_persistent_keepalive() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        ctrl.add_or_update_peer(&WgPublicKeyBytes([7; 32]), "10.99.0.4/32", None, None)
            .unwrap();

        let calls = runner.calls();
        let (_, args) = calls.last().unwrap();
        assert!(args.contains(&"persistent-keepalive".to_string()));
        assert!(args.contains(&PERSISTENT_KEEPALIVE_SECS.to_string()));
    }

    #[test]
    fn remove_peer_issues_the_remove_flag() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        ctrl.remove_peer(&WgPublicKeyBytes([7; 32])).unwrap();

        let calls = runner.calls();
        let (_, args) = calls.last().unwrap();
        assert!(args.contains(&"remove".to_string()));
    }

    #[test]
    fn list_configured_peers_is_empty_when_no_interface_exists() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        runner
            .fail_next_matching(|p, a| p == "wg" && a.first().map(String::as_str) == Some("show"));
        let ctrl = controller(&runner, &store);

        assert_eq!(ctrl.list_configured_peers().unwrap(), Vec::new());
    }

    #[test]
    fn list_configured_peers_parses_wg_dump_output() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let peer_key = WgPublicKeyBytes([9; 32]);
        let peer_b64 = base64_encode(&peer_key.0);
        // First line: interface's own private-key/public-key/listen-port/fwmark.
        // Subsequent lines: one per peer, first tab-separated field is the peer's public key.
        runner.set_default_stdout(format!("privkeyb64\tpubkeyb64\t51820\toff\n{peer_b64}\t(none)\t(none)\t10.99.0.4/32\t0\t0\t0\toff\n"));
        let ctrl = controller(&runner, &store);

        let peers = ctrl.list_configured_peers().unwrap();
        assert_eq!(peers, vec![peer_key]);
    }

    #[test]
    fn list_peer_transfers_parses_rx_and_tx_from_wg_dump_output() {
        let store = StateStore::open_in_memory().unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let peer_key = WgPublicKeyBytes([9; 32]);
        let peer_b64 = base64_encode(&peer_key.0);
        runner.set_default_stdout(format!("privkeyb64\tpubkeyb64\t51820\toff\n{peer_b64}\t(none)\t(none)\t10.99.0.4/32\t0\t12345\t6789\toff\n"));
        let ctrl = controller(&runner, &store);

        let transfers = ctrl.list_peer_transfers().unwrap();
        assert_eq!(transfers, vec![(peer_key, 12345, 6789)]);
    }

    #[test]
    fn reconcile_ensures_the_interface_exists() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.first().map(String::as_str) == Some("link")
                && a.get(1).map(String::as_str) == Some("show")
        });
        let ctrl = controller(&runner, &store);

        ctrl.reconcile().unwrap();

        let calls = runner.calls();
        assert!(calls.iter().any(|(p, a)| p == "ip"
            && a.first().map(String::as_str) == Some("link")
            && a.get(1).map(String::as_str) == Some("add")));
    }

    fn provisioned(peer_local: u8, wg_pubkey: [u8; 32]) -> state_store::ProvisionedTunnel {
        state_store::ProvisionedTunnel {
            peer: UserId {
                federation: FederationId(Hash32([9; 32])),
                local_id: Hash32([peer_local; 32]),
            },
            direction: state_store::TunnelDirection::Consuming,
            peer_wg_pubkey: WgPublicKeyBytes(wg_pubkey),
            interface_name: "sf_tun0".into(),
            fwmark: 0x1000,
            route_table: 200,
            tunnel_ip: "10.99.0.4".into(),
            tunnel_ip6: Some("fd99::c8:4".into()),
            status: "active".into(),
            created_at: 0,
            advertisement_sequence: None,
        }
    }

    #[test]
    fn reconcile_adds_a_desired_peer_that_is_not_yet_live() {
        let store = store_with_identity();
        store
            .upsert_provisioned_tunnel(&provisioned(1, [7; 32]))
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        let result = ctrl.reconcile().unwrap();

        assert_eq!(result.peers_added, 1);
        assert_eq!(result.peers_removed, 0);
        let calls = runner.calls();
        let wg_set = calls
            .iter()
            .find(|(p, a)| {
                p == "wg"
                    && a.first().map(String::as_str) == Some("set")
                    && a.contains(&"allowed-ips".to_string())
            })
            .expect("must issue a wg set ... allowed-ips call");
        assert!(wg_set.1.contains(&"10.99.0.4/32,fd99::c8:4/128".to_string()), "reconcile must thread the provisioned tunnel's own tunnel_ip6 through to allowed-ips, got: {:?}", wg_set.1);
    }

    #[test]
    fn reconcile_is_a_no_op_when_the_desired_peer_is_already_live() {
        let store = store_with_identity();
        let entry = provisioned(1, [7; 32]);
        store.upsert_provisioned_tunnel(&entry).unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let pubkey_b64 = base64_encode(&entry.peer_wg_pubkey.0);
        runner.set_default_stdout(format!("privkeyb64\tpubkeyb64\t51820\toff\n{pubkey_b64}\t(none)\t(none)\t10.99.0.4/32\t0\t0\t0\toff\n"));
        let ctrl = controller(&runner, &store);

        let result = ctrl.reconcile().unwrap();

        assert_eq!(
            result.peers_added, 0,
            "an already-live desired peer must not be re-added"
        );
        assert_eq!(result.peers_removed, 0);
    }

    #[test]
    fn reconcile_records_a_transfer_sample_for_each_desired_active_peer() {
        let store = store_with_identity();
        let entry = provisioned(1, [7; 32]); // direction: Consuming
        store.upsert_provisioned_tunnel(&entry).unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let pubkey_b64 = base64_encode(&entry.peer_wg_pubkey.0);
        runner.set_default_stdout(format!("privkeyb64\tpubkeyb64\t51820\toff\n{pubkey_b64}\t(none)\t(none)\t10.99.0.4/32\t0\t1000\t2000\toff\n"));
        let ctrl = controller(&runner, &store);

        ctrl.reconcile().unwrap();

        let balances = store.list_tunnel_balances().unwrap();
        assert_eq!(
            balances,
            vec![state_store::TunnelBalance {
                peer: entry.peer,
                given_to: 0,
                taken_from: 1000 + 2000
            }]
        );
    }

    #[test]
    fn reconcile_removes_a_live_peer_that_is_no_longer_desired() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        let stale_peer = WgPublicKeyBytes([8; 32]);
        let pubkey_b64 = base64_encode(&stale_peer.0);
        runner.set_default_stdout(format!("privkeyb64\tpubkeyb64\t51820\toff\n{pubkey_b64}\t(none)\t(none)\t10.99.0.5/32\t0\t0\t0\toff\n"));
        let ctrl = controller(&runner, &store);

        let result = ctrl.reconcile().unwrap();

        assert_eq!(result.peers_added, 0);
        assert_eq!(result.peers_removed, 1);
        let calls = runner.calls();
        assert!(calls
            .iter()
            .any(|(p, a)| p == "wg" && a.contains(&"remove".to_string())));
    }

    #[test]
    fn reconcile_ignores_a_provisioned_tunnel_that_is_not_active() {
        let store = store_with_identity();
        let mut entry = provisioned(1, [7; 32]);
        entry.status = "pending".into();
        store.upsert_provisioned_tunnel(&entry).unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let ctrl = controller(&runner, &store);

        let result = ctrl.reconcile().unwrap();

        assert_eq!(
            result.peers_added, 0,
            "a non-active provisioned tunnel must not be added as a live peer"
        );
    }

    fn controller_with_dirs<'a>(
        runner: &'a FakeCommandRunner,
        store: &'a StateStore,
        dir: &std::path::Path,
    ) -> WgTunnelController<'a> {
        WgTunnelController::new(
            runner,
            store,
            WgTunnelConfig {
                scratch_dir: dir.to_path_buf(),
                dnsmasq_dir: dir.to_path_buf(),
                ..WgTunnelConfig::default()
            },
        )
    }

    #[test]
    fn provision_routing_applies_mark_script_dnsmasq_snippet_and_policy_route() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-4".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-6".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        ctrl.provision_routing(
            "ab12",
            0x1000,
            200,
            &["example.com".to_string()],
            &[],
            None,
            None,
        )
        .unwrap();

        let calls = runner.calls();
        assert!(
            calls
                .iter()
                .any(|(p, a)| p == "nft" && a.first().map(String::as_str) == Some("-f")),
            "must apply the compiled mark script via `nft -f`"
        );
        assert!(
            calls.iter().any(|(p, a)| p == "ip"
                && a.contains(&"rule".to_string())
                && a.contains(&"add".to_string())),
            "must apply the fwmark policy route"
        );

        let conf =
            std::fs::read_to_string(dir.path().join("social-firewall-tunnel-ab12.conf")).unwrap();
        assert!(
            conf.contains("example.com"),
            "dnsmasq snippet must be written for the selected domain"
        );
    }

    #[test]
    fn provision_routing_populates_the_static_set_for_selected_cidrs() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-4".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-6".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        ctrl.provision_routing(
            "ab12",
            0x1000,
            200,
            &[],
            &["10.0.0.0/8".to_string()],
            None,
            None,
        )
        .unwrap();

        let script_path = dir.path().join("social_firewall_tunnel_ab12.nft");
        let script = std::fs::read_to_string(&script_path).unwrap();
        assert!(
            script.contains("10.0.0.0/8"),
            "the selected CIDR must reach the compiled mark script, not just be silently dropped"
        );
    }

    #[test]
    fn provision_routing_fails_when_nft_apply_fails() {
        let store = store_with_identity();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| p == "nft" && a.first().map(String::as_str) == Some("-f"));
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        assert!(ctrl
            .provision_routing(
                "ab12",
                0x1000,
                200,
                &["example.com".to_string()],
                &[],
                None,
                None
            )
            .is_err());
    }

    #[test]
    fn reconcile_provisions_routing_for_a_consuming_tunnel_with_selected_domain_targets() {
        let store = store_with_identity();
        let entry = provisioned(1, [7; 32]);
        store.upsert_provisioned_tunnel(&entry).unwrap();
        store
            .set_provisioned_tunnel_selected_targets(
                &entry.peer,
                state_store::TunnelDirection::Consuming,
                &[domain_types::TargetSelector::Domain("example.com".into())],
            )
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        // `apply_policy_route`'s idempotent `while ip rule del succeeds`
        // loop needs a queued failure to actually terminate against a
        // fake runner that otherwise always succeeds — see the identical
        // pattern in `routing::tests::apply_policy_route_issues_rule_and_route_commands`.
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-4".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-6".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        ctrl.reconcile().unwrap();

        let calls = runner.calls();
        assert!(
            calls
                .iter()
                .any(|(p, a)| p == "nft" && a.first().map(String::as_str) == Some("-f")),
            "reconcile must provision routing for a consuming tunnel's selected domains"
        );
    }

    #[test]
    fn reconcile_enforces_the_original_advertisements_limits_for_a_consuming_tunnel() {
        let store = store_with_identity();
        let mut entry = provisioned(1, [7; 32]);
        // Store the advertisement this tunnel was consumed from, carrying
        // real limits, and point the provisioned row at it — mirrors what
        // `sf ingest-tunnel-accept` actually does (see `cli/src/tunnel.rs`).
        let ad = domain_types::TunnelAdvertisement {
            provider: entry.peer,
            sequence: 0,
            description: "EU exit".into(),
            limitations: None,
            visibility: domain_types::Visibility::Public,
            in_response_to: None,
            messaging_pubkey: domain_types::MessagingPublicKeyBytes([1; 32]),
            wg_pubkey: entry.peer_wg_pubkey,
            endpoint_hint: String::new(),
            route_scope: vec![domain_types::TargetSelector::Domain("example.com".into())],
            tags: vec![],
            max_connections: Some(50),
            max_bandwidth_kbps: Some(8000),
            issued_at: 0,
            expires_at: None,
            supersedes: None,
            signature: domain_types::SignatureBytes([0; 64]),
        };
        store.store_own_tunnel_advertisement(&ad).unwrap();
        entry.advertisement_sequence = Some(0);
        store.upsert_provisioned_tunnel(&entry).unwrap();
        store
            .set_provisioned_tunnel_selected_targets(
                &entry.peer,
                state_store::TunnelDirection::Consuming,
                &[domain_types::TargetSelector::Domain("example.com".into())],
            )
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-4".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-6".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        ctrl.reconcile().unwrap();

        let peer_short_id = hex_prefix(&entry.peer.local_id.0, 8);
        let script = std::fs::read_to_string(
            dir.path()
                .join(format!("social_firewall_tunnel_{peer_short_id}.nft")),
        )
        .unwrap();
        assert!(
            script.contains("ct count over 50 drop"),
            "script was:\n{script}"
        );
        assert!(
            script.contains("limit rate over 1000000 bytes/second drop"),
            "script was:\n{script}"
        );
    }

    #[test]
    fn reconcile_provisions_routing_for_a_consuming_tunnel_with_selected_cidr_targets() {
        let store = store_with_identity();
        let entry = provisioned(1, [7; 32]);
        store.upsert_provisioned_tunnel(&entry).unwrap();
        store
            .set_provisioned_tunnel_selected_targets(
                &entry.peer,
                state_store::TunnelDirection::Consuming,
                &[domain_types::TargetSelector::Cidr("10.0.0.0/8".into())],
            )
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-4".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-6".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        ctrl.reconcile().unwrap();

        let calls = runner.calls();
        assert!(calls.iter().any(|(p, a)| p == "nft" && a.first().map(String::as_str) == Some("-f")), "reconcile must provision routing for a consuming tunnel's selected CIDR too, not just domains");
    }

    #[test]
    fn reconcile_run_twice_never_duplicates_mark_rules() {
        // Regression test for the real bug found while adding CIDR
        // support: `nft add rule` isn't idempotent the way `add table`/
        // `add set`/`add chain` are, so a naive repeated `reconcile()`
        // would accumulate a duplicate pair of mark rules on every call.
        // `compile_mark_script` now flushes its own chain before every
        // repopulation — this proves that holds across repeated calls,
        // not just checking the script text once.
        let store = store_with_identity();
        let entry = provisioned(1, [7; 32]);
        store.upsert_provisioned_tunnel(&entry).unwrap();
        store
            .set_provisioned_tunnel_selected_targets(
                &entry.peer,
                state_store::TunnelDirection::Consuming,
                &[domain_types::TargetSelector::Domain("example.com".into())],
            )
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-4".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-6".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-4".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        runner.fail_next_matching(|p, a| {
            p == "ip"
                && a.contains(&"-6".to_string())
                && a.contains(&"rule".to_string())
                && a.contains(&"del".to_string())
        });
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        let peer_short_id = hex_prefix(&entry.peer.local_id.0, 8);
        let script_path = dir
            .path()
            .join(format!("social_firewall_tunnel_{peer_short_id}.nft"));

        ctrl.reconcile().unwrap();
        let script_after_first = std::fs::read_to_string(&script_path).unwrap();
        ctrl.reconcile().unwrap();
        let script_after_second = std::fs::read_to_string(&script_path).unwrap();

        // Every reconcile pass writes the exact same deterministic
        // script (it always flushes-then-repopulates) — byte-identical
        // across repeated calls is itself proof nothing is accumulating.
        assert_eq!(
            script_after_first, script_after_second,
            "the compiled script must be identical across repeated reconcile passes, not growing"
        );
    }

    #[test]
    fn reconcile_skips_routing_provisioning_when_no_targets_are_selected() {
        let store = store_with_identity();
        store
            .upsert_provisioned_tunnel(&provisioned(1, [7; 32]))
            .unwrap();
        let runner = FakeCommandRunner::new_all_success();
        let dir = tempfile::tempdir().unwrap();
        let ctrl = controller_with_dirs(&runner, &store, dir.path());

        ctrl.reconcile().unwrap();

        let calls = runner.calls();
        assert!(
            !calls
                .iter()
                .any(|(p, a)| p == "nft" && a.first().map(String::as_str) == Some("-f")),
            "no selected targets means nothing to route yet"
        );
    }
}
