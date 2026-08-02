# Developer guidelines

Notes for anyone (human or agent) working on this repo — conventions and
gotchas that aren't obvious just from reading the code, gathered from
actually building and porting parts of it.

## Layout

- `networks/` — isolated WiFi networks (guest, untrusted/IoT): `install.sh`
  + shell tools, and `kestreld-rs/` (the Rust CGI binary serving the whole
  router UI). Runtime state lives on the router at `/etc/kestrel/networks/`.
- `split-routing/` — per-domain VPN routing: `install.sh` + shell tools, and
  `nft-resolve-rs/` (blocklist → nftables resolver). Runtime state at
  `/etc/kestrel/split-routing/`.
- `social-firewall/` — a separate, optional Rust workspace (its own
  `Cargo.toml`, own `install.sh`, own OpenWrt package under
  `release/openwrt/social-firewall/`) implementing decentralized,
  opinion-based firewall policy. Deliberately independent of everything
  else in this repo — no shared code, no shared runtime state
  (`/etc/kestrel/social-firewall/`), and no install-order dependency in
  either direction. Its own `cargo test --workspace` is fast and needs no
  QEMU VM (no shell scripts to port, no real system state to touch) —
  only the real `nft`-enforcement half (`crates/nft-enforcer`) needs the
  QEMU VM, and only for that crate's own `INTEGRATION_TESTING.md`
  checklist.
- `test/qemu/` — boots a real OpenWrt image under QEMU with virtual WiFi
  radios (`mac80211_hwsim`). See below — this is not optional for a lot of
  changes.

## Architecture: why kestreld has no daemon

`kestreld` is invoked fresh per HTTP request by uhttpd via CGI symlinks —
no daemon, no extra port, no reverse proxy. `main.rs` picks a
`current_thread` tokio runtime for that path specifically: a worker-thread
pool has no payoff when the whole process lives for one request, and that
overhead is worst on exactly the low-end single-core routers this project
targets. The one long-running mode (`kestreld <port>`, used for local dev
and the QEMU/browser tests) uses `multi_thread` instead, since it actually
serves concurrent connections.

Because of this, every data path takes `base_dir`/`split_routing_dir` as a
parameter rather than hardcoding `/etc/kestrel/...` inside logic functions
— `main.rs`/`cgi.rs` are the only places that hardcode the real paths.
Everything else (route handlers, `state::build_snapshot`, ported CLI
subcommands) takes a `&Path`, which is what lets tests point it at a
tempdir instead.

## Testing hierarchy

Each layer catches a different class of bug. Passing the earlier layers is
necessary but **not sufficient** — don't declare a change (especially a
shell → Rust port) done off `cargo test` alone if it touches real system
state.

1. **`cargo test --offline --lib`** — pure logic: parsing, string
   generation, dedup, format compatibility. Fast, no real subprocesses, no
   real files outside a tempdir.
2. **Cucumber suites** (`tests/*.rs` + `tests/features/*.feature`) —
   exercise real route handlers against tempdir fixtures. These
   deliberately do **not** mock `nft`/`curl`/`uci`/dnsmasq reload calls —
   they make the real subprocess calls, which fail harmlessly off a real
   router (permission denied / command not found) and get silently
   discarded, same as production would if one of those tools were
   missing. If you're tempted to mock one of these out, don't — the point
   is to exercise the real code path, not a stand-in for it.

   **Run these inside the QEMU VM sandbox, not directly on your dev
   machine.** Some of the paths these calls hit aren't uniquely OpenWrt
   after all — `cmd::reload_dnsmasq()` calls `/etc/init.d/dnsmasq
   reload`, and on a Debian dev machine with the `dnsmasq` package
   installed, that path really exists and really forwards to `systemctl
   reload dnsmasq.service`, which pops a real PolicyKit password prompt
   in a GUI session (confirmed directly: it fails with "Access denied"
   without one, so nothing actually gets reloaded, but the repeated
   prompt is a real nuisance and a real privileged-action attempt against
   the host, not a router). `uci`/`nft` genuinely don't exist on a
   typical dev machine and fail silently as intended, but don't assume
   every shelled-out command is equally inert locally just because it
   targets an absolute path — check, the way this one wasn't checked
   carefully enough the first time. Plain `cargo test --offline --lib`
   (step 1) never spawns a subprocess and is always safe to run locally.

   There's no single command for this yet — the recipe (verified
   working, all scenarios pass this way) applies to `join_approval` and
   `connection_approval`:
   ```sh
   # From networks/kestreld-rs/, cross-compile the test binary itself
   # (not just the app) for the VM's arch:
   cross build --release --target x86_64-unknown-linux-musl \
     --test connection_approval   # or join_approval

   # Copy it into the already-deployed repo tree on the VM (test/qemu/deploy.sh
   # must have been run at least once) and run it there over SSH — the
   # binary looks up its .feature file via a path relative to its cwd,
   # so cd into the matching kestreld-rs directory first:
   scp -O -P 2222 target/x86_64-unknown-linux-musl/release/deps/connection_approval-* \
     root@127.0.0.1:/root/openwrt-kestrel/networks/kestreld-rs/connection_approval_test
   ssh -p 2222 root@127.0.0.1 \
     "cd /root/openwrt-kestrel/networks/kestreld-rs && chmod +x connection_approval_test && ./connection_approval_test"
   ```
   Remove the copied binary from the VM afterward — it's a build
   artifact, not part of the deployed state.

   `browser_workflow` is the one exception: it starts its own
   `geckodriver` + Firefox locally, which the minimal OpenWrt VM image
   doesn't have, so it can't be copied over the same way. It still hits
   the same `reload_dnsmasq()` path when run locally — accept the
   PolicyKit prompt (deny it, don't enter a password) as a known, harmless
   side effect of this one suite specifically, rather than a sign
   something's wrong.
3. **QEMU VM** (`test/qemu/`) — the only way to validate anything that
   actually touches nftables/`fw4`/UCI/hostapd/dnsmasq end to end. A
   `cargo test` pass proves your Rust logic is internally consistent; it
   proves nothing about whether the nftables text you generated is valid
   syntax for the real `nft`, whether `fw4 -q reload` accepts it, or
   whether the resulting firewall behavior actually matches what the old
   shell script produced. For any change that writes to
   `/etc/nftables.d/`, `/etc/dnsmasq.d/`, UCI, or calls `fw4`/`nft`/`uci`
   for effect, deploy to the VM (`test/qemu/deploy.sh <config...>`) and
   check the real result (`ssh -p 2222 root@127.0.0.1`, `nft list
   ruleset`, etc.) before considering it verified.
4. **Real router** — final check before merging/releasing anything that
   reached step 3 cleanly.

See `test/qemu/README.md` for the full quickstart; there's usually a VM
already running during active development (`ps aux | grep qemu-system`
before booting a new one).

## Porting a shell script to a kestreld subcommand

Every `tools/*.sh` cron/setup script that had a Rust-side equivalent
worth reusing has been ported to a built-in kestreld CLI subcommand:

| Subcommand | Replaced | Runs |
|---|---|---|
| `--update-oui` | `tools/oui-update.sh` | weekly cron |
| `--regen-inspect IFACE` | `tools/regen-inspect.sh` | on setup + every device-rule change (in-process, not a subcommand call — see below) |
| `--check-wan` | `tools/check-wan.sh` | manual/debug only — see `--daemon` below |
| `--check-vpn` | `tools/check-vpn.sh` | manual/debug only — see `--daemon` below |
| `--check-bandwidth` | `tools/bandwidth-check.sh` | manual/debug only — see `--daemon` below |
| `--check-access-log` | `tools/check-access-log.sh` | manual/debug only — see `--daemon` below |
| `--digest` | `tools/digest.sh` | daily cron |
| `--daemon` | (new — no shell equivalent) | persistent, `procd`-supervised service |
| `--update-threat-intel` | (new — no shell equivalent) | weekly cron, staggered from `--update-oui` |

`--daemon` (`daemon.rs`) is the one genuinely long-running process in this
codebase, everything else here is one-shot. It subsumes the ongoing job of
`--check-wan`/`--check-vpn`/`--check-bandwidth`/`--check-access-log` (their
CLI subcommands stay callable by hand for debugging, but their cron
entries are gone) plus a capability that never existed at all in the Rust
port until now: capturing device-control "pending connection" events for
per-device approval. The original shell CGI only ever did that inline, by
scraping `logread` on each device-page view — the port never carried it
over. `--daemon` streams `logread -f` continuously instead of polling a
bounded log buffer once a minute, which closes a real gap the polling
design had: `logd`'s buffer can evict events between scans, silently
dropping them, not just delaying them. See `daemon.rs`'s module doc for
the full design (it also runs WAN/VPN checks on a much shorter internal
timer than their old 5-minute cron cadence, and keeps a persistent
per-network `{iface}-connection-history` audit log of every LAN-access/
allowlist-rejection/pending-connection sighting, independent of whether
any single ntfy delivery succeeds). It also runs a device-observation
materializer (`observation.rs`) and a plugin framework (`plugins.rs`) —
see their own module docs. Two plugin kinds share one `Event` enum and one
enable/disable mechanism (`{plugins_dir}/disabled`, matched by name,
re-read every 5-minute re-scan so toggling or hot-adding a plugin needs no
daemon restart):

- **External processes** — any executable dropped in
  `/etc/kestrel/plugins/` gets spawned and sent one JSON line per event
  (all 7 `Event` variants — connections, DNS, device-approval,
  WAN/VPN/bandwidth transitions) on its stdin, optionally narrowed via a
  `{"subscribe":[...]}` line it writes back, and can write a small
  whitelisted set of actions (`notify`, `log`, `add_rule`, `annotate`)
  back on its stdout — deliberately a separate process rather than a
  `dlopen`ed `.so`, since this runs as root on a router targeting 7+
  architectures and a bad plugin shouldn't be able to take the whole
  daemon down or need Rust ABI stability across separately compiled
  artifacts. A plugin also self-describes itself via an `{"info":...}`
  line (description + optional version/maintainer/website), persisted to
  `{plugins_dir}/{name}.info` for `routes::plugin_info` (a CGI-mode,
  one-shot process with no access to the daemon's live `PluginManager`)
  to read back for its detail page.
- **`RustPlugin` implementations** — compiled directly into the binary
  (see `DeviceApprovedNotifier` for the one kestreld ships), called
  in-process via a `PluginContext` with real typed methods instead of the
  external actions above — for first-party functionality, not something
  a user writes. `handle()` returns a boxed future (not a plain `async
  fn`, which isn't object-safe on stable Rust yet) so `PluginManager` can
  hold a `Vec<Arc<dyn RustPlugin>>`. Each call is run inside its own
  `tokio::spawn` and awaited via the `JoinHandle` rather than called
  directly — a panic in a `RustPlugin` would otherwise unwind straight
  into whichever `daemon.rs` task called `broadcast()`, and that task
  ending for any reason is what `daemon.rs` treats as fatal to the whole
  process (see above). Isolating it there gives compiled-in plugins the
  same crash isolation external processes get for free from the OS.

All were ported because kestreld already parses the exact same on-disk
state for the dashboard — the shell version was often re-implementing (in
`awk`/shell) logic this binary already has in Rust. When porting another
one:

- **Look for an existing reader first.** `data/files.rs` already has
  `read_labels`, `read_device_rules`, `read_mac_ip_map`,
  `read_device_limits`, `parse_sh_vars` (for shell-style `KEY=VALUE`
  `.conf` files), etc. — most device-state file formats are already
  parsed somewhere. Don't re-parse a format that already has a reader.
- **Match the shell version's exact behavior** unless you have a specific
  reason to deviate — and if you do deviate (e.g. using `IpAddr::parse`
  instead of a glob heuristic to classify an address family), say so in a
  comment, since it's a real behavior change even if a strict improvement.
- **New subcommands follow the existing dispatch pattern** in `main.rs`: a
  plain string check on `args.get(1)` before the CGI-mode branch, gated
  ahead of `cgi::is_cgi()`, dispatching to a function in its own
  `src/<name>.rs` module. Keep the module's own logic pure/testable and
  push side effects (fetch, write, subprocess calls) to the edges.
- **Call the ported function in-process where possible**, not via a
  re-exec. If the caller already has `AppState` (or `base_dir`/
  `split_routing_dir`) in scope — e.g. a route handler — call the module's
  `run()` function directly rather than shelling out to
  `/usr/bin/kestreld --subcommand`. Only re-exec (see
  `routes::rotate_password`'s `--rotate-apply`, via
  `std::env::current_exe()` — not a hardcoded path) when the operation
  must genuinely outlive the current request (a detached delayed action).
- **Delete the old shell script once nothing references it.** Grep the
  whole repo (`grep -rn <script-name>.sh`) before deleting — check
  `install.sh`, other tool scripts, docs, and code comments, not just the
  obvious caller.
- **Update `install.sh`'s corresponding section** — it likely both
  `cp`+invokes the script once at setup time and sets up a cron entry
  pointing at it; both need to switch to `kestreld --subcommand`.

**What's intentionally still shell**: `install.sh`/`uninstall.sh`'s UCI/
firewall/wireless/DHCP bootstrap, `opkg`/`apk` package installs, cron/
hotplug/init file installation, the WiFi VAP-recovery workaround, and the
admin-invoked one-shot tools (`access-schedule.sh`, `allow-service.sh`,
`expose-port.sh`, `unexpose-port.sh`, `qr.sh`, `status.sh`,
`rotate-password.sh`, `guest-info.sh`). None of these are periodic monitors
re-deriving data kestreld's dashboard already reads — they're either
one-time provisioning tied to `uci`/`opkg` mechanics (where Rust would
just be shelling out to the same commands, no type-safety win since UCI
itself isn't typed) or thin admin CLI wrappers a sysadmin might want to
read/patch directly over SSH without recompiling. Moving them wouldn't
make anything cleaner, and would cost the "hand-editable on the router"
property this project deliberately keeps for that category of script.

## Known gotchas (found the hard way)

- **busybox ash's `read` collapses consecutive tab delimiters** — unlike
  bash/dash, `while IFS=$(printf '\t') read -r a b c; do ...` silently
  misaligns fields whenever an empty field is followed by a non-empty one
  on the same line. Doesn't matter until a trailing-empty-then-non-empty
  case becomes possible (e.g. adding a 6th field after previously-always-
  trailing-empty 4th/5th fields). Use `cut -f` for per-field extraction
  instead of `read -r a b c` in any shell script that might see empty
  fields followed by non-empty ones.
- **`cross`'s `Cross.toml` auto-discovery is relative to the crate's
  `--manifest-path`, not the invocation cwd.** A stale/incomplete
  `Cross.toml` sitting inside a crate subdirectory (e.g. one that only
  lists `aarch64` from before the repo-root one existed) silently shadows
  the repo-root `Cross.toml` for any target the nested one doesn't list —
  it doesn't error, it just falls back to the host linker and fails with
  "relocations in generic ELF" for whichever target got shadowed.
  `GNUmakefile` exports `CROSS_CONFIG` explicitly for every target rather
  than relying on discovery; per-crate `Cross.toml` files were deleted.
- **`mips`/`mipsel-unknown-linux-musl` have no prebuilt `std` on stable
  Rust** — demoted to tier 3 upstream
  ([rust-lang/rust#115238](https://github.com/rust-lang/rust/pull/115238)).
  Build with nightly + the `rust-src` component +
  `-Z build-std=std,panic_abort` (`GNUmakefile`'s `BUILD_STD=yes`, wired
  through `release.yml`'s CI matrix).
- **GitHub Actions expression ternaries break when the true-branch is
  empty string.** `${{ cond && '' || fallback }}` always evaluates to
  `fallback`, even when `cond` is true — empty string is falsy, so the
  `&&` short-circuits and the `||` overrides it. Use two explicit
  conditional steps (`if: cond` / `if: !cond`) instead of a single step
  with a ternary expression whenever either branch could be empty.
- **`actions/upload-artifact`'s `path:` glob has no brace expansion.**
  `*.{apk,ipk}` matches that literal string, not either extension, and
  silently uploads nothing (`if-no-files-found: error` catches it, but
  only if you check). List each extension on its own line instead.
- **HTTP-form validation doesn't protect a daemon-automated call path to
  the same function.** `routes::device`'s `approve_domain`/`approve_pending`
  handlers validate `domain`/`dst_ip` before ever touching a dnsmasq conf
  line or `nft` command — but when `observation.rs`'s automatic window
  materialization was added to call the same rule-writing logic from the
  daemon (sourcing its domain/IP from a device's own DNS query log and
  connection history, not an HTTP form), that validation didn't come along
  for free. Fixed by validating inside the shared `write_domain_rule`/
  `write_ip_rule` functions themselves (`data::files::is_valid_domain`,
  an `IpAddr` parse) rather than trusting every caller — any function that
  ends up embedding external input in a shell command or config-file line
  needs to validate at its own entry point if it's reachable from more
  than one caller, especially once one of those callers is fed from
  network-observable data instead of a validated form.

## Release process

Version lives in `networks/kestreld-rs/Cargo.toml` and
`split-routing/nft-resolve-rs/Cargo.toml` (keep both in sync, plus their
`Cargo.lock` files). Pushing a `v*` tag
triggers `.github/workflows/release.yml`, which builds all 7 supported
architectures in parallel and publishes a single GitHub release with every
`.apk`/`.ipk`. `mips`/`mipsel` are `continue-on-error` — the release always
publishes whatever architectures actually succeeded rather than blocking on
the two with the least Rust-toolchain support.

Don't use `make release` for a full multi-arch release — it's the
aarch64-only local path and immediately calls `gh release create` itself,
which would race the CI-triggered publish job for the same tag. Just
commit, bump the version, tag, and push the tag; let CI publish.

`social-firewall` has its own, separate `make release-social-firewall` —
tagged `sf-v*` (not `v*`, so it can never collide with or accidentally
trigger the `v*`-triggered kestrel release workflow above) — but no CI
automation yet: it's aarch64-only (or whatever `CROSS_TARGET` is
overridden to) and manual, matching the "single target for now" scope
decision from when this package was built. A multi-arch CI pipeline for
it is a real but deliberately deferred follow-up, not an oversight.

## Code style

- Doc comments explain **why**, not what — a hidden constraint, a subtle
  invariant, the reason a workaround exists, prior-bug context. Skip a
  comment entirely if the code doesn't need it — well-named identifiers
  already say what something does.
- Don't reference the current task/fix/issue number in a comment ("added
  for the Y flow", "fixes the Z bug") — that belongs in the commit
  message and rots as the code evolves; the comment should stand on its
  own regardless of why it was written.
