# Repository Agent Notes

## Boundaries

- `networks/kestreld-rs` is the Rust router UI and CGI binary; uhttpd starts it fresh per `/www/cgi-bin/*` request. Its `--daemon` mode is the separate long-running procd-supervised path.
- `split-routing/nft-resolve-rs` builds the independent `nft-resolve` blocklist resolver.
- `social-firewall` is an independent Rust workspace/package (`sf`) with its own SQLite state, cron jobs, CGI endpoints, and `inet social_firewall` nftables table. Do not add a compile-time or runtime dependency between it and `kestreld`.
- `networks/` and `split-routing/` install OpenWrt shell/configuration state; the root `GNUmakefile` builds their `.apk`/`.ipk` artifacts. Social-firewall has separate suffixed make targets.

## Verification

- For `networks/kestreld-rs`, run `cargo check --all-targets` and `cargo test --offline --lib` before integration tests. Run Cucumber tests only in QEMU because route handlers can invoke real `uci`, `nft`, and `/etc/init.d/dnsmasq` commands.
- For `social-firewall`, run `cargo test --workspace` from `social-firewall`; focused checks include `cargo test -p state-store -p sf-cli`. The Iroh connectivity test is intentionally ignored unless explicitly requested with `cargo test -p p2p-transport -- --ignored`.
- Use `git diff --check`. Do not format the whole worktree blindly; large unrelated changes are commonly present.

## QEMU

- Use the real workflow for system-state changes: `test/qemu/setup.sh`, `test/qemu/provision.sh`, `test/qemu/deploy.sh`, then `test/qemu/client.sh` as needed.
- The VM uses stable OpenWrt `25.12.5`, SSH `root@127.0.0.1:2222` with a blank password, and dashboard port `8080`. Do not use snapshot images; the documented hostapd/kernel regression breaks the AP.
- `provision.sh` may reboot/restart networking and temporarily drop SSH. VM state is under gitignored `test/qemu/work/`; use `setup.sh --fresh` only when a clean disk is required.
- Do not run host `sudo` service restarts as a test shortcut. Changes affecting `/etc/nftables.d/`, `/etc/dnsmasq.d/`, UCI, `fw4`, `nft`, hostapd, or dnsmasq need QEMU validation.
- `kestreld` and `sf` only reload dnsmasq when OpenWrt markers are present; use `KESTRELD_ALLOW_SYSTEM_RELOAD=1` or `SF_ALLOW_SYSTEM_RELOAD=1` only for a deliberately controlled non-router environment.

## Build And Package

- `make build`/`make package` build the main `kestrel` binaries/package; `make build-social-firewall`/`make package-social-firewall` build/package `sf` independently.
- Cross builds require `cross` and Docker. Preserve `CROSS_CONFIG=$(CURDIR)/Cross.toml`; cross does not reliably discover `Cross.toml` when invoked with `--manifest-path`.
- Default package target is `aarch64-unknown-linux-musl`; QEMU deployment uses `x86_64-unknown-linux-musl`. MIPS/MIPSel require nightly `BUILD_STD=yes` because stable Rust has no prebuilt target std.
- Do not run `make release`, `make deploy`, or GitHub release commands unless explicitly requested; release/deploy targets can push tags, packages, or modify a router.

## Privacy And Identity

- Packet capture is opt-in via `FINGERPRINT_PACKET_CAPTURE=yes` and must remain disabled by default.
- Persist/transmit normalized fingerprint metadata only: never raw headers, payloads, browsing history, or private keys. Parsing must be bounded and fail closed; TLS/QUIC contents are not decrypted.
- `kestreld` owns local device fingerprints; `sf` owns social/trust identities. Any cross-system association must be optional, confidence-scored, ambiguity-aware, and explicitly human-confirmed; observation must not silently create or merge identities.
- The full shared-fingerprint contract, canonical fields, group-key bootstrap, UI links, and current implementation gaps are in `social-firewall/docs/fingerprints-and-ui.md`; read it before changing either fingerprint path.

## Safety

- Preserve unrelated worktree changes; this repository is routinely used with large uncommitted feature batches.
- Shared-policy route entries may reference only locally registered route profiles. Current `sf` route/VPN handling is preview/validation only; do not turn it into live route mutation without explicit materializer and QEMU tests.
