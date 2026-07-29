# QEMU + hwsim test environment

Boots a real OpenWrt image under QEMU/KVM with [`mac80211_hwsim`](https://www.kernel.org/doc/html/latest/networking/mac80211_hwsim.html)
providing virtual WiFi radios, so `hostapd`, `fw4`/nftables, `dnsmasq`, and
`kestreld` all run for real — the same code paths that run on your actual
router — before you push a config change to hardware. This is not a mock: the
firewall rules, the WiFi association, and the DHCP lease are all genuinely
exercised by the real binaries.

What this validates: `networks`/`split-routing`'s `install.sh` behavior,
the resulting firewall/bridge state, and kestreld's CGI dashboard/approval
flows, against a real (virtual) WiFi client.

What this does **not** validate: real WiFi driver/hardware quirks (the
documented `wifi-recover` VAP race condition is MediaTek-hardware-specific and
won't reproduce here), VLAN trunk behavior on a real switch, or WPA3/SAE
client association (the `wpa_supplicant` build available in the OpenWrt
package feed used here doesn't support it — see "Known gotchas" below).

## Prerequisites

- `qemu-system-x86_64` with KVM (`/dev/kvm` readable/writable)
- `cross` + Docker (for cross-compiling `kestreld`/`nft-resolve` to
  `x86_64-unknown-linux-musl` — the same tool the project's `GNUmakefile`
  already uses for the real aarch64 target)
- `rsync`, `ssh`/`scp`, internet access (to download the OpenWrt image and
  packages)

## Quickstart

```sh
test/qemu/setup.sh                                    # download + boot the VM
test/qemu/provision.sh                                # install hwsim/hostapd, fix wireless config
test/qemu/deploy.sh test/qemu/configs/guest.conf test/qemu/configs/untrusted.conf
```

Then open **http://127.0.0.1:8080/cgi-bin/status** in your browser.

SSH in directly any time: `ssh -p 2222 root@127.0.0.1` (blank password).

Simulate a client device joining the guest network:

```sh
test/qemu/client.sh hwsim-test-guest testpassword123
```

This runs real `wpa_supplicant` + `udhcpc` against the real AP. The device
will show up in the dashboard as pending approval (guest.conf's test fixture
has `JOIN_APPROVAL=yes`) — approve it from the dashboard, or:

```sh
ssh -p 2222 root@127.0.0.1 \
  "wget -qO- --post-data='net=guest&ip=<the-ip>&mac=<the-mac>&action=approve&label=Test' \
   http://127.0.0.1/cgi-bin/approve-join"
```

To test `untrusted.conf`'s `ALLOWLIST=yes` behavior, the client's MAC needs to
be added to `/etc/kestrel/networks/untrusted-allowed-macs` first (either
through the device page, once it's reachable, or by hand over SSH) — an
unlisted MAC is expected to get **no** DHCP lease at all, by design.

`provision.sh` sets up 3 independent client radios (`phy1`/`phy2`/`phy3`), so
you can run several simulated devices *concurrently* — e.g. one joining
guest and another joining untrusted at the same time — by passing a `phy` as
the 4th argument (defaults to `phy1`):

```sh
test/qemu/client.sh hwsim-test-guest     testpassword123 aa:bb:cc:dd:ee:01 phy1
test/qemu/client.sh hwsim-test-untrusted testpassword123 aa:bb:cc:dd:ee:02 phy2
```

Each `phy` gets its own station interface and `wpa_supplicant` instance, so
running one doesn't tear down another already-connected client.

## What each script does

| Script | Does |
|---|---|
| `setup.sh` | Downloads (and caches) the OpenWrt release image, boots it under QEMU with two NICs (LAN on a custom hostfwd'd subnet, WAN on default SLIRP with real internet access), waits for SSH, configures the missing WAN interface. `--fresh` discards the current disk and starts clean. |
| `provision.sh` | Installs `kmod-mac80211-hwsim`, `hostapd-mbedtls`, `wpa-supplicant`, `iw`, `qrencode`; bumps `mac80211_hwsim` to 4 radios (`radio0` as the sole AP radio — guest and untrusted run as two BSSes on it, same as a real router with one radio card and multiple SSIDs — plus 3 independent client radios, rebooting if that requires a module reload); fixes the wireless country-code issue (see below); does the full network restart needed for it to take effect. |
| `deploy.sh <config...>` | Cross-builds `kestreld`/`nft-resolve`, copies `networks/`+`split-routing/` into the VM, symlinks `kestreld` into `/www/cgi-bin/*` (matching the real packaged deployment), and runs `install.sh` for each config you pass it. Re-run any time you change Rust code or a config — idempotent. |
| `client.sh <ssid> <psk> [mac] [phy]` | Brings up a station interface on the given hwsim client radio (`phy1` by default; `phy2`/`phy3` for additional concurrent devices), associates with real `wpa_supplicant`, gets a real DHCP lease. Run it multiple times with different MACs/phys to simulate multiple devices at once. |

Everything lives under `test/qemu/work/` (gitignored) — downloaded images,
the running disk copy, QEMU's pid/monitor/serial files, and the
build-and-deploy staging tarball. Delete that directory any time for a fully
clean slate (re-run `setup.sh` to rebuild it).

## Known gotchas (found the hard way — save yourself the time)

- **`country_code '00'` silently kills the AP.** The auto-detected wireless
  config sets `option country '00'` on every radio. hostapd rejects that
  outright and never actually starts the BSS — but the failure is invisible
  from `iw dev`/`ubus`, both of which keep reporting the interface as a
  healthy AP. The only visible symptom is
  `/sys/class/net/<if>/statistics/tx_packets` stuck at 0 (no beacons ever
  sent), and `Invalid country_code '00'` buried in `logread`. `provision.sh`
  sets a real country code on **every** radio — a single radio left at `'00'`
  will silently reset the kernel's (global, not per-radio) regulatory domain
  right back after another radio's setup runs.
- **A full `/etc/init.d/network restart` is required after changing radio-level
  config** (band/channel/country) — `wifi up`/`wifi reload`/
  `ubus call network.wireless up` are not enough; the wifi-device config
  looks like it's cached at netifd-process lifetime. The restart briefly
  drops `br-lan` (and your SSH session) for ~15-20s; both `provision.sh` and
  `deploy.sh` retry-wait for it rather than treating that as a failure.
- **`wpa_supplicant` here doesn't support WPA3/SAE.** The test config fixtures
  use `psk2` for this reason — not a recommendation for real deployments,
  just what's testable with the package feed's default build.
- **The snapshot (daily-build) OpenWrt kernel/hostapd combo is currently
  broken for this**: hostapd segfaults immediately after `Set MLD config: []`
  for any AP config on the snapshot's kernel 6.18 line, even with
  `disable_11be=1`. Use the stable release (this is what `setup.sh` defaults
  to) — it doesn't have this regression.
- **netifd sometimes reports the wireless interface "up" without actually
  attaching it to the kernel bridge** (`brctl show` shows zero member ports).
  Not fully root-caused; a full network restart (which `provision.sh` already
  does for the country-code fix) resolves it as a side effect.
- **OpenSSH's `scp` defaults to the SFTP protocol, which dropbear doesn't
  implement** — every `scp` invocation in these scripts uses `-O` to force
  the legacy SCP protocol dropbear does support.
- **`ulimit -l 0` before every `qemu-system-x86_64` invocation** works around
  a sandboxed-environment quirk where a low `RLIMIT_MEMLOCK` (Docker's classic
  8MB default) makes QEMU 11's io_uring event-loop backend fail
  intermittently in a way QEMU treats as fatal rather than falling back to
  epoll. Harmless if your memlock limit is normal/unlimited.
- **Ping/ICMP through the nested SLIRP WAN NAT isn't reliable** even when the
  firewall correctly permits traffic (confirmed via the nftables set contents
  and via TCP), so don't use `ping` from inside the VM as your sole
  reachability check for "did the firewall unblock this device" — check the
  relevant `nft list set inet fw4 <iface>_join_approved_ips` instead.

## Cleanup

```sh
kill $(cat test/qemu/work/qemu.pid)   # stop the VM
rm -rf test/qemu/work                 # wipe everything (image included)
```
