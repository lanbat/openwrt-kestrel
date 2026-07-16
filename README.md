# openwrt-kestrel

Two cooperating toolkits for OpenWrt routers, delivered as a single native package. One segments your WiFi into isolated trust zones with push notifications, approval workflows, and live monitoring. The other selectively routes traffic through a WireGuard VPN by domain or category, without tunneling everything.

## Components

### kestreld

A CGI binary (`/usr/bin/kestreld`) served directly by uhttpd via symlinks at `/www/cgi-bin/`. Serves two endpoints:

- `GET /cgi-bin/status` — live dashboard: WiFi clients, nftables traffic counters, WireGuard peers, DHCP leases, neighbor table
- `GET /cgi-bin/device` — per-device management page

Renders HTML on demand and caches the result in `/tmp/kestreld/` for 5 seconds, so repeated page loads within the TTL are instant. No daemon, no extra port, no proxy — uhttpd handles HTTPS and authentication as normal.

Also runnable as a standalone HTTP server (`kestreld 8080`) for local development.

Source: [`extra-networks/kestreld-rs/`](extra-networks/kestreld-rs/)

### nft-resolve

A CLI tool (`/usr/bin/nft-resolve`) that resolves a domain blocklist into nftables `add element` commands and applies them atomically. Supports Adblock, dnsmasq, hosts, RPZ, Unbound, ipset, clash, and plain-domain formats, with parallel DNS resolution.

Source: [`split-routing/nft-resolve-rs/`](split-routing/nft-resolve-rs/)

### extra-networks

Shell scripts and CGI handlers for isolated WiFi networks (guest, untrusted IoT). Manages per-network dnsmasq config, per-device firewall rules in nftables/fw4, join approval, push notifications, password rotation, and device labelling.

Source: [`extra-networks/`](extra-networks/README.md)

### split-routing

Shell scripts that route specific domains and IPs through a WireGuard VPN without moving the default gateway. Uses nft-resolve for blocklist management and dnsmasq for lazy domain resolution.

Source: [`split-routing/`](split-routing/docs/mullvad-routing.md) · [formats](split-routing/docs/supported-formats.md) · [troubleshooting](split-routing/docs/troubleshooting.md) · [WireGuard server setup](split-routing/docs/wireguard-vpn.md)

## Install on the router

### 1. Install the package

Download the `.apk` or `.ipk` for your architecture from the [latest release](https://github.com/lanbat/openwrt-kestrel/releases/latest).

```sh
# OpenWrt snapshot (apk):
apk add --allow-untrusted /tmp/extra-networks-*.aarch64.apk

# OpenWrt stable (opkg):
opkg install --force-reinstall /tmp/extra-networks_*_aarch64_cortex-a53.ipk
```

To find your architecture: `apk info --print-arch` or `opkg print-architecture`.

### 2. Clone the repo and install the shell scripts

```sh
git clone https://github.com/lanbat/openwrt-kestrel /root/openwrt-kestrel
cd /root/openwrt-kestrel
```

**extra-networks** requires a config file per network. Copy the examples and fill in at minimum `WIFI_KEY`, `SSID`, and `SUBNET`:

```sh
cp extra-networks/configs/guest.conf.example     extra-networks/configs/guest.conf
cp extra-networks/configs/untrusted.conf.example extra-networks/configs/untrusted.conf
vi extra-networks/configs/guest.conf
vi extra-networks/configs/untrusted.conf
sh extra-networks/install.sh extra-networks/configs/guest.conf
sh extra-networks/install.sh extra-networks/configs/untrusted.conf
```

**split-routing** reads its config from `/etc/split-routing/` and needs no argument:

```sh
sh split-routing/install.sh
```

## How they interact

- Both sub-projects write to `/etc/dnsmasq.d/` and `/etc/nftables.d/` with distinct filenames — no conflicts.
- split-routing's VPN mark chain excludes traffic from extra-network bridges (`br-guest`, `br-untrusted`, etc.) so isolated network traffic always uses the normal WAN, never the VPN tunnel.
- `nft-resolve` is available to both sub-projects for bulk domain resolution.

## Building from source

Requires: [Rust](https://rustup.rs), [cross](https://github.com/cross-rs/cross), Docker, GNU make, Python 3, and `ar`.

```sh
# cross-compile both binaries for aarch64 (default)
make build

# assemble .apk and .ipk packages
make package

# build + deploy directly to a router (auto-detects apk vs opkg)
make deploy ROUTER=192.168.1.1
```

Override the target architecture:

```sh
make package \
  CROSS_TARGET=mipsel-unknown-linux-musl \
  ARCH=mipsel \
  OPENWRT_ARCH=mipsel_24kc
```

Supported targets and their `cross` Docker images are in [`Cross.toml`](Cross.toml).

## Releases

Tagging a `v*` commit triggers GitHub Actions, which builds packages for all six supported architectures in parallel and publishes them to a single GitHub release:

| Architecture | Rust target | Covers |
|---|---|---|
| `aarch64` | `aarch64-unknown-linux-musl` | aarch64_cortex-a53, aarch64_cortex-a72, … |
| `x86_64` | `x86_64-unknown-linux-musl` | x86_64 |
| `arm_cortex-a7` | `armv7-unknown-linux-musleabihf` | arm_cortex-a7, arm_cortex-a9, arm_cortex-a15, … |
| `arm_arm1176jzf-s` | `arm-unknown-linux-musleabi` | arm_arm1176jzf-s_vfp |
| `mipsel` | `mipsel-unknown-linux-musl` | mipsel_24kc, mipsel_74kc |
| `mips` | `mips-unknown-linux-musl` | mips_24kc |

To cut a release locally (aarch64 only):

```sh
# bump version in extra-networks/kestreld-rs/Cargo.toml, then:
make release
```

## Upgrading OpenWrt

Use `sysupgrade` (flash a new image) rather than `apk upgrade`. On snapshot builds, `apk upgrade` can pull kernel modules built for a different kernel version than the one running, causing modules to fail loading until reboot — and if the kernel image itself is replaced, you'd be running a mismatched system. Flashing a new image is atomic: kernel, modules, and packages all come from the same build.

### What sysupgrade preserves automatically

The installer adds paths to `/etc/sysupgrade.conf` and packages add their own paths to `/lib/upgrade/keep.d/`. These are already covered:

| Path | Contents |
|---|---|
| `/root/` | git repo (`/root/openwrt-kestrel/`) |
| `/etc/config/` | all UCI config — network, WireGuard, firewall, DHCP |
| `/etc/extra-networks/` | device data, labels, history, join lists |
| `/etc/dnsmasq.d/` | split-routing and content-filter configs |
| `/etc/nftables.d/` | all nft rules including split-routing |
| `/etc/hotplug.d/iface/99-mullvad-routing` | VPN routing hotplug script |
| `/etc/crontabs/` | crontab |
| `/etc/dropbear/` | SSH host keys and authorized_keys |
| `/etc/hosts` | static hostname entries |
| `/etc/crowdsec/` | crowdsec config |

### After sysupgrade

**Reinstall extra packages:**

```sh
apk update
apk add dnsmasq-full crowdsec crowdsec-firewall-bouncer banip pbr \
        https-dns-proxy tmux qrencode nginx
apk add --allow-untrusted /tmp/extra-networks-*.aarch64.apk
```

If `dnsmasq-full` fails with `kmod-nf-conntrack-netlink (no such package)`:

```sh
sed -i 's/^p:kmod-nf-conntrack-any$/p:kmod-nf-conntrack-any kmod-nf-conntrack-netlink/' \
    /lib/apk/db/installed
apk add dnsmasq-full
```

**Re-run the installers:**

```sh
cd /root/openwrt-kestrel
sh extra-networks/install.sh extra-networks/configs/guest.conf
sh extra-networks/install.sh extra-networks/configs/untrusted.conf
sh split-routing/install.sh
```

**Sysupgrade steps:**

```sh
# 1. Optional backup (paths above are restored automatically)
sysupgrade -b /tmp/backup-$(date +%Y%m%d).tar.gz

# 2. Flash the new image
sysupgrade /tmp/openwrt-*.bin

# 3. After reboot: reinstall packages and re-run installers (see above)
```
