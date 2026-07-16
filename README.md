# openwrt-kestrel

Two cooperating toolkits for OpenWrt routers, delivered as a single native package. One segments your WiFi into isolated trust zones with push notifications, approval workflows, and live monitoring. The other selectively routes traffic through a WireGuard VPN by domain or category, without tunneling everything.

## Components

### kestreld

A Rust HTTP daemon (`/usr/bin/kestreld`) that replaces the extra-networks shell CGI scripts. It keeps a 5-second TTL in-memory cache of router state and serves it via:

- `GET /cgi-bin/status` — live dashboard: WiFi clients, nftables traffic counters, WireGuard peers, DHCP leases, neighbor table
- `GET /cgi-bin/device` — per-device management page

Runs on port 8080 behind uhttpd (which handles everything else on port 80). Source: [`extra-networks/kestreld-rs/`](extra-networks/kestreld-rs/)

### nft-resolve

A Rust CLI (`/usr/bin/nft-resolve`) that resolves a domain blocklist into nftables `add element` commands and applies them atomically. Supports Adblock, dnsmasq, hosts, RPZ, Unbound, ipset, clash, and plain-domain formats, with parallel DNS resolution. Source: [`split-routing/nft-resolve-rs/`](split-routing/nft-resolve-rs/)

### extra-networks (shell)

Shell scripts and CGI handlers for the isolated WiFi networks feature. Manages guest and untrusted IoT networks with dnsmasq-based isolation, per-device firewall rules, join approval, password rotation, and device labelling. Source: [`extra-networks/`](extra-networks/README.md)

### split-routing (shell)

Shell scripts that route specific domains and IPs through a WireGuard VPN without moving the default gateway. Integrates with nft-resolve for blocklist management. Source: [`split-routing/`](split-routing/docs/mullvad-routing.md) · [formats](split-routing/docs/supported-formats.md) · [troubleshooting](split-routing/docs/troubleshooting.md) · [WireGuard server setup](split-routing/docs/wireguard-vpn.md)

## Install on the router

### From a pre-built package (recommended)

Download the package for your architecture from the [latest release](https://github.com/lanbat/openwrt-kestrel/releases/latest) and install it:

```sh
# OpenWrt snapshot (apk):
apk add --allow-untrusted /tmp/extra-networks-*.aarch64.apk

# OpenWrt stable (opkg):
opkg install --force-reinstall /tmp/extra-networks_*_aarch64_cortex-a53.ipk
```

To find your architecture: `apk info --print-arch` or `opkg print-architecture`.

The package installs `/usr/bin/kestreld`, `/usr/bin/nft-resolve`, and `/etc/init.d/kestreld` (procd service, starts on boot at priority 95).

### Extra-networks shell scripts

The shell layer still needs to be installed from the repo on the router:

```sh
git clone https://github.com/lanbat/openwrt-kestrel /root/openwrt-kestrel
cd /root/openwrt-kestrel
cp extra-networks/configs/guest.conf.example     extra-networks/configs/guest.conf
cp extra-networks/configs/untrusted.conf.example extra-networks/configs/untrusted.conf
vi extra-networks/configs/guest.conf
vi extra-networks/configs/untrusted.conf
sh extra-networks/install.sh extra-networks/configs/guest.conf
sh extra-networks/install.sh extra-networks/configs/untrusted.conf
```

### split-routing

```sh
sh split-routing/install.sh
```

### Proxy kestreld behind uhttpd

kestreld serves on port 8080. Move uhttpd off port 80 so nginx can front both:

```sh
uci set uhttpd.main.listen_http='127.0.0.1:8181'
uci set uhttpd.main.listen_https='127.0.0.1:8443'
uci commit uhttpd && /etc/init.d/uhttpd restart

apk add nginx
cp /root/openwrt-kestrel/release/files/kestreld-nginx.conf /etc/nginx/conf.d/
/etc/init.d/nginx enable && /etc/init.d/nginx start
```

See [`release/files/kestreld-nginx.conf`](release/files/kestreld-nginx.conf) for the full proxy config.

## Building from source

Requires: [Rust](https://rustup.rs), [cross](https://github.com/cross-rs/cross), Docker, GNU make, Python 3, and `ar`.

```sh
# cross-compile both binaries for aarch64 (default)
make build

# assemble .apk and .ipk packages
make package

# build + deploy to a router (auto-detects apk vs opkg)
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

## Release process

Tagging a `v*` commit triggers GitHub Actions, which builds packages for all six supported architectures in parallel and uploads them to a single GitHub release:

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

# reinstall the kestrel package from your local build or GitHub releases
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

## How they interact

- Both sub-projects write to `/etc/dnsmasq.d/` and `/etc/nftables.d/` with distinct filenames — no conflicts.
- split-routing's VPN mark chain automatically excludes traffic from extra-network bridges (`br-guest`, `br-untrusted`, etc.) so isolated network traffic always uses the normal WAN, never the VPN tunnel.
- `nft-resolve` is available to both sub-projects for bulk domain resolution.
