# openwrt-router

Two cooperating toolkits for OpenWrt routers, managed from a single repo: one segments your WiFi into isolated trust zones with approval workflows and live monitoring, the other selectively routes traffic through a VPN by domain or category instead of tunneling everything.

## Sub-projects

### [extra-networks](extra-networks/README.md)

Isolated WiFi networks (guest, untrusted IoT) with push notifications,
join approval, per-device outbound control, password rotation, and a
web dashboard. Uses fw4/nftables and dnsmasq.

### [split-routing](split-routing/docs/mullvad-routing.md)

Routes specific domains and IPs through a WireGuard VPN without
moving the default gateway. Supports domain lists in many formats,
dnsmasq-based lazy resolution, and daily auto-updates.

Supplementary docs: [supported formats](split-routing/docs/supported-formats.md) · [troubleshooting](split-routing/docs/troubleshooting.md) · [WireGuard VPN server](split-routing/docs/wireguard-vpn.md)

## Install

```sh
git clone <repo-url> /root/openwrt-router
cd /root/openwrt-router
```

**extra-networks** requires a config file per network. Copy the examples and fill in at minimum `WIFI_KEY`, `SSID`, and `SUBNET`:

```sh
cp extra-networks/configs/guest.conf.example     extra-networks/configs/guest.conf
cp extra-networks/configs/untrusted.conf.example extra-networks/configs/untrusted.conf
vi extra-networks/configs/guest.conf
vi extra-networks/configs/untrusted.conf
```

Then install each network:

```sh
sh extra-networks/install.sh extra-networks/configs/guest.conf
sh extra-networks/install.sh extra-networks/configs/untrusted.conf
```

**split-routing** reads its own config from `/etc/split-routing/` and needs no argument:

```sh
sh split-routing/install.sh
```

## Upgrading OpenWrt

Use `sysupgrade` (flash a new firmware image) rather than `apk upgrade`. On snapshot builds, `apk upgrade` can pull kernel modules built for a different kernel version than the one running, causing modules to fail loading until reboot — and if the kernel image itself is replaced, you'd be running a mismatched system. Flashing a new image is atomic: kernel, modules, and packages all come from the same build.

### What sysupgrade preserves automatically

The installer adds paths to `/etc/sysupgrade.conf` and packages add their own paths to `/lib/upgrade/keep.d/`. Between them, these are already covered:

| Path | Contents |
|---|---|
| `/root/` | git repo (`/root/openwrt-router/`) |
| `/etc/config/` | all UCI config — network, WireGuard, firewall, DHCP |
| `/etc/extra-networks/` | device data, labels, history, join lists |
| `/etc/dnsmasq.d/` | split-routing and content-filter configs |
| `/etc/nftables.d/` | all nft rules including split-routing |
| `/etc/hotplug.d/iface/99-mullvad-routing` | VPN routing hotplug script |
| `/etc/crontabs/` | crontab |
| `/etc/dropbear/` | SSH host keys and authorized\_keys |
| `/etc/hosts` | static hostname entries |
| `/etc/crowdsec/` | crowdsec config |

### What needs attention after sysupgrade

**Reinstall extra packages.** The base firmware image does not include packages installed via `apk add`. Reinstall anything beyond the base image, for example:

```sh
apk update
apk add dnsmasq-full crowdsec crowdsec-firewall-bouncer banip pbr \
        https-dns-proxy tmux qrencode
```

If `dnsmasq-full` fails with `kmod-nf-conntrack-netlink (no such package)`, the package index for this snapshot is missing a virtual dependency. Work around it by adding the provide to the already-installed `kmod-nf-conntrack` entry, then retry:

```sh
sed -i 's/^p:kmod-nf-conntrack-any$/p:kmod-nf-conntrack-any kmod-nf-conntrack-netlink/' \
    /lib/apk/db/installed
apk add dnsmasq-full
```

**Re-run the installers.** This redeploys the CGI scripts and init.d services (wifi-recover, extra-networks-reboot) that live outside the preserved paths:

```sh
cd /root/openwrt-router
sh extra-networks/install.sh extra-networks/configs/guest.conf
sh extra-networks/install.sh extra-networks/configs/untrusted.conf
sh split-routing/install.sh
```

### Sysupgrade steps

```sh
# 1. Create a backup (optional — paths above are restored automatically, but good practice)
sysupgrade -b /tmp/backup-$(date +%Y%m%d).tar.gz

# 2. Download the new image for your target and flash it
sysupgrade /tmp/openwrt-*.bin

# 3. After reboot: reinstall packages and re-run installers (see above)
```

## How they interact

- Both write to `/etc/dnsmasq.d/` and `/etc/nftables.d/` with distinct
  filenames — no conflicts.
- split-routing's VPN mark chain automatically excludes traffic from
  extra-network bridges (`br-guest`, `br-untrusted`, etc.) so isolated
  network traffic always uses the normal WAN, never the VPN tunnel.
- `nft-resolve` (installed by split-routing) is available to extra-networks
  for bulk domain resolution on device allowlist pages.
