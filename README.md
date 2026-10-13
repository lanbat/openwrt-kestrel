# openwrt-kestrel

**Give every device on your WiFi the trust it deserves, and send only the traffic you choose through a VPN.**

Two cooperating toolkits for OpenWrt routers, installed with plain shell scripts on top of
fw4/nftables and dnsmasq. No LuCI and no extra daemons to babysit.

- **[extra-networks](extra-networks/README.md):** isolated WiFi trust zones for guests, IoT and
  misbehaving gadgets, each with its own subnet, firewall zone, filtered DNS and rate limit. Optionally
  new devices wait for your approval, which arrives as a push notification with an **Approve** button.
- **[split-routing](split-routing/docs/mullvad-routing.md):** route chosen domains and IP ranges
  through a WireGuard VPN without moving your default gateway. Domain lists come in many formats,
  resolve lazily through dnsmasq and update daily.

Part of [LAN BAT](https://lanbat.github.io/), open home infrastructure. Pairs well with
[lanbat/nixconf](https://github.com/lanbat/nixconf), a NixOS homelab behind the same router.

## Why

Most home routers offer two levels of trust: on the WiFi, or off it. Real households need more.
Your laptop, a smart plug that phones home, and a visitor's phone should not share a network,
and you should not have to choose between "everything through the VPN" and "nothing through it".

| | extra-networks | split-routing |
|---|---|---|
| **One command** | `sh install.sh configs/guest.conf` deploys a complete zone | `sh install.sh` reads `/etc/split-routing/` |
| **Isolation** | Internet-only by default, WiFi client isolation, optional MAC allowlist | VPN marks skip isolated bridges, so guests never use your tunnel |
| **DNS** | Cloudflare for Families filtering, bypass blocked at the firewall, optional DoT | dnsmasq resolves listed domains on demand into nft sets |
| **Control** | Join approval, per-device outbound rules, access windows, password rotation | Named VPN tiers (e.g. one exit per country), each with its own domain categories |
| **Visibility** | Live web dashboard and ntfy push notifications | Daily list updates and a troubleshooting guide |

Supplementary docs: [supported formats](split-routing/docs/supported-formats.md) · [troubleshooting](split-routing/docs/troubleshooting.md) · [WireGuard VPN server](split-routing/docs/wireguard-vpn.md)

## Install

On the router:

```sh
git clone https://github.com/lanbat/openwrt-kestrel /root/openwrt-router
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
