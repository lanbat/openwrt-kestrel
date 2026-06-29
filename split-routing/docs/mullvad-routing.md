# Routing traffic through Mullvad

Selectively routes LAN traffic through a Mullvad WireGuard interface, leaving everything else on the default route. Works by marking packets destined for listed IPs with a firewall mark, then policy-routing those marked packets through a dedicated routing table that has the VPN as its default gateway.

## What install.sh sets up automatically

Before going through the steps, it helps to know what you don't need to do manually:

| Automatic | What it does |
|---|---|
| `/etc/nftables.d/30-split-routing.nft` | nft sets and mark chain — loaded by `fw4` on every reload, so they survive `fw4 reload` automatically |
| `/etc/hotplug.d/iface/99-mullvad-routing` | Restores policy routing rules (`ip rule`, `ip route`) whenever the VPN interface comes up or `fw4` reloads |
| `/etc/capabilities/dnsmasq.json` | Grants dnsmasq `CAP_NET_ADMIN` so it can write to nft sets |
| Cron entry | Refreshes all blocklists nightly at 03:17 |
| nft sets + mark rules | Applied immediately when `install.sh` runs |

The remaining steps are things you configure once on the router.

## Prerequisites

- OpenWrt with `fw4` / nftables (OpenWrt 22.03 or later)
- A working Mullvad WireGuard interface — Mullvad's website has an OpenWrt-specific config generator

Find your WireGuard interface name:

```sh
ip link show
```

Look for an interface that appears when the VPN is connected. Note the name — you'll need it for `VPN_IFACE` in the config.

## Step 1 — Install

Clone this repo onto the router and run:

```sh
cd /root
git clone https://github.com/lanbat/openwrt-split-routing.git
cd openwrt-split-routing
sh install.sh
```

This creates `/etc/split-routing/config` with defaults. Open it and set `VPN_IFACE` to your WireGuard interface name:

```sh
vi /etc/split-routing/config
```

The only value you **must** change is `VPN_IFACE`. Everything else has working defaults. Re-run install.sh to apply:

```sh
sh install.sh
```

## Configuration options

`/etc/split-routing/config` is created by `install.sh` the first time. The only value you must change is `VPN_IFACE`. Re-run `install.sh` after any change to apply it.

| Option | Default | Description |
|---|---|---|
| `VPN_IFACE` | — | WireGuard interface name, e.g. `wg0` or `mullvad` |
| `ROUTE_IPV6` | `yes` | Route marked IPv6 traffic through the VPN; set `no` if the VPN endpoint doesn't carry IPv6 (otherwise marked IPv6 is silently dropped) |
| `DNS_TIMEOUT` | `24h` | How long dnsmasq-populated IPs stay in the `dns` nft sets; shorter = faster cleanup of stale entries after a domain's IPs change |
| `FWMARK` | `0x1` | Firewall mark applied to VPN-destined packets; change if another tool (OpenVPN, mwan3) already uses `0x1` |
| `ROUTE_TABLE` | `100` | Policy routing table number; change if another tool already uses table `100` |
| `DNS_CATS` | `torrentsites pornsites sites` | Space-separated list of `dns` routing categories (dnsmasq-based) |
| `RESOLVE_CATS` | `torrenttrackers sites` | Space-separated list of `resolve` routing categories (nslookup-based) |

## Step 2 — Firewall zone

`fw4` needs a zone for the Mullvad interface so it allows forwarded LAN traffic through it. Replace `mullvad` with your UCI network name for the WireGuard interface:

```sh
uci add firewall zone
uci set firewall.@zone[-1].name='mullvad'
uci set firewall.@zone[-1].network='mullvad'
uci set firewall.@zone[-1].input='REJECT'
uci set firewall.@zone[-1].output='ACCEPT'
uci set firewall.@zone[-1].forward='REJECT'

uci add firewall forwarding
uci set firewall.@forwarding[-1].src='lan'
uci set firewall.@forwarding[-1].dest='mullvad'

uci commit firewall && fw4 reload
```

> After `fw4 reload`, the nft sets and mark chain are restored automatically by fw4 (they live in `/etc/nftables.d/30-split-routing.nft`). The hotplug script also fires to restore the policy routing rules (`ip rule` / `ip route`).

## Step 3 — dnsmasq setup

The `dns` mechanism relies on dnsmasq's `nftset` directive, which requires `dnsmasq-full`. The standard OpenWrt package is compiled without it.

### Check if you already have it

```sh
dnsmasq --version 2>&1 | grep -o nftset
```

If this prints `nftset`, skip to [Point dnsmasq at the config directory](#point-dnsmasq-at-the-config-directory).

### Install dnsmasq-full (stable releases)

```sh
opkg update
opkg install dnsmasq-full
```

### Install dnsmasq-full (snapshot / apk-based)

On snapshots, `dnsmasq-full` depends on `kmod-nf-conntrack-netlink` which is built into the kernel rather than packaged separately, so `apk add dnsmasq-full` fails. Install the binary manually:

```sh
cd /root
apk fetch dnsmasq-full libnetfilter-conntrack3 libnfnetlink0 libnettle8 libgmp10 libmnl0

# Extract and install dependency libraries
for pkg in libnetfilter-conntrack3-*.apk libnfnetlink0-*.apk libnettle8-*.apk libgmp10-*.apk libmnl0-*.apk; do
  apk extract --allow-untrusted --destination /tmp/libs "$pkg"
done
for lib in /tmp/libs/usr/lib/*.so.*.*; do
  cp "$lib" /usr/lib/
  chmod 0755 "/usr/lib/$(basename "$lib")"
  ln -sf "$(basename "$lib")" "/usr/lib/$(basename "$lib" | sed 's/\(.*\.so\.[0-9]*\).*/\1/')"
done

# Replace the dnsmasq binary
apk extract --allow-untrusted --destination /tmp/dnsmasq dnsmasq-full-*.apk
/etc/init.d/dnsmasq stop
cp /tmp/dnsmasq/usr/sbin/dnsmasq /usr/sbin/dnsmasq
chmod 0755 /usr/sbin/dnsmasq
```

### Point dnsmasq at the config directory

Tell dnsmasq to load config files from `/etc/dnsmasq.d/`, where `update-routing-sets` writes the `nftset=` directives:

```sh
uci set dhcp.@dnsmasq[0].confdir='/etc/dnsmasq.d'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

`install.sh` has already granted dnsmasq `CAP_NET_ADMIN`. If you installed dnsmasq-full after running install.sh, run `sh install.sh` again to restart dnsmasq with the correct capabilities.

## Step 4 — Load the blocklists

Run the updater to fetch all lists, populate the nft sets, and write the dnsmasq configs:

```sh
/usr/sbin/update-routing-sets
```

This will take a few minutes — the `resolve` categories run `nslookup` on hundreds of tracker hostnames. Each category prints its name before starting so you can see progress.

Expected output:

```
==> dns torrentsites
--- <date> ---
Domains: 3846 entries written to /etc/dnsmasq.d/torrentsites.conf
dnsmasq reloaded.
==> dns pornsites
...
==> resolve torrenttrackers
Updated nft sets in inet fw4
IPv4 set resolve_torrenttrackers4: 456 elements
...
```

## Step 5 — Verify

From a **LAN device** (not the router itself — the router's own traffic bypasses the mark rules):

```sh
# Should return a Mullvad IP if ifconfig.co is in local-dns-sites.txt
curl -4 ifconfig.co

# Should return your home WAN IP
curl -4 icanhazip.com
```

On the router, confirm dnsmasq is populating sets on DNS queries:

```sh
nslookup thepiratebay.org 127.0.0.1 > /dev/null
nft list set inet fw4 dns_torrentsites4
```

## Customizing what gets routed

### Adding individual domains or IPs

Each category has a local file in `/etc/split-routing/` that you can edit directly:

- `local-dns-sites.txt` — domains routed via the `dns` mechanism (dnsmasq `nftset=`)
- `local-resolve-sites.txt` — domains or IPs routed via the `resolve` mechanism (batch DNS lookup)
- `local-dns-torrentsites.txt`, `local-resolve-torrenttrackers.txt` — same for the torrent categories
- `local-dns-pornsites.txt` — adult content category

These files accept any format supported by `nft-resolve` — one domain per line is simplest. After editing, run:

```sh
/usr/sbin/update-routing-sets
```

The local files are created once by `install.sh` and **never overwritten** by subsequent runs, so your changes persist across re-installs.

### Adding remote sources

`/usr/sbin/update-routing-sets` is also written once and never overwritten. Open it and add `dns()` or `resolve()` calls with remote URLs:

```sh
# Route all domains from a remote blocklist through the VPN
dns torrentsites "https://example.com/torrent-domains.txt"

# Resolve and route IPs from a remote list
resolve torrenttrackers "https://example.com/tracker-ips.txt"
```

Each function accepts any number of URLs and local files. Any [supported format](supported-formats.md) works.

### Adding a new category

1. Add the category name to `DNS_CATS` or `RESOLVE_CATS` in `/etc/split-routing/config`
2. Re-run `sh install.sh` — this creates the nft sets and mark rules for the new category
3. Add `dns <name> ...` or `resolve <name> ...` calls to `update-routing-sets`
4. Run `/usr/sbin/update-routing-sets` to populate the new sets

> Renaming a category in config and re-running `install.sh` will delete the old nft set. If you rename mid-session without re-running, the old set is still marked and routes traffic; the new name won't work until `install.sh` runs.

### Using nft-resolve directly

`nft-resolve` is a standalone tool you can call independently of `update-routing-sets`:

```sh
# Load a domain list into specific nft sets
nft-resolve -4 my_set4 -6 my_set6 domain=/etc/split-routing/local-dns-sites.txt

# Load from a URL (format auto-detected)
nft-resolve -4 resolve_sites4 -6 resolve_sites6 https://example.com/domains.txt

# Load IP-only list (skip DNS resolution)
nft-resolve -4 my_set4 -6 my_set6 --no-resolve ip=/path/to/iplist.txt

# Print the normalized domain list without loading into nft
nft-resolve -4 - -6 - -d /tmp/domains.txt domain=/etc/split-routing/local-dns-sites.txt
```

See `supported-formats.md` for all accepted input formats.

## IPv6 considerations

If your Mullvad endpoint doesn't carry IPv6, set `ROUTE_IPV6=no` in `/etc/split-routing/config` and re-run `install.sh`. This removes the IPv6 policy rule and route, and the hotplug script will only add IPv4 mark rules going forward.

Without this, marked IPv6 traffic is silently dropped rather than routed.

## Hotplug script reference

For reference, here is what the generated `/etc/hotplug.d/iface/99-mullvad-routing` looks like. It fires on `ifup` and `ifupdate` — both when the VPN interface first comes up and when it reconnects after a brief interruption.

The nft sets and mark chain are **not** managed here — they live in `/etc/nftables.d/30-split-routing.nft` and are loaded automatically by `fw4` on every reload. The hotplug script's only job is to restore the policy routing rules (`ip rule` / `ip route`) that `fw4 reload` clears.

```sh
#!/bin/sh
[ "$ACTION" = ifup ] || [ "$ACTION" = ifupdate ] || exit 0
. /etc/split-routing/config
ip link show "$VPN_IFACE" 2>/dev/null | grep -q "LOWER_UP" || exit 0

ip    rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE" 2>/dev/null || true
ip    rule add fwmark "$FWMARK" lookup "$ROUTE_TABLE"
ip    route replace default dev "$VPN_IFACE" table "$ROUTE_TABLE"
if [ "$ROUTE_IPV6" = yes ]; then
  ip -6 rule del fwmark "$FWMARK" lookup "$ROUTE_TABLE" 2>/dev/null || true
  ip -6 rule add fwmark "$FWMARK" lookup "$ROUTE_TABLE"
  ip -6 route replace default dev "$VPN_IFACE" table "$ROUTE_TABLE"
fi
```

To trigger it manually (e.g. to restore routing rules after a `fw4 reload` without rebooting):

```sh
ACTION=ifup sh /etc/hotplug.d/iface/99-mullvad-routing
```
