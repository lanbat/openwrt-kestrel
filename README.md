# openwrt-extra-networks

Manage multiple isolated WiFi networks on OpenWrt from a single script. Each network gets its own subnet, firewall zone, DNS policy, and rate limit — deployed in seconds, no LuCI needed.

Built for households that need more than one level of trust: your own devices, IoT gadgets that shouldn't touch anything, and guests who just need internet.

Works with OpenWrt `fw4` / nftables.

## Networks

| Network | Purpose | DNS | Rate | Allowlist |
|---|---|---|---|---|
| `untrusted` | IoT devices (Nest Protect, smart plugs) | 1.1.1.3 filtered | 500kbit shared | MAC-based — unlisted devices get nothing |
| `guest` | Visitors | 1.1.1.3 filtered | 10mbit shared | none — open to any device |

Each network is a config file. Add a new one by copying an example.

## Features

- **One script, any network** — `sh install.sh configs/guest.conf` deploys a complete isolated network
- **Strict firewall isolation** — each network can reach the internet and nothing else by default
- **Filtered DNS** — Cloudflare for Families (1.1.1.3) blocks malware and adult content; switch to 1.1.1.1 for plain DNS
- **DNS bypass prevention** — firewall blocks port 53 to any server other than the one assigned via DHCP
- **Rate limiting** — per-network bandwidth cap via nftables; supports `mbit` and `kbit` units
- **MAC allowlist** — for IoT networks: unlisted devices get no DHCP lease and are blocked from forwarding even with a manual IP
- **LAN → isolated access** — optionally allow LAN devices to reach isolated network devices (e.g. check on your Nest Protects), never the reverse
- **WPA3 support** — use `sae` for WPA3-only or `sae-mixed` for WPA3 with WPA2 fallback
- **Legacy device support** — use `psk+psk2` for hardware that can't do WPA3
- **Temporary port forwarding** — expose a LAN game server to guests for a fixed time; auto-removed via cron when the timer expires
- **No secrets in the repo** — WiFi keys live only in gitignored config files on the router
- **Idempotent installs** — re-running `install.sh` updates an existing network cleanly

## Setup

### 1. Clone onto your router

```sh
cd /root
git clone https://github.com/lanbat/openwrt-extra-networks.git
cd openwrt-extra-networks
```

### 2. Create a config

```sh
cp configs/untrusted.conf.example configs/untrusted.conf
vi configs/untrusted.conf   # set WIFI_KEY and adjust to your setup
```

### 3. Install

```sh
sh install.sh configs/untrusted.conf
```

Repeat for each network you want.

## Configuration

Config files live in `configs/` and are gitignored — they never leave the router. Copy an example, fill in `WIFI_KEY`, adjust anything else.

| Option | Required | Default | Description |
|---|---|---|---|
| `WIFI_KEY` | yes | — | WiFi password (min 8 chars) |
| `IFACE` | yes | — | UCI interface name — must be unique (e.g. `guest`, `untrusted`) |
| `SSID` | yes | — | WiFi network name |
| `RADIO` | no | `radio0` | `radio0` = 2.4GHz, `radio1` = 5GHz |
| `WIFI_UCI` | no | `$IFACE` | UCI wireless section name — created automatically if absent |
| `ENCRYPTION` | no | `psk2+psk3` | `sae` = WPA3 only, `sae-mixed` = WPA3+WPA2, `psk+psk2` = WPA2+WPA (legacy) |
| `SUBNET` | yes | — | First three octets — router gets `.1`, clients `.100`–`.249` (e.g. `192.168.3`) |
| `RATE_LIMIT` | no | `0` | Bandwidth cap for the whole network — `10mbit`, `500kbit`, `0` to disable |
| `DNS_SERVER` | no | `1.1.1.3` | DNS given to clients via DHCP — `1.1.1.3` filtered, `1.1.1.1` plain |
| `ALLOWLIST` | no | `no` | `yes` = MAC allowlist enabled; see [Allowlist](#allowlist) |
| `LAN_ACCESS` | no | `no` | `yes` = LAN devices can initiate connections to this network (not vice versa) |

## Allowlist

When `ALLOWLIST=yes`, only devices listed in `/etc/${IFACE}-allowed-macs` can get a DHCP lease or forward traffic. The file is created automatically on first install.

Format — one device per line:

```
# mac  ip  description
aa:bb:cc:dd:ee:ff  192.168.2.100  Nest Protect Living Room
11:22:33:44:55:66  192.168.2.101  Nest Protect Bedroom
```

After editing, apply without restarting:

```sh
ACTION=ifup INTERFACE=untrusted sh /etc/hotplug.d/iface/51-untrusted-macfilter
```

Two-layer enforcement:
1. **DHCP** — dnsmasq ignores DHCP requests from unlisted MACs
2. **nftables** — forwarding from unlisted IPs is dropped even if a device sets a manual IP

> Bridge-family nftables is not available on all platforms. This approach covers the gap without kernel modules.

## Tools

### Expose a port to an isolated network

Forward a specific port from an isolated network to a LAN host — useful for gaming sessions or temporary access.

```sh
# Permanent
sh tools/expose-port.sh guest 27015 192.168.1.50

# Auto-remove after 2 hours
sh tools/expose-port.sh guest 27015 192.168.1.50 2h

# With protocol and custom name
sh tools/expose-port.sh guest 25565 192.168.1.50 3h tcp minecraft
```

```
Arguments: <src-zone> <port> <dest-ip> [duration] [proto] [name]

  duration   30m, 2h, 1h30m — auto-removed via cron, survives reboots
  proto      tcp, udp, or "tcp udp" (default)
  name       label for the rule (default: expose-<zone>-<port>)
```

Guests connect to the router's zone IP (e.g. `192.168.3.1:27015`) — the router NATs the connection to the LAN host.

### Remove an exposed port

```sh
sh tools/unexpose-port.sh expose-guest-27015

# Or use the custom name you gave it
sh tools/unexpose-port.sh minecraft
```

Also cancels any scheduled cron removal.

## Adding a new network

1. Copy an example config: `cp configs/guest.conf.example configs/mynetwork.conf`
2. Set `IFACE`, `SSID`, `SUBNET`, `WIFI_KEY` — ensure the subnet doesn't overlap with existing networks
3. Run `sh install.sh configs/mynetwork.conf`

## Notes

- **Rate limiting** uses `nft limit rate` (drop) rather than `tc tbf` — `kmod-sched-core` is not packaged on all platforms. Packets exceeding the cap are dropped rather than queued; for IoT and guest traffic this is fine.
- **Wireless sections** are created automatically if they don't exist in UCI. To use an existing section (e.g. one you configured in LuCI), set `WIFI_UCI` to its name.
- **Re-running** `install.sh` on an existing network is safe — it updates all settings cleanly.
