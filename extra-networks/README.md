# openwrt-extra-networks

Manage isolated WiFi networks on OpenWrt — IoT, guest, untrusted — with a single parameterized install script. Each network gets its own subnet, firewall zone, DNS policy, and rate limit, plus optional push-notified join approval, per-device outbound access control, scheduled access windows, password rotation, and a live web dashboard — deployed in seconds, no LuCI needed.

Built for households that need more than one level of trust: your own devices, IoT gadgets that shouldn't touch anything, and guests who just need internet.

Works with OpenWrt `fw4` / nftables.

## Networks

| Network | Purpose | DNS | Rate | Allowlist |
|---|---|---|---|---|
| `untrusted` | IoT / misbehaving devices | 1.1.1.3 filtered | 500kbit shared | MAC-based — unlisted devices get nothing |
| `guest` | Visitors | 1.1.1.3 filtered | 10mbit shared / 5mbit per device | none — open to any device |

Each network is a config file. Add a new one by copying an example.

## Features

- **One script, any network** — `sh install.sh configs/guest.conf` deploys a complete isolated network
- **Strict firewall isolation** — each network can reach the internet and nothing else by default
- **WiFi client isolation** — devices on the same network can't reach each other
- **Filtered DNS** — Cloudflare for Families (1.1.1.3) blocks malware and adult content
- **DNS bypass prevention** — port 53 to any unauthorised server is blocked at the firewall
- **Encrypted DNS (DoT)** — optionally route DNS through `https-dns-proxy` for encrypted queries
- **Rate limiting** — aggregate cap + optional per-device cap via nftables; no kernel modules required
- **Port restriction** — limit outbound ports (e.g. web-only guests)
- **MAC allowlist** — for IoT networks: unlisted devices get no lease and are blocked from forwarding
- **Join approval** — optionally block all new devices from internet access until you approve them; a push notification fires with an **Approve** button the moment they connect; approvals persist across reboots and are reset when the password is rotated
- **Per-device control** — when enabled, each approved device must explicitly allow every outbound domain or IP it tries to reach; blocked attempts accumulate on a per-device management page; approved rules persist across reboots
- **LAN ↔ isolated access** — optionally let LAN devices reach isolated network devices (`LAN_ACCESS=yes`); separately, isolated devices that try to reach LAN services trigger a push notification with an **Approve** button so you can grant temporary per-service access
- **mDNS reflection** — let guests discover shared services (Chromecast, AirPrint) via avahi
- **Push notifications** — event-driven alerts via ntfy.sh: new device joined, join approved/denied/revoked, LAN access request/approval/expiry, allowlist rejection, bandwidth alert, port forwarded/removed, password rotated, daily digest, VPN state change, router reboot
- **Live status dashboard** — web page on the router showing all networks, connected devices with per-device traffic (IPv4 and IPv6), VPN status, WireGuard server peers, pending LAN access requests, active LAN access rules, and port forwards
- **Traffic counters** — bytes in/out per network since last firewall reload, shown in status
- **Access schedule** — restrict internet to specific hours; auto-blocked outside the window
- **Temporary port forwarding** — expose a LAN host to guests for a fixed time; auto-removed via cron
- **Password rotation** — generate a new key, apply it live, disconnect old clients, and print a fresh QR code
- **Guest info page** — LAN-accessible HTML page with SSID, password, and QR code
- **WPA3 support** — `sae` for WPA3-only, `sae-mixed` for WPA3+WPA2, `psk+psk2` for legacy
- **Dual-band** — broadcast the same network on both 2.4GHz and 5GHz radios
- **IPv6** — optional DHCPv6 + RA with auto-derived IPv6 DNS; IPv6 addresses supported throughout (device table, approval flow, firewall rules)
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
cp configs/guest.conf.example     configs/guest.conf
cp configs/untrusted.conf.example configs/untrusted.conf
vi configs/guest.conf      # set WIFI_KEY, SSID, SUBNET, and anything else
vi configs/untrusted.conf
```

### 3. Install

```sh
sh install.sh configs/guest.conf
sh install.sh configs/untrusted.conf
```

Run `install.sh` once per network. To add another network later, copy any example, edit it, and run `install.sh` with that file.

## Configuration

Config files live in `configs/` and are gitignored — they never leave the router. Copy an example, fill in `WIFI_KEY`, adjust anything else.

### Required

| Option | Description |
|---|---|
| `WIFI_KEY` | WiFi password (min 8 chars) |
| `IFACE` | UCI interface name — must be unique (e.g. `guest`, `untrusted`) |
| `SSID` | WiFi network name |
| `SUBNET` | First three octets — router gets `.1`, clients `.100`–`.249` (e.g. `192.168.3`) |

### Wireless

| Option | Default | Description |
|---|---|---|
| `RADIO` | `radio0` | `radio0` = 2.4GHz, `radio1` = 5GHz |
| `RADIO_EXTRA` | — | Second radio for dual-band (e.g. `radio1`); leave blank for single-band |
| `ENCRYPTION` | `psk2+psk3` | `sae` = WPA3 only, `sae-mixed` = WPA3+WPA2, `psk+psk2` = WPA2+WPA |
| `ISOLATE` | `yes` | Prevent clients on the same network from reaching each other |

### Network

| Option | Default | Description |
|---|---|---|
| `RATE_LIMIT` | `0` | Aggregate bandwidth cap — `10mbit`, `500kbit`, `0` to disable |
| `RATE_LIMIT_PER_DEVICE` | `0` | Per-device cap; both limits apply simultaneously when set |
| `DNS_SERVER` | `1.1.1.3` | DNS given to clients — `1.1.1.3` filtered, `1.1.1.1` plain |
| `DOT` | `no` | Route DNS through `https-dns-proxy` for encrypted DoT/DoH; requires it to be installed and configured |
| `IPV6` | `no` | Enable IPv6 (DHCPv6 + RA); IPv6 DNS auto-derived from `DNS_SERVER` for Cloudflare and Google addresses; set `DNS_SERVER_V6` explicitly for any other resolver |
| `DNS_SERVER_V6` | auto | IPv6 DNS server handed to clients via DHCPv6; derived automatically from `DNS_SERVER` when possible; without it the IPv6 DNS bypass-prevention rule is not created |
| `ALLOWED_PORTS` | — | Restrict outbound TCP/UDP ports, e.g. `"80 443"`; NTP (123) always allowed |

### Access and isolation

| Option | Default | Description |
|---|---|---|
| `LAN_ACCESS` | `no` | Allow LAN devices to initiate connections to this network (not vice versa) |
| `ALLOWLIST` | `no` | MAC allowlist — only listed devices get a lease or can forward traffic |
| `VLAN_ID` | — | 802.1Q VLAN ID — bridge a tagged wired port into this network alongside WiFi, e.g. `20` |
| `VLAN_TRUNK` | — | Physical interface carrying the VLAN trunk, e.g. `eth0` — required when `VLAN_ID` is set |
| `MDNS` | `no` | Reflect mDNS between LAN and this network; installs avahi-daemon if absent |
| `NOTIFY_URL` | — | ntfy.sh URL for push notifications, e.g. `https://ntfy.sh/my-topic` |
| `NOTIFY_JOIN` | `no` | Send a push notification each time a device gets a DHCP lease |
| `REJOIN_NOTIFY_AFTER` | — | Send a notification when a known device reconnects after being absent for at least this long — e.g. `7d`, `12h`; blank to disable |
| `JOIN_APPROVAL` | `no` | Block internet for new devices until you approve them via push notification (requires `NOTIFY_URL`) |
| `FINGERPRINT_SUGGEST` | `yes` | When a device with a randomized (privacy) MAC joins, suggest a possible match against already-labeled devices on the join-approval prompt; see [Recognizing a randomized-MAC device again after it rotates](#oui-database-manufacturer-lookup). Never applied automatically, and never affects whether approval itself works — set `no` to stop the guessing entirely |
| `JOIN_HISTORY_RETENTION` | `90d` | Keep join approval, denial, and revocation history this long; plain numbers mean days |
| `DEVICE_CONTROL` | `no` | Per-device outbound control — each approved device must explicitly allow every destination domain or IP it tries to reach; requires `JOIN_APPROVAL=yes`; see [Per-device control](#per-device-control) |
| `DEFAULT_DURATION` | `24h` | Pre-selected duration in the LAN access approval form (`1h` `6h` `12h` `24h` `2d` `7d` `30d`) |
| `MAX_DURATION` | `30d` | Longest duration available in the LAN access approval form — options above this are hidden |
| `REASON_REQUIRED` | `no` | `yes` — approver must enter a reason before LAN access is granted |
| `BANDWIDTH_THRESHOLD_MB` | `0` | Alert when a device transfers this many MB in a session; `0` to disable |
| `SHOW_QR` | `no` | Show WiFi QR code and password in the status dashboard; ignored for the `untrusted` network |
| `ROTATE_PASSWORD` | `no` | Show a manual "Rotate password" button in the status dashboard |
| `DESCRIPTION` | — | Label shown in the status dashboard header for this network |

> `ACCESS_HOURS` appears in the example config files as a reminder that a schedule can be set, but `install.sh` does not read it — the line is inert. Use `tools/access-schedule.sh` to set or remove the schedule.

## Allowlist

When `ALLOWLIST=yes`, only devices listed in `/etc/${IFACE}-allowed-macs` can get a DHCP lease or forward traffic.

Format — one device per line:

```
# mac  ip  description
aa:bb:cc:dd:ee:ff  192.168.2.100  Nest Protect Living Room
11:22:33:44:55:66  192.168.2.101  Nest Protect Bedroom
```

The file lives at `/etc/kestrel/networks/${IFACE}-allowed-macs`. After editing, apply without restarting:

```sh
ACTION=ifup INTERFACE=untrusted sh /etc/hotplug.d/iface/51-untrusted-macfilter
```

Two-layer enforcement:
1. **DHCP** — dnsmasq ignores DHCP requests from unlisted MACs
2. **nftables** — forwarding from unlisted IPs is dropped even with a manual static IP

## Encrypted DNS (DoT)

When `DOT=yes`, clients are given the router's own IP as their DNS server. Queries go to dnsmasq, which forwards them to `https-dns-proxy` over DoH/DoT — encrypted all the way to the resolver.

External DNS is blocked at the firewall: port 53 to any external server is rejected, and port 853 (DoT bypass) is also blocked. Clients cannot escape.

Requires `https-dns-proxy` to be installed and configured on the router. On this setup it resolves via Mullvad and Quad9.

## mDNS reflection

mDNS multicast packets are confined to a single subnet — a guest on `192.168.3.x` can't discover a Chromecast on `192.168.1.x` because the broadcast stops at the router.

`MDNS=yes` installs and configures `avahi-daemon` to relay mDNS packets between LAN and the isolated network. Guests can then discover and use shared services: Chromecast, AirPrint, game lobbies.

**Note:** avahi reflects all mDNS services, not just specific ones. Guests would see printers, file shares, and other LAN devices that advertise via mDNS. Use `MDNS=yes` only on networks where that level of sharing is intentional.

## Device notifications

Set `NOTIFY_URL` to an [ntfy.sh](https://ntfy.sh) topic URL. Subscribe in the ntfy app on your phone. Each network can have its own topic.

```sh
NOTIFY_URL=https://ntfy.sh/my-unique-topic-name
```

All notifications include a link to the status dashboard. LAN access requests include an **Approve** action button.

| Event | Trigger | Priority |
|---|---|---|
| New device joined | Device gets a DHCP lease (when `NOTIFY_JOIN=yes`) | Low |
| Device reconnected | Known device returns after being absent for `REJOIN_NOTIFY_AFTER` or longer | Low |
| Join request | New device needs internet approval (when `JOIN_APPROVAL=yes`) | Default |
| Join approved | Device internet access approved via web form | Default |
| Join denied | Device internet access denied via web form | Default |
| Access revoked | Previously approved device's internet access revoked via device page | Default |
| Device removed | Device fully removed from the network via device page | Default |
| Rule added | Domain or IP allow rule added for a device (when `DEVICE_CONTROL=yes`) | Default |
| LAN access request | Isolated device blocked from reaching a LAN service | Default |
| LAN access approved | Access granted via web form or `allow-service.sh` | Default |
| LAN access expired | Temporary rule removed by cron | Low |
| Allowlist rejection | Unlisted device attempts to use the network | High |
| Bandwidth alert | Device exceeds `BANDWIDTH_THRESHOLD_MB` in a session | Default |
| Port forwarded | `expose-port.sh` adds a redirect | Default |
| Port forward removed | Rule expired or `unexpose-port.sh` called | Low |
| Password rotated | `rotate-password.sh` generates a new key | Default |
| Daily digest | System health, VPN/routing set status, WG peers, traffic, blocked counts, expiring rules, calendar | Low |
| Router reboot | Router comes back online (30s delay) | Low |
| VPN state change | VPN goes down or recovers | High / Default |

### Approval workflows at a glance

There are two independent approval flows. Both work the same way on every network — a push notification with a button, tap it, decide on your phone — but they answer different questions:

| | Join approval | LAN access approval |
|---|---|---|
| **Question it answers** | "Should this device be allowed on the internet at all?" | "Should this isolated device be allowed to reach something on my home LAN?" |
| **Turned on with** | `JOIN_APPROVAL=yes` | Always on — no config needed, just set `NOTIFY_URL` |
| **Triggers when** | A new device gets a DHCP lease | An isolated device tries to reach a 192.168.1.x (LAN) service |
| **What you approve** | The device, once — future reconnects are silent | One specific destination + port, for a chosen duration |
| **Approval page** | `/cgi-bin/approve-join` | `/cgi-bin/approve-access` |

Use **join approval** to control who's allowed on a network at all (e.g. vetting every guest's phone before it gets internet). Use **LAN access approval** to make one-off exceptions when an otherwise-isolated device legitimately needs to reach something of yours (e.g. a smart TV needing your Plex server) — you don't need to configure anything for this one; it works automatically as soon as `NOTIFY_URL` is set.

#### guest vs. untrusted: which approvals make sense where

The two example networks are built for different situations, so the right approval settings differ:

- **`guest`** is open — any device can connect with the WiFi password, there's no MAC allowlist. If you want to know (and approve) every device before it gets online, this is the network where `JOIN_APPROVAL=yes` earns its keep: a friend's phone joins, you get a push, you tap Approve, done. If you're fine with "anyone with the password is trusted enough," leave it off (the default) — `NOTIFY_JOIN=yes` still tells you when someone new shows up, just without blocking them first.
- **`untrusted`** (IoT) already gates membership a different way: `ALLOWLIST=yes` means a device needs its MAC pre-registered in `/etc/kestrel/networks/untrusted-allowed-macs` just to get a DHCP lease at all — unlisted hardware is blocked before it ever reaches the join-approval step. Since you're already vetting devices by MAC, `JOIN_APPROVAL=yes` by itself adds little here — but it's worth turning on anyway as the prerequisite for **`DEVICE_CONTROL=yes`** ([below](#per-device-control)), which is where `untrusted` really earns its name: every allowlisted IoT device still has to explicitly allow each destination it talks to, so a device phoning home somewhere unexpected gets caught and blocked rather than waved through just because its MAC was on the list.

In short: `guest` → gate who joins; `untrusted` → gate what already-known devices can reach.

### LAN access approval

When an isolated device tries to reach a service on your LAN (192.168.1.x or its IPv6 equivalent), nftables logs the connection attempt and `check-access-log.sh` (runs every minute via cron) catches it and sends you a push notification with an **Approve** button.

What happens, step by step:

1. A device on `guest` or `untrusted` tries to connect to something on your LAN — say, a smart display trying to reach your Plex server.
2. nftables logs the blocked attempt; within a minute, a push notification arrives on your phone naming both devices.
3. Tap the notification → a form opens on the router (`/cgi-bin/approve-access`) showing the requesting device (IP, MAC, hostname) and the LAN destination it's after.
4. Pick how long to allow it (1 hour up to 30 days — `DEFAULT_DURATION` pre-selects one, `MAX_DURATION` hides longer options), optionally explain why, and submit.
5. The firewall rule goes live immediately. It's removed automatically when the chosen duration expires — no cleanup needed.
6. You get a confirmation push once it's granted, and another when it later expires.

Set `REASON_REQUIRED=yes` if you want the reason field to be mandatory rather than optional (enforced both in the form and on the router). The approval page itself is only reachable from your home LAN — isolated zones have `INPUT=REJECT`, so a compromised guest device can't even load the form. Both IPv4 and IPv6 are supported throughout.

### Join approval

`JOIN_APPROVAL=yes` flips a network from "anyone with the password gets online" to "every new device is blocked from the internet until you personally approve it" — useful the moment you want to know exactly which devices are using your WiFi, not just that *something* joined.

What happens, step by step:

1. A device connects and gets a DHCP lease. Its IP is immediately added to an nftables block set — it has a working local address but no path to the internet.
2. A push notification fires: *"unknown (aa:bb:cc:dd:ee:ff) joined guest at 192.168.3.105 and needs internet approval"*, with an **Approve** button.
3. Tap it → a form opens (`/cgi-bin/approve-join`) showing the device's hostname, IP, and MAC, with two buttons: **Approve internet access** and **Deny internet access**. Approving requires giving the device a label (e.g. "Alice's Phone") — that label is what you'll see everywhere else in the dashboard from now on.
4. Approve → the device's MAC is recorded and it's unblocked immediately, typically within a second or two.
5. From then on, that MAC passes straight through with no notification at all, on any IP it's later assigned — you only get asked once per device, ever (unless you revoke it or rotate the WiFi password).

If you tap **Deny** instead, the device stays blocked. It's not gone from the dashboard, though — the device row shows "Denied" and you can flip it to Approved later from the same row without waiting for it to reconnect.

Everything is visible afterwards: the dashboard's device table shows each device's join state (Pending / Approved / Denied) at a glance, and every approval, denial, and revocation sends a push notification naming the device and who made the call. The full history (with timestamps) lives on each device's own page and in `/etc/kestrel/networks/${IFACE}-join-history`, kept for `JOIN_HISTORY_RETENTION` (default 90 days) and preserved across reboots and sysupgrades.

Two things worth knowing before you turn this on:

- **Rotating the WiFi password resets unlabeled approvals.** Devices you've already labeled stay approved through a password change; anything still pending, denied, or approved-but-never-labeled gets cleared, since those devices have to reconnect with the new password anyway.
- **The block is enforced at the firewall, not just in the app.** The pending-devices block set is rebuilt from the state file on every `fw4 reload` and on boot, so a device you haven't approved stays blocked even across router restarts — there's no window where a pending device sneaks online.

### Per-device control

`DEVICE_CONTROL=yes` places each approved device under its own nftables inspect chain. All new outbound connections are **blocked by default** and logged. The device can only reach destinations you've explicitly approved — by domain or by IP. Best suited for IoT devices that should only contact known servers.

Requires `JOIN_APPROVAL=yes` — the approval step records each device's IP, which the inspect chain needs to generate per-device rules. Set both in the config file and re-run `install.sh`.

**Approving connections**

When a device's outbound connection is blocked, it appears in the **Pending connections** table on that device's page. Open the page by clicking the device's MAC address in the status dashboard:

1. Find the device in the dashboard's network table
2. Click its MAC address link → opens `/cgi-bin/device?net=<iface>&mac=<mac>`
3. The **Pending connections** table lists each blocked destination (IP, port, protocol, reverse DNS)
4. Click **Allow** to permit that destination, or **Deny** to dismiss it without approving

Use **Approve domain** to allow a hostname: the router adds a dnsmasq `nftset=` rule so all IPs that domain resolves to are automatically allowed for this device going forward.

Approved rules are written to `/etc/kestrel/networks/<iface>-device-rules` and survive reboots. Domains are written to `/etc/dnsmasq.d/<iface>-device-<mac>.conf`.

**Routing an approved domain through a VPN instead of WAN**

If [`split-routing`](../split-routing/docs/mullvad-routing.md) is configured, the **Approve domain** form includes a **Route** dropdown listing "WAN" plus each configured VPN tier (`/etc/kestrel/split-routing/vpn-<name>.conf`) — the same tiers shown in the dashboard's VPN status panel. Choosing a tier routes just that domain's traffic for that one device through the VPN rather than the default gateway; everything else the device does still goes over WAN. The Rules table shows each domain's chosen route, and it can be changed later by re-approving the same domain with a different route.

This only applies to domain rules (`Approve domain`), not raw IP/port allow rules from the pending-connections table — those always go over WAN.

**Device page**

Every device with a label has a dedicated management page — not just DEVICE_CONTROL networks. Click any MAC address in the status dashboard to open it.

| Section | Available when | What it shows |
|---|---|---|
| Device | Always | Label, manufacturer (from OUI database; shows "Randomized MAC" for privacy MACs), MAC, tracked IPv4/IPv6, network, DNS name, join approval state and actions, and a link to the [known identity](#oui-database-manufacturer-lookup) page if this MAC has been fingerprint-matched |
| Connection rate limit | Always | New-connection cap per minute (default 120); configurable per device |
| Approve domain | `DEVICE_CONTROL=yes` | Add a hostname allow rule, optionally routed through a configured VPN tier instead of WAN — see [Per-device control](#per-device-control) |
| Pending connections | `DEVICE_CONTROL=yes` | Blocked outbound attempts — Allow / Deny each. Destinations matching a banIP threat-intel feed (spamhaus, feodo, dshield, turris, urlhaus, cinsscore, ...) are labeled with which feed flagged them |
| Rules | `DEVICE_CONTROL=yes` | Active domain and IP allow rules — revoke individually; domain rules show their route (WAN or VPN tier name) |
| DNS query history | Always | Last 50 DNS queries made by this device (parsed from dnsmasq's query log), each flagged with an "⚠ adblock" badge if the domain is on the adblock blocklist |
| History | Always | Last 20 join decisions (approve/deny/revoke) for this device, with timestamp, IP, and approver |
| Approval activity | Always | Join decisions where this device was the approver on another device |
| Danger zone | Always | Remove device — deletes label, rules, approval, and DNS entry; takes effect immediately |

**Connection rate limit**

Every device's new-connection rate is capped to prevent port scans and misbehaving apps from flooding the network. The default is 120 new connections/minute. Adjust it per device on the device page — takes effect immediately without reloading the firewall. The limit applies whether or not `DEVICE_CONTROL` is enabled.

**Per-device DNS names**

When a device is labeled — either at approval time or later via the device page — its label is registered in dnsmasq. Labels accept any text: Unicode, accented characters, emoji, whatever is useful to you. The DNS hostname is derived automatically by lowercasing the label and replacing non-alphanumeric characters with hyphens, so "Alice's Phone" becomes reachable at `alices-phone.lan` from the rest of the LAN. If the label produces an empty hostname (e.g. a label made entirely of symbols), DNS registration is silently skipped — the device still has a label in the dashboard. The DNS entry is written to `/etc/dnsmasq.d/<iface>-dns-<mac>.conf` and survives reboots. Re-labeling a device updates the entry immediately.

### Bandwidth alerts

`BANDWIDTH_THRESHOLD_MB` triggers an alert when a device exceeds that many MB in a session. Counters reset on `fw4 reload` or after 24 hours of inactivity. An IP is only alerted once per session.

### Daily digest

Sent every morning at 08:00. Includes:

- **System health** — uptime, 1-min load average, memory usage %
- **VPN status** — up/down per tier (if split-routing is configured)
- **Blocklists** — domain and IP count per category (from the last `update-routing-sets` run), and how long ago it ran
- **WireGuard server peers** — how many peers were active in the last 24h (for server-mode WG interfaces)
- **Traffic** — ↓/↑ totals, connected device count (active DHCP leases), active LAN access rule count per network
- **Blocked counts** — LAN access requests and allowlist rejections logged since boot
- **Expiring rules** — any temporary LAN access rules expiring today or tomorrow
- **Calendar events** — upcoming events for the next 7 days (if `GCAL_URL` is configured — see [Global settings](#global-settings)); recurring weekly and biweekly events are expanded correctly

### Including the main LAN in the digest

The digest covers every network that has a `*-notify.conf` file in `/etc/kestrel/networks/`. Isolated networks get one automatically from `install.sh`. The main LAN does not, so create it manually:

```sh
cat >/etc/kestrel/networks/lan-notify.conf <<EOF
NOTIFY_URL=https://ntfy.sh/your-topic
SUBNET=192.168.1
IFACE_NAME=lan
EOF
```

Traffic reporting also requires a counter chain, which `install.sh` now creates automatically at `/etc/nftables.d/24-lan-counter.nft` on every run. If you're adding the main LAN before running `install.sh` again, create it manually and reload:

```sh
cat >/etc/nftables.d/24-lan-counter.nft <<'EOF'
chain lan_counter {
    type filter hook forward priority 0; policy accept;
    iifname "br-lan" counter
    oifname "br-lan" counter
}
EOF
fw4 reload
```

Device count reflects active DHCP leases matching the `SUBNET` prefix. Devices with static IPs that never request a lease are not counted.

### WAN monitoring

WAN connectivity is checked every 5 minutes by pinging `1.1.1.1` and `8.8.8.8`. When WAN goes down there is no alert (no internet to send it), but the outage start time is recorded locally. When connectivity is restored a notification is sent with the outage duration.

### VPN monitoring

If `/etc/kestrel/split-routing/` is present, each VPN tier (`vpn-*.conf`) is monitored independently every 5 minutes. A high-priority alert fires when a tier goes down; a default-priority alert fires when it recovers. State is persisted in `/etc/kestrel/networks/vpn-state-<iface>` so only transitions trigger alerts. Uses the `NOTIFY_URL` from the first configured extra-networks network.

### WireGuard VPN server peers

The status dashboard automatically detects WireGuard interfaces configured in server mode (those where no peer has an `endpoint_host` set in UCI). For each such interface, a table appears showing only currently connected peers — those with a handshake within the last 3 minutes. Each row includes:

- **Online** — ● if a handshake occurred within the last 3 minutes, ○ otherwise
- **Description** — the peer's description from LuCI (`network.@wireguard_<iface>[N].description`)
- **Endpoint** — the peer's public IP address
- **Last handshake** — time since last handshake (seconds, minutes, hours, or days ago); `—` if never connected
- **Traffic** — bytes received / sent since the last `wg` counter reset

All configured peers are shown regardless of connection state. No configuration is required: the dashboard reads this directly from `wg show` output and UCI.

## Status dashboard

When `NOTIFY_URL` is set, a live web dashboard is installed at:

```
http://192.168.1.1/cgi-bin/status
```

The page auto-refreshes every 60 seconds and shows:

- **System** — uptime, memory, load, WAN IPv4/IPv6
- **WiFi** — one row per radio showing band (2.4 / 5 / 6 GHz), channel, and VAP count; highlighted in amber if any VAPs are missing
- **VPN** — interface and state (up / down / routing fault)
- **WireGuard server peers** — auto-detected for any WireGuard interface in server mode (no outbound peers); shows all configured peers with an online indicator (● / ○), endpoint IP, last handshake, and bytes transferred
- **Networks** — for each network: state, subnet, IPv6 prefix, traffic (↓/↑), device count, DNS, rate limits, isolation settings, join alert state, and which WiFi VAP carries it (interface name, channel, band). Followed by a device table with hostname, IP, MAC, join approval state, recent join decisions, and per-device traffic. An IPv6 column appears automatically when the network has IPv6 configured or clients with IPv6 addresses are present.
- **Pending LAN access** — blocked isolated→LAN connection attempts logged since the last check, with **Approve** buttons linking directly to the approval form
- **Active LAN access** — temporary allowances in both directions (LAN→isolated and isolated→LAN) with destination, port, protocol, and time remaining
- **Port forwards** — active redirects with zone, port, destination, and expiry
- **Recent blocked** — last 10 blocked forwarding attempts from allowlist-restricted networks (`ALLOWLIST=yes`), showing time, source device, destination, and port/proto
- **WiFi QR codes** — SSID, password, and scannable QR code per network (when `SHOW_QR=yes`)

Only reachable from LAN — isolated zones have `INPUT=REJECT`.

To disable the 60-second auto-refresh, add `STATUS_AUTOREFRESH=no` to `/etc/kestrel/networks/config` on the router. The "Refresh" link at the top of the page always works regardless of this setting.

## VLAN trunk

Set `VLAN_ID` and `VLAN_TRUNK` to bridge a tagged wired port into the network alongside the WiFi SSID. Devices on that VLAN from a managed switch land on the same L2 segment as WiFi clients — same subnet, same firewall rules, same DHCP pool.

```sh
VLAN_ID=20       # tag used on the switch trunk port
VLAN_TRUNK=eth0  # physical interface the trunk arrives on (hardware-specific)
```

The trunk interface name depends on your board — check with `ip link show`. Common values: `eth0`, `eth1`, `lan1`. `install.sh` creates an `8021q` VLAN device (`eth0.20`) and adds it to `br-${IFACE}`; netifd brings it up automatically.

Omit both variables (or leave them blank) for WiFi-only — the feature is entirely opt-in.

## WiFi VAP recovery

On some MediaTek Filogic boards (MT7986 / Alder Lake), a race condition in the mac80211 driver causes VAPs to disappear after a `wifi reload` — the radio is up but no interfaces appear. Two complementary services handle this automatically:

- **`wifi-recover` (init.d, START=99)** — runs at boot after everything else has started; checks each radio for live VAPs and replays the hostapd config via ubus if any are missing. Retries up to 5 times with a 3-second delay between attempts.
- **`wifi-recover-hotplug`** — listens for `phy0-ap*` interface-removal events mid-session (triggered by package upgrades or re-running `install.sh`); applies the same recovery after a 3-second settling delay. Uses an atomic lock so only one recovery runs at a time.

Both are installed by `install.sh` and are harmless on hardware not affected by the race — they exit immediately when VAPs are already present.

## Tools

### Status

```sh
sh tools/status.sh
```

CLI summary of all isolated networks: bridge IP and state, WiFi SSID and encryption, connected clients, DHCP leases, rate limits, traffic counters, access schedule state, port forwards, and LAN access status.

When `NOTIFY_URL` is set, a web dashboard is also available at `http://192.168.1.1/cgi-bin/status` — see [Status dashboard](#status-dashboard).

### Uninstall

```sh
sh tools/uninstall.sh configs/guest.conf
sh tools/uninstall.sh configs/untrusted.conf --purge   # also removes allowed-macs file
```

Removes all UCI sections, nftables files, hotplug scripts, cron entries, and the generated web page for the network.

### QR code

```sh
sh tools/qr.sh configs/guest.conf
```

Prints the WiFi credentials as a QR code in the terminal. Requires `qrencode` (`apk add qrencode`).

### Access schedule

Restrict internet access to specific hours. Enforced via nftables — all forwarding is dropped outside the window. Schedule survives reboots via cron.

```sh
# Restrict guest internet to 8am–11pm
sh tools/access-schedule.sh configs/guest.conf 8-23

# Remove schedule (always on)
sh tools/access-schedule.sh configs/guest.conf always

# Show current schedule and state
sh tools/access-schedule.sh configs/guest.conf status

# Force internet off right now, regardless of schedule
sh tools/access-schedule.sh configs/guest.conf block

# Re-enable internet right now, regardless of schedule
sh tools/access-schedule.sh configs/guest.conf unblock
```

`block` and `unblock` are one-off manual overrides — they don't modify the schedule. The next scheduled transition will resume normal operation.

### Temporary LAN access

The tool works in both directions and supports IPv4 and IPv6 addresses.

**Isolated → LAN** (the primary use case): when a guest or IoT device tries to reach a LAN service, a push notification fires with an **Approve** button. The web form shows the requesting device (IP, MAC, hostname) and the target service. Submit to add a temporary firewall rule for that specific device + port combination.

**LAN → isolated**: allow a LAN device to reach a specific isolated device — for example, to SSH into a guest VM.

You can also grant or revoke access directly from the command line:

```sh
# Allow a guest device to reach a LAN service (isolated → LAN)
sh tools/allow-service.sh guest 192.168.1.100 tcp 443 24h lan

# Allow a LAN device to reach a guest device (LAN → isolated)
sh tools/allow-service.sh guest 192.168.3.105 tcp 22 24h

# List all active temporary allowances (both directions)
sh tools/allow-service.sh list

# Remove one manually (rule name shown by list)
sh tools/allow-service.sh remove allow_guest_lan_192_168_1_100_443_tcp
sh tools/allow-service.sh remove allow_lan_guest_192_168_3_105_22_tcp
```

```
Usage: allow-service.sh <network> <dest-ip> <proto> <port> <duration> [dest-zone]

  network     UCI interface name (e.g. guest, untrusted)
  dest-ip     IPv4 or IPv6 destination address
  proto       tcp or udp
  duration    1h, 6h, 12h, 24h, 2d, 7d, 30d — auto-removed via cron, survives reboots
  dest-zone   lan = create an isolated→LAN rule; omit for LAN→isolated (default)
```

Rule names follow the pattern:
- `allow_<network>_lan_<ip>_<port>_<proto>` — isolated→LAN rules
- `allow_lan_<network>_<ip>_<port>_<proto>` — LAN→isolated rules

Rules are stored in UCI (persist across reboots). If the router reboots after the scheduled removal time has passed, remove the rule manually with `sh tools/allow-service.sh list` then `remove`.

### Expose a port

Forward a specific port from an isolated network to a LAN host — useful for gaming sessions or temporary server access.

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

# Or use the custom name
sh tools/unexpose-port.sh minecraft
```

Also cancels any scheduled cron removal.

### Rotate password

Generate a new random password, apply it immediately, and print a QR code. Password rotation is never scheduled automatically; use this only when you intentionally need to replace the current WiFi password.

```sh
sh tools/rotate-password.sh configs/guest.conf
```

Updates the config file in place, applies the new key to the active WiFi network, and disconnects clients still using the old password. When `JOIN_APPROVAL=yes`, labeled approved devices stay approved; unlabeled approvals, pending requests, and denied requests are cleared.

The same action is available from the status dashboard when `ROTATE_PASSWORD=yes` is set. The dashboard button calls `/cgi-bin/rotate-password` (POST only, CSRF-checked), which generates a new password, applies it live via hostapd without reloading WiFi, syncs the config file on disk, and sends a push notification containing the new password. The dashboard page refreshes automatically so the updated QR code is visible immediately.

> The dashboard rotation does **not** regenerate the guest-info HTML page — run `sh tools/guest-info.sh configs/<iface>.conf` manually to update it if you use that page.

The QR code shown in the dashboard is served as an SVG by `/cgi-bin/qr?net=<iface>` (requires `qrencode`). This endpoint returns `403` for networks where `SHOW_QR=no` or for the `untrusted` network.

### Guest info page

Generate a LAN-accessible webpage with the network name, password, and QR code.

```sh
sh tools/guest-info.sh configs/guest.conf
# → http://192.168.1.1/net/guest.html  (LAN only)
```

The page is served by the router's built-in web server (uhttpd). Isolated network zones have `INPUT=REJECT`, so guests and IoT devices cannot access it — only LAN devices can.

Re-run after rotating the password to update the page.

### OUI database (manufacturer lookup)

The device page shows the hardware manufacturer for each device based on its MAC address OUI prefix. The database is downloaded from four sources and merged:

| Source | Coverage |
|---|---|
| Wireshark manuf | Most complete — community-maintained, all prefix lengths |
| IEEE MA-L | 24-bit OUI blocks (standard) |
| IEEE MA-M | 28-bit OUI blocks (large vendors with sub-ranges) |
| IEEE MA-S | 36-bit OUI blocks (product-line level) |

The database is refreshed automatically every Sunday at 03:00. To refresh it manually:

```sh
sh /etc/kestrel/networks/oui-update.sh
```

**Randomized MACs:** Modern phones and laptops randomize their MAC address per network for privacy. These MACs have the locally-administered bit set (second bit of the first byte) and have no OUI entry by design — the device page shows "Randomized MAC" for them instead of a blank.

**Recognizing a randomized-MAC device again after it rotates:** when a randomized-MAC device joins a `JOIN_APPROVAL=yes` network, the join prompt tries to correlate it against devices you've already labeled, using whatever it can gather from already-running services — no new packet capture, no new daemons:

- the DHCP option-request-list order and vendor class (from dnsmasq's `--log-dhcp` output)
- WiFi capability flags (HT/VHT/HE, WMM, MFP) via `hostapd`'s own `ubus` interface
- an mDNS device name/model, queried directly (bypassing `avahi-browse`, which needs D-Bus support this install doesn't have — see the "why not avahi-browse" note in `kestreld-rs/src/data/mdns.rs`)

If it finds a plausible match it's shown as a suggestion with a one-tap "yes, same device" button — **it is never applied automatically**. Set `FINGERPRINT_SUGGEST=no` on a network to turn the suggestion off entirely (approval itself is unaffected either way).

Once a device has been matched at least once, its device page shows a **Known identity** link to `/cgi-bin/identity?net=<iface>&id=<id>` — a detail page for that identity (independent of any single MAC) showing every MAC it has ever answered to, first/last seen times, the raw DHCP/WiFi/mDNS signals last observed for it, its label history (so a rename never loses the trail), and any *other* registered identity that scores as a plausible look-alike, for spotting when the matcher might be confusing two similar devices.

Worth understanding the limits before trusting it:

- **Accuracy depends on how many similar devices you own.** None of these signals uniquely identify a physical unit — they identify a device *class* (make/model/OS version). One iPhone in the house and a persistent mDNS name → a genuinely reliable suggestion. Two identical phones in the house → the system often can't tell them apart, and may even suggest the wrong one with a plausible-looking score. When two candidates score too close to call, the prompt shows both rather than confidently guessing one.
- **mDNS does not cross a VLAN/subnet boundary** (it's link-local multicast, by design — RFC 6762). The query is bound to the joining device's own bridge for exactly this reason. If a device sits behind something that relays DHCP from a different L2 segment (e.g. a smart VLAN switch), the DHCP signal should still work — the vendor forwards the original packet fields untouched — but mDNS won't reach it unless that segment has its own reflector.
- Apple has been progressively reducing what iOS broadcasts over mDNS on untrusted networks, for the same privacy reasons MAC randomization exists — expect this signal to keep getting weaker on newer iOS versions, not stronger.

## Global settings

Some settings apply to the status page and tools as a whole rather than to a single network. Set them in `/etc/kestrel/networks/config` on the router — this file is created by `install.sh` and survives re-runs.

| Setting | Default | Description |
|---|---|---|
| `STATUS_AUTOREFRESH` | `yes` | Set to `no` to disable the 60-second auto-refresh on the status page |
| `GCAL_URL` | — | Google Calendar `.ics` URL — when set, the daily digest includes upcoming events for the next 7 days |
| `GCAL_TZ_OFFSET` | `0` | Hours offset from UTC for event time display in the digest |

Example:

```sh
# /etc/kestrel/networks/config
REPO_DIR=/root/openwrt-kestrel/extra-networks
STATUS_AUTOREFRESH=no
GCAL_URL=https://calendar.google.com/calendar/ical/<your-calendar-id>/basic.ics
GCAL_TZ_OFFSET=1
```

To get your calendar's `.ics` URL: open Google Calendar → Settings → the calendar you want → "Integrate calendar" → copy the **Secret address in iCal format** link. Keep it private — anyone with the URL can read your calendar.

## Adding a new network

1. Copy an example: `cp configs/guest.conf.example configs/mynetwork.conf`
2. Set `IFACE`, `SSID`, `SUBNET`, `WIFI_KEY` — ensure the subnet doesn't overlap with existing networks
3. Run `sh install.sh configs/mynetwork.conf`

## Notes

- **Rate limiting** uses `nft limit rate` (drop) rather than `tc tbf` — `kmod-sched-core` is not packaged on all platforms. Packets exceeding the cap are dropped rather than queued; for IoT and guest traffic this is acceptable.
- **Traffic counters** reset on `fw4 reload` (which happens on every `install.sh` run). For persistent usage stats, consider `vnstat`.
- **Re-running** `install.sh` on an existing network is safe — it updates all settings cleanly.
- **Wireless sections** are created automatically if they don't exist in UCI. `WIFI_UCI` can be set to reuse a pre-existing UCI wireless section with a different name than `IFACE` — useful when migrating an existing setup; omit it for new networks.
- **DEVICE_CONTROL requires JOIN_APPROVAL** — without join approval, device IPs are never recorded and the per-device nft rules can't be generated. Set both in the config and re-run `install.sh`.
- **DHCP pool** is fixed at `.100`–`.249` (150 addresses) with a 12-hour lease time. To change these, edit the UCI directly after install: `uci set dhcp.<iface>.start=100`, `uci set dhcp.<iface>.limit=150`, `uci set dhcp.<iface>.leasetime=12h`, then `uci commit dhcp && /etc/init.d/dnsmasq restart`.
- **Join history** is stored in `/etc/kestrel/networks/<iface>-join-history` as a tab-delimited file and is included in `sysupgrade.conf` — it survives reboots and normal OpenWrt upgrades. `JOIN_HISTORY_RETENTION` controls how long entries are kept (default 90 days).
