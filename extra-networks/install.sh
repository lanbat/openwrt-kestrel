#!/bin/sh
set -eu

[ $# -eq 1 ] || { echo "Usage: sh install.sh <config-file>"; exit 1; }

CONFIG="$1"
[ -f "$CONFIG" ] || { echo "ERROR: config not found: $CONFIG"; exit 1; }
. "$CONFIG"

[ -z "${IFACE:-}"    ] && { echo "ERROR: IFACE not set";    exit 1; }
[ -z "${SSID:-}"     ] && { echo "ERROR: SSID not set";     exit 1; }
[ -z "${WIFI_KEY:-}" ] && { echo "ERROR: WIFI_KEY not set"; exit 1; }
[ ${#WIFI_KEY} -lt 8 ] && { echo "ERROR: WIFI_KEY must be at least 8 characters"; exit 1; }

BASE_DIR=/etc/extra-networks
mkdir -p "$BASE_DIR"
grep -qF "$BASE_DIR" /etc/sysupgrade.conf 2>/dev/null || printf '%s\n' "$BASE_DIR" >> /etc/sysupgrade.conf

# Store repo location so tools can reference each other by absolute path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
printf 'REPO_DIR=%s\n' "$SCRIPT_DIR" > "${BASE_DIR}/config"

RADIO="${RADIO:-radio0}"
RADIO_EXTRA="${RADIO_EXTRA:-}"
ENCRYPTION="${ENCRYPTION:-psk2+psk3}"
ALLOWLIST="${ALLOWLIST:-no}"
RATE_LIMIT="${RATE_LIMIT:-0}"
RATE_LIMIT_PER_DEVICE="${RATE_LIMIT_PER_DEVICE:-0}"
DNS_SERVER="${DNS_SERVER:-1.1.1.3}"
IPV6="${IPV6:-no}"
WIFI_UCI="${WIFI_UCI:-$IFACE}"
LAN_ACCESS="${LAN_ACCESS:-no}"
ISOLATE="${ISOLATE:-yes}"
DOT="${DOT:-no}"
ALLOWED_PORTS="${ALLOWED_PORTS:-}"
NOTIFY_URL="${NOTIFY_URL:-}"
DEFAULT_DURATION="${DEFAULT_DURATION:-24h}"
MAX_DURATION="${MAX_DURATION:-30d}"
REASON_REQUIRED="${REASON_REQUIRED:-no}"
BANDWIDTH_THRESHOLD_MB="${BANDWIDTH_THRESHOLD_MB:-0}"
SHOW_QR="${SHOW_QR:-no}"
NOTIFY_JOIN="${NOTIFY_JOIN:-no}"
JOIN_APPROVAL="${JOIN_APPROVAL:-no}"
JOIN_HISTORY_RETENTION="${JOIN_HISTORY_RETENTION:-90d}"
REJOIN_NOTIFY_AFTER="${REJOIN_NOTIFY_AFTER:-}"
ROTATE_PASSWORD="${ROTATE_PASSWORD:-no}"
DEVICE_CONTROL="${DEVICE_CONTROL:-no}"
DESCRIPTION="${DESCRIPTION:-}"
MDNS="${MDNS:-no}"
VLAN_ID="${VLAN_ID:-}"
VLAN_TRUNK="${VLAN_TRUNK:-}"

if [ "$IFACE" = untrusted ]; then
    SHOW_QR=no
fi

if [ -n "$VLAN_ID" ]; then
    printf '%s' "$VLAN_ID" | grep -qE '^[1-9][0-9]{0,3}$' \
        && [ "$VLAN_ID" -le 4094 ] 2>/dev/null \
        || { echo "ERROR: VLAN_ID must be 1–4094"; exit 1; }
    [ -z "$VLAN_TRUNK" ] && { echo "ERROR: VLAN_TRUNK must be set when VLAN_ID is set"; exit 1; }
fi

# ── network ──────────────────────────────────────────────────────────────────

# DSA requires an explicit bridge device — netifd won't auto-create one for WiFi-only networks.
uci -q delete network."br_${IFACE}" || true
uci set network."br_${IFACE}"=device
uci set network."br_${IFACE}".name="br-${IFACE}"
uci set network."br_${IFACE}".type=bridge

# VLAN trunk — bridge a tagged wired port (e.g. eth0.20) into this network alongside WiFi.
uci -q delete network."${IFACE}_vdev" || true
if [ -n "$VLAN_ID" ] && [ -n "$VLAN_TRUNK" ]; then
    uci set network."${IFACE}_vdev"=device
    uci set network."${IFACE}_vdev".name="${VLAN_TRUNK}.${VLAN_ID}"
    uci set network."${IFACE}_vdev".type=8021q
    uci set network."${IFACE}_vdev".ifname="${VLAN_TRUNK}"
    uci set network."${IFACE}_vdev".vid="${VLAN_ID}"
    uci add_list network."br_${IFACE}".ports="${VLAN_TRUNK}.${VLAN_ID}"
fi

uci -q delete network."$IFACE" || true
uci set network."$IFACE"=interface
uci set network."$IFACE".proto=static
uci set network."$IFACE".device="br-${IFACE}"
uci set network."$IFACE".ipaddr="${SUBNET}.1"
uci set network."$IFACE".netmask=255.255.255.0

if [ "$IPV6" = yes ]; then
    uci set network."$IFACE".ip6assign=64
else
    uci -q delete network."$IFACE".ip6assign || true
fi

uci commit network

# ── dhcp ─────────────────────────────────────────────────────────────────────

uci -q delete dhcp."$IFACE" || true
uci set dhcp."$IFACE"=dhcp
uci set dhcp."$IFACE".interface="$IFACE"
uci set dhcp."$IFACE".start=100
uci set dhcp."$IFACE".limit=150
uci set dhcp."$IFACE".leasetime=12h
# DOT: give clients the router's bridge IP so queries go through dnsmasq → https-dns-proxy.
# Otherwise hand the external DNS server directly so queries bypass the router.
if [ "$DOT" = yes ]; then
    _client_dns="${SUBNET}.1"
else
    _client_dns="$DNS_SERVER"
fi
uci add_list dhcp."$IFACE".dhcp_option="6,$_client_dns"

if [ "$IPV6" = yes ]; then
    uci set dhcp."$IFACE".dhcpv6=server
    uci set dhcp."$IFACE".ra=server
    # Derive IPv6 DNS from DNS_SERVER if not explicitly set.
    if [ -z "${DNS_SERVER_V6:-}" ]; then
        case "$DNS_SERVER" in
            1.1.1.3) DNS_SERVER_V6=2606:4700:4700::1113 ;;
            1.0.0.3) DNS_SERVER_V6=2606:4700:4700::1003 ;;
            1.1.1.1) DNS_SERVER_V6=2606:4700:4700::1111 ;;
            1.0.0.1) DNS_SERVER_V6=2606:4700:4700::1001 ;;
            8.8.8.8) DNS_SERVER_V6=2001:4860:4860::8888 ;;
            *)       DNS_SERVER_V6= ;;
        esac
    fi
fi

# Register this interface with dnsmasq's listener list (idempotent).
# Without this, dnsmasq's bind-dynamic mode silently skips DHCP on the bridge.
_dm_ifaces=$(uci -q get dhcp.@dnsmasq[0].interface 2>/dev/null || true)
case " $_dm_ifaces " in
    *" $IFACE "*) ;;
    *) uci add_list dhcp.@dnsmasq[0].interface="$IFACE" ;;
esac

uci commit dhcp

# ── firewall ──────────────────────────────────────────────────────────────────

uci -q delete firewall."${IFACE}_zone" || true
uci set firewall."${IFACE}_zone"=zone
uci set firewall."${IFACE}_zone".name="$IFACE"
uci set firewall."${IFACE}_zone".network="$IFACE"
uci set firewall."${IFACE}_zone".input=REJECT
uci set firewall."${IFACE}_zone".output=ACCEPT
uci set firewall."${IFACE}_zone".forward=REJECT

# Allow DHCP (and DHCPv6 if IPv6 enabled).
uci -q delete firewall."${IFACE}_dhcp" || true
uci set firewall."${IFACE}_dhcp"=rule
uci set firewall."${IFACE}_dhcp".name="Allow-DHCP-${IFACE}"
uci set firewall."${IFACE}_dhcp".src="$IFACE"
uci set firewall."${IFACE}_dhcp".proto=udp
uci set firewall."${IFACE}_dhcp".dest_port=67
uci set firewall."${IFACE}_dhcp".target=ACCEPT

if [ "$IPV6" = yes ]; then
    uci -q delete firewall."${IFACE}_dhcp6" || true
    uci set firewall."${IFACE}_dhcp6"=rule
    uci set firewall."${IFACE}_dhcp6".name="Allow-DHCPv6-${IFACE}"
    uci set firewall."${IFACE}_dhcp6".src="$IFACE"
    uci set firewall."${IFACE}_dhcp6".proto=udp
    uci set firewall."${IFACE}_dhcp6".src_ip=fe80::/10
    uci set firewall."${IFACE}_dhcp6".dest_ip=fe80::/10
    uci set firewall."${IFACE}_dhcp6".dest_port=547
    uci set firewall."${IFACE}_dhcp6".target=ACCEPT
fi

# Forward to WAN (internet access).
uci -q delete firewall."${IFACE}_wan" || true
uci set firewall."${IFACE}_wan"=forwarding
uci set firewall."${IFACE}_wan".src="$IFACE"
uci set firewall."${IFACE}_wan".dest=wan

# DNS bypass prevention — block all external port 53 forwarding.
# When DOT=yes, clients query the router and all external DNS is blocked outright.
# When DOT=no, only block DNS to servers other than the designated one.
uci -q delete firewall."${IFACE}_dns_block" || true
uci set firewall."${IFACE}_dns_block"=rule
uci set firewall."${IFACE}_dns_block".name="Block-DNS-bypass-${IFACE}"
uci set firewall."${IFACE}_dns_block".src="$IFACE"
uci set firewall."${IFACE}_dns_block".dest=wan
uci set firewall."${IFACE}_dns_block".proto="tcp udp"
uci set firewall."${IFACE}_dns_block".dest_port=53
uci set firewall."${IFACE}_dns_block".target=REJECT
if [ "$DOT" != yes ]; then
    uci set firewall."${IFACE}_dns_block".dest_ip="!$DNS_SERVER"
fi

if [ "$IPV6" = yes ] && [ -n "${DNS_SERVER_V6:-}" ]; then
    uci -q delete firewall."${IFACE}_dns_block6" || true
    uci set firewall."${IFACE}_dns_block6"=rule
    uci set firewall."${IFACE}_dns_block6".name="Block-DNS6-bypass-${IFACE}"
    uci set firewall."${IFACE}_dns_block6".src="$IFACE"
    uci set firewall."${IFACE}_dns_block6".dest=wan
    uci set firewall."${IFACE}_dns_block6".proto="tcp udp"
    uci set firewall."${IFACE}_dns_block6".dest_port=53
    uci set firewall."${IFACE}_dns_block6".target=REJECT
    [ "$DOT" != yes ] && uci set firewall."${IFACE}_dns_block6".dest_ip="!$DNS_SERVER_V6"
fi

# DOT — allow DNS queries to the router's own IP; block DoT/DoH bypass.
uci -q delete firewall."${IFACE}_dns_input" || true
uci -q delete firewall."${IFACE}_dot_block" || true
if [ "$DOT" = yes ]; then
    uci set firewall."${IFACE}_dns_input"=rule
    uci set firewall."${IFACE}_dns_input".name="Allow-DNS-Input-${IFACE}"
    uci set firewall."${IFACE}_dns_input".src="$IFACE"
    uci set firewall."${IFACE}_dns_input".proto="tcp udp"
    uci set firewall."${IFACE}_dns_input".dest_port=53
    uci set firewall."${IFACE}_dns_input".target=ACCEPT

    uci set firewall."${IFACE}_dot_block"=rule
    uci set firewall."${IFACE}_dot_block".name="Block-DoT-bypass-${IFACE}"
    uci set firewall."${IFACE}_dot_block".src="$IFACE"
    uci set firewall."${IFACE}_dot_block".dest=wan
    uci set firewall."${IFACE}_dot_block".proto="tcp udp"
    uci set firewall."${IFACE}_dot_block".dest_port=853
    uci set firewall."${IFACE}_dot_block".target=REJECT
fi

# LAN → isolated network (optional, never the reverse).
uci -q delete firewall."lan_${IFACE}" || true
if [ "${LAN_ACCESS:-no}" = yes ]; then
    uci set firewall."lan_${IFACE}"=forwarding
    uci set firewall."lan_${IFACE}".src=lan
    uci set firewall."lan_${IFACE}".dest="$IFACE"
fi

uci commit firewall

# ── wireless ──────────────────────────────────────────────────────────────────

_setup_wifi() {
    _uci="$1"; _radio="$2"
    if ! uci -q get wireless."$_uci" >/dev/null 2>&1; then
        uci set wireless."$_uci"=wifi-iface
        uci set wireless."$_uci".device="$_radio"
        uci set wireless."$_uci".mode=ap
    fi
    uci set wireless."$_uci".ssid="$SSID"
    uci set wireless."$_uci".key="$WIFI_KEY"
    uci set wireless."$_uci".encryption="$ENCRYPTION"
    uci set wireless."$_uci".network="$IFACE"
    uci set wireless."$_uci".disabled=0
    uci set wireless."$_uci".isolate=$([ "$ISOLATE" = yes ] && echo 1 || echo 0)
}

_setup_wifi "$WIFI_UCI" "$RADIO"

if [ -n "$RADIO_EXTRA" ]; then
    _setup_wifi "${WIFI_UCI}_extra" "$RADIO_EXTRA"
else
    # Clean up extra radio section if RADIO_EXTRA was removed from config.
    uci -q delete wireless."${WIFI_UCI}_extra" || true
fi

uci commit wireless

# ── rate limiting via nftables ────────────────────────────────────────────────
# tc tbf requires kmod-sched-core which is not packaged for this platform.
# nft limit rate drops excess packets — acceptable for IoT/guest traffic.

mkdir -p /etc/nftables.d

_parse_rate() {
    case "$1" in
        *[Mm]bit) echo $(( $(echo "$1" | sed 's/[Mm]bit$//') * 125 )) ;;
        *[Kk]bit) echo $(( $(echo "$1" | sed 's/[Kk]bit$//') / 8 )) ;;
        *) echo "ERROR: rate must be mbit or kbit (e.g. 1mbit, 500kbit)" >&2; exit 1 ;;
    esac
}

_agg=0
_per=0
[ "${RATE_LIMIT:-0}"            != "0" ] && _agg=$(_parse_rate "$RATE_LIMIT")
[ "${RATE_LIMIT_PER_DEVICE:-0}" != "0" ] && _per=$(_parse_rate "$RATE_LIMIT_PER_DEVICE")

if [ "$_agg" -gt 0 ] || [ "$_per" -gt 0 ]; then
    # Files in /etc/nftables.d/ are included inside table inet fw4 by fw4.
    {
        echo "chain ${IFACE}_ratelimit {"
        echo "    type filter hook forward priority 1; policy accept;"
        if [ "$_per" -gt 0 ]; then
            echo "    iifname \"br-${IFACE}\" meter ${IFACE}_per_src { ip saddr limit rate over ${_per} kbytes/second } drop"
            echo "    oifname \"br-${IFACE}\" meter ${IFACE}_per_dst { ip daddr limit rate over ${_per} kbytes/second } drop"
        fi
        if [ "$_agg" -gt 0 ]; then
            echo "    iifname \"br-${IFACE}\" limit rate over ${_agg} kbytes/second drop"
            echo "    oifname \"br-${IFACE}\" limit rate over ${_agg} kbytes/second drop"
        fi
        echo "}"
    } >/etc/nftables.d/20-${IFACE}-ratelimit.nft
else
    rm -f /etc/nftables.d/20-${IFACE}-ratelimit.nft
fi

# ── device allowlist (MAC → IP) ───────────────────────────────────────────────
# Bridge-family nftables is unavailable on this platform (kmod not compiled in).
# Two-layer approach:
#   1. dnsmasq ignores DHCP requests from unlisted MACs
#   2. nft drops forwarding from any IP not assigned to a listed MAC

if [ "${ALLOWLIST:-no}" = yes ]; then
    MAC_FILE=${BASE_DIR}/${IFACE}-allowed-macs
    if [ ! -f "$MAC_FILE" ]; then
        cat >"$MAC_FILE" <<MACEOF
# Devices allowed on the ${IFACE} network.
# Format: mac  ip  description
# The IP becomes a static DHCP lease — pick one within the DHCP range (.100–.249).
# Devices not listed get no lease and are blocked from forwarding.
# Example:
# aa:bb:cc:dd:ee:ff  ${SUBNET}.100  My Device
MACEOF
    fi

    cat >/etc/nftables.d/21-${IFACE}-allowlist.nft <<EOF
set ${IFACE}_allowed_ips {
    type ipv4_addr
}

chain ${IFACE}_allowlist {
    type filter hook forward priority -1; policy accept;
    iifname "br-${IFACE}" ip saddr != @${IFACE}_allowed_ips ct state new limit rate 3/minute log prefix "EXTNET-DENY-${IFACE}: " level info
    iifname "br-${IFACE}" ip saddr != @${IFACE}_allowed_ips drop
}
EOF

    cat >/etc/hotplug.d/iface/51-${IFACE}-macfilter <<EOF
#!/bin/sh
[ "\$ACTION" = ifup ] || exit 0
[ "\$INTERFACE" = ${IFACE} ] || exit 0

MAC_FILE=${BASE_DIR}/${IFACE}-allowed-macs
DNSMASQ_CONF=/etc/dnsmasq.d/${IFACE}-macfilter.conf

nft flush set inet fw4 ${IFACE}_allowed_ips 2>/dev/null || true
: >"\$DNSMASQ_CONF"

_any=0
while read -r mac ip rest; do
    case "\$mac" in '#'*|'') continue ;; esac
    printf 'dhcp-host=%s,set:${IFACE}_ok,%s\n' "\$mac" "\$ip" >>"\$DNSMASQ_CONF"
    nft add element inet fw4 ${IFACE}_allowed_ips "{ \$ip }" 2>/dev/null
    _any=1
done <"\$MAC_FILE"

[ "\$_any" = 1 ] && printf 'dhcp-ignore=tag:${IFACE},tag:!${IFACE}_ok\n' >>"\$DNSMASQ_CONF"

/etc/init.d/dnsmasq reload
EOF
    chmod 0755 /etc/hotplug.d/iface/51-${IFACE}-macfilter

else
    rm -f /etc/nftables.d/21-${IFACE}-allowlist.nft
    rm -f /etc/hotplug.d/iface/51-${IFACE}-macfilter
    rm -f /etc/dnsmasq.d/${IFACE}-macfilter.conf
fi

# ── port restriction ──────────────────────────────────────────────────────────

rm -f /etc/nftables.d/22-${IFACE}-ports.nft
if [ -n "$ALLOWED_PORTS" ]; then
    _ports_nft=$(echo "$ALLOWED_PORTS" | tr ' ' '\n' | awk 'NR==1{p=$0} NR>1{p=p", "$0} END{print p}')
    cat >/etc/nftables.d/22-${IFACE}-ports.nft <<EOF
chain ${IFACE}_port_filter {
    type filter hook forward priority -2; policy accept;
    iifname "br-${IFACE}" udp dport 123 accept
    iifname "br-${IFACE}" tcp dport { ${_ports_nft} } accept
    iifname "br-${IFACE}" udp dport { ${_ports_nft} } accept
    iifname "br-${IFACE}" drop
}
EOF
fi

# ── LAN access monitor ────────────────────────────────────────────────────────
# When NOTIFY_URL is set and LAN_ACCESS is not fully open, log new connection
# attempts FROM the isolated network TO the LAN so the dashboard can surface
# them and allow-service.sh can grant per-service access.

rm -f /etc/nftables.d/25-${IFACE}-lanmonitor.nft
if [ -n "$NOTIFY_URL" ] && [ "${LAN_ACCESS:-no}" != yes ]; then
    cat >/etc/nftables.d/25-${IFACE}-lanmonitor.nft <<EOF
chain ${IFACE}_lan_monitor {
    type filter hook forward priority -2; policy accept;
    iifname "br-${IFACE}" oifname "br-lan" ct state new log prefix "EXTNET-2LAN-${IFACE}: " level info
}
EOF
fi

# ── join approval gate ────────────────────────────────────────────────────────
# When JOIN_APPROVAL=yes, new devices are blocked from forwarding until approved
# via the approve-join CGI. Approved MACs are stored in ${IFACE}-join-approved;
# pending (blocked) IPs are stored in ${IFACE}-join-pending for rehydration on
# fw4 reload.

if [ "${JOIN_APPROVAL:-no}" = yes ]; then
    cat >/etc/nftables.d/23-${IFACE}-joingate.nft <<EOF
set ${IFACE}_join_pending {
    type ipv4_addr
}

set ${IFACE}_join_pending6 {
    type ipv6_addr
}

set ${IFACE}_join_approved_ips {
    type ipv4_addr
}

set ${IFACE}_join_approved_ips6 {
    type ipv6_addr
}

chain ${IFACE}_join_gate {
    type filter hook forward priority -3; policy accept;
    iifname "br-${IFACE}" ip saddr @${IFACE}_join_approved_ips accept
    iifname "br-${IFACE}" ip6 saddr @${IFACE}_join_approved_ips6 accept
    iifname "br-${IFACE}" drop
}
EOF

    cat >/etc/hotplug.d/iface/52-${IFACE}-joingate <<EOF
#!/bin/sh
[ "\$ACTION" = ifup ] || exit 0
[ "\$INTERFACE" = ${IFACE} ] || exit 0

BASE_DIR=/etc/extra-networks
PENDING_FILE="\${BASE_DIR}/${IFACE}-join-pending"
APPROVED_FILE="\${BASE_DIR}/${IFACE}-join-approved"
APPROVED_IPS_FILE="\${BASE_DIR}/${IFACE}-join-approved-ips"

nft flush set inet fw4 ${IFACE}_join_approved_ips 2>/dev/null || true
nft flush set inet fw4 ${IFACE}_join_approved_ips6 2>/dev/null || true
nft flush set inet fw4 ${IFACE}_join_pending 2>/dev/null || true
nft flush set inet fw4 ${IFACE}_join_pending6 2>/dev/null || true

# Restore approved IPs so already-approved devices are not blocked after reboot/fw4 reload
if [ -f "\$APPROVED_IPS_FILE" ]; then
    while IFS=' ' read -r _mac _ip; do
        case "\$_mac" in '#'*|'') continue ;; esac
        grep -qF "\$_mac" "\$APPROVED_FILE" 2>/dev/null || continue
        case "\$_ip" in
            *:*) nft add element inet fw4 ${IFACE}_join_approved_ips6 "{ \$_ip }" 2>/dev/null || true ;;
            *)   nft add element inet fw4 ${IFACE}_join_approved_ips  "{ \$_ip }" 2>/dev/null || true ;;
        esac
    done < "\$APPROVED_IPS_FILE"
fi

# Restore pending IPs for display on the status dashboard
[ -f "\$PENDING_FILE" ] || exit 0
while IFS= read -r _line; do
    case "\$_line" in '#'*|'') continue ;; esac
    _mac="\${_line%% *}"
    _ip="\${_line##* }"
    if grep -qF "\$_mac" "\$APPROVED_FILE" 2>/dev/null; then
        grep -v "^\${_mac} " "\$PENDING_FILE" >"\${PENDING_FILE}.tmp" 2>/dev/null \
            && mv "\${PENDING_FILE}.tmp" "\$PENDING_FILE" || true
        continue
    fi
    case "\$_ip" in
        *:*) nft add element inet fw4 ${IFACE}_join_pending6 "{ \$_ip }" 2>/dev/null || true ;;
        *)   nft add element inet fw4 ${IFACE}_join_pending "{ \$_ip }" 2>/dev/null || true ;;
    esac
done <"\$PENDING_FILE"
EOF
    chmod 0755 /etc/hotplug.d/iface/52-${IFACE}-joingate
else
    rm -f /etc/nftables.d/23-${IFACE}-joingate.nft
    rm -f /etc/hotplug.d/iface/52-${IFACE}-joingate
fi

# ── device control inspect chain ─────────────────────────────────────────────
# When DEVICE_CONTROL=yes, new outbound connections from approved devices are
# inspected per-device. regen-inspect.sh generates the nftables chain; it is
# also called from approve-join.cgi when a device is approved.

if [ "${DEVICE_CONTROL:-no}" = yes ]; then
    cp "${SCRIPT_DIR}/tools/regen-inspect.sh" "${BASE_DIR}/_regen-inspect.sh"
    cp "${SCRIPT_DIR}/tools/device.cgi"       /www/cgi-bin/device
    chmod 0755 "${BASE_DIR}/_regen-inspect.sh" /www/cgi-bin/device
    if ! uci -q get uhttpd.main.cgi_prefix >/dev/null 2>&1; then
        uci set uhttpd.main.cgi_prefix=/cgi-bin
        uci commit uhttpd
        /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
    fi
    sh "${BASE_DIR}/_regen-inspect.sh" "$IFACE" || true
else
    rm -f /etc/nftables.d/25-${IFACE}-inspect.nft
fi

# ── traffic counters ──────────────────────────────────────────────────────────
# Always create — status.sh reads these to show bytes transferred since last fw4 reload.

cat >/etc/nftables.d/24-${IFACE}-counter.nft <<EOF
chain ${IFACE}_counter {
    type filter hook forward priority 0; policy accept;
    iifname "br-${IFACE}" counter
    oifname "br-${IFACE}" counter
}
EOF

# Main LAN counter — created once; used by digest.sh when lan-notify.conf exists.
cat >/etc/nftables.d/24-lan-counter.nft <<'EOF'
chain lan_counter {
    type filter hook forward priority 0; policy accept;
    iifname "br-lan" counter
    oifname "br-lan" counter
}
EOF

# Per-device byte tracking (used by bandwidth-check.sh and the status dashboard).
# Created when NOTIFY_URL is set; removed when it is unset.
rm -f /etc/nftables.d/26-${IFACE}-device-track.nft
if [ -n "$NOTIFY_URL" ]; then
    cat >/etc/nftables.d/26-${IFACE}-device-track.nft <<EOF
set ${IFACE}_device_bytes {
    type ipv4_addr
    flags dynamic, timeout
    timeout 24h
    counter
}

set ${IFACE}_device_bytes6 {
    type ipv6_addr
    flags dynamic, timeout
    timeout 24h
    counter
}

chain ${IFACE}_device_track {
    type filter hook forward priority 1; policy accept;
    iifname "br-${IFACE}" update @${IFACE}_device_bytes  { ip  saddr }
    iifname "br-${IFACE}" update @${IFACE}_device_bytes6 { ip6 saddr }
}
EOF
fi

# ── device notifications ───────────────────────────────────────────────────────
# The notify.conf is always written — the status dashboard reads it even when
# NOTIFY_URL is unset. NOTIFY_URL-dependent features (dhcp hook, CGIs, crons)
# are only set up when NOTIFY_URL is provided.

{ printf 'SUBNET=%s\nNOTIFY_URL=%s\nIFACE_NAME=%s\nDEFAULT_DURATION=%s\nMAX_DURATION=%s\nREASON_REQUIRED=%s\nBANDWIDTH_THRESHOLD_MB=%s\nRATE_LIMIT=%s\nRATE_LIMIT_PER_DEVICE=%s\nDNS_SERVER=%s\nDNS_SERVER_V6=%s\nISOLATE=%s\nLAN_ACCESS=%s\nDOT=%s\nSHOW_QR=%s\nNOTIFY_JOIN=%s\nJOIN_APPROVAL=%s\nJOIN_HISTORY_RETENTION=%s\nREJOIN_NOTIFY_AFTER=%s\nROTATE_PASSWORD=%s\nDEVICE_CONTROL=%s\n' \
    "$SUBNET" "$NOTIFY_URL" "$IFACE" \
    "$DEFAULT_DURATION" "$MAX_DURATION" "$REASON_REQUIRED" "$BANDWIDTH_THRESHOLD_MB" \
    "${RATE_LIMIT:-}" "${RATE_LIMIT_PER_DEVICE:-}" "$DNS_SERVER" "${DNS_SERVER_V6:-}" \
    "$ISOLATE" "${LAN_ACCESS:-no}" "$DOT" "$SHOW_QR" "$NOTIFY_JOIN" "$JOIN_APPROVAL" \
    "$JOIN_HISTORY_RETENTION" "${REJOIN_NOTIFY_AFTER:-}" "$ROTATE_PASSWORD" "$DEVICE_CONTROL"
  # DESCRIPTION may contain spaces so it must be single-quoted in the conf file.
  printf "DESCRIPTION='%s'\n" "${DESCRIPTION:-}"; } \
    >"${BASE_DIR}/${IFACE}-notify.conf"

# Idempotently set a cron entry identified by tag (remove old, add new).
_cron_set() { ( crontab -l 2>/dev/null | grep -vF "# $1"; echo "$2  # $1" ) | crontab -; }

cp "${SCRIPT_DIR}/tools/_lib.sh" "${BASE_DIR}/_lib.sh"

# Password rotation should only happen from an explicit user action.
( crontab -l 2>/dev/null | grep -v 'rotate-password' ) | crontab - 2>/dev/null || true

if [ -n "$NOTIFY_URL" ]; then
    mkdir -p /etc/hotplug.d/dhcp
    cat >/etc/hotplug.d/dhcp/50-extra-networks <<'NOTIFYEOF'
#!/bin/sh
[ "$ACTION" = add ] || [ "$ACTION" = del ] || exit 0

BASE_DIR=/etc/extra-networks

if [ "$ACTION" = add ]; then
    # Record join time (mac → timestamp) for the status dashboard
    _jfile=/tmp/extra-networks-joins
    { grep -v "^${MACADDR}	" "$_jfile" 2>/dev/null
      printf '%s\t%s\n' "$MACADDR" "$(date '+%d %b %H:%M')"; } > "${_jfile}.tmp" \
        && mv "${_jfile}.tmp" "$_jfile" || true
fi

_router_ip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')

. /etc/extra-networks/_lib.sh
for _conf in /etc/extra-networks/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset SUBNET NOTIFY_URL IFACE_NAME NOTIFY_JOIN JOIN_APPROVAL JOIN_HISTORY_RETENTION REJOIN_NOTIFY_AFTER
    . "$_conf"
    case "$IPADDR" in "$SUBNET".*) ;; *) continue ;; esac

    if [ "$ACTION" = del ]; then
        _join_history_add "$IFACE_NAME" disconnected "$MACADDR" "$IPADDR" "" \
            "${HOSTNAME:-unknown}" "system" "" "" "" "${JOIN_HISTORY_RETENTION:-90d}"
        continue
    fi

    # ACTION=add — capture last-seen time before the current event enters history
    _hist_f="${BASE_DIR}/${IFACE_NAME}-join-history"
    _last_seen=0
    [ -f "$_hist_f" ] && _last_seen=$(awk -F'\t' -v m="$MACADDR" \
        'tolower($4)==tolower(m)&&$1+0>t{t=$1+0}END{print t+0}' "$_hist_f")

    _join_history_add "$IFACE_NAME" connected "$MACADDR" "$IPADDR" "" \
        "${HOSTNAME:-unknown}" "system" "" "" "" "${JOIN_HISTORY_RETENTION:-90d}"

    # Absence notification — fires when device returns after configurable gap
    if [ -n "${REJOIN_NOTIFY_AFTER:-}" ] && [ "${_last_seen:-0}" -gt 0 ] \
            && [ -n "${NOTIFY_URL:-}" ]; then
        _thresh=$(_duration_secs "$REJOIN_NOTIFY_AFTER")
        _absent=$(( $(date +%s) - _last_seen ))
        if [ "$_absent" -gt "$_thresh" ]; then
            _rlabel=$(_label_for_mac "$MACADDR" "$IFACE_NAME")
            if [ "$_absent" -ge 86400 ]; then
                _d=$(( _absent / 86400 ))
                _absent_str="${_d} day$([ "$_d" = 1 ] || printf 's')"
            elif [ "$_absent" -ge 3600 ]; then
                _h=$(( _absent / 3600 ))
                _absent_str="${_h} hour$([ "$_h" = 1 ] || printf 's')"
            else
                _min=$(( _absent / 60 ))
                _absent_str="${_min} minute$([ "$_min" = 1 ] || printf 's')"
            fi
            _ntfy "Back online — ${IFACE_NAME}" default mobile_phone_back \
"${_rlabel} (${IPADDR}) returned after ${_absent_str} away."
        fi
    fi

    if [ "${JOIN_APPROVAL:-no}" = yes ] && [ -n "${NOTIFY_URL:-}" ]; then
        _approved="${BASE_DIR}/${IFACE_NAME}-join-approved"
        _pending="${BASE_DIR}/${IFACE_NAME}-join-pending"
        if grep -qF "$MACADDR" "$_approved" 2>/dev/null; then
            _approved_ips="${BASE_DIR}/${IFACE_NAME}-join-approved-ips"
            { grep -v "^${MACADDR} " "$_approved_ips" 2>/dev/null
              printf '%s %s\n' "$MACADDR" "$IPADDR"; } >"${_approved_ips}.tmp" \
                && mv "${_approved_ips}.tmp" "$_approved_ips" || true
            nft add element inet fw4 ${IFACE_NAME}_join_approved_ips "{ $IPADDR }" 2>/dev/null || true
            [ "${NOTIFY_JOIN:-no}" = yes ] && \
                _ntfy "Device joined — $IFACE_NAME" low "" \
"${HOSTNAME:-unknown} ($MACADDR) joined $IFACE_NAME at $IPADDR."
        else
            nft add element inet fw4 ${IFACE_NAME}_join_pending "{ $IPADDR }" 2>/dev/null || true
            { grep -v "^${MACADDR} " "$_pending" 2>/dev/null
              printf '%s %s\n' "$MACADDR" "$IPADDR"; } >"${_pending}.tmp" \
                && mv "${_pending}.tmp" "$_pending" || true
            _approve_url="http://${_router_ip}/cgi-bin/approve-join?net=${IFACE_NAME}&ip=${IPADDR}&mac=${MACADDR}&host=${HOSTNAME:-}"
            _ntfy "Join request — ${IFACE_NAME}" default wifi \
"${HOSTNAME:-unknown} ($MACADDR) joined ${IFACE_NAME} at $IPADDR and needs internet approval." \
                "view, Approve, ${_approve_url}"
        fi
    else
        [ "${NOTIFY_JOIN:-no}" = yes ] || continue
        [ -n "${NOTIFY_URL:-}" ] || continue
        _ntfy "Device joined — $IFACE_NAME" low "" \
"${HOSTNAME:-unknown} ($MACADDR) joined $IFACE_NAME at $IPADDR."
    fi
done
NOTIFYEOF
    chmod 0755 /etc/hotplug.d/dhcp/50-extra-networks
    rm -f "${BASE_DIR}/dhcp-notify"
    uci -q del dhcp.@dnsmasq[0].dhcpscript || true
    uci commit dhcp

    # Install CGIs and enable uhttpd CGI support
    mkdir -p /www/cgi-bin
    cp "${SCRIPT_DIR}/tools/approve-access.cgi"    /www/cgi-bin/approve-access
    cp "${SCRIPT_DIR}/tools/approve-join.cgi"      /www/cgi-bin/approve-join
    cp "${SCRIPT_DIR}/tools/device.cgi"            /www/cgi-bin/device
    cp "${SCRIPT_DIR}/tools/status.cgi"            /www/cgi-bin/status
    cp "${SCRIPT_DIR}/tools/rotate-password.cgi"   /www/cgi-bin/rotate-password
    cp "${SCRIPT_DIR}/tools/qr.cgi"                /www/cgi-bin/qr
    chmod 0755 /www/cgi-bin/approve-access /www/cgi-bin/approve-join \
               /www/cgi-bin/device /www/cgi-bin/status \
               /www/cgi-bin/rotate-password /www/cgi-bin/qr
    if ! uci -q get uhttpd.main.cgi_prefix >/dev/null 2>&1; then
        uci set uhttpd.main.cgi_prefix=/cgi-bin
        uci commit uhttpd
        /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
    fi

    _cron_set extra-networks-monitor  "* * * * * sh ${SCRIPT_DIR}/tools/check-access-log.sh"
    _cron_set extra-networks-reboot   "@reboot sleep 30 && sh ${SCRIPT_DIR}/tools/notify-reboot.sh"
    _cron_set extra-networks-digest   "0 8 * * * sh ${SCRIPT_DIR}/tools/digest.sh"
    _cron_set extra-networks-bwcheck  "0 * * * * sh ${SCRIPT_DIR}/tools/bandwidth-check.sh"
    _cron_set extra-networks-vpncheck "*/5 * * * * sh ${SCRIPT_DIR}/tools/check-vpn.sh"
    _cron_set extra-networks-wancheck "*/5 * * * * sh ${SCRIPT_DIR}/tools/check-wan.sh"
else
    # Remove crons only if no remaining network has NOTIFY_URL configured
    if ! grep -qE 'NOTIFY_URL=.+' "${BASE_DIR}/"*-notify.conf 2>/dev/null; then
        ( crontab -l 2>/dev/null | grep -v '# extra-networks-' ) | crontab -
    fi
fi

# ── mDNS reflection ───────────────────────────────────────────────────────────
# Reflects mDNS (Bonjour/Avahi) between this network and LAN so guests can
# discover shared services like Chromecast, AirPrint, or game lobbies.
# Note: avahi reflects ALL mDNS services — no selective filtering.

if [ "$MDNS" = yes ]; then
    if ! command -v avahi-daemon >/dev/null 2>&1; then
        apk add avahi-dbus-daemon >/dev/null
    fi
    mkdir -p /etc/avahi
    # Gather all interfaces that already have mDNS enabled, plus this one.
    _ifaces=br-lan
    if [ -f /etc/avahi/avahi-daemon.conf ]; then
        for _if in $(awk -F= '/^allow-interfaces/ { print $2 }' \
                    /etc/avahi/avahi-daemon.conf | tr ',' ' '); do
            case " $_ifaces " in *" $_if "*) ;; *) _ifaces="${_ifaces},${_if}" ;; esac
        done
    fi
    case " $(echo $_ifaces | tr ',' ' ') " in
        *" br-${IFACE} "*) ;;
        *) _ifaces="${_ifaces},br-${IFACE}" ;;
    esac
    cat >/etc/avahi/avahi-daemon.conf <<AVAHIEOF
[server]
allow-interfaces=${_ifaces}

[reflector]
enable-reflector=yes
reflect-ipv=no
AVAHIEOF
    /etc/init.d/avahi-daemon enable 2>/dev/null || true
    /etc/init.d/avahi-daemon restart 2>/dev/null || true
fi

# ── apply ─────────────────────────────────────────────────────────────────────

/etc/init.d/network reload
/etc/init.d/dnsmasq restart
fw4 reload

# wifi reload triggers a MAC80211 race condition on phy0 that destroys all BSS
# interfaces and leaves them uncreated. Instead, update the UCI config and then
# restart hostapd per-phy via config_set — same approach as rotate-password.cgi.
wifi reload 2>/dev/null || true
sleep 5
for _hconf in /var/run/hostapd-*.conf; do
    [ -f "$_hconf" ] || continue
    _phy="${_hconf##*/hostapd-}"; _phy="${_phy%.conf}"
    ubus call hostapd config_set \
        "{\"phy\":\"${_phy}\",\"radio\":-1,\"config\":\"${_hconf}\",\"prev_config\":\"${_hconf}.prev\"}" \
        >/dev/null 2>&1 || true
done

# ── summary ───────────────────────────────────────────────────────────────────

echo "Installed: $IFACE"
echo "  Network:   ${SUBNET}.1/24, DHCP ${SUBNET}.100–${SUBNET}.249"
if [ "$IPV6" = yes ]; then
    echo "  IPv6:      enabled (ip6assign /64, DHCPv6 + RA)"
fi
if [ "$DOT" = yes ]; then
    echo "  DNS:       DoT via https-dns-proxy → ${DNS_SERVER}$([ "$IPV6" = yes ] && [ -n "${DNS_SERVER_V6:-}" ] && echo " / $DNS_SERVER_V6")"
else
    echo "  DNS:       ${DNS_SERVER}$([ "$IPV6" = yes ] && [ -n "${DNS_SERVER_V6:-}" ] && echo " / $DNS_SERVER_V6") direct (bypass blocked)"
fi
_radios="${RADIO}${RADIO_EXTRA:+ + ${RADIO_EXTRA}}"
echo "  Wireless:  $SSID ($ENCRYPTION on $_radios)"
[ "$_agg" -gt 0 ] && echo "  Rate:      $RATE_LIMIT aggregate"
[ "$_per" -gt 0 ] && echo "  Rate:      $RATE_LIMIT_PER_DEVICE per device"
[ "$_agg" -eq 0 ] && [ "$_per" -eq 0 ] && echo "  Rate:      none"
if [ "${LAN_ACCESS:-no}" = yes ]; then
    echo "  Firewall:  ${IFACE}→WAN yes  |  ${IFACE}→LAN no  |  LAN→${IFACE} yes"
else
    echo "  Firewall:  ${IFACE}→WAN yes  |  ${IFACE}→LAN no  |  LAN→${IFACE} no"
fi
if [ "${ALLOWLIST:-no}" = yes ]; then
    echo "  Allowlist: ${BASE_DIR}/${IFACE}-allowed-macs"
    echo "             edit then run: ACTION=ifup INTERFACE=${IFACE} sh /etc/hotplug.d/iface/51-${IFACE}-macfilter"
fi
[ "$ISOLATE" = yes ] && echo "  Isolate:   clients cannot reach each other"
[ -n "$ALLOWED_PORTS" ] && echo "  Ports:     restricted to $ALLOWED_PORTS + NTP"
[ -n "$VLAN_ID" ] && echo "  VLAN:      ${VLAN_TRUNK}.${VLAN_ID} bridged into br-${IFACE}"
[ -n "$NOTIFY_URL" ] && echo "  Notify:    new devices → ntfy"
[ "${JOIN_APPROVAL:-no}" = yes ] && echo "  Join gate: new devices blocked until approved via push notification"
[ "${DEVICE_CONTROL:-no}" = yes ] && echo "  Device control: per-device outbound inspect chain enabled"
[ "$MDNS" = yes ] && echo "  mDNS:      reflecting between LAN and $IFACE"
true
