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
MDNS="${MDNS:-no}"

# ── network ──────────────────────────────────────────────────────────────────

# DSA requires an explicit bridge device — netifd won't auto-create one for WiFi-only networks.
uci -q delete network."br_${IFACE}" || true
uci set network."br_${IFACE}"=device
uci set network."br_${IFACE}".name="br-${IFACE}"
uci set network."br_${IFACE}".type=bridge

uci -q delete network."$IFACE" || true
uci set network."$IFACE"=interface
uci set network."$IFACE".proto=static
uci set network."$IFACE".device="br-${IFACE}"
uci set network."$IFACE".ipaddr="${SUBNET}.1"
uci set network."$IFACE".netmask=255.255.255.0

if [ "$IPV6" = yes ]; then
    uci set network."$IFACE".ip6assign=60
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

[ "\$_any" = 1 ] && printf 'dhcp-ignore=tag:!${IFACE}_ok\n' >>"\$DNSMASQ_CONF"

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
# attempts from LAN so check-access-log.sh can notify and allow-service.sh can grant.

rm -f /etc/nftables.d/25-${IFACE}-lanmonitor.nft
if [ -n "$NOTIFY_URL" ] && [ "${LAN_ACCESS:-no}" != yes ]; then
    cat >/etc/nftables.d/25-${IFACE}-lanmonitor.nft <<EOF
chain ${IFACE}_lan_monitor {
    type filter hook forward priority -2; policy accept;
    iifname "br-lan" oifname "br-${IFACE}" ct state new log prefix "EXTNET-LAN2${IFACE}: " level info
}
EOF
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

# ── device notifications ───────────────────────────────────────────────────────
# When NOTIFY_URL is set, dnsmasq calls /usr/sbin/dhcp-notify on each new lease.
# ntfy.sh is the simplest backend: NOTIFY_URL=https://ntfy.sh/my-unique-topic

if [ -n "$NOTIFY_URL" ]; then
    printf 'SUBNET=%s\nNOTIFY_URL=%s\nIFACE_NAME=%s\n' \
        "$SUBNET" "$NOTIFY_URL" "$IFACE" >"${BASE_DIR}/${IFACE}-notify.conf"

    cat >"${BASE_DIR}/dhcp-notify" <<'NOTIFYEOF'
#!/bin/sh
[ "$1" = add ] || exit 0
_mac="$2"; _ip="$3"; _host="${4:-unknown}"
for _conf in /etc/extra-networks/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset SUBNET NOTIFY_URL IFACE_NAME
    . "$_conf"
    case "$_ip" in "$SUBNET".*) ;; *) continue ;; esac
    curl -sf -X POST "$NOTIFY_URL" \
        -H "Title: New device — $IFACE_NAME" \
        -H "Priority: low" \
        -d "${_host} (${_mac}) joined at ${_ip}" >/dev/null &
done
NOTIFYEOF
    chmod 0755 "${BASE_DIR}/dhcp-notify"
    uci set dhcp.@dnsmasq[0].dhcpscript="${BASE_DIR}/dhcp-notify"
    uci commit dhcp

    # Install approval CGI and enable uhttpd CGI support
    mkdir -p /www/cgi-bin
    cp "${SCRIPT_DIR}/tools/approve-access.cgi" /www/cgi-bin/approve-access
    chmod 0755 /www/cgi-bin/approve-access
    if ! uci -q get uhttpd.main.cgi_prefix >/dev/null 2>&1; then
        uci set uhttpd.main.cgi_prefix=/cgi-bin
        uci commit uhttpd
        /etc/init.d/uhttpd restart >/dev/null 2>&1 || true
    fi

    # Cron: check access log every minute for blocked LAN→zone attempts
    ( crontab -l 2>/dev/null | grep -v '# extra-networks-monitor' ) | crontab -
    ( crontab -l 2>/dev/null
      echo "* * * * * sh ${SCRIPT_DIR}/tools/check-access-log.sh  # extra-networks-monitor"
    ) | crontab -
else
    rm -f "${BASE_DIR}/${IFACE}-notify.conf"
    # Remove monitor cron only if no other network still has NOTIFY_URL configured
    if ! ls "${BASE_DIR}"/*-notify.conf >/dev/null 2>&1; then
        ( crontab -l 2>/dev/null | grep -v '# extra-networks-monitor' ) | crontab -
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
wifi reload

# ── summary ───────────────────────────────────────────────────────────────────

echo "Installed: $IFACE"
echo "  Network:   ${SUBNET}.1/24, DHCP ${SUBNET}.100–${SUBNET}.249"
if [ "$IPV6" = yes ]; then
    echo "  IPv6:      enabled (ip6assign /60, DHCPv6 + RA)"
fi
if [ "$DOT" = yes ]; then
    echo "  DNS:       DoT via https-dns-proxy → ${DNS_SERVER}$([ "$IPV6" = yes ] && [ -n "${DNS_SERVER_V6:-}" ] && echo " / $DNS_SERVER_V6")"
else
    echo "  DNS:       ${DNS_SERVER}$([ "$IPV6" = yes ] && [ -n "${DNS_SERVER_V6:-}" ] && echo " / $DNS_SERVER_V6") direct (bypass blocked)"
fi
_radios="$RADIO$([ -n "$RADIO_EXTRA" ] && echo " + $RADIO_EXTRA")"
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
[ -n "$NOTIFY_URL" ] && echo "  Notify:    new devices → ntfy"
[ "$MDNS" = yes ] && echo "  mDNS:      reflecting between LAN and $IFACE"
