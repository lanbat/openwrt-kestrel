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

RADIO="${RADIO:-radio0}"
ENCRYPTION="${ENCRYPTION:-psk2+psk3}"
ALLOWLIST="${ALLOWLIST:-no}"
RATE_LIMIT="${RATE_LIMIT:-0}"
DNS_SERVER="${DNS_SERVER:-1.1.1.3}"
WIFI_UCI="${WIFI_UCI:-$IFACE}"

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

uci commit network

# ── dhcp ─────────────────────────────────────────────────────────────────────

uci -q delete dhcp."$IFACE" || true
uci set dhcp."$IFACE"=dhcp
uci set dhcp."$IFACE".interface="$IFACE"
uci set dhcp."$IFACE".start=100
uci set dhcp."$IFACE".limit=150
uci set dhcp."$IFACE".leasetime=12h
# Give clients the filtered DNS server directly — they never talk to the router's dnsmasq.
uci -q delete dhcp."$IFACE".dhcp_option || true
uci add_list dhcp."$IFACE".dhcp_option="6,$DNS_SERVER"

uci commit dhcp

# ── firewall ──────────────────────────────────────────────────────────────────

uci -q delete firewall."${IFACE}_zone" || true
uci set firewall."${IFACE}_zone"=zone
uci set firewall."${IFACE}_zone".name="$IFACE"
uci set firewall."${IFACE}_zone".network="$IFACE"
uci set firewall."${IFACE}_zone".input=REJECT
uci set firewall."${IFACE}_zone".output=ACCEPT
uci set firewall."${IFACE}_zone".forward=REJECT

uci -q delete firewall."${IFACE}_dhcp" || true
uci set firewall."${IFACE}_dhcp"=rule
uci set firewall."${IFACE}_dhcp".name="Allow-DHCP-${IFACE}"
uci set firewall."${IFACE}_dhcp".src="$IFACE"
uci set firewall."${IFACE}_dhcp".proto=udp
uci set firewall."${IFACE}_dhcp".dest_port=67
uci set firewall."${IFACE}_dhcp".target=ACCEPT

uci -q delete firewall."${IFACE}_wan" || true
uci set firewall."${IFACE}_wan"=forwarding
uci set firewall."${IFACE}_wan".src="$IFACE"
uci set firewall."${IFACE}_wan".dest=wan

# Block DNS bypass — clients must use the DHCP-assigned DNS server.
uci -q delete firewall."${IFACE}_dns_block" || true
uci set firewall."${IFACE}_dns_block"=rule
uci set firewall."${IFACE}_dns_block".name="Block-DNS-bypass-${IFACE}"
uci set firewall."${IFACE}_dns_block".src="$IFACE"
uci set firewall."${IFACE}_dns_block".dest=wan
uci set firewall."${IFACE}_dns_block".dest_ip="!$DNS_SERVER"
uci set firewall."${IFACE}_dns_block".proto="tcp udp"
uci set firewall."${IFACE}_dns_block".dest_port=53
uci set firewall."${IFACE}_dns_block".target=REJECT

uci commit firewall

# ── wireless ──────────────────────────────────────────────────────────────────

# Create the wifi-iface section if it doesn't exist yet.
if ! uci -q get wireless."$WIFI_UCI" >/dev/null 2>&1; then
    uci set wireless."$WIFI_UCI"=wifi-iface
    uci set wireless."$WIFI_UCI".device="$RADIO"
    uci set wireless."$WIFI_UCI".mode=ap
fi
uci set wireless."$WIFI_UCI".ssid="$SSID"
uci set wireless."$WIFI_UCI".key="$WIFI_KEY"
uci set wireless."$WIFI_UCI".encryption="$ENCRYPTION"
uci set wireless."$WIFI_UCI".network="$IFACE"
uci set wireless."$WIFI_UCI".disabled=0

uci commit wireless

# ── rate limiting via nftables ────────────────────────────────────────────────
# tc tbf requires kmod-sched-core which is not packaged for this platform.
# nft limit rate drops excess packets instead of queuing — acceptable for IoT/guest.

mkdir -p /etc/nftables.d

if [ "${RATE_LIMIT:-0}" != "0" ]; then
    case "$RATE_LIMIT" in
        *[Mm]bit) _rate_kbytes=$(( $(echo "$RATE_LIMIT" | sed 's/[Mm]bit$//') * 125 )) ;;
        *[Kk]bit) _rate_kbytes=$(( $(echo "$RATE_LIMIT" | sed 's/[Kk]bit$//') / 8 )) ;;
        *) echo "ERROR: RATE_LIMIT must be in mbit or kbit (e.g. 1mbit, 500kbit)"; exit 1 ;;
    esac
    # Files in /etc/nftables.d/ are included inside table inet fw4 by fw4.
    cat >/etc/nftables.d/20-${IFACE}-ratelimit.nft <<EOF
chain ${IFACE}_ratelimit {
    type filter hook forward priority 1; policy accept;
    iifname "br-${IFACE}" limit rate over ${_rate_kbytes} kbytes/second drop
    oifname "br-${IFACE}" limit rate over ${_rate_kbytes} kbytes/second drop
}
EOF
else
    rm -f /etc/nftables.d/20-${IFACE}-ratelimit.nft
fi

# ── device allowlist (MAC → IP) ───────────────────────────────────────────────
# Bridge-family nftables is unavailable on this platform (kmod not compiled in),
# so MAC filtering is done in two layers:
#   1. dnsmasq denies DHCP leases to unlisted MACs
#   2. nft blocks forwarding from any IP not assigned to an allowed MAC

if [ "${ALLOWLIST:-no}" = yes ]; then
    MAC_FILE=/etc/${IFACE}-allowed-macs
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

MAC_FILE=/etc/${IFACE}-allowed-macs
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

# ── apply ─────────────────────────────────────────────────────────────────────

/etc/init.d/network reload
/etc/init.d/dnsmasq restart
fw4 reload
wifi reload

# ── summary ───────────────────────────────────────────────────────────────────

echo "Installed: $IFACE"
echo "  Network:   ${SUBNET}.1/24, DHCP ${SUBNET}.100–${SUBNET}.249"
echo "  DNS:       $DNS_SERVER (bypass blocked)"
echo "  Wireless:  $SSID ($ENCRYPTION on $RADIO)"
echo "  Rate:      ${RATE_LIMIT:-none}"
echo "  Firewall:  ${IFACE}→WAN yes  |  ${IFACE}→LAN no  |  ${IFACE}→router no"
if [ "${ALLOWLIST:-no}" = yes ]; then
    echo "  Allowlist: /etc/${IFACE}-allowed-macs"
    echo "             edit then run: ACTION=ifup INTERFACE=${IFACE} sh /etc/hotplug.d/iface/51-${IFACE}-macfilter"
fi
