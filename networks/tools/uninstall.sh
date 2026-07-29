#!/bin/sh
# Remove a network installed by install.sh.
#
# Usage: sh uninstall.sh <config-file> [--purge]
#
#   --purge   also remove the allowed-macs file (permanent device list)

set -eu

[ $# -ge 1 ] || { echo "Usage: sh uninstall.sh <config-file> [--purge]"; exit 1; }

CONFIG="$1"
PURGE=no
[ "${2:-}" = "--purge" ] && PURGE=yes

[ -f "$CONFIG" ] || { echo "ERROR: config not found: $CONFIG"; exit 1; }
. "$CONFIG"

[ -z "${IFACE:-}" ] && { echo "ERROR: IFACE not set in config"; exit 1; }

BASE_DIR=/etc/kestrel/networks

echo "Removing network: $IFACE"

# ── wireless ──────────────────────────────────────────────────────────────────

WIFI_UCI="${WIFI_UCI:-$IFACE}"
if uci -q get wireless."$WIFI_UCI" >/dev/null 2>&1; then
    uci delete wireless."$WIFI_UCI"
    echo "  Removed wireless UCI section: $WIFI_UCI"
fi
# Extra radio (dual-band)
if [ -n "${RADIO_EXTRA:-}" ] && uci -q get wireless."${WIFI_UCI}_extra" >/dev/null 2>&1; then
    uci delete wireless."${WIFI_UCI}_extra"
    echo "  Removed wireless UCI section: ${WIFI_UCI}_extra"
fi
uci commit wireless

# ── network ───────────────────────────────────────────────────────────────────

uci -q delete network."$IFACE"    && echo "  Removed network interface: $IFACE"
uci -q delete network."br_${IFACE}" && echo "  Removed bridge device: br-${IFACE}"
uci commit network

# ── dhcp ─────────────────────────────────────────────────────────────────────

uci -q delete dhcp."$IFACE" && echo "  Removed DHCP config: $IFACE"
uci commit dhcp

# ── firewall ──────────────────────────────────────────────────────────────────

for section in \
    "${IFACE}_zone" "${IFACE}_dhcp" "${IFACE}_dhcp6" "${IFACE}_wan" \
    "${IFACE}_dns_block" "${IFACE}_dns_block6" \
    "${IFACE}_dns_input" "${IFACE}_dot_block" "lan_${IFACE}"; do
    uci -q delete firewall."$section" 2>/dev/null && echo "  Removed firewall: $section"
done

# Remove any port forward rules sourced from this zone.
changed=1
while [ "$changed" = 1 ]; do
    changed=0
    for s in $(uci show firewall 2>/dev/null \
               | awk -F= '/=redirect/ { sec=$1; sub(/=redirect/,"",sec); print sec }'); do
        src=$(uci -q get firewall."$s".src 2>/dev/null || true)
        if [ "$src" = "$IFACE" ]; then
            name=$(uci -q get firewall."$s".name 2>/dev/null || echo "$s")
            uci delete firewall."$s"
            ( crontab -l 2>/dev/null | grep -v "# $name" ) | crontab -
            echo "  Removed port forward: $name"
            changed=1
            break
        fi
    done
done

uci commit firewall

# ── nftables ──────────────────────────────────────────────────────────────────

for f in \
    /etc/nftables.d/20-${IFACE}-ratelimit.nft \
    /etc/nftables.d/21-${IFACE}-allowlist.nft \
    /etc/nftables.d/22-${IFACE}-ports.nft \
    /etc/nftables.d/24-${IFACE}-counter.nft \
    /etc/nftables.d/25-${IFACE}-lanmonitor.nft \
    /etc/nftables.d/30-${IFACE}-timeblock.nft; do
    [ -f "$f" ] && rm -f "$f" && echo "  Removed: $f"
done

# Remove any temporary LAN allow rules for this network
for s in $(uci show firewall 2>/dev/null \
           | awk -F= "/^firewall\\.allow_lan_${IFACE}_/ { gsub(/\\..*/, \"\", \$1); print \$1 }" \
           | sort -u | sed 's/^firewall\.//'); do
    uci -q delete firewall."$s" 2>/dev/null && echo "  Removed temp allow: $s"
    ( crontab -l 2>/dev/null | grep -v "# $s" ) | crontab -
done
[ -n "$(uci changes firewall 2>/dev/null)" ] && uci commit firewall

# ── hotplug / dnsmasq / allowlist ─────────────────────────────────────────────

rm -f /etc/hotplug.d/iface/51-${IFACE}-macfilter \
      /etc/dnsmasq.d/${IFACE}-macfilter.conf \
      "${BASE_DIR}/${IFACE}-notify.conf" \
      /www/net/${IFACE}.html
( crontab -l 2>/dev/null | grep -v "# access-${IFACE}" ) | crontab - 2>/dev/null || true
echo "  Removed hotplug, notify, schedule, and dnsmasq macfilter files"

if [ "$PURGE" = yes ]; then
    rm -f "${BASE_DIR}/${IFACE}-allowed-macs" && echo "  Removed allowed-macs file (--purge)"
else
    [ -f "${BASE_DIR}/${IFACE}-allowed-macs" ] \
        && echo "  Kept ${BASE_DIR}/${IFACE}-allowed-macs (pass --purge to remove)"
fi

# ── apply ─────────────────────────────────────────────────────────────────────

wifi reload
/etc/init.d/network reload
/etc/init.d/dnsmasq restart
fw4 reload

echo "Done. Network '$IFACE' has been removed."
