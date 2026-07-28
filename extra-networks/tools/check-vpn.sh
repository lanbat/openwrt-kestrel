#!/bin/sh
# Push an alert when any VPN tier (split-routing) changes state (up ↔ down).
# Runs every 5 minutes via cron. Installed by install.sh when NOTIFY_URL is set.
# Each vpn-*.conf in /etc/kestrel/split-routing/ is monitored independently.

VPN_BASE=/etc/kestrel/split-routing
BASE_DIR=/etc/kestrel/networks

[ -d "$VPN_BASE" ] || exit 0

# Use NOTIFY_URL from the first extra-networks conf that has one.
_notify_url=""
for _conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset NOTIFY_URL
    . "$_conf"
    [ -n "${NOTIFY_URL:-}" ] && _notify_url="$NOTIFY_URL" && break
done
[ -z "$_notify_url" ] && exit 0

_router_ip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
_dashboard_url="http://${_router_ip:-192.168.1.1}/cgi-bin/status"

for _vpnconf in "${VPN_BASE}"/vpn-*.conf; do
    [ -f "$_vpnconf" ] || continue
    unset VPN_IFACE ROUTE_TABLE FWMARK
    . "$_vpnconf"
    [ -n "${VPN_IFACE:-}" ] || continue

    STATE_FILE="${BASE_DIR}/vpn-state-${VPN_IFACE}"

    _if_up=no; ip link show "$VPN_IFACE" 2>/dev/null | grep -q "LOWER_UP" && _if_up=yes
    _rule=no;  ip rule show 2>/dev/null | grep -q "lookup ${ROUTE_TABLE:-}" && _rule=yes
    _rt=no;    ip route show table "${ROUTE_TABLE:-}" 2>/dev/null | grep -q "^default" && _rt=yes

    [ "$_if_up$_rule$_rt" = yesyesyes ] && _state=up || _state=down

    _last=$(cat "$STATE_FILE" 2>/dev/null || echo "")
    [ "$_state" = "$_last" ] && continue
    printf '%s\n' "$_state" >"$STATE_FILE"

    if [ "$_state" = up ]; then
        curl -sf -X POST "$_notify_url" \
            -H "Title: VPN up — ${VPN_IFACE}" \
            -H "Priority: default" \
            -H "Tags: white_check_mark" \
            -H "Actions: view, Dashboard, ${_dashboard_url}" \
            -d "VPN (${VPN_IFACE}) came back up.
Dashboard: ${_dashboard_url}" >/dev/null &
    else
        curl -sf -X POST "$_notify_url" \
            -H "Title: VPN down — ${VPN_IFACE}" \
            -H "Priority: high" \
            -H "Tags: warning" \
            -H "Actions: view, Dashboard, ${_dashboard_url}" \
            -d "VPN (${VPN_IFACE}) went down. Check the connection.
Dashboard: ${_dashboard_url}" >/dev/null &
    fi
done
