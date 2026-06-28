#!/bin/sh
# Shared helpers for extra-networks tools. Copied to /etc/extra-networks/_lib.sh by install.sh.
# Source with: . /etc/extra-networks/_lib.sh

# Load NOTIFY_URL (and other fields) from a network's notify.conf.
_load_notify() {
    unset NOTIFY_URL DEVICE_CONTROL
    _ln_c="/etc/extra-networks/${1}-notify.conf"
    [ -f "$_ln_c" ] && . "$_ln_c"
    true
}

# Resolve a hostname for an IP (IPv4: DHCP leases; IPv6: neighbour → leases).
_name_for_ip() {
    case "$1" in
        *:*) _m=$(ip -6 neigh show 2>/dev/null | \
                awk -v ip="$1" 'tolower($1)==tolower(ip)&&/lladdr/{print $3;exit}')
             [ -n "$_m" ] && awk -v m="$_m" \
                'tolower($2)==tolower(m){print $4;exit}' /tmp/dhcp.leases 2>/dev/null \
             || true ;;
        *)   awk -v ip="$1" '$3==ip{print $4;exit}' /tmp/dhcp.leases 2>/dev/null ;;
    esac
}

# Resolve a MAC address for an IP (IPv4: DHCP leases; IPv6: neighbour table).
_mac_for_ip() {
    case "$1" in
        *:*) ip -6 neigh show 2>/dev/null | \
                awk -v ip="$1" 'tolower($1)==tolower(ip)&&/lladdr/{print $3;exit}' ;;
        *)   awk -v ip="$1" '$3==ip{print $2;exit}' /tmp/dhcp.leases 2>/dev/null ;;
    esac
}

# Send a push notification via ntfy. Requires NOTIFY_URL to be set.
# Usage: _ntfy <title> <priority> <tags> <body> [extra_action]
# extra_action: prepended before the dashboard action, e.g. "view, Approve, URL"
_ntfy() {
    [ -n "${NOTIFY_URL:-}" ] || return 0
    _ntfy_rip=$(ip addr show br-lan 2>/dev/null \
        | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
    _ntfy_dash="http://${_ntfy_rip:-192.168.1.1}/cgi-bin/status"
    curl -sf -X POST "$NOTIFY_URL" \
        -H "Title: $1" \
        -H "Priority: $2" \
        -H "Tags: $3" \
        -H "Actions: ${5:+${5}; }view, Dashboard, ${_ntfy_dash}" \
        -d "$4
Dashboard: ${_ntfy_dash}" >/dev/null &
}

# Resolve a device label for a MAC from {iface}-device-labels; falls back to MAC.
_label_for_mac() {
    _lf="/etc/extra-networks/${2}-device-labels"
    [ -f "$_lf" ] || { printf '%s' "$1"; return; }
    _l=$(awk -v m="$1" 'tolower($1)==tolower(m){sub(/^[^\t]+\t/,""); print; exit}' "$_lf")
    printf '%s' "${_l:-$1}"
}

# Return the static IP for a MAC from {iface}-device-ips, or empty.
_ip_for_mac() {
    _if="/etc/extra-networks/${2}-device-ips"
    [ -f "$_if" ] || return 0
    awk -v m="$1" 'tolower($1)==tolower(m){print $2; exit}' "$_if"
}
