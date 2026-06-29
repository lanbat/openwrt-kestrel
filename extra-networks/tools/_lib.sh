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

# Convert a small duration string to seconds. Plain numbers mean days.
_duration_secs() {
    _dur="${1:-90d}"
    case "$_dur" in
        *d) _n="${_dur%d}"; printf '%s' "$_n" | grep -qE '^[0-9]+$' && printf '%s' $(( _n * 86400 )) || printf '%s' $(( 90 * 86400 )) ;;
        *h) _n="${_dur%h}"; printf '%s' "$_n" | grep -qE '^[0-9]+$' && printf '%s' $(( _n * 3600 )) || printf '%s' $(( 90 * 86400 )) ;;
        *m) _n="${_dur%m}"; printf '%s' "$_n" | grep -qE '^[0-9]+$' && printf '%s' $(( _n * 60 )) || printf '%s' $(( 90 * 86400 )) ;;
        *[!0-9]*|'') printf '%s' $(( 90 * 86400 )) ;;
        *) printf '%s' $(( _dur * 86400 )) ;;
    esac
}

# Keep join decision history bounded by the configured retention window.
_join_history_prune() {
    _hist="/etc/extra-networks/${1}-join-history"
    [ -f "$_hist" ] || return 0
    _secs=$(_duration_secs "${2:-90d}")
    [ "$_secs" -gt 0 ] 2>/dev/null || { : > "$_hist"; return 0; }
    _cut=$(( $(date +%s) - _secs ))
    awk -F '\t' -v cut="$_cut" '$1 >= cut' "$_hist" > "${_hist}.tmp" \
        && mv "${_hist}.tmp" "$_hist" || true
}

# Append a join approval decision: iface action mac ip host approver retention.
_join_history_add() {
    _hist="/etc/extra-networks/${1}-join-history"
    _ret="${7:-90d}"
    _join_history_prune "$1" "$_ret"
    _when=$(date '+%d %b %H:%M')
    _host=$(printf '%s' "${5:-unknown}" | tr '\t\n' '  ')
    _actor=$(printf '%s' "${6:-unknown}" | tr '\t\n' '  ')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date +%s)" "$_when" "$2" "$3" "$4" "$_host" "$_actor" >> "$_hist"
}
