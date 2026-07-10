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
                awk -v ip="$1" 'tolower($1)==tolower(ip)&&/lladdr/{for(i=1;i<=NF;i++)if($i=="lladdr"){print $(i+1);exit}}' ;;
        *)   _m=$(awk -v ip="$1" '$3==ip{print $2;exit}' /tmp/dhcp.leases 2>/dev/null)
             [ -n "$_m" ] || _m=$(ip neigh show 2>/dev/null | \
                awk -v ip="$1" '$1==ip&&/lladdr/{for(i=1;i<=NF;i++)if($i=="lladdr"){print $(i+1);exit}}')
             printf '%s' "$_m" ;;
    esac
}

_ip4_for_mac() {
    _m=$(awk -v m="$1" 'tolower($2)==tolower(m){print $3;exit}' /tmp/dhcp.leases 2>/dev/null)
    [ -n "$_m" ] || _m=$(ip neigh show 2>/dev/null | \
        awk -v m="$1" '$1!~/:/&&/lladdr/{for(i=1;i<=NF;i++)if($i=="lladdr"&&tolower($(i+1))==tolower(m)){print $1;exit}}')
    printf '%s' "$_m"
}

_ip6_for_mac() {
    ip -6 neigh show 2>/dev/null | \
        awk -v m="$1" '!/^fe80:/ && /lladdr/ { for(i=1;i<=NF;i++) if($i=="lladdr" && tolower($(i+1))==tolower(m)){print $1; exit} }'
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

# Write per-device dnsmasq DNS file: dhcp-host for DHCP hostname + host-record for A/AAAA.
# Usage: _write_device_dns iface mac slug ip4 ip6
_write_device_dns() {
    _wd_iface="$1" _wd_mac="$2" _wd_slug="$3" _wd_ip4="${4:-}" _wd_ip6="${5:-}"
    [ -n "$_wd_slug" ] || return 0
    _wd_macn=$(printf '%s' "$_wd_mac" | tr -d ':')
    _wd_domain=$(uci -q get dhcp.@dnsmasq[0].domain 2>/dev/null || true)
    _wd_domain="${_wd_domain:-lan}"
    _wd_fqdn="${_wd_slug}.${_wd_domain}"
    _wd_conf="/etc/dnsmasq.d/${_wd_iface}-dns-${_wd_macn}.conf"
    {   if [ -n "$_wd_ip4" ]; then
            printf 'dhcp-host=%s,%s\n' "$_wd_mac" "$_wd_ip4"
        fi
        if [ -n "$_wd_ip4" ] && [ -n "$_wd_ip6" ]; then
            printf 'host-record=%s,%s,%s\n' "$_wd_fqdn" "$_wd_ip4" "$_wd_ip6"
        elif [ -n "$_wd_ip4" ]; then
            printf 'host-record=%s,%s\n' "$_wd_fqdn" "$_wd_ip4"
        elif [ -n "$_wd_ip6" ]; then
            printf 'host-record=%s,%s\n' "$_wd_fqdn" "$_wd_ip6"
        fi
    } > "$_wd_conf"
    /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
}

# Slugify a label for use as a dnsmasq hostname: lowercase, non-alnum → hyphen.
_slugify() {
    printf '%s' "$1" \
        | tr 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 'abcdefghijklmnopqrstuvwxyz' \
        | sed "s/[^a-z0-9]/-/g; s/--*/-/g; s/^-//; s/-$//"
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
    _htmp="${_hist}.${$}.tmp"
    awk -F '\t' -v cut="$_cut" '$1 >= cut' "$_hist" > "$_htmp" \
        && mv "$_htmp" "$_hist" || { rm -f "$_htmp"; true; }
}

# Append a join approval decision:
# iface action device_mac device_ip4 device_ip6 device_name approver approver_ip4 approver_ip6 approver_mac retention.
_join_history_add() {
    _hist="/etc/extra-networks/${1}-join-history"
    _ret="${11:-90d}"
    _join_history_prune "$1" "$_ret"
    _when=$(date '+%d %b %H:%M')
    _host=$(printf '%s' "${6:-unknown}" | tr '\t\n' '  ')
    _actor=$(printf '%s' "${7:-unknown}" | tr '\t\n' '  ')
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(date +%s)" "$_when" "$2" "$3" "${4:-}" "${5:-}" "$_host" \
        "$_actor" "${8:-}" "${9:-}" "${10:-}" >> "$_hist"
}
