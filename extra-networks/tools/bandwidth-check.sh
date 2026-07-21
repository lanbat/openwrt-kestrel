#!/bin/sh
# Alert when a device on an isolated network exceeds BANDWIDTH_THRESHOLD_MB
# in a session (counter resets on fw4 reload or after 24h of inactivity).
# Combines IPv4 and IPv6 bytes per device (matched by MAC address).
# Runs hourly via cron. Installed by install.sh when NOTIFY_URL is set.

BASE_DIR=/etc/extra-networks
. "${BASE_DIR}/_lib.sh"

_human() {
    awk -v b="${1:-0}" 'BEGIN {
        if      (b+0 >= 1073741824) printf "%.1f GB", b/1073741824
        else if (b+0 >= 1048576)   printf "%.1f MB", b/1048576
        else if (b+0 >= 1024)      printf "%.1f KB", b/1024
        else                       printf "%d B",     b+0
    }'
}

# Parse "IP bytes" pairs from an nft set listing.
# $1 = ip (dot-separated) or ip6 (colon-separated)
_nft_entries() {
    awk -v fam="$1" '/bytes/ {
        ip=""; bytes=0
        for (i=1; i<=NF; i++) {
            if (fam == "ip"  && $i ~ /^[0-9]+\.[0-9.]+$/) ip=$i
            if (fam == "ip6" && split($i,a,":") >= 3)      ip=$i
            if ($i == "bytes") bytes = $(i+1)
        }
        if (ip) print ip, bytes
    }'
}

_rip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
_rip="${_rip:-192.168.1.1}"

for _conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset NOTIFY_URL SUBNET IFACE_NAME BANDWIDTH_THRESHOLD_MB
    . "$_conf"
    [ -z "${NOTIFY_URL:-}" ] && continue
    [ -z "${IFACE_NAME:-}" ] && continue

    _thresh="${BANDWIDTH_THRESHOLD_MB:-0}"
    [ "$_thresh" -le 0 ] 2>/dev/null && continue

    _thresh_bytes=$(( _thresh * 1048576 ))
    _iface="$IFACE_NAME"
    _alerted="${BASE_DIR}/${_iface}-bw-alerted"

    # Read IPv4 and IPv6 byte counts; both may be empty if no traffic yet.
    _v4=$(nft list set inet fw4 "${_iface}_device_bytes"  2>/dev/null | _nft_entries ip)
    _v6=$(nft list set inet fw4 "${_iface}_device_bytes6" 2>/dev/null | _nft_entries ip6)
    [ -z "$_v4" ] && [ -z "$_v6" ] && continue

    # Cache the neigh table for IPv6→MAC mapping (one call per network).
    _neigh6=$(ip -6 neigh show dev "br-${_iface}" 2>/dev/null \
        | awk '/lladdr/ { for(i=1;i<=NF;i++) if($i=="lladdr") { print $1"\t"tolower($(i+1)); break } }')

    # Combine IPv4 and IPv6 bytes per MAC.
    # Output: MAC  rep_ip  total_bytes
    _combined=$(
        {
            printf '%s\n' "$_v4" | while read -r _ip _bytes; do
                _mac=$(awk -v ip="$_ip" '$3==ip{print tolower($2);exit}' /tmp/dhcp.leases 2>/dev/null)
                [ -n "$_mac" ] && printf '%s\t%s\t%s\n' "$_mac" "$_ip" "$_bytes"
            done
            printf '%s\n' "$_v6" | while read -r _ip6 _bytes; do
                _mac=$(printf '%s\n' "$_neigh6" \
                    | awk -v ip="$_ip6" '$1==ip{print $2; exit}')
                [ -n "$_mac" ] && printf '%s\t%s\t%s\n' "$_mac" "$_ip6" "$_bytes"
            done
        } | awk -F'\t' '
            NF==3 {
                if (!rep[$1]) rep[$1]=$2
                total[$1]+=$3
            }
            END { for (m in total) print m"\t"rep[m]"\t"total[m] }
        '
    )

    [ -z "$_combined" ] && continue

    printf '%s\n' "$_combined" | while IFS=$(printf '\t') read -r _mac _ip _bytes; do
        grep -qixF "$_mac" "$_alerted" 2>/dev/null && continue

        if [ "$_bytes" -gt "$_thresh_bytes" ] 2>/dev/null; then
            _name=$(awk -v ip="$_ip" '$3==ip{print $4;exit}' /tmp/dhcp.leases 2>/dev/null)
            _label="${_name:+${_name} (${_ip})}${_name:-${_ip}}"
            printf '%s\n' "$_mac" >> "$_alerted"
            _ntfy "Bandwidth alert — ${_iface}" default warning \
"Type: Bandwidth alert

${_label} has used $(_human "$_bytes") on ${_iface} (threshold: ${_thresh} MB)." \
                "view, Device, http://${_rip}/cgi-bin/device?net=${_iface}&mac=${_mac}"
        fi
    done

    # Remove MACs from the alerted file that are no longer in the tracking sets.
    if [ -f "$_alerted" ]; then
        printf '%s\n' "$_combined" | awk -F'\t' '{print $1}' \
            | grep -ixFf - "$_alerted" > "${_alerted}.tmp" 2>/dev/null \
            && mv "${_alerted}.tmp" "$_alerted" || rm -f "${_alerted}.tmp"
    fi
done
