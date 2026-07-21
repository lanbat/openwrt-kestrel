#!/bin/sh
# Runs every minute via cron. Scans the system log for blocked LAN→isolated-network
# connection attempts and sends ntfy push notifications for new ones.
#
# Installed automatically by install.sh when NOTIFY_URL is set.

BASE_DIR=/etc/extra-networks
CHECKPOINT=${BASE_DIR}/log-checkpoint
SEEN_FILE=${BASE_DIR}/notified-attempts
TMPLOG=${BASE_DIR}/log-scan.tmp

. "${BASE_DIR}/_lib.sh"

_trim_seen() {
    [ "$(wc -l < "$SEEN_FILE" 2>/dev/null)" -gt 500 ] || return 0
    tail -400 "$SEEN_FILE" > "${SEEN_FILE}.tmp" && mv "${SEEN_FILE}.tmp" "$SEEN_FILE"
}

# Determine repo directory from the stored config
REPO_DIR=$(awk -F= '/^REPO_DIR/ { print $2 }' "${BASE_DIR}/config" 2>/dev/null)

# Count total log lines; reset checkpoint if the log was cleared (reboot)
total=$(logread 2>/dev/null | wc -l)
last=$(cat "$CHECKPOINT" 2>/dev/null || echo 0)
[ "$total" -lt "$last" ] && last=0
echo "$total" > "$CHECKPOINT"
[ "$total" -le "$last" ] && exit 0

# Extract only new lines from this run
new=$(( total - last ))
logread 2>/dev/null | tail -"$new" | grep 'EXTNET-2LAN\|EXTNET-DENY' > "$TMPLOG" || true

[ -s "$TMPLOG" ] || { rm -f "$TMPLOG"; exit 0; }

_router_ip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')

while IFS= read -r line; do
    case "$line" in
    # ── allowlist rejection ───────────────────────────────────────────────────
    *EXTNET-DENY*)
        _t="${line##*EXTNET-DENY-}"; iface="${_t%%[: ]*}"
        [ -z "$iface" ] && continue

        conf="${BASE_DIR}/${iface}-notify.conf"
        [ -f "$conf" ] || continue
        unset NOTIFY_URL SUBNET IFACE_NAME
        . "$conf"
        [ -z "${NOTIFY_URL:-}" ] && continue

        _t="${line##*SRC=}"; src="${_t%% *}"
        [ -z "$src" ] && continue

        key="deny:${iface}:${src}:$(date +%Y%m%d)"
        grep -qxF "$key" "$SEEN_FILE" 2>/dev/null && continue
        printf '%s\n' "$key" >> "$SEEN_FILE"
        _trim_seen

        src_mac=$(awk -v ip="$src" '$1==ip { print $4; exit }' /proc/net/arp 2>/dev/null)
        src_name=$(awk -v ip="$src" '$3==ip { print $4; exit }' /tmp/dhcp.leases 2>/dev/null)
        src_label=$([ -n "$src_name" ] && echo "${src_name} (${src})" || echo "$src")
        if [ -n "$src_mac" ]; then
            _view_url="http://${_router_ip}/cgi-bin/device?net=${iface}&mac=${src_mac}"
        else
            _view_url="http://${_router_ip}/cgi-bin/network?net=${iface}"
        fi
        _ntfy "Blocked device — ${iface}" high no_entry \
"Type: Allowlist rejection

${src_label}${src_mac:+ [${src_mac}]} tried to use the ${iface} network but is not on the allowlist." \
            "view, View device, ${_view_url}"
        continue
        ;;
    # ── LAN access request ────────────────────────────────────────────────────
    *EXTNET-2LAN*) ;;
    *) continue ;;
    esac

    _t="${line##*EXTNET-2LAN-}"; iface="${_t%%[: ]*}"
    [ -z "$iface" ] && continue

    conf="${BASE_DIR}/${iface}-notify.conf"
    [ -f "$conf" ] || continue
    unset NOTIFY_URL SUBNET IFACE_NAME
    . "$conf"
    [ -z "${NOTIFY_URL:-}" ] && continue

    _t="${line##*SRC=}";   src="${_t%% *}"
    _t="${line##*DST=}";   dst="${_t%% *}"
    _t="${line##*PROTO=}"; proto=$(printf '%s' "${_t%% *}" | tr '[:upper:]' '[:lower:]')
    _t="${line##*DPT=}";   port="${_t%% *}"

    [ -z "$src" ] || [ -z "$dst" ] || [ -z "$proto" ] || [ -z "$port" ] && continue

    key="${iface}:${src}:${dst}:${proto}:${port}"
    grep -qxF "$key" "$SEEN_FILE" 2>/dev/null && continue
    printf '%s\n' "$key" >> "$SEEN_FILE"
    _trim_seen

    src_name=$(awk -v ip="$src" '$3==ip { print $4; exit }' /tmp/dhcp.leases 2>/dev/null)
    dst_name=$(awk -v ip="$dst" '$3==ip { print $4; exit }' /tmp/dhcp.leases 2>/dev/null)
    src_label=$([ -n "$src_name" ] && echo "${src_name} (${src})" || echo "$src")
    dst_label=$([ -n "$dst_name" ] && echo "${dst_name} (${dst})" || echo "$dst")

    APPROVE_URL="http://${_router_ip}/cgi-bin/approve-access?net=${iface}&src=${src}&dst=${dst}&proto=${proto}&port=${port}"
    _ntfy "Access request — ${iface}" default lock \
"Type: Access request

${src_label} → ${dst_label}:${port}/${proto}
Approve: ${APPROVE_URL}" \
        "view, Approve, ${APPROVE_URL}"

done < "$TMPLOG"

rm -f "$TMPLOG"
