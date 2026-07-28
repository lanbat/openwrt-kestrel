#!/bin/sh
# Alert when WAN connectivity is restored after an outage.
# Records the outage start time locally (can't alert when down — no internet)
# and sends a recovery notification with the outage duration.
# Runs every 5 minutes via cron.

BASE_DIR=/etc/kestrel/networks
STATE_FILE="${BASE_DIR}/wan-state"
DOWN_SINCE="${BASE_DIR}/wan-down-since"

_notify_url=""
for _conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$_conf" ] || continue
    unset NOTIFY_URL
    . "$_conf"
    [ -n "${NOTIFY_URL:-}" ] && _notify_url="$NOTIFY_URL" && break
done
[ -z "$_notify_url" ] && exit 0

_router_ip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
_dash="http://${_router_ip:-192.168.1.1}/cgi-bin/status"

if ping -c 1 -W 3 1.1.1.1 >/dev/null 2>&1 || ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    _state=up
else
    _state=down
fi

_last=$(cat "$STATE_FILE" 2>/dev/null || echo up)

if [ "$_state" = down ] && [ "$_last" != down ]; then
    printf '%s\n' "$(date +%s)" > "$DOWN_SINCE"
    printf 'down\n' > "$STATE_FILE"
    # Can't send alert — no internet. Will notify on recovery.
elif [ "$_state" = up ] && [ "$_last" = down ]; then
    _since=$(cat "$DOWN_SINCE" 2>/dev/null || echo 0)
    _dur=$(( $(date +%s) - ${_since:-0} ))
    if [ "$_dur" -ge 3600 ]; then
        _dur_str="$(( _dur / 3600 ))h $(( (_dur % 3600) / 60 ))m"
    else
        _dur_str="$(( _dur / 60 ))m"
    fi
    printf 'up\n' > "$STATE_FILE"
    rm -f "$DOWN_SINCE"
    curl -sf -X POST "$_notify_url" \
        -H "Title: WAN restored" \
        -H "Priority: default" \
        -H "Tags: white_check_mark" \
        -H "Actions: view, Dashboard, ${_dash}" \
        -d "WAN connectivity restored after ${_dur_str} outage.
Dashboard: ${_dash}" >/dev/null &
else
    printf '%s\n' "$_state" > "$STATE_FILE"
fi
