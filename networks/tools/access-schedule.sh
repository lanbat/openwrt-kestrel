#!/bin/sh
# Restrict internet access for an isolated network to specific hours.
#
# Usage:
#   sh access-schedule.sh <config-file> <HH-HH>   set hours (e.g. 8-23 = 8am–11pm)
#   sh access-schedule.sh <config-file> always     remove schedule — always on
#   sh access-schedule.sh <config-file> status     show current schedule and state
#
# Access outside the window is blocked at the nftables level — all forwarding from
# the network is dropped until the window opens again. The schedule survives reboots
# via cron.

set -eu

[ $# -ge 2 ] || { echo "Usage: sh access-schedule.sh <config-file> <HH-HH|always|status>"; exit 1; }

CONFIG="$1"
CMD="$2"

[ -f "$CONFIG" ] || { echo "ERROR: config not found: $CONFIG"; exit 1; }
. "$CONFIG"
[ -z "${IFACE:-}" ] && { echo "ERROR: IFACE not set"; exit 1; }

SCRIPT_ABS="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
CONFIG_ABS="$(cd "$(dirname "$CONFIG")" && pwd)/$(basename "$CONFIG")"
BLOCK_FILE="/etc/nftables.d/30-${IFACE}-timeblock.nft"
CRON_TAG="# access-${IFACE}"

_block() {
    cat >"$BLOCK_FILE" <<EOF
chain ${IFACE}_timeblock {
    type filter hook forward priority -3; policy accept;
    iifname "br-${IFACE}" drop
    oifname "br-${IFACE}" drop
}
EOF
    fw4 reload >/dev/null
    printf '  Blocked:  %s (no internet)\n' "$IFACE"
}

_unblock() {
    rm -f "$BLOCK_FILE"
    fw4 reload >/dev/null
    printf '  Open:     %s (internet on)\n' "$IFACE"
}

_remove_cron() {
    ( crontab -l 2>/dev/null | grep -v "$CRON_TAG" ) | crontab -
}

case "$CMD" in

    always)
        _remove_cron
        _unblock
        echo "Schedule removed — $IFACE always on."
        ;;

    status)
        printf '\n  Schedule for %s:\n' "$IFACE"
        entries=$(crontab -l 2>/dev/null | grep "$CRON_TAG" || true)
        if [ -z "$entries" ]; then
            printf '  Hours:    always on (no schedule)\n'
        else
            on_h=$(echo "$entries"  | awk '/unblock/ { print $2 }')
            off_h=$(echo "$entries" | awk '/block/   { print $2 }')
            printf '  Hours:    %s:00 – %s:00\n' "${on_h:-?}" "${off_h:-?}"
        fi
        if [ -f "$BLOCK_FILE" ]; then
            printf '  State:    BLOCKED\n'
        else
            printf '  State:    open\n'
        fi
        ;;

    block)   _block   ;;
    unblock) _unblock ;;

    *-*)
        START="${CMD%-*}"
        END="${CMD#*-}"
        ( [ "$START" -ge 0 ] && [ "$START" -le 23 ] ) 2>/dev/null \
            || { echo "ERROR: invalid start hour '$START'"; exit 1; }
        ( [ "$END" -ge 0 ]   && [ "$END" -le 23 ] ) 2>/dev/null \
            || { echo "ERROR: invalid end hour '$END'"; exit 1; }

        _remove_cron
        {
            crontab -l 2>/dev/null
            printf '0 %s * * * sh %s %s unblock %s\n' "$START" "$SCRIPT_ABS" "$CONFIG_ABS" "$CRON_TAG"
            printf '0 %s * * * sh %s %s block   %s\n' "$END"   "$SCRIPT_ABS" "$CONFIG_ABS" "$CRON_TAG"
        } | crontab -

        CURR_H=$(date +%H | sed 's/^0*//')
        CURR_H="${CURR_H:-0}"
        if [ "$CURR_H" -ge "$START" ] && [ "$CURR_H" -lt "$END" ]; then
            _unblock
        else
            _block
        fi
        printf 'Schedule set: %s on %s:00 – %s:00 daily\n' "$IFACE" "$START" "$END"
        ;;

    *)
        echo "ERROR: unknown command '$CMD' — use HH-HH, always, or status"
        exit 1
        ;;
esac
