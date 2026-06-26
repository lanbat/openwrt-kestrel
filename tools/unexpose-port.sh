#!/bin/sh
# Remove a port forwarding rule created by expose-port.sh.
#
# Usage: sh unexpose-port.sh <name>
#
# Example: sh unexpose-port.sh expose-guest-27015

set -eu

[ $# -eq 1 ] || { echo "Usage: sh unexpose-port.sh <name>"; exit 1; }

NAME="$1"

# ── remove firewall redirect ───────────────────────────────────────────────────

found=0
for s in $(uci show firewall | grep '=redirect' | cut -d. -f2 | cut -d= -f1); do
    n=$(uci -q get firewall."$s".name 2>/dev/null || true)
    if [ "$n" = "$NAME" ]; then
        uci delete firewall."$s"
        found=1
        break
    fi
done

[ "$found" = 0 ] && { echo "ERROR: no rule named '$NAME' found"; exit 1; }

uci commit firewall
fw4 reload >/dev/null

# ── remove scheduled cron entry ───────────────────────────────────────────────

( crontab -l 2>/dev/null | grep -v "# $NAME" ) | crontab -

echo "Removed: $NAME"
