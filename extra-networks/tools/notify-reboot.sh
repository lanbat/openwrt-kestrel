#!/bin/sh
# Send a push notification when the router comes back online.
# Installed as a @reboot cron entry by install.sh when NOTIFY_URL is set.
# Loops through all configured networks so one script serves all.

BASE_DIR=/etc/kestrel/networks
hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null || echo router)
timestamp=$(date '+%H:%M on %d/%m/%Y')

seen_urls=""
for conf in "${BASE_DIR}"/*-notify.conf; do
    [ -f "$conf" ] || continue
    unset NOTIFY_URL
    . "$conf"
    [ -z "${NOTIFY_URL:-}" ] && continue

    # Send once per unique URL even if multiple networks share a topic
    case " $seen_urls " in *" $NOTIFY_URL "*) continue ;; esac
    seen_urls="$seen_urls $NOTIFY_URL"

    _router_ip=$(ip addr show br-lan 2>/dev/null | awk '/inet / { split($2,a,"/"); print a[1]; exit }')
    _dashboard_url="http://${_router_ip:-192.168.1.1}/cgi-bin/status"
    curl -sf -X POST "$NOTIFY_URL" \
        -H "Title: Router online — ${hostname}" \
        -H "Priority: low" \
        -H "Tags: white_check_mark" \
        -H "Actions: view, Dashboard, ${_dashboard_url}" \
        -d "Type: Router reboot

Router came back online at ${timestamp}.
Dashboard: ${_dashboard_url}" >/dev/null
done
