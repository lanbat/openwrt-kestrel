#!/bin/sh
# CGI: rotate the WiFi password for a network.
# Only reachable from LAN — isolated network zones have INPUT=REJECT.

BASE_DIR=/etc/extra-networks
. "${BASE_DIR}/_lib.sh"

_html()      { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }
_get_param() { printf '%s' "$1" | tr '&' '\n' | grep "^${2}=" | head -1 | sed "s/^${2}=//"; }

# Only allow POST
[ "${REQUEST_METHOD:-GET}" = "POST" ] || {
    printf 'Content-Type: text/html\r\n\r\n<h1>Method not allowed</h1>'
    exit 0
}

# CSRF: reject POSTs whose Origin/Referer is not a private address
_origin="${HTTP_ORIGIN:-${HTTP_REFERER:-}}"
case "$_origin" in
    ""|http://192.168.*|http://10.*|http://172.1[6-9].*|http://172.2[0-9].*|http://172.3[01].*) ;;
    *) printf 'Content-Type: text/html\r\n\r\nForbidden'; exit 0 ;;
esac

# Read POST body
_cl="${CONTENT_LENGTH:-0}"
printf '%s' "$_cl" | grep -qE '^[0-9]+$' && [ "$_cl" -le 256 ] \
    || { printf 'Content-Type: text/html\r\n\r\nBad request'; exit 0; }
_params=$(head -c "$_cl")
[ -n "${QUERY_STRING:-}" ] && _params="${QUERY_STRING}&${_params}"

NET=$(_get_param "$_params" net)
printf '%s' "$NET" | grep -qE '^[a-z][a-z0-9_]*$' \
    || { printf 'Content-Type: text/html\r\n\r\n<h1>Invalid network</h1>'; exit 0; }

# Load notify config and check feature is enabled
_conf="${BASE_DIR}/${NET}-notify.conf"
[ -f "$_conf" ] || { printf 'Content-Type: text/html\r\n\r\n<h1>Unknown network</h1>'; exit 0; }
unset NOTIFY_URL IFACE_NAME ROTATE_PASSWORD
. "$_conf"
[ "${ROTATE_PASSWORD:-no}" = yes ] \
    || { printf 'Content-Type: text/html\r\n\r\n<h1>Not enabled for this network</h1>'; exit 0; }

_iface="${IFACE_NAME:-$NET}"
uci -q get wireless."$_iface" >/dev/null 2>&1 \
    || { printf 'Content-Type: text/html\r\n\r\n<h1>Wireless section not found: %s</h1>' "$(_html "$_iface")"; exit 0; }

# Generate new password (read until we have 20 alphanumeric chars)
_newpw=$(tr -dc 'a-zA-Z0-9' </dev/urandom 2>/dev/null | head -c 20)
[ "${#_newpw}" -eq 20 ] || { printf 'Content-Type: text/html\r\n\r\n<h1>Failed to generate password</h1>'; exit 0; }

# Apply to UCI (primary + extra radio if present)
uci set wireless."${_iface}".key="$_newpw"
uci -q get wireless."${_iface}_extra" >/dev/null 2>&1 \
    && uci set wireless."${_iface}_extra".key="$_newpw"
uci commit wireless

# Clear join approvals — everyone re-connects with the new password and needs re-approval
rm -f "${BASE_DIR}/${_iface}-join-approved" "${BASE_DIR}/${_iface}-join-pending"

# Update config file if it exists (keeps rotate-password.sh in sync)
REPO_DIR=$(awk -F'=' '/^REPO_DIR/ { gsub(/[[:space:]]/, "", $2); print $2 }' "${BASE_DIR}/config" 2>/dev/null || true)
_cfg="${REPO_DIR}/configs/${_iface}.conf"
[ -n "$REPO_DIR" ] && [ -f "$_cfg" ] && grep -q '^WIFI_KEY=' "$_cfg" \
    && sed -i "s|^WIFI_KEY=.*|WIFI_KEY=${_newpw}|" "$_cfg"

# Reload wireless after a delay so the browser can receive and render the
# response before the WiFi drops. 5s gives plenty of time even on slow links.
(sleep 5 && wifi reload >/dev/null 2>&1) &

# Push notification with new password
_load_notify "$_iface"
_ntfy "Password rotated — ${_iface}" default key \
"The WiFi password for ${_iface} was rotated. Scan the QR code on the dashboard to reconnect."

printf 'Content-Type: text/html\r\n\r\n'
printf '<!DOCTYPE html><html><head><meta http-equiv="refresh" content="1;url=/cgi-bin/status"></head>'
printf '<body>Password rotated. Returning to dashboard&hellip;</body></html>\n'
