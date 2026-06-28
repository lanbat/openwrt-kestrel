#!/bin/sh
# CGI: serve a WiFi QR code as SVG for a given network.
# Only reachable from LAN. Only works for networks with SHOW_QR=yes.

BASE_DIR=/etc/extra-networks

_get_param() { printf '%s' "$1" | tr '&' '\n' | grep "^${2}=" | head -1 | sed "s/^${2}=//"; }

NET=$(_get_param "${QUERY_STRING:-}" net)
printf '%s' "$NET" | grep -qE '^[a-z][a-z0-9_]*$' \
    || { printf 'Status: 400\r\nContent-Type: text/plain\r\n\r\nBad request'; exit 0; }

_conf="${BASE_DIR}/${NET}-notify.conf"
[ -f "$_conf" ] || { printf 'Status: 404\r\nContent-Type: text/plain\r\n\r\nNot found'; exit 0; }
unset SHOW_QR IFACE_NAME
. "$_conf"

[ "${SHOW_QR:-no}" = yes ] \
    || { printf 'Status: 403\r\nContent-Type: text/plain\r\n\r\nForbidden'; exit 0; }

_iface="${IFACE_NAME:-$NET}"
_ssid=$(uci -q get wireless."$_iface".ssid 2>/dev/null || true)
_key=$(uci -q get wireless."$_iface".key 2>/dev/null || true)
_enc=$(uci -q get wireless."$_iface".encryption 2>/dev/null || true)

[ -n "$_ssid" ] && [ -n "$_key" ] && command -v qrencode >/dev/null 2>&1 \
    || { printf 'Status: 404\r\nContent-Type: text/plain\r\n\r\nNot found'; exit 0; }

case "$_enc" in sae*|psk*) _wtype=WPA ;; wep*) _wtype=WEP ;; *) _wtype=nopass ;; esac

printf 'Content-Type: image/svg+xml\r\nCache-Control: no-store\r\n\r\n'
qrencode -t SVG -s 4 -m 2 -o - "WIFI:S:${_ssid};T:${_wtype};P:${_key};;" 2>/dev/null
